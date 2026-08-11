"""Политика решения: три исхода и асимметрия ошибок.

Ключевой принцип: **турникет открывается только когда система уверена по всем
осям сразу**. Любая неуверенность — качество, liveness, малый отрыв от второго
кандидата, деградированный режим — уходит охране, а не открывает дверь.

Порядок проверок выбран не произвольно:

1. `no_face` — сначала выясняем, есть ли вообще кого проверять;
2. **жёсткий liveness** — раньше проверки качества, потому что предъявление
   экрана или распечатки это активная атака, и её нужно записать как атаку.
   Если поставить качество раньше, атакующий гарантированно уходит в мягкий
   `manual_review`, просто испортив кадр, и в метриках безопасности атаки исчезнут;
3. качество кадра — дальше считать бессмысленно;
4. мягкий liveness — сомнение без явной атаки;
5. идентификация и только потом авторизация — см. docs/architecture.md;
6. деградация — последним, потому что она ужесточает пороги, а не заменяет их.

Асимметрия ошибок: false accept — инцидент безопасности с ценой на три порядка
выше цены false reject (допущение A5 в docs/product.md). Поэтому рабочая точка
выбирается по FAR, а не по accuracy, а в offline-режиме пороги ужесточаются.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional

from .contracts import AccessDecision, AccessEvent, MatchResult, QualityReport

POLICY_VERSION = "policy-2026.08.1"


@dataclass(frozen=True)
class Thresholds:
    """Рабочая точка. Числа — целевые из docs/ml.md, а не измеренные здесь."""

    quality_min: float = 0.55
    liveness_deny_below: float = 0.35
    liveness_min: float = 0.70
    match_allow: float = 0.72
    match_review: float = 0.55
    margin_min: float = 0.08
    # Деградированный режим: те же оси, но строже.
    offline_match_allow: float = 0.80
    offline_margin_min: float = 0.15
    offline_max_cache_age_minutes: int = 60

    def degraded(self) -> "Thresholds":
        return replace(self, match_allow=self.offline_match_allow, margin_min=self.offline_margin_min)


DEFAULT_THRESHOLDS = Thresholds()


@dataclass
class PolicyOutcome:
    decision: str
    reasons: list[str]
    requires_human_review: bool


def _hold(reasons: list[str], *, review: bool = True) -> PolicyOutcome:
    return PolicyOutcome("manual_review", reasons, review)


def _deny(reasons: list[str], *, review: bool = False) -> PolicyOutcome:
    return PolicyOutcome("deny", reasons, review)


def evaluate(
    event: AccessEvent,
    quality: QualityReport,
    match: Optional[MatchResult],
    visible_status: str,
    *,
    degraded: bool,
    stale_cache: bool,
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
) -> PolicyOutcome:
    """Чистая функция: одни и те же входы всегда дают одно и то же решение."""

    t = thresholds.degraded() if degraded else thresholds

    if not quality.face_detected:
        reason = "frame_unreadable" if "frame_unreadable" in quality.notes else "no_face_detected"
        return _hold([reason])

    if quality.faces_in_frame > 1:
        # Несколько лиц в кадре — кандидат на проход «паровозиком».
        return _hold(["multiple_faces_in_frame", "tailgating_suspected"])

    if quality.liveness_score < t.liveness_deny_below:
        return _deny(["liveness_failed", "presentation_attack_suspected"], review=True)

    if quality.quality_score < t.quality_min:
        return _hold(["quality_below_threshold"])

    if quality.liveness_score < t.liveness_min:
        return _hold(["liveness_uncertain"])

    if match is None or match.employee_id is None:
        return _deny(["no_match_in_directory"])

    # --- авторизация отделена от идентификации ---
    if visible_status in ("revoked", "suspended"):
        # Человека узнали, но доступа у него нет. Охрану зовём обязательно:
        # появление уволенного на проходной — событие безопасности, а не рутина.
        return _deny([f"access_{visible_status}", "known_person_without_access"], review=True)
    if visible_status == "unknown":
        return _deny(["employee_not_in_directory"])

    if match.match_score < t.match_review:
        return _deny(["match_below_review_threshold"])

    # --- деградация: доверять авторизации из устаревшего кеша нельзя ---
    if stale_cache:
        return _hold(["degraded_mode", "stale_access_cache", "revocation_may_be_missing"])

    reasons: list[str] = ["quality_ok", "liveness_ok"]
    if degraded:
        reasons.append("degraded_mode_strict_thresholds")

    ambiguous = match.margin_to_second_best < t.margin_min
    if match.match_score < t.match_allow:
        extra = ["match_below_allow_threshold"]
        if ambiguous:
            # Отдельная причина: охране важно знать, что кандидатов было двое.
            extra.append("ambiguous_candidates")
        return _hold(reasons + extra)
    if ambiguous:
        return _hold(reasons + ["ambiguous_candidates", "margin_below_threshold"])

    return PolicyOutcome("allow", reasons + ["match_above_threshold", "margin_ok"], False)


def turnstile_command(decision: str, *, duplicate: bool) -> str:
    """Идемпотентность: повтор того же события никогда не открывает турникет дважды."""
    if duplicate:
        return "noop"
    return "open" if decision == "allow" else "hold"


def build_decision(
    event: AccessEvent,
    quality: QualityReport,
    match: Optional[MatchResult],
    outcome: PolicyOutcome,
    *,
    decision_id: str,
    audit_id: str,
    degraded: bool,
    latency_ms: int,
    duplicate: bool = False,
) -> AccessDecision:
    reasons = list(outcome.reasons) + (["duplicate_event"] if duplicate else [])
    return AccessDecision(
        event_id=event.event_id,
        decision_id=decision_id,
        decision=outcome.decision,
        employee_id=match.employee_id if match else None,
        match_score=round(match.match_score, 4) if match else 0.0,
        margin_to_second_best=round(match.margin_to_second_best, 4) if match else 0.0,
        quality={
            "face_detected": quality.face_detected,
            "quality_score": round(quality.quality_score, 4),
            "liveness_score": round(quality.liveness_score, 4),
            "faces_in_frame": quality.faces_in_frame,
            "notes": quality.notes,
        },
        reasons=reasons,
        turnstile_command=turnstile_command(outcome.decision, duplicate=duplicate),
        requires_human_review=outcome.requires_human_review,
        degraded_mode=degraded,
        audit_id=audit_id,
        latency_ms=latency_ms,
        policy_version=POLICY_VERSION,
    )
