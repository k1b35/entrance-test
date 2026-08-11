"""Оркестрация горячего пути: событие -> решение -> audit log.

Это единственное место, где компоненты соединяются. Каждый шаг остаётся заменяемым:
mock-детектор и mock-эмбеддер меняются на реальные модели без правок этого файла.

Синхронный горячий путь (укладывается в ориентир 1 c): детекция, качество,
liveness, эмбеддинг, ANN-поиск, политика, команда турникету.
Асинхронно (вне PoC): выгрузка события в центральную аналитику, обновление
метрик drift, доставка события в очередь ручной проверки охраны.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from . import cv, embedder
from .audit import AuditLog
from .contracts import AccessDecision, AccessEvent, MatchResult
from .index import TemplateIndex, build_index
from .policy import DEFAULT_THRESHOLDS, Thresholds, build_decision, evaluate

_NAMESPACE = uuid.UUID("6f1b7f28-6a2c-4d4f-9a0e-1f9d6f0a1c11")


def _stable_id(prefix: str, event_id: str) -> str:
    """Идентификаторы детерминированы: ретрай события не плодит новые decision_id."""
    return f"{prefix}-{uuid.uuid5(_NAMESPACE, f'{prefix}:{event_id}').hex[:12]}"


@dataclass
class GateContext:
    """Что известно о режиме работы проходной в момент события."""

    degraded: bool
    index: TemplateIndex
    stale_cache: bool
    reason: Optional[str] = None


class AccessService:
    def __init__(
        self,
        audit: Optional[AuditLog] = None,
        thresholds: Thresholds = DEFAULT_THRESHOLDS,
        review_queue_path: Optional[Path] = None,
    ):
        self.audit = audit or AuditLog()
        self.thresholds = thresholds
        self.review_queue_path = review_queue_path or self.audit.path.parent / "review_queue.jsonl"
        self._central = build_index()

    # ------------------------------------------------------------------ режим
    def _context(self, event: AccessEvent) -> GateContext:
        central_down = str(event.metadata.get("central_service", "available")).lower() == "unavailable"
        if not event.is_offline and not central_down:
            return GateContext(degraded=False, index=self._central, stale_cache=False)

        age = event.cache_age_minutes
        if age is None:
            age = 0  # кеш только что синхронизирован
        index = build_index(cache_age_minutes=age)
        return GateContext(
            degraded=True,
            index=index,
            stale_cache=index.is_stale(self.thresholds.offline_max_cache_age_minutes),
            reason="network_offline" if event.is_offline else "central_service_unavailable",
        )

    # ------------------------------------------------------------- горячий путь
    def verify(self, raw_event: dict[str, Any]) -> AccessDecision:
        started = time.perf_counter()
        event = AccessEvent.from_dict(raw_event)

        previous = self.audit.find(event.event_id)
        if previous is not None:
            return self._replay(previous, started)

        quality = cv.analyse(event)
        ctx = self._context(event)

        match: Optional[MatchResult] = None
        visible_status = "unknown"

        if quality.face_detected and quality.faces_in_frame == 1:
            probe = embedder.embed(event)
            if probe is not None:
                candidates = ctx.index.search(probe, top_k=2)
                if candidates:
                    best_id, best_score = candidates[0]
                    second_id, second_score = candidates[1] if len(candidates) > 1 else (None, 0.0)
                    match = MatchResult(
                        employee_id=best_id,
                        match_score=best_score,
                        margin_to_second_best=best_score - second_score,
                        second_best_employee_id=second_id,
                        index_source=ctx.index.source,
                        searched_templates=len(ctx.index),
                    )
                    visible_status = ctx.index.visible_status(best_id)

        outcome = evaluate(
            event,
            quality,
            match,
            visible_status,
            degraded=ctx.degraded,
            stale_cache=ctx.stale_cache,
            thresholds=self.thresholds,
        )
        if ctx.reason:
            outcome.reasons.append(ctx.reason)

        latency_ms = int((time.perf_counter() - started) * 1000)
        decision = build_decision(
            event,
            quality,
            match,
            outcome,
            decision_id=_stable_id("d", event.event_id),
            audit_id=_stable_id("a", event.event_id),
            degraded=ctx.degraded,
            latency_ms=latency_ms,
        )

        self._persist(event, decision, match, ctx)
        return decision

    # ---------------------------------------------------------------- побочные
    def _replay(self, previous: dict[str, Any], started: float) -> AccessDecision:
        """Повтор события: то же решение, но команда турникету — noop."""
        decision = AccessDecision(**{k: v for k, v in previous["decision"].items()})
        decision.turnstile_command = "noop"
        decision.reasons = list(decision.reasons) + ["duplicate_event"]
        decision.latency_ms = int((time.perf_counter() - started) * 1000)
        return decision

    def _persist(
        self,
        event: AccessEvent,
        decision: AccessDecision,
        match: Optional[MatchResult],
        ctx: GateContext,
    ) -> None:
        record = {
            "audit_id": decision.audit_id,
            "event_id": event.event_id,
            "logged_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "gate_id": event.gate_id,
            "camera_id": event.camera_id,
            "captured_at": event.captured_at,
            "direction": event.metadata.get("direction"),
            "edge_node": event.metadata.get("edge_node"),
            "index_source": match.index_source if match else ctx.index.source,
            "degraded_reason": ctx.reason,
            "decision": decision.to_dict(),
        }
        self.audit.append(record)

        if decision.requires_human_review or decision.decision == "manual_review":
            self._enqueue_for_security(event, decision)

    def _enqueue_for_security(self, event: AccessEvent, decision: AccessDecision) -> None:
        """Очередь ручной проверки охраны.

        В PoC — файл. В целевой системе это топик очереди, из которого читает
        консоль охраны; кадр к карточке подтягивается по ссылке с коротким TTL,
        а не хранится в самой очереди (docs/risks-and-ops.md).
        """
        import json

        self.review_queue_path.parent.mkdir(parents=True, exist_ok=True)
        card = {
            "decision_id": decision.decision_id,
            "event_id": event.event_id,
            "gate_id": event.gate_id,
            "captured_at": event.captured_at,
            "candidate_employee_id": decision.employee_id,
            "match_score": decision.match_score,
            "margin_to_second_best": decision.margin_to_second_best,
            "reasons": decision.reasons,
            "frame_ref": {"uri": event.frame_uri, "ttl_seconds": 900},
            "sla_seconds": 60,
        }
        with self.review_queue_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(card, ensure_ascii=False, sort_keys=True) + "\n")
