"""Контракты внешнего API и внутренние структуры горячего пути.

Внешний контракт совпадает с референсным из задания (POST /v1/access/verify),
за одним осознанным расширением: в ответе есть поле `policy_version`.
Без него нельзя расследовать инцидент задним числом — решение зависит от
порогов, а пороги меняются (см. docs/monitoring.md, раздел про audit trail).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Literal, Optional

Decision = Literal["allow", "manual_review", "deny"]
TurnstileCommand = Literal["open", "hold", "noop"]


@dataclass(frozen=True)
class AccessEvent:
    """Событие с камеры проходной — вход горячего пути."""

    event_id: str
    gate_id: str
    camera_id: str
    captured_at: str
    frame_uri: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "AccessEvent":
        missing = [k for k in ("event_id", "gate_id", "camera_id", "captured_at", "frame_uri") if k not in raw]
        if missing:
            raise ValueError(f"в событии отсутствуют обязательные поля: {', '.join(missing)}")
        return AccessEvent(
            event_id=str(raw["event_id"]),
            gate_id=str(raw["gate_id"]),
            camera_id=str(raw["camera_id"]),
            captured_at=str(raw["captured_at"]),
            frame_uri=str(raw["frame_uri"]),
            metadata=dict(raw.get("metadata") or {}),
        )

    @property
    def is_offline(self) -> bool:
        return str(self.metadata.get("network", "online")).lower() == "offline"

    @property
    def cache_age_minutes(self) -> Optional[int]:
        raw = self.metadata.get("cache_age_minutes")
        return int(raw) if raw is not None else None


@dataclass
class QualityReport:
    """Результат детекции и оценки пригодности кадра."""

    face_detected: bool
    quality_score: float
    liveness_score: float
    faces_in_frame: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class MatchResult:
    """Результат поиска one-to-many по базе шаблонов."""

    employee_id: Optional[str]
    match_score: float
    margin_to_second_best: float
    second_best_employee_id: Optional[str] = None
    index_source: Literal["central", "edge_cache", "unavailable"] = "central"
    searched_templates: int = 0


@dataclass
class AccessDecision:
    """Итог горячего пути. Ровно это уходит турникету, охране и в audit log."""

    event_id: str
    decision_id: str
    decision: Decision
    employee_id: Optional[str]
    match_score: float
    margin_to_second_best: float
    quality: dict[str, Any]
    reasons: list[str]
    turnstile_command: TurnstileCommand
    requires_human_review: bool
    degraded_mode: bool
    audit_id: str
    latency_ms: int
    policy_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
