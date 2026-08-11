"""Демо-прогон: все референсные сценарии через горячий путь.

Запуск: python scripts/run_demo.py

Показывает happy path (allow, турникет открывается) и несколько fallback/risky
путей, ни один из которых турникет автоматически не открывает.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from poc.audit import AuditLog  # noqa: E402
from poc.service import AccessService  # noqa: E402

EVENTS_DIR = REPO_ROOT / "demo" / "events"
AUDIT_PATH = REPO_ROOT / "var" / "audit_log.jsonl"

SCENARIOS = {
    "e-1001": "happy path — хорошие условия, уверенное совпадение",
    "e-1002": "маска и контровый свет — кадр непригоден",
    "e-1003": "presentation attack — фото с экрана телефона",
    "e-1004": "два близких кандидата — малый отрыв",
    "e-1005": "offline + доступ отозван — кеш об отзыве знает",
    "e-1006": "offline + устаревший кеш у действующего сотрудника",
    "e-1007": "два лица в кадре — подозрение на проход паровозиком",
}

ICON = {"allow": "[OPEN ]", "manual_review": "[GUARD]", "deny": "[DENY ]"}


def main() -> int:
    if AUDIT_PATH.exists():
        AUDIT_PATH.unlink()  # чистый прогон демо; в проде audit log не удаляется никогда
    queue_path = AUDIT_PATH.parent / "review_queue.jsonl"
    if queue_path.exists():
        queue_path.unlink()

    service = AccessService(audit=AuditLog(AUDIT_PATH))
    opened = 0
    to_guard = 0

    print("=" * 96)
    print("ДЕМО: горячий путь проходной — событие с камеры до команды турникету")
    print("=" * 96)

    for event_id, title in SCENARIOS.items():
        raw = json.loads((EVENTS_DIR / f"{event_id}.json").read_text(encoding="utf-8"))
        d = service.verify(raw)

        print(f"\n{ICON[d.decision]} {event_id} — {title}")
        print(f"         решение      : {d.decision}  (турникет: {d.turnstile_command})")
        print(f"         сотрудник    : {d.employee_id or '—'}")
        print(f"         score/margin : {d.match_score:.3f} / {d.margin_to_second_best:.3f}")
        print(f"         качество     : q={d.quality['quality_score']:.2f} "
              f"liveness={d.quality['liveness_score']:.2f} лиц={d.quality['faces_in_frame']}")
        print(f"         режим        : {'degraded' if d.degraded_mode else 'normal'}"
              f"{'  ОХРАНЕ' if d.requires_human_review else ''}")
        print(f"         причины      : {', '.join(d.reasons)}")

        opened += d.turnstile_command == "open"
        to_guard += d.requires_human_review or d.decision == "manual_review"

    # Идемпотентность: повторяем happy path и убеждаемся, что второй раз не откроется.
    raw = json.loads((EVENTS_DIR / "e-1001.json").read_text(encoding="utf-8"))
    repeat = service.verify(raw)
    print("\n" + "-" * 96)
    print("ПОВТОР e-1001 (ретрай сети или дубль от камеры):")
    print(f"         то же решение: {repeat.decision}, decision_id совпадает, "
          f"команда турникету: {repeat.turnstile_command}")
    print(f"         причины      : {', '.join(repeat.reasons)}")

    print("\n" + "=" * 96)
    print(f"Открытий турникета: {opened} из {len(SCENARIOS)} событий. "
          f"Ушло охране: {to_guard}.")
    print(f"Audit log      : {AUDIT_PATH.relative_to(REPO_ROOT)} ({len(service.audit.records())} записей)")
    print(f"Очередь охраны : {queue_path.relative_to(REPO_ROOT)}")
    print("=" * 96)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
