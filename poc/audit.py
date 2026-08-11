"""Audit log решений о доступе и защита от двойного открытия турникета.

Требование задания: audit log всех решений доступа. Здесь он append-only в JSONL.

Три свойства, которые важны для дизайна и реализованы по-настоящему:

1. **Append-only.** Записи не обновляются и не удаляются — только дописываются.
   Иначе audit trail не имеет доказательной силы при разборе инцидента.
2. **Идемпотентность по `event_id`.** Повтор того же события (ретрай сети, дубль
   от камеры) возвращает исходное решение и команду `noop`. Турникет физически
   не может открыться дважды по одному событию.
3. **Биометрии в логе нет.** Пишутся идентификаторы, оценки и причины — но ни
   кадра, ни эмбеддинга. Audit log читают служба безопасности и эксплуатация,
   и он не должен становиться вторым хранилищем биометрии.

В целевой системе это не файл, а append-only таблица с WORM-политикой и отдельным
контуром доступа (см. docs/risks-and-ops.md).
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUDIT_PATH = REPO_ROOT / "var" / "audit_log.jsonl"

_lock = threading.Lock()


class AuditLog:
    def __init__(self, path: Path | str = DEFAULT_AUDIT_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seen: dict[str, dict[str, Any]] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        """Восстановление индекса идемпотентности после рестарта edge-узла."""
        if not self.path.is_file():
            return
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue  # битая строка не должна ронять проходную
                event_id = record.get("event_id")
                if event_id and event_id not in self._seen:
                    self._seen[event_id] = record

    def find(self, event_id: str) -> Optional[dict[str, Any]]:
        return self._seen.get(event_id)

    def append(self, record: dict[str, Any]) -> str:
        audit_id = record["audit_id"]
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with _lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())  # решение о доступе не должно теряться при отключении питания
            self._seen.setdefault(record["event_id"], record)
        return audit_id

    def records(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        out = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out
