"""Справочник сотрудников и хранилище шаблонов — единственный источник истины.

Отделён от индекса намеренно: справочник отвечает на вопрос «кто есть в компании
и какой у него статус доступа», индекс — на вопрос «на кого похожа эта проба».
В целевой системе это два разных хранилища с разными владельцами и разным
контуром доступа (docs/architecture.md).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from .templates import enrollment_template, similar_template
from .vectors import Vector

REPO_ROOT = Path(__file__).resolve().parent.parent
EMPLOYEES_PATH = REPO_ROOT / "demo" / "employees.json"

AccessStatus = Literal["active", "revoked", "suspended"]


@dataclass(frozen=True)
class Employee:
    employee_id: str
    display_name: str
    status: AccessStatus
    status_changed_minutes_ago: Optional[int] = None
    similar_to: Optional[str] = None
    similarity: Optional[float] = None

    def template(self) -> Vector:
        if self.similar_to and self.similarity is not None:
            return similar_template(self.employee_id, self.similar_to, self.similarity)
        return enrollment_template(self.employee_id)


@lru_cache(maxsize=1)
def load_employees() -> tuple[Employee, ...]:
    with EMPLOYEES_PATH.open(encoding="utf-8") as fh:
        raw = json.load(fh)
    return tuple(Employee(**row) for row in raw["employees"])


def find(employee_id: str) -> Optional[Employee]:
    return next((e for e in load_employees() if e.employee_id == employee_id), None)


def template_for(employee_id: str) -> Optional[Vector]:
    """Шаблон сотрудника ровно в том виде, в каком он лежит в хранилище.

    Проба с камеры моделируется относительно **этого** вектора. Любой другой
    базовый вектор означает, что система сравнивает пробу не с тем шаблоном.
    """
    employee = find(employee_id)
    return employee.template() if employee else None
