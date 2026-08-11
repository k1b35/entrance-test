"""Индекс шаблонов и поиск one-to-many.

=== Что упрощено ===
Вместо HNSW-индекса — полный перебор по 8 демо-шаблонам. На сотнях тысяч лиц так
делать нельзя; целевое решение описано в docs/ml.md.

=== Что реализовано по-настоящему и важно для дизайна ===
1. **Идентификация и авторизация разделены.** Поиск отвечает «кто это» и ищет по
   всем шаблонам, включая отозванные. Вопрос «можно ли внутрь» решается отдельно
   в политике. Если слить их, уволенный сотрудник выглядит как «неизвестный»,
   и охрана не узнает, кто именно пришёл на проходную.
2. **Edge-кеш отстаёт от центра.** Снимок базы, снятый `cache_age_minutes` назад,
   не знает об изменениях статуса, случившихся позже. Это и есть причина, по
   которой offline-режим не имеет права открывать турникет автоматически.
"""

from __future__ import annotations

from typing import Literal, Optional

from .directory import Employee, load_employees
from .vectors import Vector, cosine

IndexSource = Literal["central", "edge_cache", "unavailable"]


class TemplateIndex:
    """Хранилище шаблонов с поиском ближайших.

    `cache_age_minutes=None` — центральный индекс, видит актуальные статусы.
    Иначе это снимок на edge-узле, снятый указанное число минут назад.
    """

    def __init__(self, employees: tuple[Employee, ...], cache_age_minutes: Optional[int] = None):
        self.cache_age_minutes = cache_age_minutes
        self.source: IndexSource = "central" if cache_age_minutes is None else "edge_cache"
        self._employees = {e.employee_id: e for e in employees}
        self._templates = {e.employee_id: e.template() for e in employees}

    def __len__(self) -> int:
        return len(self._templates)

    def visible_status(self, employee_id: str) -> str:
        """Статус, каким его видит именно этот индекс.

        Центральный индекс видит текущий статус. Edge-кеш не знает об изменениях,
        произошедших после снятия снимка, и показывает предыдущее состояние.
        """
        employee = self._employees.get(employee_id)
        if employee is None:
            return "unknown"
        if self.cache_age_minutes is None:
            return employee.status
        changed = employee.status_changed_minutes_ago
        if changed is not None and changed < self.cache_age_minutes:
            return "active"  # изменение статуса ещё не доехало до проходной
        return employee.status

    def is_stale(self, max_age_minutes: int) -> bool:
        return self.cache_age_minutes is not None and self.cache_age_minutes > max_age_minutes

    def search(self, probe: Vector, top_k: int = 2) -> list[tuple[str, float]]:
        """Полный перебор. В целевой системе — ANN-запрос, см. docs/ml.md."""
        scored = [(eid, cosine(probe, tpl)) for eid, tpl in self._templates.items()]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:top_k]

    def display_name(self, employee_id: str) -> str:
        employee = self._employees.get(employee_id)
        return employee.display_name if employee else "неизвестен"


def build_index(cache_age_minutes: Optional[int] = None) -> TemplateIndex:
    return TemplateIndex(load_employees(), cache_age_minutes)
