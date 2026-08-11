"""MOCK: извлечение эмбеддинга пробы с кадра.

=== Что здесь заглушка ===
Вместо инференса модели проба строится как вектор с точно заданным косинусом к
хранимому шаблону сотрудника; величина косинуса берётся из `capture_fidelity`
манифеста сцены. Это даёт полный контроль над match_score и margin, поэтому
пороги политики проверяются детерминированными тестами, а не «на глаз».

=== Чем заменяется в целевой архитектуре ===
`embed(event) -> Vector` остаётся тем же вызовом; внутри появляется
детекция -> alignment по 5 точкам -> ArcFace (512-d, ONNX Runtime FP16).
Ни политика, ни оркестрация от этой замены не меняются.

=== Важно ===
Проба строится от шаблона из справочника (`directory.template_for`), а не от
заново сгенерированного вектора. Иначе для сотрудников, чей шаблон построен
относительно другого человека, система сравнивала бы пробу не с тем эталоном.
"""

from __future__ import annotations

from . import directory
from .contracts import AccessEvent
from .cv import scene_of
from .vectors import Vector, blend


def embed(event: AccessEvent) -> Vector | None:
    """Эмбеддинг пробы. None означает «лицо непригодно для матчинга»."""
    scene = scene_of(event)
    person_id = scene.get("person_id")
    if not person_id:
        return None

    target = directory.template_for(person_id)
    if target is None:
        # Человека нет в справочнике — в проде это «неизвестное лицо»:
        # эмбеддинг посчитается, но совпадения в базе не найдётся.
        return None

    fidelity = float(scene.get("capture_fidelity", 0.85))
    if fidelity >= 0.999:
        return target
    return blend(target, f"probe::{event.event_id}", fidelity)
