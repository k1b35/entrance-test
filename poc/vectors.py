"""Векторная арифметика на стандартной библиотеке.

В целевой системе эмбеддинги считает ArcFace, а сравнение делает ANN-индекс
(HNSW/IVF-PQ). Здесь тот же интерфейс реализован на списках float — этого
достаточно для 8 демо-шаблонов и не тянет numpy в зависимости.
"""

from __future__ import annotations

import hashlib
import math
import random

DIM = 128

Vector = list[float]


def _rng(seed_material: str) -> random.Random:
    """Детерминированный ГПСЧ: одинаковый вход -> одинаковый вектор всегда."""
    digest = hashlib.sha256(seed_material.encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def unit_random(seed_material: str, dim: int = DIM) -> Vector:
    rng = _rng(seed_material)
    return normalize([rng.gauss(0.0, 1.0) for _ in range(dim)])


def normalize(v: Vector) -> Vector:
    n = math.sqrt(sum(x * x for x in v))
    if n == 0.0:
        raise ValueError("нулевой вектор не нормализуется")
    return [x / n for x in v]


def dot(a: Vector, b: Vector) -> float:
    return sum(x * y for x, y in zip(a, b))


def cosine(a: Vector, b: Vector) -> float:
    """Оба вектора единичные, поэтому косинус = скалярное произведение."""
    return dot(a, b)


def orthogonal_component(v: Vector, base: Vector) -> Vector:
    """Грам-Шмидт: компонента v, ортогональная base, нормированная."""
    proj = dot(v, base)
    residual = [x - proj * b for x, b in zip(v, base)]
    return normalize(residual)


def blend(base: Vector, seed_material: str, similarity: float) -> Vector:
    """Вектор с точно заданным косинусом `similarity` к `base`.

    Используется дважды: чтобы построить похожих сотрудников (близнецов в базе)
    и чтобы смоделировать пробу, снятую в плохих условиях. Точная ортогонализация
    делает косинус детерминированным — на этом держатся тесты порогов.
    """
    if not 0.0 <= similarity <= 1.0:
        raise ValueError("similarity должна лежать в [0, 1]")
    noise = orthogonal_component(unit_random(seed_material), base)
    residual = math.sqrt(max(0.0, 1.0 - similarity * similarity))
    return normalize([similarity * b + residual * n for b, n in zip(base, noise)])
