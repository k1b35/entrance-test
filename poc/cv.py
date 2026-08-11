"""MOCK: детекция лица, оценка качества кадра и liveness.

=== Что здесь заглушка ===
Настоящие модели заменены детерминированными функциями от манифеста сцены
(demo/frames/manifest.json). Манифест описывает условия съёмки — освещение,
окклюзию, поворот головы, признак предъявления с экрана — а функции переводят
их в те же три числа, которые в целевой системе выдают модели.

=== Чем заменяется в целевой архитектуре (docs/ml.md) ===
* детекция + 5 ключевых точек -> SCRFD или RetinaFace, ONNX Runtime на edge-GPU;
* оценка качества -> регрессор поверх landmarks + резкость/экспозиция/yaw-pitch-roll;
* liveness -> пассивная 2D-модель против print/replay + сигнал с IR-камеры.

Байты кадра читаются по-настоящему: контракт «на вход приходит файл» проверяется,
а отсутствие или порча файла обрабатываются так же, как в проде — как отказ
детекции, а не как исключение.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .contracts import AccessEvent, QualityReport

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "demo" / "frames" / "manifest.json"

_manifest_cache: dict[str, Any] | None = None


def _manifest() -> dict[str, Any]:
    global _manifest_cache
    if _manifest_cache is None:
        with MANIFEST_PATH.open(encoding="utf-8") as fh:
            _manifest_cache = json.load(fh)
    return _manifest_cache


def resolve_frame_path(frame_uri: str) -> Path:
    """`file://demo/frames/x.png` -> абсолютный путь внутри репозитория."""
    relative = frame_uri[len("file://"):] if frame_uri.startswith("file://") else frame_uri
    return (REPO_ROOT / relative).resolve()


def read_frame_bytes(frame_uri: str) -> bytes | None:
    path = resolve_frame_path(frame_uri)
    try:
        if not path.is_file() or os.path.getsize(path) == 0:
            return None
        return path.read_bytes()
    except OSError:
        return None


def scene_of(event: AccessEvent) -> dict[str, Any]:
    """Условия сцены для кадра. В проде этой функции не существует."""
    frames = _manifest()["frames"]
    key = Path(resolve_frame_path(event.frame_uri)).name
    return frames.get(key, frames["__default__"])


def analyse(event: AccessEvent) -> QualityReport:
    """Единый вызов детекции, качества и liveness — как в целевом edge-пайплайне.

    Порядок важен: сначала есть ли лицо, потом пригоден ли кадр, и только потом
    liveness. Считать liveness на непригодном кадре бессмысленно и дорого.
    """
    frame = read_frame_bytes(event.frame_uri)
    if frame is None:
        return QualityReport(
            face_detected=False,
            quality_score=0.0,
            liveness_score=0.0,
            faces_in_frame=0,
            notes=["frame_unreadable"],
        )

    scene = scene_of(event)
    notes: list[str] = []

    faces = int(scene.get("faces_in_frame", 1))
    if faces == 0:
        return QualityReport(False, 0.0, 0.0, 0, ["no_face_detected"])
    if faces > 1:
        notes.append("multiple_faces_in_frame")

    quality = float(scene.get("quality_score", 0.9))
    liveness = float(scene.get("liveness_score", 0.95))

    for hint, note in (
        ("occlusion_hint", "occlusion"),
        ("head_pose_hint", "head_pose"),
        ("illumination", "illumination"),
    ):
        value = event.metadata.get(hint)
        if value and value != "normal":
            notes.append(f"{note}:{value}")

    if scene.get("spoof_kind"):
        notes.append(f"spoof_suspected:{scene['spoof_kind']}")

    return QualityReport(
        face_detected=True,
        quality_score=quality,
        liveness_score=liveness,
        faces_in_frame=faces,
        notes=notes,
    )
