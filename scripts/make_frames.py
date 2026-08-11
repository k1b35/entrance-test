"""Генератор синтетических кадров для демо.

Реальные лица использовать нельзя (прямой запрет в задании), поэтому кадры —
детерминированные градиентные PNG 64x64, собранные вручную из zlib+struct, без
внешних зависимостей. Содержимое кадра mock-моделями не анализируется: условия
сцены берутся из demo/frames/manifest.json. Файлы нужны, чтобы контракт
«на вход приходит настоящий файл по frame_uri» проверялся по-настоящему, включая
ветку с нечитаемым кадром.

Запуск: python scripts/make_frames.py
"""

from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FRAMES_DIR = REPO_ROOT / "demo" / "frames"
SIZE = 64


def _chunk(tag: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + tag
        + payload
        + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    )


def write_png(path: Path, seed: int) -> None:
    """Градиент 64x64 в оттенках серого; seed делает каждый кадр отличимым."""
    rows = bytearray()
    for y in range(SIZE):
        rows.append(0)  # filter type 0 для каждой строки
        for x in range(SIZE):
            rows.append((x * 3 + y * 5 + seed * 17) % 256)

    png = b"\x89PNG\r\n\x1a\n"
    png += _chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 0, 0, 0, 0))
    png += _chunk(b"IDAT", zlib.compress(bytes(rows), 9))
    png += _chunk(b"IEND", b"")
    path.write_bytes(png)


def main() -> None:
    manifest = json.loads((FRAMES_DIR / "manifest.json").read_text(encoding="utf-8"))
    names = [n for n in manifest["frames"] if n != "__default__"]
    for seed, name in enumerate(sorted(names), start=1):
        write_png(FRAMES_DIR / name, seed)
        print(f"создан {name}")
    print(f"готово: {len(names)} кадров в {FRAMES_DIR}")


if __name__ == "__main__":
    main()
