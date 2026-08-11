"""HTTP-контракт горячего пути: POST /v1/access/verify.

На стандартной библиотеке (`http.server`), без веб-фреймворка — PoC не должен
тянуть зависимости. В целевой системе это gRPC или HTTP/2 внутри edge-узла,
без выхода в публичную сеть (docs/architecture.md).

Запуск: python -m poc.api  [--port 8080]
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import AccessService

MAX_BODY_BYTES = 64 * 1024  # кадры передаются по ссылке, тело запроса всегда маленькое

_service = AccessService()


class Handler(BaseHTTPRequestHandler):
    server_version = "FaceGatePoC/0.1"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "service": "face-gate-poc"})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/access/verify":
            self._send(404, {"error": "not_found"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send(413, {"error": "invalid_body_size"})
            return

        try:
            raw = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send(400, {"error": "malformed_json"})
            return

        try:
            decision = _service.verify(raw)
        except ValueError as exc:
            self._send(400, {"error": "invalid_event", "detail": str(exc)})
            return
        except Exception:  # noqa: BLE001
            # Отказ сервиса не имеет права превратиться в открытие турникета:
            # клиент на проходной обязан трактовать 5xx как «зовём охрану».
            self._send(500, {"error": "internal_error", "fail_safe": "manual_review"})
            return

        self._send(200, decision.to_dict())

    def log_message(self, fmt: str, *args) -> None:
        return  # тише в демо; в проде это структурный лог, см. docs/monitoring.md


def main() -> None:
    parser = argparse.ArgumentParser(description="PoC сервиса проходной")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"POST http://{args.host}:{args.port}/v1/access/verify  (Ctrl+C для остановки)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nостановлено")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
