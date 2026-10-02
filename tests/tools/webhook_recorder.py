"""Récepteur de webhook LOCAL pour les tests (Phase E) : aucun appel externe, jamais.

Deux usages :
  - en Python (tests unitaires) : `with Recorder(statuses=[500, 204]) as r:` puis `r.url`,
    `r.messages` (corps JSON reçus) ;
  - en ligne de commande (scénarios d'intégration) :
        webhook_recorder.py --port-file PORT --log MESSAGES.jsonl
    écoute sur 127.0.0.1 (port libre choisi par le système, écrit dans --port-file) et ajoute
    une ligne JSON par message reçu dans --log, jusqu'à ce qu'on le tue.

Comportements simulables (tests de l'envoi) : statut fixe ou séquence de statuts, délai avant la
réponse (pour provoquer un délai dépassé), redirection 302 vers une autre URL.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SECRET_PATH = "/hook/SENTINEL-WEBHOOK-TOKEN-4f9c2a"   # chemin qui joue le rôle de secret


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 (nom imposé par http.server)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        server: Recorder = self.server.recorder  # type: ignore[attr-defined]
        try:
            body = json.loads(raw.decode("utf-8"))
        except ValueError:
            body = {"_raw": raw.decode("utf-8", "replace")}
        server.record(self.path, body, dict(self.headers))
        if server.delay:
            time.sleep(server.delay)
        try:
            if server.redirect_to:
                self.send_response(302)
                self.send_header("Location", server.redirect_to)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(server.next_status())
            self.send_header("Content-Length", "0")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass  # le client a abandonné (délai dépassé) : voulu dans certains tests

    def log_message(self, *args):  # silence
        pass


class Recorder:
    def __init__(self, status: int = 204, statuses: list[int] | None = None, delay: float = 0.0,
                 redirect_to: str | None = None, log_file: str | Path | None = None):
        self.status, self._statuses = status, list(statuses or [])
        self.delay, self.redirect_to = delay, redirect_to
        self.log_file = Path(log_file) if log_file else None
        self.requests: list[dict] = []
        self._lock = threading.Lock()
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.daemon_threads = True
        self._httpd.recorder = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}{SECRET_PATH}"

    @property
    def messages(self) -> list[dict]:
        return [r["body"] for r in self.requests]

    @property
    def count(self) -> int:
        return len(self.requests)

    def next_status(self) -> int:
        with self._lock:
            return self._statuses.pop(0) if self._statuses else self.status

    def record(self, path: str, body: dict, headers: dict) -> None:
        with self._lock:
            self.requests.append({"path": path, "body": body, "headers": headers})
            if self.log_file:
                with self.log_file.open("a", encoding="utf-8") as f:
                    f.write(json.dumps({"path": path, "body": body}, ensure_ascii=False) + "\n")

    def __enter__(self) -> Recorder:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()
    Path(args.log).write_text("", encoding="utf-8")
    with Recorder(log_file=args.log) as recorder:
        Path(args.port_file).write_text(str(recorder.port), encoding="utf-8")
        threading.Event().wait()   # jusqu'à SIGTERM
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
