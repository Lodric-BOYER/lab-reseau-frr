#!/usr/bin/env python3
"""Proxy HTTP de TEST qui réécrit l'en-tête `Host` : reproduit un NetBox derrière un nom ou un port
différent.

    hostproxy.py --listen 18000 --target 127.0.0.1:8000 --host localhost:8000 [--count-file FICHIER]

NetBox construit le lien `next` de la pagination à partir de l'en-tête `Host` de la requête. Derrière ce
proxy, un client qui parle à 127.0.0.1:18000 reçoit des liens `next` vers localhost:8000 : autre hôte et
autre port que ceux qu'il a configurés. netcheck doit alors REFUSER clairement, jamais boucler ni rendre
un résultat partiel. Le proxy compte les requêtes reçues (une par ligne dans --count-file) pour prouver
qu'il n'y a ni boucle ni requête de trop. Bibliothèque standard seulement ; écoute en 127.0.0.1 ; une
requête par connexion (`Connection: close`)."""

from __future__ import annotations

import argparse
import re
import socket
import socketserver
import sys
import threading


def rewrite(head: bytes, host: str) -> bytes:
    """Réécrit `Host` et force `Connection: close` dans l'en-tête d'une requête."""
    text = head.decode("latin-1")
    text = re.sub(r"(?im)^host:[^\r\n]*", f"Host: {host}", text, count=1)
    text = re.sub(r"(?im)^connection:[^\r\n]*\r\n", "", text)
    text = text.replace("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1)
    return text.encode("latin-1")


class Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, listen: int, target: tuple[str, int], host: str, count_file: str | None = None):
        self.target, self.host, self.count_file = target, host, count_file
        self.requests = 0
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", listen), _Handler)

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server: Proxy = self.server  # type: ignore[assignment]
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(65536)
            if not chunk:
                return
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        with server.lock:
            server.requests += 1
            if server.count_file:
                with open(server.count_file, "a", encoding="utf-8") as handle:
                    handle.write(head.split(b"\r\n", 1)[0].decode("latin-1").split(" ")[1] + "\n")
        with socket.create_connection(server.target, timeout=30) as upstream:
            upstream.sendall(rewrite(head + b"\r\n\r\n", server.host) + body)
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                self.request.sendall(chunk)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0], allow_abbrev=False)
    parser.add_argument("--listen", type=int, required=True)
    parser.add_argument("--target", required=True, help="hôte:port du vrai serveur")
    parser.add_argument("--host", required=True, help="valeur de l'en-tête Host envoyée au serveur")
    parser.add_argument("--count-file")
    args = parser.parse_args(argv)
    host, _, port = args.target.rpartition(":")
    with Proxy(args.listen, (host, int(port)), args.host, args.count_file) as proxy:
        try:
            proxy.serve_forever()
        except KeyboardInterrupt:
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
