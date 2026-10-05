"""Faux NetBox local pour les tests de la phase C6 : aucun conteneur, aucun réseau, aucune écriture possible.

Il répond comme NetBox à `GET /api/status/` et `GET /api/dcim/devices/` (filtres site, role, tag, status ;
pagination limit/offset avec un lien `next` construit sur l'en-tête Host). Tout le reste reçoit un
405 ou un 404,
et CHAQUE requête est enregistrée (méthode, chemin, paramètres, en-tête d'autorisation) : les tests
prouvent ainsi
ce que netcheck a envoyé, et surtout ce qu'il n'a PAS envoyé (zéro requête après un refus).

Des attributs règlent les pannes : `replies` (réponse imposée par chemin), `delay`, `count_delta`,
`page_counts`,
`next_base`, `next_mutator`, `max_limit`, `auth_status`. TLS : `enable_tls(certificat, clé)`.
"""

from __future__ import annotations

import json
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlencode, urlsplit

TOKEN = "nbt_FAKEkey0123.FAKEsecret0123456789abcdefghijklmnop"
NEXT_FIELDS = ("site", "role", "tag", "status", "limit", "offset")


def device(
    name,
    ip="10.0.0.1/24",
    platform="frr",
    ident=1,
    site="lab",
    role="router",
    tags=("netcheck",),
    status="active",
    **extra,
):
    """Un équipement, au format de /api/dcim/devices/ (seuls les champs lus par netcheck sont réalistes)."""
    data = {
        "id": ident,
        "name": name,
        "status": {"value": status, "label": status.title()},
        "site": {"slug": site},
        "role": {"slug": role},
        "platform": {"slug": platform, "name": platform} if platform else None,
        "primary_ip": {"address": ip} if ip else None,
        "tags": [{"slug": tag} for tag in tags],
    }
    data.update(extra)
    return data


def standard_devices():
    return [
        device("r1", "10.0.0.1/24", "frr", 1),
        device("r4", "10.0.0.4/24", "eos", 4),
        device("r5", "10.0.0.5/24", "srlinux", 5),
    ]


class _QuietServer(ThreadingHTTPServer):
    """Un client qui abandonne ne doit laisser aucune trace sur stderr (voir tests/test_vault.py)."""

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)


class FakeNetbox:
    def __init__(self, devices=None, token=TOKEN, version="4.7.3"):
        self.devices = standard_devices() if devices is None else devices
        self.token, self.version = token, version
        self.requests: list[dict] = []
        self.replies: dict[str, tuple] = {}  # chemin -> (code, corps bytes|dict, en-têtes)
        self.delay = 0.0
        self.count_delta = 0
        self.page_counts = None  # callable(numéro de page) -> count
        self.next_base: str | None = None
        self.next_from_host = False  # comme le vrai NetBox : le lien `next` est construit sur l'en-tête Host
        self.next_mutator = None  # callable(url, numéro de page) -> url | None
        self.max_limit = 1000
        self.auth_status = 403
        self.tls = False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def _send(self, code, body, headers=None):
                payload = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(payload)

            def _handle(self):
                parts = urlsplit(self.path)
                query = dict_of_lists(parts.query)
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                outer.requests.append(
                    {
                        "method": self.command,
                        "path": parts.path,
                        "query": query,
                        "authorization": self.headers.get("Authorization"),
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                    }
                )
                if outer.delay:
                    time.sleep(outer.delay)
                if self.command != "GET":
                    return self._send(405, {"detail": "méthode refusée par le faux NetBox"})
                if self.headers.get("Authorization") != f"Bearer {outer.token}":
                    return self._send(
                        outer.auth_status, {"detail": "Authentication credentials were not provided."}
                    )
                if parts.path in outer.replies:
                    reply = outer.replies[parts.path]
                    return self._send(reply[0], reply[1], reply[2] if len(reply) > 2 else None)
                if parts.path == "/api/status/":
                    return self._send(200, {"netbox-version": outer.version, "python-version": "3.12"})
                if parts.path == "/api/dcim/devices/":
                    return self._send(200, outer.devices_page(query, parts.query, self.headers.get("Host")))
                return self._send(404, {"detail": "introuvable"})

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle

        self.server = _QuietServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.02), daemon=True
        )
        self.thread.start()

    # --- pages ---------------------------------------------------------------------------------------------
    @staticmethod
    def _matches(item, query):
        if "site" in query and (item.get("site") or {}).get("slug") not in query["site"]:
            return False
        if "role" in query and (item.get("role") or {}).get("slug") not in query["role"]:
            return False
        if "status" in query and (item.get("status") or {}).get("value") not in query["status"]:
            return False
        return not ("tag" in query and not set(query["tag"]) <= {t["slug"] for t in item.get("tags", [])})

    def devices_page(self, query, raw_query, host=None):
        limit = min(int(query.get("limit", ["50"])[0]), self.max_limit)
        offset = int(query.get("offset", ["0"])[0])
        rows = [d for d in self.devices if self._matches(d, query)]
        number = offset // limit if limit else 0
        count = len(rows) + self.count_delta
        if self.page_counts:
            count = self.page_counts(number)
        link = None
        if offset + limit < len(rows):
            pairs = [(k, v) for k, v in parse_qsl(raw_query, keep_blank_values=True) if k != "offset"]
            pairs.append(("offset", str(offset + limit)))
            scheme = "https" if self.tls else "http"
            base = self.next_base or f"{scheme}://127.0.0.1:{self.server.server_address[1]}"
            if self.next_from_host and host and not self.next_base:
                base = f"{scheme}://{host}"
            link = f"{base}/api/dcim/devices/?{urlencode(pairs)}"
            if self.next_mutator:
                link = self.next_mutator(link, number)
        return {"count": count, "next": link, "previous": None, "results": rows[offset : offset + limit]}

    # --- vie du serveur -------------------------------------------------------------------------------------
    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def addr(self) -> str:
        return f"{'https' if self.tls else 'http'}://127.0.0.1:{self.port}"

    def enable_tls(self, crt: str, key: str) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(crt, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.tls = True

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def paths(self) -> list[str]:
        return [r["path"] for r in self.requests]


def dict_of_lists(query: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key, value in parse_qsl(query, keep_blank_values=True):
        out.setdefault(key, []).append(value)
    return out
