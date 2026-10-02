"""Envoi d'alertes par webhook (`netcheck monitor`, Phase E, SPEC_v3 §8).

L'URL d'un webhook est un SECRET : quiconque la connaît peut poster dans le salon. Elle ne vient
donc que de la variable d'environnement NETCHECK_WEBHOOK_URL (C15) et n'apparaît jamais, ni dans
un message d'erreur, ni dans un journal, ni dans un rapport. Ce module n'affiche et ne renvoie
que des descriptions construites ici (type d'erreur, code HTTP), JAMAIS `str(exception)` : le texte
d'une exception de bibliothèque peut citer l'URL.

Règles d'envoi (décisions validées) :
  - https obligatoire ; http accepté seulement vers localhost / 127.0.0.1 / ::1 (tests locaux) ;
  - aucune redirection suivie : un 3xx est un échec, sans réessai, et la cible n'est jamais
    contactée (une redirection pourrait envoyer le message, et l'URL, ailleurs) ;
  - délai court (5 s, appliqué à chaque opération réseau) ; UN SEUL réessai, uniquement sur
    erreur réseau, délai dépassé ou 5xx -- jamais sur un 4xx (permanent) ni un 3xx ;
  - tout 2xx vaut succès (Discord répond 204, Slack répond 200 avec « ok »).
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from netcheck import secrets

ENV_VAR = "NETCHECK_WEBHOOK_URL"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
DEFAULT_TIMEOUT = 5.0
MAX_RETRIES = 1
RETRY_DELAY = 1.0


class WebhookConfigError(ValueError):
    """Configuration de webhook refusée. Le message ne contient JAMAIS l'URL."""


def validate_url(url: str) -> str:
    """Renvoie l'URL si elle est acceptable, sinon lève WebhookConfigError (sans la citer)."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        _ = parts.port  # lève ValueError si le port est invalide
    except ValueError as e:
        raise WebhookConfigError(f"{ENV_VAR} invalide : URL illisible") from e
    if parts.scheme not in ("https", "http"):
        raise WebhookConfigError(f"{ENV_VAR} invalide : le schéma doit être https")
    if not host:
        raise WebhookConfigError(f"{ENV_VAR} invalide : hôte absent")
    if parts.username or parts.password:
        raise WebhookConfigError(f"{ENV_VAR} invalide : identifiants dans l'URL refusés")
    if parts.scheme == "http" and host.lower() not in LOOPBACK_HOSTS:
        raise WebhookConfigError(
            f"{ENV_VAR} invalide : http n'est accepté que vers localhost (tests) ; utilise https")
    return url


def from_environment(environ: Mapping[str, str] | None = None) -> str | None:
    """URL validée de NETCHECK_WEBHOOK_URL, ou None si la variable est absente ou vide."""
    value = (os.environ if environ is None else environ).get(ENV_VAR, "").strip()
    return validate_url(value) if value else None


def redact(text: str, url: str | None = None) -> str:
    """Retire du texte l'URL configurée (telle quelle) et toute URL de webhook reconnue."""
    if url:
        text = text.replace(url, "<webhook>")
    return secrets.mask_secrets(text)


@dataclass
class SendResult:
    ok: bool
    attempts: int
    error: str | None = None  # description sûre (jamais l'URL) ; None si ok


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse de suivre toute redirection : urllib lève alors HTTPError avec le code 3xx."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _build_opener(url: str) -> urllib.request.OpenerDirector:
    handlers: list = [_NoRedirect()]
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host in LOOPBACK_HOSTS:
        handlers.append(urllib.request.ProxyHandler({}))  # un proxy ne doit jamais voir le loopback
    return urllib.request.build_opener(*handlers)


def _describe(reason: object) -> str:
    if isinstance(reason, TimeoutError):
        return "délai dépassé"
    if isinstance(reason, ConnectionRefusedError):
        return "connexion refusée"
    if isinstance(reason, socket.gaierror):
        return "nom d'hôte introuvable"
    if isinstance(reason, ssl.SSLError):
        return "erreur TLS"
    return f"erreur réseau ({type(reason).__name__})"


def _attempt(opener: urllib.request.OpenerDirector, url: str, body: bytes,
             timeout: float) -> tuple[bool, str | None]:
    """Une tentative. Renvoie (réessayable, erreur) ; erreur None = succès."""
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "netcheck-monitor"},
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as e:  # sous-classe d'URLError : à traiter AVANT elle
        code = e.code
        e.close()
        if 300 <= code < 400:
            return False, f"redirection refusée (HTTP {code})"
        return code >= 500, f"HTTP {code}"
    except urllib.error.URLError as e:
        return True, _describe(e.reason)
    except TimeoutError:
        return True, "délai dépassé"
    except http.client.HTTPException:
        return True, "réponse invalide"
    except OSError as e:
        return True, _describe(e)
    if 200 <= status < 300:
        return False, None
    return False, f"HTTP {status} inattendu"


def post(
    url: str, payload: dict, *, timeout: float = DEFAULT_TIMEOUT, retries: int = MAX_RETRIES,
    retry_delay: float | None = None, sleep: Callable[[float], None] | None = None,
) -> SendResult:
    """POST JSON, avec les règles d'envoi du docstring de module. Ne lève jamais d'exception
    liée au réseau : l'échec est dans SendResult (un échec d'envoi ne fait pas échouer monitor).

    `retry_delay` et `sleep` sont résolus à l'appel (et non à la définition) : les tests peuvent
    ainsi supprimer la pause sans toucher à la signature."""
    delay = RETRY_DELAY if retry_delay is None else retry_delay
    pause = sleep or time.sleep
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    opener = _build_opener(url)
    attempts = 0
    error: str | None = None
    for attempt in range(retries + 1):
        attempts += 1
        retryable, error = _attempt(opener, url, body, timeout)
        if error is None:
            return SendResult(True, attempts)
        if not retryable or attempt == retries:
            break
        pause(delay)
    return SendResult(False, attempts, error)
