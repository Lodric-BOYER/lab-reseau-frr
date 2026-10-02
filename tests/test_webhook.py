"""Tests de l'envoi de webhook (Phase E) : serveur HTTP LOCAL uniquement, aucun appel externe.

Chaque scénario d'échec vérifie aussi que l'URL (un secret) n'apparaît dans aucune description
d'erreur : c'est la règle la plus facile à casser par inadvertance (`str(exception)` cite l'URL).
"""
import socket

import pytest
from webhook_recorder import SECRET_PATH, Recorder

from netcheck import secrets, webhook

# ------------------------------------------------------------------------------------------
# Validation de l'URL
# ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://discord.com/api/webhooks/123/abc",
    "https://example.org/hook",
    "http://localhost:8080/hook",
    "http://127.0.0.1:9/x",
    "http://[::1]:9/x",
])
def test_acceptable_urls(url):
    assert webhook.validate_url(url) == url


@pytest.mark.parametrize("url", [
    "http://example.com/hook",             # http hors loopback
    "http://localhost.evil.example/hook",  # préfixe « localhost » trompeur
    "http://127.0.0.1.evil.example/hook",
    "ftp://example.com/hook",
    "https://user:pass@example.com/hook",  # identifiants dans l'URL
    "https:///hook",                       # hôte absent
    "https://example.com:notaport/hook",
    "pas une url",
])
def test_refused_urls_and_error_never_quotes_the_url(url):
    with pytest.raises(webhook.WebhookConfigError) as err:
        webhook.validate_url(url)
    assert url not in str(err.value)
    assert webhook.ENV_VAR in str(err.value)


def test_from_environment():
    assert webhook.from_environment({}) is None
    assert webhook.from_environment({webhook.ENV_VAR: "  "}) is None
    assert webhook.from_environment({webhook.ENV_VAR: " https://example.org/h "}) == "https://example.org/h"
    with pytest.raises(webhook.WebhookConfigError):
        webhook.from_environment({webhook.ENV_VAR: "http://example.com/h"})


# ------------------------------------------------------------------------------------------
# Envoi
# ------------------------------------------------------------------------------------------

def _post(url, **kwargs):
    kwargs.setdefault("timeout", 2.0)
    kwargs.setdefault("retry_delay", 0.0)
    return webhook.post(url, {"hello": "monde", "accent": "é"}, **kwargs)


def test_success_204_sends_json_once():
    with Recorder() as r:
        result = _post(r.url)
    assert result.ok and result.attempts == 1 and result.error is None
    assert r.count == 1
    assert r.messages[0] == {"hello": "monde", "accent": "é"}
    assert r.requests[0]["headers"]["Content-Type"] == "application/json"
    assert r.requests[0]["path"] == SECRET_PATH


def test_any_2xx_is_success_slack_answers_200():
    with Recorder(status=200) as r:
        assert _post(r.url).ok


def test_5xx_is_retried_exactly_once_then_succeeds():
    with Recorder(statuses=[500, 204]) as r:
        result = _post(r.url)
    assert result.ok and result.attempts == 2 and r.count == 2


def test_persistent_5xx_gives_up_after_one_retry():
    with Recorder(status=503) as r:
        result = _post(r.url)
    assert not result.ok and result.attempts == 2 and r.count == 2
    assert result.error == "HTTP 503"


@pytest.mark.parametrize("code", [400, 401, 404, 429])
def test_4xx_is_not_retried(code):
    with Recorder(status=code) as r:
        result = _post(r.url)
    assert not result.ok and result.attempts == 1 and r.count == 1
    assert result.error == f"HTTP {code}"


def test_timeout_is_reported_and_retried_once():
    with Recorder(delay=1.0) as r:
        result = _post(r.url, timeout=0.2)
    assert not result.ok and result.attempts == 2
    assert result.error == "délai dépassé"
    assert SECRET_PATH not in result.error


def test_redirect_is_never_followed_nor_retried():
    with Recorder() as target, Recorder(redirect_to=target.url) as redirecting:
        result = _post(redirecting.url)
    assert not result.ok and result.attempts == 1
    assert "redirection refusée" in result.error
    assert target.count == 0, "la cible de la redirection ne doit jamais être contactée"
    assert redirecting.count == 1
    assert SECRET_PATH not in result.error


def test_connection_refused_is_reported_and_retried_once():
    with socket.socket() as s:   # port libre puis fermé : plus personne n'écoute
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    url = f"http://127.0.0.1:{port}{SECRET_PATH}"
    result = _post(url)
    assert not result.ok and result.attempts == 2
    assert result.error == "connexion refusée"
    assert SECRET_PATH not in result.error and str(port) not in result.error


def test_retry_waits_between_attempts_using_the_injected_sleep():
    delays = []
    with Recorder(status=500) as r:
        webhook.post(r.url, {}, timeout=2.0, retry_delay=0.75, sleep=delays.append)
    assert delays == [0.75]


# ------------------------------------------------------------------------------------------
# Masquage de l'URL
# ------------------------------------------------------------------------------------------

def test_redact_replaces_the_configured_url_wherever_it_appears():
    url = "https://chat.example.org/hooks/SUPERSECRET"
    out = webhook.redact(f"échec sur {url} (timeout) puis {url}", url)
    assert "SUPERSECRET" not in out and "chat.example.org" not in out


@pytest.mark.parametrize(("url", "secret"), [
    ("https://discord.com/api/webhooks/1234567890/AbCdEf_hidden-token", "AbCdEf_hidden-token"),
    ("https://discordapp.com/api/v10/webhooks/1234567890/AbCdEf_hidden?wait=true", "AbCdEf_hidden"),
    ("https://hooks.slack.com/services/T000/B000/XXXXhiddenXXXX", "XXXXhiddenXXXX"),
    ("https://acme.webhook.office.com/webhookb2/aaaa@bbbb/IncomingWebhook/hidden/cccc", "hidden"),
    ("https://prod-12.westeurope.logic.azure.com:443/workflows/x/triggers/manual?sig=HIDDEN", "HIDDEN"),
])
def test_known_webhook_url_formats_are_masked_everywhere(url, secret):
    text = f"voir {url} pour plus"
    masked = secrets.mask_secrets(text)
    assert secret not in masked
    assert url not in masked
    assert secrets.WEBHOOK_URL_MASK in masked
    assert masked.startswith("voir ") and masked.endswith(" pour plus")


def test_ordinary_urls_and_text_are_left_alone():
    text = "voir https://docs.discord.com/developers/resources/webhook et https://example.org/a"
    assert secrets.mask_secrets(text) == text
