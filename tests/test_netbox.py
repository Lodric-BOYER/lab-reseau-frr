"""Client NetBox de la phase C6.1 contre un FAUX NetBox local (aucun conteneur, aucun NetBox réel).

Ce qui est prouvé :
- liste blanche EXACTE : GET /api/status/ et GET /api/dcim/devices/ (site, role, tag, status, limit, offset
  validés) ; tout le reste est refusé AVANT d'ouvrir une connexion ; aucune redirection ; proxys ignorés ;
- pagination : `next` contrôlé (même schéma, hôte, port, chemin, filtres, décalage croissant),
plafond de pages,
  `count` égal au nombre d'objets reçus ; le jeton ne part jamais vers un autre hôte ;
- jeton v2 en en-tête Bearer, variable ou fichier 0600, source affichée, SecretStr, registre d'expurgation ;
- TLS vérifié par défaut (faux serveur HTTPS auto-signé : refus sans autorité, OK avec elle, nom d'hôte
  contrôlé) ; http:// seulement pour le bouclage ET un inventaire `lab: true` ;
- fusion avec l'inventaire local, tous les écarts listés ensemble ; toute indisponibilité = code 3,
aucun repli,
  aucun résultat partiel ; hors ligne, NetBox n'est jamais contacté ;
- le jeton n'apparaît dans aucune sortie, aucun fichier, même quand une exception le recopie.
"""

from __future__ import annotations

import ast
import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest
import yaml
from fake_netbox import TOKEN, FakeNetbox, device

from netcheck import cli, collector, inventory, netbox, secrets, snapshot
from netcheck.credentials import CredentialError
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.model import DeviceState
from netcheck.netbox import (
    NetboxCallRefused,
    NetboxConfig,
    NetboxConfigError,
    NetboxInventoryError,
    NetboxUnavailable,
)
from netcheck.secrets import SecretStr
from netcheck.usage import UsageError

ROOT = Path(__file__).resolve().parent.parent
PLATFORMS = {"frr": "frr", "eos": "eos", "srlinux": "srlinux"}
OTHER_TOKEN = "nbt_AUTREclef0123.AUTREsecret0123456789abcdefghij"
REDIRECT = {"Location": "http://x/"}
TOKEN_PARTS = (TOKEN, "FAKEkey0123", "FAKEsecret0123456789abcdefghijklmnop")
DEFAULTS = {"device_type": "linux", "username": "netops", "password": "netops-pass-1", "vtysh": "vtysh"}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in list(os.environ):
        if var.startswith(("NETCHECK_", "LAB_")) or var.lower().endswith("_proxy"):
            monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NETCHECK_KNOWN_HOSTS", str(tmp_path / "known_hosts"))


@pytest.fixture
def nb():
    server = FakeNetbox()
    yield server
    server.stop()


def cfg(url, **kw):
    return NetboxConfig(
        url=url,
        platforms=kw.get("platforms", dict(PLATFORMS)),
        filters=kw.get("filters", {"status": ("active",)}),
        cacert=kw.get("cacert"),
    )


def tok():
    return netbox.read_token({netbox.ENV_TOKEN: TOKEN})


def many(count):
    return [device(f"r{i}", f"10.1.{i // 250}.{i % 250 + 1}/24", "frr", i) for i in range(1, count + 1)]


def reasons(error) -> str:
    return " ".join(str(error.value).split())


# === 1. liste blanche exacte ==============================================================================

PATHS = ("/api/status/", "/api/dcim/devices/")


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/api/status/", {}),
        ("/api/dcim/devices/", {}),
        (
            "/api/dcim/devices/",
            {
                "site": ["lab"],
                "role": ["router"],
                "tag": ["a", "b"],
                "status": ["active", "staged"],
                "limit": [100],
                "offset": [0],
            },
        ),
        ("/api/dcim/devices/", {"limit": ["1000"], "offset": ["999999"]}),
    ],
)
def test_the_allowed_calls_are_accepted(path, params):
    netbox.validate_call("GET", path, params)


@pytest.mark.parametrize(
    "method", ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "get", "Get", ""]
)
@pytest.mark.parametrize("path", PATHS)
def test_every_method_but_get_is_refused(method, path):
    with pytest.raises(NetboxCallRefused):
        netbox.validate_call(method, path, {})


@pytest.mark.parametrize(
    "path",
    [
        "/api/",
        "/api/status",
        "/api/dcim/devices",
        "/api/dcim/devices/1/",
        "/api/dcim/sites/",
        "/api/dcim/interfaces/",
        "/api/ipam/ip-addresses/",
        "/api/users/tokens/",
        "/api/users/users/",
        "/api/extras/scripts/",
        "/api/core/jobs/",
        "/graphql/",
        "/admin/",
        "/login/",
        "/api/status//",
        "//api/status/",
        "/API/status/",
        "/api/dcim/devices/../status/",
        "/api/status/?x=1",
        "http://evil.example/api/status/",
        "api/status/",
        "",
    ],
)
def test_every_other_path_is_refused(path):
    with pytest.raises(NetboxCallRefused):
        netbox.validate_call("GET", path, {})


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/api/status/", {"limit": ["1"]}),
        ("/api/status/", {"site": ["lab"]}),
        ("/api/dcim/devices/", {"brief": ["1"]}),
        ("/api/dcim/devices/", {"q": ["r1"]}),
        ("/api/dcim/devices/", {"id": ["1"]}),
        ("/api/dcim/devices/", {"name": ["r1"]}),
        ("/api/dcim/devices/", {"ordering": ["name"]}),
        ("/api/dcim/devices/", {"fields": ["name"]}),
        ("/api/dcim/devices/", {"config_context": ["1"]}),
        ("/api/dcim/devices/", {"tag__n": ["x"]}),
        ("/api/dcim/devices/", {"site_id": ["1"]}),
        ("/api/dcim/devices/", {"Site": ["lab"]}),
        ("/api/dcim/devices/", {"limit ": ["1"]}),
    ],
)
def test_an_unknown_parameter_is_refused(path, params):
    with pytest.raises(NetboxCallRefused):
        netbox.validate_call("GET", path, params)


@pytest.mark.parametrize(
    ("key", "values"),
    [
        ("site", ["a b"]),
        ("site", ["a;b"]),
        ("site", ["a/b"]),
        ("site", ["../x"]),
        ("site", ["a%20b"]),
        ("site", ["a&b=c"]),
        ("site", [""]),
        ("site", ["é"]),
        ("site", ["a\nb"]),
        ("site", ["x" * 101]),
        ("role", ["-x"]),
        ("tag", []),
        ("status", ["a", "b c"]),
        ("limit", ["0"]),
        ("limit", ["1001"]),
        ("limit", ["-1"]),
        ("limit", ["abc"]),
        ("limit", ["1.5"]),
        ("limit", ["²"]),
        ("limit", ["1", "2"]),
        ("offset", ["-1"]),
        ("offset", [""]),
        ("offset", ["1", "2"]),
        ("offset", ["1000000"]),
    ],
)
def test_a_doubtful_value_is_refused(key, values):
    with pytest.raises(NetboxCallRefused):
        netbox.validate_call("GET", "/api/dcim/devices/", {key: values})


def test_a_refused_call_never_reaches_the_network():
    class Boom:
        def open(self, *_a, **_k):
            raise AssertionError("le réseau a été touché")

    for path, params in (
        ("/api/dcim/sites/", {}),
        ("/api/dcim/devices/", {"brief": ["1"]}),
        ("/api/dcim/devices/", {"site": ["a b"]}),
        ("/api/users/tokens/", {}),
    ):
        with pytest.raises(NetboxCallRefused):
            netbox._get(cfg("http://127.0.0.1:1"), tok(), Boom(), path, params)


def test_a_fetch_sends_exactly_two_get_requests_with_the_bearer_token(nb):
    nb.devices = [device("r1", tags=("netcheck", "core"))]
    filters = {"site": ("lab",), "role": ("router",), "tag": ("netcheck", "core"), "status": ("active",)}
    netbox.fetch(cfg(nb.addr, filters=filters), tok())
    assert [(r["method"], r["path"]) for r in nb.requests] == [
        ("GET", "/api/status/"),
        ("GET", "/api/dcim/devices/"),
    ]
    assert nb.requests[0]["query"] == {}
    assert nb.requests[1]["query"] == {
        "site": ["lab"],
        "role": ["router"],
        "tag": ["netcheck", "core"],
        "status": ["active"],
        "limit": ["100"],
        "offset": ["0"],
    }
    for request in nb.requests:
        assert request["authorization"] == f"Bearer {TOKEN}"
        assert not [k for k, v in request["headers"].items() if k != "authorization" and TOKEN in v]


def test_the_filters_are_applied_by_netbox_and_every_device_returned_is_kept(nb):
    nb.devices = [device("r1", ident=1), device("x2", "10.9.0.2/24", ident=2, site="autre")]
    fetched = netbox.fetch(cfg(nb.addr, filters={"site": ("lab",), "status": ("active",)}), tok())
    assert [d.name for d in fetched.devices] == ["r1"]


def test_the_status_check_requires_a_netbox_version(nb):
    nb.replies["/api/status/"] = (200, {"hello": "world"})
    with pytest.raises(NetboxUnavailable, match="ne ressemble pas à NetBox"):
        netbox.fetch(cfg(nb.addr), tok())
    assert nb.paths() == ["/api/status/"]  # rien n'est demandé au-delà


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_redirect_is_refused_and_never_followed(nb, code):
    other = FakeNetbox()
    try:
        nb.replies["/api/status/"] = (code, {}, {"Location": other.addr + "/api/status/"})
        with pytest.raises(NetboxUnavailable) as error:
            netbox.fetch(cfg(nb.addr), tok())
        assert "redirection refusée" in reasons(error)
        assert other.requests == []  # le jeton n'est pas parti ailleurs
    finally:
        other.stop()


def test_environment_proxies_are_ignored(nb, monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    assert len(netbox.fetch(cfg(nb.addr), tok()).devices) == 3
    assert nb.paths() == ["/api/status/", "/api/dcim/devices/"]


# === 2. pagination ==========================================================================================


def test_a_long_list_is_read_page_by_page(nb):
    nb.devices = many(250)
    fetched = netbox.fetch(cfg(nb.addr), tok())
    assert (fetched.count, fetched.pages, len(fetched.devices)) == (250, 3, 250)
    offsets = [r["query"]["offset"] for r in nb.requests if r["path"].endswith("devices/")]
    assert offsets == [["0"], ["100"], ["200"]]


def _refused_next(nb, mutate, regex):
    nb.devices = many(250)
    nb.next_mutator = mutate
    with pytest.raises(NetboxUnavailable, match=regex):
        netbox.fetch(cfg(nb.addr), tok())
    assert [r["query"]["offset"] for r in nb.requests if r["path"].endswith("devices/")] == [["0"]]


def test_a_next_link_to_another_host_is_refused_and_nothing_is_sent_there(nb):
    other = FakeNetbox(devices=many(250))
    try:
        nb.devices = many(250)
        nb.next_base = other.addr
        with pytest.raises(NetboxUnavailable, match="hors du NetBox configuré"):
            netbox.fetch(cfg(nb.addr), tok())
        assert other.requests == []
    finally:
        other.stop()


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("schéma", lambda url, _n: url.replace("http://", "https://", 1)),
        ("port", lambda url, _n: url.replace(url.split("/")[2], "127.0.0.1:9", 1)),
        ("hôte", lambda url, _n: url.replace("127.0.0.1", "127.0.0.2", 1)),
        ("relatif", lambda url, _n: "/api/dcim/devices/?offset=100"),
        ("identifiants", lambda url, _n: url.replace("://", "://u:p@", 1)),
        ("fragment", lambda url, _n: url + "#x"),
    ],
)
def test_a_next_link_from_another_origin_is_refused(nb, label, mutate):
    _refused_next(nb, mutate, "hors du NetBox configuré")


def test_a_next_link_to_another_path_is_refused(nb):
    _refused_next(nb, lambda url, _n: url.replace("/api/dcim/devices/", "/api/dcim/sites/"), "autre chemin")


@pytest.mark.parametrize(
    "extra", ["&brief=1", "&fields=name", "&q=x", "&limit=0", "&offset=-1", "&site=a%20b"]
)
def test_a_next_link_with_unauthorised_parameters_is_refused(nb, extra):
    _refused_next(nb, lambda url, _n: url + extra, "paramètres non autorisés")


def test_a_next_link_with_other_filters_is_refused(nb):
    _refused_next(nb, lambda url, _n: url.replace("status=active", "status=offline"), "d'autres filtres")
    nb.requests.clear()
    _refused_next(nb, lambda url, _n: url.replace("status=active&", ""), "d'autres filtres")
    nb.requests.clear()
    _refused_next(nb, lambda url, _n: url + "&tag=intrus", "d'autres filtres")


@pytest.mark.parametrize(
    ("hop", "old", "new", "pages_read"),
    [(0, "offset=100", "offset=0", 1), (1, "offset=200", "offset=100", 2), (1, "offset=200", "offset=50", 2)],
)
def test_a_pagination_that_does_not_advance_is_stopped(nb, hop, old, new, pages_read):
    nb.devices = many(250)
    nb.next_mutator = lambda url, number: url.replace(old, new) if number == hop else url
    with pytest.raises(NetboxUnavailable, match="n'avance pas"):
        netbox.fetch(cfg(nb.addr), tok())
    assert len([r for r in nb.requests if r["path"].endswith("devices/")]) == pages_read


def test_a_next_link_that_is_not_text_is_refused(nb):
    nb.devices = many(250)
    nb.next_mutator = lambda url, _n: 5
    with pytest.raises(NetboxUnavailable, match="illisible"):
        netbox.fetch(cfg(nb.addr), tok())


def test_the_page_cap_stops_a_runaway_list(nb, monkeypatch):
    monkeypatch.setattr(netbox, "MAX_PAGES", 3)
    monkeypatch.setattr(netbox, "PAGE_SIZE", 2)
    nb.devices = many(10)
    with pytest.raises(NetboxUnavailable, match="plus de 3 pages"):
        netbox.fetch(cfg(nb.addr), tok())
    assert len([r for r in nb.requests if r["path"].endswith("devices/")]) == 3


def test_a_list_that_fits_in_the_cap_is_accepted(nb, monkeypatch):
    monkeypatch.setattr(netbox, "MAX_PAGES", 5)
    monkeypatch.setattr(netbox, "PAGE_SIZE", 2)
    nb.devices = many(10)
    assert netbox.fetch(cfg(nb.addr), tok()).pages == 5


@pytest.mark.parametrize("delta", [1, -1, 5])
def test_a_count_that_differs_from_the_objects_received_is_refused(nb, delta):
    nb.count_delta = delta
    with pytest.raises(NetboxUnavailable, match="incohérente"):
        netbox.fetch(cfg(nb.addr), tok())


def test_a_total_that_changes_between_pages_is_refused(nb):
    nb.devices = many(250)
    nb.page_counts = lambda page: 250 if page == 0 else 251
    with pytest.raises(NetboxUnavailable, match="total change"):
        netbox.fetch(cfg(nb.addr), tok())


@pytest.mark.parametrize(
    "body",
    [
        {"count": 1, "next": None, "results": "x"},
        {"count": "1", "next": None, "results": [device("r1")]},
        {"count": True, "next": None, "results": [device("r1")]},
        {"count": -1, "next": None, "results": []},
        {"next": None, "results": [device("r1")]},
        {"count": 1, "next": None},
    ],
)
def test_an_unexpected_page_shape_is_refused(nb, body):
    nb.replies["/api/dcim/devices/"] = (200, body)
    with pytest.raises(NetboxUnavailable, match="pagination inattendue"):
        netbox.fetch(cfg(nb.addr), tok())


def test_zero_devices_is_an_error_not_an_empty_inventory(nb):
    nb.devices = []
    with pytest.raises(NetboxUnavailable, match="aucun équipement"):
        netbox.fetch(cfg(nb.addr, filters={"site": ("lab",), "status": ("active",)}), tok())


# === 3. indisponibilités : code 3, jamais de repli ================================================


@pytest.mark.parametrize(
    ("path", "reply", "expected"),
    [
        ("/api/status/", (401, {}), "jeton refusé, HTTP 401"),
        ("/api/status/", (403, {}), "jeton refusé, HTTP 403"),
        ("/api/dcim/devices/", (403, {}), "jeton refusé, HTTP 403"),
        ("/api/status/", (404, {}), "introuvable, HTTP 404"),
        ("/api/status/", (500, {}), "NetBox en erreur, HTTP 500"),
        ("/api/dcim/devices/", (502, {}), "NetBox en erreur, HTTP 502"),
        ("/api/dcim/devices/", (503, {}), "NetBox en erreur, HTTP 503"),
        ("/api/status/", (418, {}), "réponse HTTP 418"),
        ("/api/status/", (200, b"<html>pas du JSON</html>"), "réponse illisible"),
        ("/api/dcim/devices/", (200, b"[]"), "objet JSON attendu"),
        ("/api/status/", (200, b"null"), "objet JSON attendu"),
        ("/api/status/", (200, {"netbox-version": "../x"}), "ne ressemble pas à NetBox"),
        ("/api/status/", (200, {"netbox-version": 4}), "ne ressemble pas à NetBox"),
    ],
)
def test_every_failure_is_unavailable_with_the_host_and_never_the_token(nb, path, reply, expected):
    nb.replies[path] = reply
    with pytest.raises(NetboxUnavailable) as error:
        netbox.fetch(cfg(nb.addr), tok())
    text = reasons(error)
    assert text.startswith("inventaire NetBox indisponible (")
    assert expected in text and f"127.0.0.1:{nb.port}" in text
    assert not any(part in text for part in TOKEN_PARTS)


def test_a_wrong_token_is_refused(nb):
    nb.token = "nbt_AUTREclef0123.AUTREsecret0123456789abcdefghij"
    with pytest.raises(NetboxUnavailable, match="jeton refusé"):
        netbox.fetch(cfg(nb.addr), tok())


def test_a_slow_netbox_times_out(nb, monkeypatch):
    monkeypatch.setattr(netbox, "TIMEOUT", 0.3)
    nb.delay = 1.0
    with pytest.raises(NetboxUnavailable, match=r"délai de 0\.3 s dépassé"):
        netbox.fetch(cfg(nb.addr), tok())


def test_a_closed_port_is_unreachable():
    server = FakeNetbox()
    address = server.addr
    server.stop()
    with pytest.raises(NetboxUnavailable, match="injoignable"):
        netbox.fetch(cfg(address), tok())


def test_a_body_beyond_the_limit_is_refused(nb, monkeypatch):
    monkeypatch.setattr(netbox, "MAX_BODY_BYTES", 100)
    nb.replies["/api/status/"] = (200, b"x" * 500)
    with pytest.raises(NetboxUnavailable, match="trop grande"):
        netbox.fetch(cfg(nb.addr), tok())


# === 4. jeton ===============================================================================================


def test_the_token_comes_from_the_variable_and_says_so():
    token = netbox.read_token({netbox.ENV_TOKEN: f" {TOKEN}\n"})
    assert token.reveal() == TOKEN and token.source == f"variable {netbox.ENV_TOKEN}"


def test_the_token_comes_from_a_0600_file_and_says_so(tmp_path):
    path = tmp_path / "nbtoken"
    path.write_text(TOKEN + "\n", encoding="utf-8")
    path.chmod(0o600)
    token = netbox.read_token({netbox.ENV_TOKEN_FILE: str(path)})
    assert token.reveal() == TOKEN
    assert str(path) in token.source and "0600" in token.source


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o660])
def test_a_token_file_others_can_read_is_refused_without_the_value(tmp_path, mode):
    path = tmp_path / "nbtoken"
    path.write_text(TOKEN + "\n", encoding="utf-8")
    path.chmod(mode)
    with pytest.raises(CredentialError) as error:
        netbox.read_token({netbox.ENV_TOKEN_FILE: str(path)})
    assert "droits" in str(error.value) and not any(part in str(error.value) for part in TOKEN_PARTS)


def test_a_token_file_with_several_lines_or_empty_is_refused(tmp_path):
    for content in (TOKEN + "\nautre\n", "", "\n"):
        path = tmp_path / "nbtoken"
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        with pytest.raises(CredentialError):
            netbox.read_token({netbox.ENV_TOKEN_FILE: str(path)})


def test_the_variable_wins_over_the_file(tmp_path):
    path = tmp_path / "nbtoken"
    path.write_text("nbt_AUTREclef0123.AUTREsecret0123456789abcdefghij\n", encoding="utf-8")
    path.chmod(0o600)
    token = netbox.read_token({netbox.ENV_TOKEN: TOKEN, netbox.ENV_TOKEN_FILE: str(path)})
    assert token.reveal() == TOKEN


def test_a_missing_token_names_both_variables():
    with pytest.raises(NetboxConfigError) as error:
        netbox.read_token({})
    assert netbox.ENV_TOKEN in str(error.value) and netbox.ENV_TOKEN_FILE in str(error.value)
    with pytest.raises(NetboxConfigError):
        netbox.read_token({netbox.ENV_TOKEN: "   "})


V1 = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize("bad", [V1, "pas-un-jeton", "nbt_sans-point", "nbt_.x", "nbt_a.", "Bearer " + TOKEN])
def test_only_a_v2_token_is_accepted_and_the_message_never_has_the_value(bad):
    with pytest.raises(NetboxConfigError) as error:
        netbox.read_token({netbox.ENV_TOKEN: bad})
    assert bad not in str(error.value)
    assert ("v1" in str(error.value)) == (bad == V1)
    assert secrets.redact_known(f"x {bad} y") == "x **** y" or len(bad) < secrets.MIN_REGISTERED_LENGTH


def test_the_token_is_a_secretstr_registered_whole_and_by_parts():
    token = tok()
    assert isinstance(token, SecretStr)
    for text in (str(token), repr(token), f"{token}", f"{token:>10}"):
        assert not any(part in text for part in TOKEN_PARTS)
    out = secrets.redact_known(f"a {TOKEN} b {TOKEN_PARTS[1]} c {TOKEN_PARTS[2]} d")
    assert out == "a **** b **** c **** d"


def test_the_token_is_not_accepted_in_the_inventory_block():
    with pytest.raises(NetboxConfigError, match="clé"):
        netbox.parse_block(
            {"url": "https://nb.example", "platforms": PLATFORMS, "token": TOKEN}, "inv.yml", False
        )


# === 5. TLS =======================================================================================


def _certificate(directory: Path, name: str, san: str = "IP:127.0.0.1"):
    if shutil.which("openssl") is None:
        pytest.skip("openssl absent")
    key, crt = directory / f"{name}.key", directory / f"{name}.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(key), "-out", str(crt), "-days", "1", "-subj", "/CN=127.0.0.1",
            "-addext", f"subjectAltName={san}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    return str(crt), str(key)


@pytest.fixture
def tls_nb(tmp_path):
    server = FakeNetbox()
    crt, key = _certificate(tmp_path, "server")
    server.enable_tls(crt, key)
    server.crt = crt
    yield server
    server.stop()


def test_tls_is_verified_by_default_an_untrusted_certificate_is_refused(tls_nb):
    with pytest.raises(NetboxUnavailable) as error:
        netbox.fetch(cfg(tls_nb.addr), tok())
    assert "certificat TLS refusé" in reasons(error) and "--netbox-cacert" in reasons(error)
    assert tls_nb.requests == []  # la poignée de main échoue : aucune requête, donc aucun jeton envoyé


def test_the_given_authority_makes_the_certificate_acceptable(tls_nb):
    fetched = netbox.fetch(cfg(tls_nb.addr, cacert=tls_nb.crt), tok())
    assert len(fetched.devices) == 3
    assert all(r["authorization"] == f"Bearer {TOKEN}" for r in tls_nb.requests)


def test_another_authority_is_not_enough(tls_nb, tmp_path):
    other_crt, _ = _certificate(tmp_path, "autre")
    with pytest.raises(NetboxUnavailable, match="certificat TLS refusé"):
        netbox.fetch(cfg(tls_nb.addr, cacert=other_crt), tok())
    assert tls_nb.requests == []


def test_the_host_name_is_checked_even_with_the_right_authority(tls_nb):
    with pytest.raises(NetboxUnavailable, match="certificat TLS refusé"):
        netbox.fetch(cfg(f"https://localhost:{tls_nb.port}", cacert=tls_nb.crt), tok())
    assert tls_nb.requests == []


def test_an_unreadable_authority_file_is_a_configuration_error(tls_nb, tmp_path):
    garbage = tmp_path / "garbage.pem"
    garbage.write_text("pas un certificat\n", encoding="utf-8")
    with pytest.raises(NetboxConfigError, match="illisible"):
        netbox.fetch(cfg(tls_nb.addr, cacert=str(garbage)), tok())
    assert tls_nb.requests == []


def test_a_missing_authority_file_is_refused_and_the_option_wins_over_the_block(tmp_path):
    config = cfg("https://nb.example", cacert="/chemin/yaml.pem")
    with pytest.raises(NetboxConfigError, match="introuvable"):
        netbox.with_cacert(config, str(tmp_path / "absente.pem"))
    with pytest.raises(NetboxConfigError, match="introuvable"):
        netbox.with_cacert(config, None)  # le chemin du bloc compte aussi
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    assert netbox.with_cacert(config, str(ca)).cacert == str(ca)
    assert netbox.with_cacert(cfg("https://nb.example"), None).cacert is None


@pytest.mark.parametrize("key", ["verify", "insecure", "tls_verify", "ssl_verify", "verify_ssl", "token"])
def test_there_is_no_way_to_turn_verification_off(key):
    spec = {"url": "https://nb.example", "platforms": PLATFORMS, key: False}
    with pytest.raises(NetboxConfigError, match="inconnue"):
        netbox.parse_block(spec, "inv.yml", True)


def _block(url, lab=False, **extra):
    return netbox.parse_block({"url": url, "platforms": PLATFORMS, **extra}, "inv.yml", lab)


def test_plain_http_is_for_loopback_on_a_lab_inventory_only():
    assert _block("http://127.0.0.1:8000", lab=True).is_http
    assert _block("http://localhost:8000", lab=True).is_http
    assert _block("http://[::1]:8000", lab=True).is_http
    with pytest.raises(NetboxConfigError, match="lab: true"):
        _block("http://127.0.0.1:8000", lab=False)
    for host in ("nb.example", "10.0.0.5", "192.168.1.1", "127.0.0.1.evil.example", "0.0.0.0"):
        with pytest.raises(NetboxConfigError, match="bouclage"):
            _block(f"http://{host}", lab=True)


def test_https_is_accepted_anywhere_with_or_without_lab():
    for lab in (True, False):
        assert not _block("https://nb.example:8443", lab=lab).is_http
        assert _block("https://127.0.0.1:8443", lab=lab).url == "https://127.0.0.1:8443"


@pytest.mark.parametrize(
    "url",
    [
        "", None, 5, "nb.example", "ftp://nb.example", "file:///etc/passwd", "https://",
        "https://u:p@nb.example",
        "https://nb.example/api", "https://nb.example/?a=1", "https://nb.example/#x",
        "https://nb.example:99999",
        "https://nb.example:abc",
    ],
)  # fmt: skip
def test_an_unusable_url_is_refused(url):
    with pytest.raises(NetboxConfigError):
        _block(url, lab=True)


def test_the_plain_http_use_is_announced_in_the_output():
    info = netbox.NetboxInfo(
        "http://127.0.0.1:8000", "4.7.3", "variable X", {"status": ("active",)}, 3, plain_http=True
    )
    text = "\n".join(info.lines())
    assert "http://" in text and "en clair" in text and "lab" in text
    assert "en clair" not in "\n".join(netbox.NetboxInfo("https://x", "4", "v", {}, 1).lines())


# === 6. bloc de configuration =====================================================================


@pytest.mark.parametrize(
    "spec",
    [
        None, [], "x", {},
        {"url": "https://nb.example"},
        {"url": "https://nb.example", "platforms": {}},
        {"url": "https://nb.example", "platforms": {"frr": "cisco"}},
        {"url": "https://nb.example", "platforms": {"frr": 5}},
        {"url": "https://nb.example", "platforms": {"bad slug": "frr"}},
        {"url": "https://nb.example", "platforms": PLATFORMS, "site": ""},
        {"url": "https://nb.example", "platforms": PLATFORMS, "site": ["a b"]},
        {"url": "https://nb.example", "platforms": PLATFORMS, "role": []},
        {"url": "https://nb.example", "platforms": PLATFORMS, "tag": [5]},
        {"url": "https://nb.example", "platforms": PLATFORMS, "cacert": ""},
        {"url": "https://nb.example", "platforms": PLATFORMS, "inconnue": 1},
    ],
)  # fmt: skip
def test_a_malformed_block_is_refused(spec):
    with pytest.raises(NetboxConfigError):
        netbox.parse_block(spec, "inv.yml", True)


def test_the_block_defaults_to_active_devices_and_accepts_lists():
    config = _block("https://nb.example/", site=["a", "b"], tag="netcheck")
    assert config.url == "https://nb.example"
    assert config.filters == {"site": ("a", "b"), "tag": ("netcheck",), "status": ("active",)}
    assert _block("https://nb.example", status=["active", "staged"]).filters["status"] == ("active", "staged")


def test_every_mapped_driver_exists_and_has_a_device_type():
    assert set(netbox.DEVICE_TYPES) == {"frr", "eos", "srlinux"}
    assert set(netbox.DEVICE_TYPES) <= set(DRIVER_REGISTRY)


# === 7. appareils inutilisables : TOUS listés d'un coup ===========================================


def _raw(**kw):
    base = {"id": 1, "name": "r1", "platform": {"slug": "frr"}, "primary_ip": {"address": "10.0.0.1/24"}}
    base.update(kw)
    return base


def test_all_the_faulty_devices_are_listed_at_once_sorted():
    raw = [
        _raw(id=1, name="r1"),
        _raw(id=2, name="r7", primary_ip=None),
        _raw(id=3, name="r8", primary_ip={"address": None}),
        _raw(id=4, name="r9", platform=None),
        _raw(id=5, name="r10", platform={"slug": "cisco-ios"}),
        _raw(id=6, name="r 11"),
        _raw(id=7, name="r12", primary_ip={"address": "pas-une-ip"}),
        _raw(id=8, name="r13", primary_ip=None, platform=None),
        _raw(id=9, name="r1", primary_ip={"address": "10.0.0.2/24"}),
        "n'importe quoi",
    ]
    with pytest.raises(NetboxInventoryError) as error:
        netbox.to_devices(raw, cfg("https://nb.example"))
    text = reasons(error)
    assert text.startswith("équipement(s) NetBox inutilisable(s), 9 sur 10 : ")
    for fragment in (
        "r7 (IP primaire absente)",
        "r8 (IP primaire absente)",
        "r9 (plateforme absente)",
        "r10 (plateforme « cisco-ios » sans correspondance dans `platforms`)",
        "r12 (IP primaire illisible)",
        "r13 (IP primaire absente, plateforme absente)",
        "r1 (nom en double)",
        "(équipement n°6) (nom inutilisable",
    ):
        assert fragment in text, fragment
    assert text.index("r1 (") < text.index("r10 (") < text.index("r12 (")  # triés


def test_a_clean_list_gives_devices_with_ip_without_mask_and_driver():
    raw = [
        _raw(id=1, name="r1"),
        _raw(id=2, name="r2", platform={"slug": "eos"}, primary_ip={"address": "2001:db8::2/64"}),
    ]
    devices = netbox.to_devices(raw, cfg("https://nb.example"))
    assert [(d.name, d.host, d.driver) for d in devices] == [
        ("r1", "10.0.0.1", "frr"),
        ("r2", "2001:db8::2", "eos"),
    ]


# === 8. fusion avec l'inventaire local ============================================================


def _fetched(*devices):
    return netbox.Fetched(version="4.7.3", devices=list(devices), count=len(devices), pages=1)


def D(name, host="10.0.0.1", driver="frr"):  # noqa: N802
    return netbox.Device(name=name, host=host, driver=driver, platform=driver)


def _merge(local, devices, defaults=None):
    return netbox.merge(local, defaults or {}, _fetched(*devices), cfg("https://nb.example"), "variable T")


def test_a_netbox_only_device_gets_netbox_facts_and_the_device_type_of_its_driver():
    merged, info = _merge({}, [D("r9", "10.0.0.9", "eos")], {"device_type": "linux"})
    assert merged == {"r9": {"host": "10.0.0.9", "driver": "eos", "device_type": "arista_eos"}}
    assert info.netbox_only == ["r9"] and info.both == []


def test_a_device_in_both_keeps_every_local_attribute():
    local = {
        "r1": {"ospf_neighbors": 2, "bgp_peers": {"1.1.1.1": 2}, "device_type": "custom", "username": "x"}
    }
    merged, info = _merge(local, [D("r1", "10.0.0.1", "frr")])
    assert merged["r1"] == {**local["r1"], "host": "10.0.0.1", "driver": "frr"}
    assert info.both == ["r1"] and info.netbox_only == []


def test_a_local_entry_without_host_or_driver_is_filled_by_netbox():
    merged, _ = _merge({"r1": None, "r4": {"ospf_neighbors": 1}}, [D("r1"), D("r4", "10.0.0.4", "eos")])
    assert merged["r1"] == {"host": "10.0.0.1", "driver": "frr", "device_type": "linux"}
    assert merged["r4"]["host"] == "10.0.0.4" and merged["r4"]["device_type"] == "arista_eos"
    assert merged["r4"]["ospf_neighbors"] == 1


def test_the_same_address_written_differently_is_not_a_conflict():
    merged, _ = _merge({"r2": {"host": "2001:0db8:0:0:0:0:0:2"}}, [D("r2", "2001:db8::2")])
    assert merged["r2"]["host"] == "2001:0db8:0:0:0:0:0:2"  # le local est conservé tel quel


def test_every_conflict_and_every_missing_device_is_reported_together():
    local = {
        "r1": {"host": "10.0.0.99"},
        "r3": {"host": "r3.lab.example"},
        "r4": {"driver": "srlinux"},
        "r6": {},
        "r8": {},
    }
    devices = [D("r1"), D("r3", "10.0.0.3"), D("r4", "10.0.0.4", "eos"), D("r5", "10.0.0.5")]
    with pytest.raises(NetboxInventoryError) as error:
        _merge(local, devices)
    text = reasons(error)
    assert "conflit entre NetBox et l'inventaire local, 3 équipement(s)" in text
    assert "r1 (adresse : NetBox 10.0.0.1, local 10.0.0.99)" in text
    assert "r3 (adresse : NetBox 10.0.0.3, local r3.lab.example)" in text
    assert "r4 (driver : NetBox eos, local srlinux)" in text
    assert "absent(s) de NetBox" in text and "r6, r8" in text
    assert text.index("r1 (adresse") < text.index("r3 (adresse") < text.index("r4 (driver")


def test_a_default_driver_that_contradicts_netbox_is_a_conflict_for_a_local_entry_only():
    with pytest.raises(NetboxInventoryError, match=r"r1 \(driver : NetBox frr, local eos\)"):
        netbox.merge({"r1": {}}, {"driver": "eos"}, _fetched(D("r1")), cfg("https://nb.example"), "v")
    merged, _ = netbox.merge({}, {"driver": "eos"}, _fetched(D("r2")), cfg("https://nb.example"), "v")
    assert (
        merged["r2"]["driver"] == "frr"
    )  # un équipement de NetBox seul : NetBox décide, `defaults` n'est qu'un repli


def test_the_local_only_error_names_the_filters_that_may_have_hidden_the_device():
    config = cfg("https://nb.example", filters={"site": ("lab",), "status": ("active",)})
    with pytest.raises(NetboxInventoryError, match=r"filtres site=lab, status=active\) : r9"):
        netbox.merge({"r9": {}}, {}, _fetched(D("r1")), config, "v")


def test_the_information_lines_say_where_the_list_comes_from_and_what_is_not_evaluable():
    _, info = _merge({"r1": {}}, [D("r1"), D("r9", "10.0.0.9")])
    first, second = info.lines()
    assert "https://nb.example (NetBox 4.7.3)" in first and "2 équipement(s)" in first
    assert "1 aussi dans l'inventaire local, 1 de NetBox seulement" in first
    assert "jeton : variable T" in first
    assert second.startswith("Attendus locaux absents pour : r9") and "NON ÉVALUABLE" in second
    assert len(_merge({}, [D("r1")])[1].lines()) == 2
    assert len(_merge({"r1": {}}, [D("r1")])[1].lines()) == 1


# === 9. inventory.load : NetBox seulement en direct ===============================================


def write_inventory(tmp_path, url, routers=None, lab=True, block=None, defaults=None):
    data = {
        "lab": lab,
        "defaults": DEFAULTS if defaults is None else defaults,
        "management_interfaces": ["eth0"],
        "netbox": {
            "url": url,
            "platforms": PLATFORMS,
            "site": "lab",
            "role": "router",
            "tag": "netcheck",
            **(block or {}),
        },
    }
    if routers is not None:
        data["routers"] = routers
    path = tmp_path / "inventory.yml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


@pytest.fixture
def live(nb, monkeypatch):
    monkeypatch.setenv(netbox.ENV_TOKEN, TOKEN)
    return nb


def test_the_inventory_is_merged_from_netbox_and_the_local_file(tmp_path, live):
    live.devices = [device("r1", "10.0.0.1/24", "frr", 1), device("r9", "10.0.0.9/24", "eos", 9)]
    path = write_inventory(tmp_path, live.addr, routers={"r1": {"ospf_neighbors": 2}})
    inv = inventory.load(path=path)
    assert sorted(inv.routers) == ["r1", "r9"]
    assert inv.routers["r1"]["host"] == "10.0.0.1" and inv.routers["r1"]["ospf_neighbors"] == 2
    r9 = inv.routers["r9"]
    assert (r9["host"], r9["driver"], r9["device_type"]) == ("10.0.0.9", "eos", "arista_eos")
    assert r9["username"] == "netops" and "ospf_neighbors" not in r9  # défauts, aucun attendu
    assert inv.netbox_info.netbox_only == ["r9"] and inv.netbox_info.both == ["r1"]
    assert (
        inv.netbox_info.version == "4.7.3" and inv.netbox_info.token_source == f"variable {netbox.ENV_TOKEN}"
    )
    assert inv.lab is True and inv.management_interfaces == ["eth0"]


def test_netbox_never_decides_lab_credentials_or_expectations(tmp_path, live):
    hostile = {"lab": False, "password": "pris-dans-netbox-1", "ospf_neighbors": 9, "username": "intrus"}
    live.devices = [
        device(
            "r1", "10.0.0.1/24", "frr", 1, comments="lab: false password: x", custom_fields=hostile, **hostile
        )
    ]
    inv = inventory.load(path=write_inventory(tmp_path, live.addr))
    router = inv.routers["r1"]
    assert inv.lab is True  # `lab` vient du fichier local, jamais de NetBox
    assert router["username"] == "netops" and router["password"] == "netops-pass-1"
    assert "ospf_neighbors" not in router and "privilege_wrapper" not in router and "bastion" not in router
    assert set(router) - {"credential_sources", "password"} >= {"host", "driver", "device_type", "name"}


def test_routers_may_be_absent_with_a_netbox_block_but_not_without(tmp_path, live):
    inv = inventory.load(path=write_inventory(tmp_path, live.addr))
    assert sorted(inv.routers) == ["r1", "r4", "r5"]
    plain = tmp_path / "plain.yml"
    plain.write_text(yaml.safe_dump({"defaults": DEFAULTS}), encoding="utf-8")
    with pytest.raises(UsageError, match="routers"):
        inventory.load(path=str(plain))


def test_offline_loading_never_contacts_netbox_and_needs_no_token(tmp_path, nb):
    path = write_inventory(tmp_path, nb.addr, routers={"r1": {"host": "10.0.0.1"}})
    inv = inventory.load(path=path, resolve_credentials=False)
    assert nb.requests == []
    assert sorted(inv.routers) == ["r1"] and inv.netbox_info is None
    empty = inventory.load(path=write_inventory(tmp_path, nb.addr), resolve_credentials=False)
    assert empty.routers == {} and nb.requests == []


def test_the_block_structure_is_checked_even_offline(tmp_path, nb):
    path = write_inventory(tmp_path, nb.addr, block={"inconnue": 1})
    with pytest.raises(NetboxConfigError):
        inventory.load(path=path, resolve_credentials=False)
    assert nb.requests == []


def test_a_missing_token_stops_before_any_request(tmp_path, nb):
    with pytest.raises(NetboxConfigError, match="jeton NetBox absent"):
        inventory.load(path=write_inventory(tmp_path, nb.addr))
    assert nb.requests == []


def test_the_device_filter_applies_after_the_merge(tmp_path, live):
    inv = inventory.load(only=["r4"], path=write_inventory(tmp_path, live.addr))
    assert sorted(inv.routers) == ["r4"]
    with pytest.raises(UsageError, match="inconnu"):
        inventory.load(only=["r77"], path=write_inventory(tmp_path, live.addr))


def test_a_local_router_missing_from_netbox_is_an_error_and_nothing_else_happens(tmp_path, live):
    path = write_inventory(tmp_path, live.addr, routers={"r1": {}, "r8": {}, "r6": {}})
    with pytest.raises(NetboxInventoryError, match="r6, r8"):
        inventory.load(path=path)


def test_credentials_are_resolved_after_the_merge(tmp_path, live, monkeypatch):
    monkeypatch.setenv("NETCHECK_EOS_USER", "operateur-eos")
    inv = inventory.load(path=write_inventory(tmp_path, live.addr))
    assert inv.routers["r4"]["username"] == "operateur-eos" and inv.routers["r1"]["username"] == "netops"
    assert "credential_sources" in inv.routers["r1"]


def test_the_cacert_option_reaches_the_client(tmp_path, tls_nb, monkeypatch):
    monkeypatch.setenv(netbox.ENV_TOKEN, TOKEN)
    path = write_inventory(tmp_path, tls_nb.addr)
    with pytest.raises(NetboxUnavailable, match="certificat"):
        inventory.load(path=path)
    assert sorted(inventory.load(path=path, netbox_cacert=tls_nb.crt).routers) == ["r1", "r4", "r5"]


# === 10. CLI : annonce, codes, aucun repli ========================================================


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setattr(cli, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(inventory, "REPO_ROOT", tmp_path)
    seen = {}

    def fake_collect(routers, driver=None, workers=5):
        seen["routers"] = routers
        return {
            name: (
                True,
                DeviceState(name=name, host=r["host"], timestamp="t", reachable=True, driver=r["driver"]),
            )
            for name, r in routers.items()
        }

    monkeypatch.setattr(collector, "collect_all", fake_collect)
    return seen


def test_snapshot_reads_the_list_from_netbox_and_announces_the_source(tmp_path, live, cli_env, capsys):
    path = write_inventory(tmp_path, live.addr, routers={"r1": {"ospf_neighbors": 2}})
    assert cli.main(["snapshot", "s1", "-i", path]) == 0
    captured = capsys.readouterr()
    assert sorted(cli_env["routers"]) == ["r1", "r4", "r5"]
    assert cli_env["routers"]["r4"]["host"] == "10.0.0.4" and cli_env["routers"]["r4"]["driver"] == "eos"
    assert "Inventaire NetBox : " in captured.err and f"jeton : variable {netbox.ENV_TOKEN}" in captured.err
    assert "2 de NetBox seulement" in captured.err and "NON ÉVALUABLE" in captured.err
    assert "http://" in captured.err and "en clair" in captured.err  # http en bouclage : annoncé
    assert (tmp_path / "snaps" / "s1").is_dir()


UNAVAILABLE = [
    ("status 500", lambda nb: nb.replies.update({"/api/status/": (500, {})}), "NetBox en erreur"),
    ("jeton refusé", lambda nb: setattr(nb, "token", OTHER_TOKEN), "jeton refusé"),
    ("JSON illisible", lambda nb: nb.replies.update({"/api/dcim/devices/": (200, b"<html>")}), "illisible"),
    ("compte faux", lambda nb: setattr(nb, "count_delta", 1), "incohérente"),
    ("zéro équipement", lambda nb: setattr(nb, "devices", []), "aucun équipement"),
    ("redirection", lambda nb: nb.replies.update({"/api/status/": (302, {}, REDIRECT)}), "redirection"),
]  # fmt: skip


@pytest.mark.parametrize(("label", "break_it", "expected"), UNAVAILABLE, ids=[u[0] for u in UNAVAILABLE])
def test_every_failure_is_code_3_with_one_line_and_no_collection_no_fallback(
    tmp_path, live, cli_env, capsys, monkeypatch, label, break_it, expected
):
    break_it(live)
    path = write_inventory(
        tmp_path, live.addr, routers={"r1": {"host": "10.0.0.1"}}
    )  # un YAML tentant : jamais utilisé
    monkeypatch.setattr(
        collector, "collect_all", lambda *a, **k: pytest.fail("aucune collecte ne doit avoir lieu")
    )
    assert cli.main(["snapshot", "s1", "-i", path]) == 3
    captured = capsys.readouterr()
    lines = [ln for ln in captured.err.splitlines() if ln.strip()]
    assert len(lines) == 1 and lines[0].startswith("Erreur : inventaire NetBox indisponible (")
    assert expected in lines[0] and "Traceback" not in captured.err
    assert not (tmp_path / "snaps").exists()  # aucun résultat partiel


def test_an_unreachable_netbox_is_code_3_on_every_live_command(tmp_path, cli_env, capsys, monkeypatch):
    server = FakeNetbox()
    address = server.addr
    server.stop()
    monkeypatch.setenv(netbox.ENV_TOKEN, TOKEN)
    monkeypatch.setattr(collector, "collect_all", lambda *a, **k: pytest.fail("aucune collecte"))
    snapshot.save("base", {})
    path = write_inventory(tmp_path, address)
    intent = next((ROOT / "intents").glob("*.yml"))
    for argv in (
        ["snapshot", "s1", "-i", path],
        ["check", "-i", path],
        ["assert", "--intent", str(intent), "-i", path],
        ["monitor", "--baseline", "base", "-i", path],
    ):
        assert cli.main(argv) == 3, argv
        err = capsys.readouterr().err
        assert "Erreur : inventaire NetBox indisponible (" in err and "injoignable" in err, (argv, err)


def test_offline_commands_never_contact_netbox(tmp_path, nb, capsys, monkeypatch):
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    path = write_inventory(tmp_path, nb.addr, routers={"r1": {"host": "10.0.0.1"}})
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    (config_dir / "r1.conf").write_text(
        "hostname r1\nrouter ospf\n ospf router-id 1.1.1.1\n", encoding="utf-8"
    )
    cli.main(["check", "--config-dir", str(config_dir), "-i", path, "--driver", "frr"])
    assert nb.requests == []
    snap = {"r1": (True, DeviceState(name="r1", host="10.0.0.1", timestamp="t", reachable=True))}
    snapshot.save("base", snap)
    cli.main(["check", "--snapshot", "base", "-i", path])
    cli.main(["diff", "base", "base", "-i", path])
    assert nb.requests == []


def test_netbox_cacert_is_refused_with_offline_commands(tmp_path, nb, capsys):
    path = write_inventory(tmp_path, nb.addr)
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    assert cli.main(["check", "--snapshot", "base", "-i", path, "--netbox-cacert", str(ca)]) == 3
    assert "hors ligne, NetBox n'est jamais contacté" in capsys.readouterr().err
    assert nb.requests == []


def test_every_live_command_has_the_netbox_cacert_option_and_the_offline_ones_do_not():
    parser = cli.build_parser()
    commands = parser._subparsers._group_actions[0].choices
    with_option = {n for n, p in commands.items() if "--netbox-cacert" in p.format_help()}
    assert with_option == {"snapshot", "check", "guard", "assert", "monitor"}


def test_netbox_cacert_works_end_to_end_through_the_cli(tmp_path, tls_nb, cli_env, monkeypatch, capsys):
    monkeypatch.setenv(netbox.ENV_TOKEN, TOKEN)
    path = write_inventory(tmp_path, tls_nb.addr)
    assert cli.main(["snapshot", "s1", "-i", path]) == 3
    assert "certificat TLS refusé" in capsys.readouterr().err and tls_nb.requests == []
    assert cli.main(["snapshot", "s2", "-i", path, "--netbox-cacert", tls_nb.crt]) == 0
    assert "en clair" not in capsys.readouterr().err  # https : pas d'avertissement http


# === 11. jeton sentinelle : aucune sortie, aucun fichier, même si une exception le recopie ========


def _everything_written(tmp_path: Path) -> str:
    chunks = []
    for item in sorted(tmp_path.rglob("*")):
        if item.is_file():
            chunks.append(item.read_bytes().decode("utf-8", errors="replace"))
    return "\n".join(chunks)


def _assert_no_token(*texts):
    for text in texts:
        for part in TOKEN_PARTS:
            assert part not in text, f"le jeton (ou un morceau) est apparu : {text[:200]!r}"


@pytest.mark.parametrize("mode", ["succès", "jeton refusé", "500", "JSON", "injoignable"])
def test_the_token_is_in_no_output_and_no_file(tmp_path, live, cli_env, capsys, mode):
    if mode == "jeton refusé":
        live.token = "nbt_AUTREclef0123.AUTREsecret0123456789abcdefghij"
    elif mode == "500":
        live.replies["/api/dcim/devices/"] = (500, {"detail": f"erreur {TOKEN}"})
    elif mode == "JSON":
        live.replies["/api/status/"] = (200, f"<html>{TOKEN}</html>".encode())
    path = write_inventory(tmp_path, live.addr)
    if mode == "injoignable":
        live.stop()
    code = cli.main(["snapshot", "s1", "-i", path])
    captured = capsys.readouterr()
    assert code == (0 if mode == "succès" else 3)
    _assert_no_token(captured.out, captured.err, _everything_written(tmp_path))


class _CopyingOpener:
    """Un opener dont l'exception recopie le jeton dans son message, comme une bibliothèque maladroite."""

    def __init__(self, error):
        self.error = error

    def open(self, request, timeout=None):
        raise self.error(f"échec avec {request.get_header('Authorization')} et {TOKEN}")


@pytest.mark.parametrize("error", [RuntimeError, ValueError, KeyError, OSError, ssl.SSLError])
def test_an_exception_that_copies_the_token_never_reaches_the_user(
    tmp_path, live, cli_env, capsys, monkeypatch, error
):
    monkeypatch.setattr(netbox, "_build_opener", lambda config: _CopyingOpener(error))
    path = write_inventory(tmp_path, live.addr)
    assert cli.main(["snapshot", "s1", "-i", path]) == 3
    captured = capsys.readouterr()
    assert "inventaire NetBox indisponible" in captured.err
    _assert_no_token(captured.out, captured.err, _everything_written(tmp_path))


def test_a_defect_that_copies_the_token_is_masked_by_the_last_resort_handler(
    tmp_path, live, cli_env, capsys, monkeypatch
):
    def broken(config, token, opener=None):
        raise RuntimeError(f"défaut interne qui recopie {token.reveal()}")

    monkeypatch.setattr(netbox, "fetch", broken)
    assert cli.main(["snapshot", "s1", "-i", write_inventory(tmp_path, live.addr)]) == 70
    captured = capsys.readouterr()
    assert "Erreur interne de netcheck" in captured.err
    _assert_no_token(captured.out, captured.err, _everything_written(tmp_path))


def test_a_refused_v1_token_is_masked_everywhere_too(tmp_path, live, cli_env, capsys, monkeypatch):
    monkeypatch.setenv(netbox.ENV_TOKEN, V1)
    assert cli.main(["snapshot", "s1", "-i", write_inventory(tmp_path, live.addr)]) == 3
    captured = capsys.readouterr()
    assert V1 not in captured.err and "v1" in captured.err and live.requests == []


def test_the_token_is_never_in_the_command_line_of_the_process_by_design():
    parser = cli.build_parser()
    for command in parser._subparsers._group_actions[0].choices.values():
        options = " ".join(command.format_help().split())
        assert "--netbox-token" not in options and "--token" not in options


# === 13. compléments issus de la passe de mutations ===================================================


@pytest.mark.parametrize("error", [RuntimeError, ValueError, KeyError, OSError, ssl.SSLError])
def test_the_exception_itself_never_carries_the_library_text_nor_the_token(live, error):
    """Le masquage de la CLI cacherait un message qui recopie le jeton : on regarde l'exception elle-même."""
    with pytest.raises(NetboxUnavailable) as raised:
        netbox.fetch(cfg(live.addr), tok(), opener=_CopyingOpener(error))
    text = str(raised.value)
    assert not any(part in text for part in TOKEN_PARTS) and "échec avec" not in text
    assert raised.value.__cause__ is None and raised.value.__suppress_context__ is True


class _TlsError(ssl.SSLError):
    """Une erreur TLS avec la `reason` d'OpenSSL qu'on veut simuler (le constructeur ne la fixe pas)."""

    def __init__(self, reason):
        super().__init__(1, f"[SSL: {reason}] simulé")
        self.reason = reason


class _RaisingOpener:
    def __init__(self, error):
        self.error = error

    def open(self, request, timeout=None):
        raise self.error


def _fetch_with(live, error):
    return netbox.fetch(cfg(live.addr), tok(), opener=_RaisingOpener(error))


def test_a_certificate_verification_error_is_a_certificate_refusal(live):
    with pytest.raises(NetboxUnavailable) as raised:
        _fetch_with(live, ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] simulé"))
    assert "certificat TLS refusé" in str(raised.value) and "--netbox-cacert" in str(raised.value)
    assert "ne parle pas TLS" not in str(raised.value)


@pytest.mark.parametrize(
    "reason",
    ["WRONG_VERSION_NUMBER", "RECORD_LAYER_FAILURE", "UNKNOWN_PROTOCOL", "HTTP_REQUEST", "WRONG_SSL_VERSION"],
)
def test_a_server_that_does_not_speak_tls_is_told_apart_from_a_refused_certificate(live, reason):
    for error in (_TlsError(reason), urllib.error.URLError(_TlsError(reason))):
        with pytest.raises(NetboxUnavailable) as raised:
            _fetch_with(live, error)
        text = str(raised.value)
        assert "ne parle pas TLS sur ce port" in text and "schéma et le port" in text
        assert "certificat TLS refusé" not in text and reason not in text


def test_any_other_tls_failure_is_a_negotiation_failure_without_the_library_text(live):
    for error in (ssl.SSLError("texte de bibliothèque secret"), _TlsError("SSLV3_ALERT_HANDSHAKE_FAILURE")):
        with pytest.raises(NetboxUnavailable) as raised:
            _fetch_with(live, error)
        text = str(raised.value)
        assert "échec de la négociation TLS" in text
        assert "secret" not in text and "HANDSHAKE" not in text and "certificat TLS refusé" not in text


def test_https_towards_a_plain_http_server_says_it_does_not_speak_tls(live):
    with pytest.raises(NetboxUnavailable, match="ne parle pas TLS sur ce port"):
        netbox.fetch(cfg(live.addr.replace("http://", "https://")), tok())
    assert live.requests == []


def test_the_body_is_read_with_a_bound_so_an_endless_stream_cannot_exhaust_memory():
    asked = []

    class Endless:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def read(self, size=-1):
            asked.append(size)
            return b"x" * (size if size > 0 else 10**9)

    class Opener:
        def open(self, request, timeout=None):
            return Endless()

    with pytest.raises(NetboxUnavailable, match="trop grande"):
        netbox.fetch(cfg("https://nb.example"), tok(), opener=Opener())
    assert asked == [netbox.MAX_BODY_BYTES + 1]


def test_the_lab_flag_of_the_file_decides_plain_http_at_load_time_even_offline(tmp_path, nb):
    for lab in (False, None):
        path = write_inventory(tmp_path, nb.addr, lab=bool(lab), routers={"r1": {"host": "10.0.0.1"}})
        if lab is None:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
            del data["lab"]
            Path(path).write_text(yaml.safe_dump(data), encoding="utf-8")
        for offline in (True, False):
            with pytest.raises(NetboxConfigError, match="lab: true"):
                inventory.load(path=path, resolve_credentials=not offline)
    assert nb.requests == []


def test_an_empty_routers_object_is_still_an_error_without_a_netbox_block(tmp_path):
    for routers in ({}, None, []):
        data = {"defaults": DEFAULTS, "routers": routers}
        path = tmp_path / "plain.yml"
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        with pytest.raises(UsageError, match="routers"):
            inventory.load(path=str(path))


def test_the_default_driver_of_the_file_is_checked_against_netbox_at_load_time(tmp_path, live):
    path = write_inventory(tmp_path, live.addr, routers={"r1": {}}, defaults={**DEFAULTS, "driver": "eos"})
    with pytest.raises(NetboxInventoryError, match=r"r1 \(driver : NetBox frr, local eos\)"):
        inventory.load(path=path)


# === 12. analyse statique : stdlib seulement, rien d'autre que deux GET ===========================


def _imports(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_the_client_uses_the_standard_library_and_netcheck_only():
    allowed = set(sys.stdlib_module_names) | {"netcheck", "__future__"}
    assert _imports(ROOT / "netcheck" / "netbox.py") <= allowed


def test_pynetbox_is_used_nowhere_in_netcheck_and_the_client_has_no_third_party_http_library():
    for path in sorted((ROOT / "netcheck").rglob("*.py")):
        if ".venv" not in path.parts:
            assert "pynetbox" not in _imports(path), path
    assert not {"requests", "httpx", "urllib3", "aiohttp"} & _imports(ROOT / "netcheck" / "netbox.py")


def test_no_netbox_dependency_is_declared():
    for name in ("requirements.txt", "requirements-dev.txt"):
        assert "netbox" not in (ROOT / "netcheck" / name).read_text(encoding="utf-8").lower()
    extras = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "pynetbox" not in extras and "netbox =" not in extras


def test_the_client_names_no_http_method_but_get():
    tree = ast.parse((ROOT / "netcheck" / "netbox.py").read_text(encoding="utf-8"))
    words = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert not words & {"POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
    assert "GET" in words


def test_the_allowed_paths_are_exactly_two():
    assert set(netbox.ALLOWED_PARAMS) == {"/api/status/", "/api/dcim/devices/"}
    assert netbox.ALLOWED_PARAMS["/api/status/"] == frozenset()
    assert netbox.ALLOWED_PARAMS["/api/dcim/devices/"] == {"site", "role", "tag", "status", "limit", "offset"}
