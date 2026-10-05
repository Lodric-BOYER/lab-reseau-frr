"""Outils du lab NetBox (phase C6.2) : inventaire alimenté par NetBox, proxy qui réécrit `Host`, scripts,
périmètre.

Ce qui est prouvé SANS NetBox réel (le vrai NetBox est joué par tests/integration_netbox.sh) :
- l'inventaire produit pour chaque lab, fusionné avec un NetBox qui contient les équipements de
  l'inventaire d'origine, redonne EXACTEMENT les mêmes routeurs (hôte, driver, device_type, attendus,
  identifiants propres) ;
- derrière un nom ou un port différent (en-tête `Host` réécrit), le lien `next` est refusé clairement,
  sans boucle, sans résultat partiel, et le jeton ne part pas vers l'autre adresse ; avec `localhost`
  comme avec `127.0.0.1`, tout passe ;
- pynetbox ne vit que dans lab-access/netbox/ (jamais importé par netcheck/), installé avec hash dans un
  dossier ignoré ;
- le script de démarrage attend lui-même (deux temps, limite, volumes conservés), l'override n'a ni
  valeur publique ni image sans digest, et n'écoute qu'en 127.0.0.1 ;
- les scripts n'affichent jamais un secret et n'écrivent que sur l'instance de lab."""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml
from fake_netbox import TOKEN, FakeNetbox, device

from netcheck import inventory, netbox

ROOT = Path(__file__).resolve().parent.parent
LAB_DIR = ROOT / "lab-access" / "netbox"
sys.path.insert(0, str(LAB_DIR))
sys.path.insert(0, str(ROOT / "tests" / "tools"))

import hostproxy  # noqa: E402
import make_inventory  # noqa: E402

DRIVER_MGMT = {"frr": "eth0", "srlinux": "mgmt0", "eos": "Management0"}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in list(os.environ):
        if var.startswith(("NETCHECK_", "LAB_")) or var.lower().endswith("_proxy"):
            monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(netbox.ENV_TOKEN, TOKEN)


def netbox_with(lab: str) -> FakeNetbox:
    """Un faux NetBox qui contient les équipements de l'inventaire d'origine du lab (comme load_lab.py)."""
    relative, site = make_inventory.LABS[lab]
    original = yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))
    defaults = original.get("defaults") or {}
    devices = []
    for number, (name, attrs) in enumerate(original["routers"].items(), 1):
        attrs = attrs or {}
        driver = attrs.get("driver", defaults.get("driver", "frr"))
        devices.append(device(name, f"{attrs['host']}/24", driver, number, site=site))
    server = FakeNetbox(devices=devices)
    server.next_from_host = True
    return server


def effective(router: dict) -> dict:
    keys = ("host", "device_type", "ospf_neighbors", "ospf6_neighbors", "bgp_peers", "bgp6_peers", "username")
    return {"driver": router.get("driver", "frr"), **{k: router[k] for k in keys if k in router}}


# === 1. l'inventaire alimenté par NetBox redonne l'inventaire d'origine ===========================


@pytest.mark.parametrize("lab", sorted(make_inventory.LABS))
def test_the_netbox_fed_inventory_gives_back_the_original_routers_exactly(lab, tmp_path):
    server = netbox_with(lab)
    try:
        path = tmp_path / "inv.yml"
        make_inventory.main([lab, "--url", server.addr, "--out", str(path)])
        fed = inventory.load(path=path)
        relative, _ = make_inventory.LABS[lab]
        original = inventory.load(path=ROOT / relative, resolve_credentials=False)
        assert sorted(fed.routers) == sorted(original.routers)
        for name, router in original.routers.items():
            assert effective(fed.routers[name]) == effective(router), name
        assert fed.netbox_info.both == sorted(original.routers) and fed.netbox_info.netbox_only == []
        assert fed.lab is True and fed.management_interfaces == original.management_interfaces
    finally:
        server.stop()


@pytest.mark.parametrize("lab", sorted(make_inventory.LABS))
def test_the_generated_file_keeps_what_netbox_never_provides_and_drops_what_it_does(lab):
    generated = make_inventory.build_inventory(lab)
    relative, site = make_inventory.LABS[lab]
    original = yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))
    assert generated["lab"] is True and generated["defaults"] == original["defaults"]
    assert generated["netbox"]["site"] == site and generated["netbox"]["role"] == "router"
    assert generated["netbox"]["platforms"] == {"frr": "frr", "srlinux": "srlinux", "eos": "eos"}
    for name, attrs in generated["routers"].items():
        assert not {"host", "driver", "device_type"} & set(attrs), name
        assert {
            k: v for k, v in original["routers"][name].items() if k not in ("host", "driver", "device_type")
        } == attrs
    assert "token" not in generated["netbox"] and "TOKEN" not in yaml.safe_dump(
        generated
    )  # le jeton n'y est jamais


def test_the_mixed_and_ceos_overlays_keep_their_own_credentials():
    assert make_inventory.build_inventory("multivendor")["routers"]["r5"]["username"] == "admin"
    assert "username" in make_inventory.build_inventory("ceos")["routers"]["r4"]


def test_local_only_adds_a_router_netbox_does_not_know_and_page_size_is_carried():
    generated = make_inventory.build_inventory("frr", page_size=2, local_only=("r8",))
    assert "r8" in generated["routers"] and generated["netbox"]["page_size"] == 2
    assert "page_size" not in make_inventory.build_inventory("frr")["netbox"]


def test_a_local_only_router_is_an_error_listing_it(tmp_path):
    server = netbox_with("frr")
    try:
        path = tmp_path / "inv.yml"
        make_inventory.main(["frr", "--url", server.addr, "--local-only", "r8", "--out", str(path)])
        with pytest.raises(netbox.NetboxInventoryError, match="r8"):
            inventory.load(path=path)
    finally:
        server.stop()


# === 2. nom ou port différent : le lien `next` est refusé, jamais suivi ===========================


def _generate(server, tmp_path, url=None, page_size=2, lab="frr"):
    path = tmp_path / "inv.yml"
    make_inventory.main([lab, "--url", url or server.addr, "--page-size", str(page_size), "--out", str(path)])
    return path


def test_the_proxy_rewrites_host_and_forces_connection_close():
    head = (
        b"GET /api/status/ HTTP/1.1\r\nHost: 127.0.0.1:18000\r\n"
        b"Connection: keep-alive\r\nAuthorization: x\r\n\r\n"
    )
    out = hostproxy.rewrite(head, "localhost:8000").decode()
    assert "Host: localhost:8000\r\n" in out and "127.0.0.1:18000" not in out
    assert out.count("Connection:") == 1 and "Connection: close" in out and "Authorization: x" in out


@pytest.fixture
def proxied(tmp_path):
    """NetBox (faux, `next` construit sur Host) derrière un proxy qui annonce `localhost:<port réel>`."""
    server = netbox_with("frr")
    count = tmp_path / "count.txt"
    proxy = hostproxy.Proxy(0, ("127.0.0.1", server.port), f"localhost:{server.port}", str(count))
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    yield server, proxy, count
    proxy.shutdown()
    proxy.server_close()
    server.stop()


def test_behind_a_rewritten_host_the_next_link_is_refused_clearly_without_loop_or_partial_result(
    tmp_path, proxied
):
    server, proxy, count = proxied
    path = _generate(server, tmp_path, url=f"http://127.0.0.1:{proxy.server_address[1]}", page_size=2)
    with pytest.raises(netbox.NetboxUnavailable, match="hors du NetBox configuré"):
        inventory.load(path=path)
    # status + première page, rien de plus : pas de boucle ; et rien n'a été envoyé au « nouvel »
    # hôte par netcheck
    seen = count.read_text(encoding="utf-8").split()
    assert len(seen) == 2 and seen[0] == "/api/status/" and seen[1].startswith("/api/dcim/devices/?")
    assert [r["path"] for r in server.requests] == [
        "/api/status/",
        "/api/dcim/devices/",
    ]  # via le proxy seulement
    assert all(r["headers"]["host"] == f"localhost:{server.port}" for r in server.requests)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_with_localhost_or_127_0_0_1_directly_the_pagination_works(tmp_path, host):
    server = netbox_with("frr")
    try:
        path = _generate(server, tmp_path, url=f"http://{host}:{server.port}", page_size=2)
        fed = inventory.load(path=path)
        assert sorted(fed.routers) == ["r1", "r2", "r3", "r4", "r5"]
        assert "5 équipement(s) en 3 page(s) de 2 au plus" in fed.netbox_info.lines()[0]
        offsets = [r["query"]["offset"] for r in server.requests if r["path"].endswith("devices/")]
        assert offsets == [["0"], ["2"], ["4"]]
    finally:
        server.stop()


def test_a_mismatch_with_a_named_url_is_refused_too(tmp_path):
    """Config en localhost, serveur qui construit ses liens sur 127.0.0.1 (le cas inverse) : refus,
    pas de boucle."""
    server = netbox_with("frr")
    server.next_from_host = False  # liens construits sur 127.0.0.1:<port>
    try:
        path = _generate(server, tmp_path, url=f"http://localhost:{server.port}", page_size=2)
        with pytest.raises(netbox.NetboxUnavailable, match="hors du NetBox configuré"):
            inventory.load(path=path)
        assert len([r for r in server.requests if r["path"].endswith("devices/")]) == 1
    finally:
        server.stop()


# === 3. périmètre : pynetbox seulement ici, installé avec hash, ignoré par Git ====================


def _imports(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_pynetbox_is_imported_only_by_the_lab_scripts_and_never_by_netcheck():
    users = sorted(p.name for p in LAB_DIR.glob("*.py") if "pynetbox" in _imports(p))
    assert users == ["load_lab.py", "netbox_admin.py"]
    for path in sorted((ROOT / "netcheck").rglob("*.py")):
        if ".venv" not in path.parts:
            assert "pynetbox" not in _imports(path), path
    for path in sorted((ROOT / "tests").glob("*.py")):
        assert "pynetbox" not in _imports(path), path


def test_pynetbox_is_pinned_with_a_hash_and_installed_nowhere_but_in_an_ignored_folder():
    text = (LAB_DIR / "requirements.txt").read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    assert len(lines) == 1 and re.fullmatch(r"pynetbox==7\.8\.0 --hash=sha256:[0-9a-f]{64}", lines[0])
    assert "--no-deps" in text and "--require-hashes" in text and "lab-access/netbox/.pylib" in text
    # un fichier DANS le dossier : le dossier lui-même n'existe pas dans un dépôt fraîchement cloné
    probe = "lab-access/netbox/.pylib/pynetbox/__init__.py"
    ignored = subprocess.run(["git", "check-ignore", "-q", probe], cwd=ROOT).returncode == 0
    assert ignored
    for name in ("requirements.txt", "requirements-dev.txt"):
        assert "pynetbox" not in (ROOT / "netcheck" / name).read_text(encoding="utf-8")


def test_the_lab_scripts_import_only_the_standard_library_requests_yaml_and_pynetbox():
    allowed = set(sys.stdlib_module_names) | {
        "requests",
        "yaml",
        "pynetbox",
        "nblab",
        "load_lab",
        "__future__",
    }
    for path in sorted(LAB_DIR.glob("*.py")):
        assert _imports(path) <= allowed, (path.name, _imports(path) - allowed)


def test_no_script_prints_a_secret_or_a_response_body():
    for path in sorted(LAB_DIR.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "print":
                text = ast.unparse(node)
                assert not re.search(r"\.token\b|password|PASSWORD|\.text\b|\.content\b|\.json\(\)", text), (
                    path.name,
                    text,
                )


def test_the_token_file_is_written_0600_in_a_0700_folder_without_leaving_a_temporary(tmp_path):
    import nblab

    target = tmp_path / "dossier" / "netbox-ro.token"
    nblab.write_token_file(target, "nbt_abcdef.0123456789")
    assert target.read_text(encoding="utf-8") == "nbt_abcdef.0123456789\n"
    assert (
        oct(target.stat().st_mode & 0o777) == "0o600" and oct(target.parent.stat().st_mode & 0o777) == "0o700"
    )
    assert sorted(p.name for p in target.parent.iterdir()) == ["netbox-ro.token"]


def test_an_existing_folder_keeps_its_permissions_and_only_a_created_one_becomes_0700(tmp_path):
    import nblab

    shared = tmp_path / "partage"
    shared.mkdir()
    shared.chmod(0o755)
    nblab.write_token_file(shared / "t.token", "nbt_a.b")
    assert (
        oct(shared.stat().st_mode & 0o777) == "0o755"
        and oct((shared / "t.token").stat().st_mode & 0o777) == "0o600"
    )
    nblab.write_token_file(tmp_path / "a" / "b" / "t.token", "nbt_a.b")
    assert (
        oct((tmp_path / "a").stat().st_mode & 0o777)
        == "0o700"
        == oct((tmp_path / "a" / "b").stat().st_mode & 0o777)
    )


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o666])
def test_the_env_file_is_refused_unless_0600_or_0400(tmp_path, mode):
    import nblab

    env = tmp_path / ".env"
    env.write_text("NB_SUPERUSER_NAME=lab-admin\nNB_SUPERUSER_PASSWORD=secret\n", encoding="utf-8")
    env.chmod(mode)
    with pytest.raises(SystemExit, match="droits"):
        nblab.read_env(env)
    env.chmod(0o600)
    assert nblab.read_env(env)["NB_SUPERUSER_NAME"] == "lab-admin"


def test_a_bearer_token_is_rebuilt_from_either_reply_shape():
    import nblab

    assert nblab.bearer_from({"token": "nbt_k.s"}) == "nbt_k.s"
    assert nblab.bearer_from({"key": "k", "token": "s"}) == "nbt_k.s"
    with pytest.raises(SystemExit):
        nblab.bearer_from({"key": "k"})


# === 4. le script de démarrage et l'override ======================================================


def _script() -> str:
    return (LAB_DIR / "netbox_lab.sh").read_text(encoding="utf-8")


def test_the_start_script_waits_itself_in_two_phases_with_a_limit_and_clear_messages():
    text = _script()
    assert 'TIMEOUT="${NETBOX_START_TIMEOUT:-1200}"' in text  # 20 minutes
    assert "--no-deps postgres redis redis-cache netbox" in text and "--no-deps netbox-worker" in text
    assert text.index("--no-deps postgres redis redis-cache netbox") < text.index("--no-deps netbox-worker")
    assert text.index('wait_healthy netbox "$TIMEOUT"') < text.index("--no-deps netbox-worker")
    for message in ("n'est pas sain après", "s'est arrêté", "migrations appliquées", "docker logs --tail 20"):
        assert message in text, message


def test_the_volumes_are_removed_only_by_the_explicit_destroy_command():
    text = _script()
    assert text.count("down -v") == 1
    branch = text.split("destroy)", 1)[1]
    assert "--yes-destroy-volumes" in branch and branch.index("--yes-destroy-volumes") < branch.index(
        "down -v"
    )
    assert "down -v" not in text.split("destroy)", 1)[0]


def test_the_start_script_checks_the_pinned_clone_and_proves_loopback_only_listening():
    text = _script()
    assert "PINNED_COMMIT=7689fec7a70717f7e72feecb383e7a3f55538b5f" in text
    assert "listening_on_loopback_only" in text and "127\\.0\\.0\\.1" in text
    assert "umask 077" in text and "chmod 600" in text and "non affichées" in text


def test_the_override_pins_every_image_by_digest_and_listens_on_loopback_only():
    data = yaml.safe_load((LAB_DIR / "docker-compose.override.yml").read_text(encoding="utf-8"))
    for name, service in data["services"].items():
        assert re.search(r"@sha256:[0-9a-f]{64}$", service["image"].split()[0]), name
    assert data["services"]["netbox"]["ports"] == ["127.0.0.1:8000:8080"]
    assert not [s for s in data["services"].values() if "ports" in s and s is not data["services"]["netbox"]]
    digests = {s["image"].split("@")[1] for s in data["services"].values()}
    assert digests == {
        "sha256:3cf9d3bd77aa186233b84d0ea1cf1755581d5e5678fa7d86ec3be62f79d0c643",
        "sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873",
        "sha256:48332870af354a799964c0012ae1194a0bf2bf894eb508f945810596dc2d8d11",
    }


def test_the_override_has_no_public_default_secret_and_every_secret_comes_from_the_env_file():
    text = (LAB_DIR / "docker-compose.override.yml").read_text(encoding="utf-8")
    for public_default in (
        "J5brHrAXFLQSif0K",
        "H733Kdjndks81",
        "t4Ph722qJ5QHeQ1qfu36",
        "Qy+F=OTeGskWQ",
        "r(m)9nLGnz",
    ):
        assert public_default not in text
    for variable in (
        "SECRET_KEY",
        "API_TOKEN_PEPPER_1",
        "DB_PASSWORD",
        "REDIS_PASSWORD",
        "REDIS_CACHE_PASSWORD",
        "SUPERUSER_PASSWORD",
        "POSTGRES_PASSWORD",
    ):
        assert re.search(rf"{variable}: \$\{{NB_[A-Z_]+:\?\}}", text), variable
    assert 'CORS_ORIGIN_ALLOW_ALL: "false"' in text and 'RELEASE_CHECK_URL: ""' in text


def test_the_env_file_is_ignored_by_git_and_never_in_the_repository():
    for candidate in ("lab-access/netbox/.env", "lab-access/netbox/netbox-docker/.env"):
        assert subprocess.run(["git", "check-ignore", "-q", candidate], cwd=ROOT).returncode == 0
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    assert not [f for f in tracked if f.endswith(".env") or "netbox-ro.token" in f]
