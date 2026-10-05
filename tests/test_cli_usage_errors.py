"""Erreurs d'usage hors argparse : code 3, une ligne claire sur stderr, jamais de traceback ni de contenu.

Balayage systématique des chemins d'erreur de chaque sous-commande (inventaire, fichiers fournis par
l'opérateur, snapshots, options incohérentes, chemins de sortie, clés d'hôte, identifiants). Pour chaque cas :

- code 3 (EXIT_USAGE), pas 1 (ATTENTION / injoignable) ni 2 (ÉCHEC) ;
- UNE ligne sur stderr, qui commence par « Erreur » ; aucun « Traceback » ;
- aucune collecte (le test échoue si le réseau est sollicité) ;
- aucun contenu de fichier (mot de passe d'inventaire, secret) dans la sortie.

Un vrai défaut interne reste distinct : code 70, avec trace (masquée des secrets).
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from netcheck import cli, collector, hostkeys, inventory, secrets, snapshot
from netcheck.model import DeviceState

PASSWORD = "SENTINEL-usage-pw-0123"  # 8 caractères ou plus : le registre d'expurgation le connaît
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


@dataclass
class Env:
    tmp: Path
    inv: str
    base: str = "base"

    def w(self, name: str, text: str, mode: int | None = None) -> str:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if mode is not None:
            path.chmod(mode)
        return str(path)

    def inventory(self, name: str, body: str) -> str:
        return self.w(name, body)


def _valid_inventory(extra: str = "") -> str:
    return (
        "lab: true\n"
        f'defaults: {{device_type: linux, username: u, password: "{PASSWORD}"}}\n'
        "management_interfaces: [eth0]\n"
        f"{extra}"
        "routers:\n  r1: {host: 127.0.0.1, ospf_neighbors: 1}\n"  # un attendu : guard refuse sinon (phase C6)
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    for var in list(os.environ):
        if var.startswith(("NETCHECK_", "LAB_")):
            monkeypatch.delenv(var)
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(cli, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(hostkeys, "_policy", None)

    def never(*_a, **_k):
        raise AssertionError("aucune collecte ne doit avoir lieu sur une erreur d'usage")

    monkeypatch.setattr(collector, "collect_all", never)
    monkeypatch.setattr(collector, "wait_for_convergence", never)

    e = Env(tmp_path, "")
    e.inv = e.w("inv.yml", _valid_inventory())
    state = DeviceState(
        name="r1",
        host="127.0.0.1",
        timestamp="2026-01-01T00:00:00+00:00",
        reachable=True,
        running_config="hostname r1\n",
    )
    snapshot.save("base", {"r1": (True, state)})
    return e


def _kh_dir(e):
    return str(e.tmp / "kh_dir")


# ---------------------------------------------------------------------------------------------------
# Les cas : (identifiant, fabrique d'arguments, fragment attendu dans le message)
# ---------------------------------------------------------------------------------------------------


def _inv_cases():
    """Défauts d'inventaire, valables pour toute sous-commande qui le lit en direct (snapshot)."""
    broken = {
        "absent": (lambda e: str(e.tmp / "absent.yml"), "introuvable"),
        "dossier": (lambda e: str(e.tmp), "dossier"),
        "yaml-invalide": (
            lambda e: e.w("i.yml", f"defaults: {{password: {PASSWORD}\nrouters: [\n"),
            "YAML invalide",
        ),
        "pas-un-objet": (lambda e: e.w("i.yml", "- r1\n- r2\n"), "objet YAML"),
        "sans-routers": (lambda e: e.w("i.yml", "defaults: {}\n"), "routers"),
        "routers-vide": (lambda e: e.w("i.yml", "routers: {}\n"), "routers"),
        "routers-null": (lambda e: e.w("i.yml", "routers:\n"), "routers"),
        "routeur-pas-objet": (lambda e: e.w("i.yml", "routers:\n  r1: 12\n"), "routeur r1"),
        "nom-numerique": (lambda e: e.w("i.yml", "routers:\n  1: {host: h}\n"), "nom de routeur"),
        "defaults-liste": (lambda e: e.w("i.yml", "defaults: [a]\nrouters:\n  r1: {host: h}\n"), "defaults"),
        "mot-de-passe-nombre": (
            lambda e: e.w(
                "i.yml",
                "defaults: {device_type: linux, username: u, "
                "password: 12345678}\nrouters:\n  r1: {host: h}\n",
            ),
            "texte",
        ),
        "port-invalide": (
            lambda e: e.w(
                "i.yml", "defaults: {device_type: linux}\nrouters:\n  r1: {host: h, port: 99999}\n"
            ),
            "port",
        ),
        "port-texte": (
            lambda e: e.w("i.yml", "defaults: {device_type: linux}\nrouters:\n  r1: {host: h, port: ssh}\n"),
            "port",
        ),
        "port-booleen": (
            lambda e: e.w("i.yml", "defaults: {device_type: linux}\nrouters:\n  r1: {host: h, port: true}\n"),
            "port",
        ),
        "lab-texte": (lambda e: e.w("i.yml", _valid_inventory().replace("lab: true", 'lab: "oui"')), "lab"),
        "interfaces-pas-liste": (
            lambda e: e.w(
                "i.yml",
                _valid_inventory().replace("management_interfaces: [eth0]", "management_interfaces: eth0"),
            ),
            "management_interfaces",
        ),
        "host-manquant": (
            lambda e: e.w(
                "i.yml",
                "defaults: {device_type: linux, username: u, "
                f'password: "{PASSWORD}"}}\nrouters:\n  r1: {{}}\n',
            ),
            "host",
        ),
        "device-type-manquant": (
            lambda e: e.w(
                "i.yml", f'defaults: {{username: u, password: "{PASSWORD}"}}\nrouters:\n  r1: {{host: h}}\n'
            ),
            "device_type",
        ),
        "driver-inconnu": (
            lambda e: e.w(
                "i.yml",
                "defaults: {device_type: linux, username: u, password: "
                f'"{PASSWORD}"}}\nrouters:\n  r1: {{host: h, driver: nosuch}}\n',
            ),
            "driver",
        ),
    }
    return [
        pytest.param(make, fragment, id=f"inventaire-{name}") for name, (make, fragment) in broken.items()
    ]


@pytest.mark.parametrize(("make", "fragment"), _inv_cases())
def test_snapshot_refuses_a_bad_inventory(make, fragment, env, capsys):
    argv = ["snapshot", "s", "-i", make(env)]
    _expect_usage_error(argv, fragment, capsys)


def _expect_usage_error(argv, fragment, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    assert code == 3, (code, out.err)
    assert "Traceback" not in out.err
    lines = [ln for ln in out.err.splitlines() if ln.strip()]
    assert len(lines) == 1 and lines[0].startswith("Erreur"), out.err
    assert fragment in lines[0], lines[0]
    assert PASSWORD not in out.out + out.err
    return out


def _cases():
    """(id, fabrique(env) -> argv, fragment). Une entrée par chemin d'erreur d'usage, par sous-commande."""
    C = []

    def add(cid, make, fragment):
        C.append(pytest.param(make, fragment, id=cid))

    base = "base"
    bad_yaml = f"rules: [\n  {PASSWORD}: [oops\n"

    # --- snapshot -------------------------------------------------------------------------------
    add("snapshot-appareil-inconnu", lambda e: ["snapshot", "s", "-d", "nosuch", "-i", e.inv], "inconnu")
    for bad in ("../x", "a/b", ".cache", "x y"):
        add(
            f"snapshot-nom-{bad}",
            lambda e, bad=bad: ["snapshot", bad, "-i", e.inv],
            "nom de snapshot invalide",
        )
    add(
        "snapshot-known-hosts-dossier",
        lambda e: [
            "snapshot",
            "s",
            "-i",
            e.inv,
            "--known-hosts",
            (e.tmp / "kh").mkdir() or str(e.tmp / "kh"),
        ],
        "dossier",
    )
    add(
        "snapshot-known-hosts-ecriture-par-autres",
        lambda e: ["snapshot", "s", "-i", e.inv, "--known-hosts", e.w("kh2", "", 0o666)],
        "modifiable",
    )
    add(
        "snapshot-accept-new-hors-lab",
        lambda e: [
            "snapshot",
            "s",
            "-i",
            e.w("nl.yml", _valid_inventory().replace("lab: true\n", "")),
            "--host-keys",
            "accept-new",
        ],
        "lab",
    )

    # --- list -----------------------------------------------------------------------------------
    add(
        "list-meta-corrompu",
        lambda e: e.w("snapshots/bad/meta.json", "{pas du json " + PASSWORD) and ["list"],
        "meta.json",
    )
    add("list-meta-pas-un-objet", lambda e: e.w("snapshots/bad/meta.json", "[1]") and ["list"], "meta.json")

    # --- diff -----------------------------------------------------------------------------------
    add("diff-avant-absent", lambda e: ["diff", "nosuch", base], "introuvable")
    add("diff-apres-absent", lambda e: ["diff", base, "nosuch"], "introuvable")
    add(
        "diff-snapshot-json-invalide",
        lambda e: e.w("snapshots/bad/r1.json", "{" + PASSWORD) and ["diff", base, "bad"],
        "corrompu",
    )
    add(
        "diff-snapshot-structure-fausse",
        lambda e: e.w("snapshots/bad/r1.json", "{}") and ["diff", base, "bad"],
        "corrompu",
    )
    add(
        "diff-snapshot-pas-un-objet",
        lambda e: e.w("snapshots/bad/r1.json", "[1]") and ["diff", base, "bad"],
        "corrompu",
    )
    add("diff-expect-absent", lambda e: ["diff", base, base, "--expect", str(e.tmp / "x.yml")], "introuvable")
    add("diff-expect-dossier", lambda e: ["diff", base, base, "--expect", str(e.tmp)], "dossier")
    add(
        "diff-expect-yaml-invalide",
        lambda e: ["diff", base, base, "--expect", e.w("x.yml", bad_yaml)],
        "YAML invalide",
    )
    add("diff-expect-schema", lambda e: ["diff", base, base, "--expect", e.w("x.yml", "- 1\n")], "objet")
    add("diff-expect-non-utf8", lambda e: ["diff", base, base, "--expect", _binary(e, "x.yml")], "UTF-8")
    add("diff-inventaire-absent", lambda e: ["diff", base, base, "-i", str(e.tmp / "no.yml")], "introuvable")
    add(
        "diff-inventaire-invalide",
        lambda e: ["diff", base, base, "-i", e.w("i.yml", bad_yaml)],
        "YAML invalide",
    )
    add(
        "diff-json-dossier-absent",
        lambda e: ["diff", base, base, "--json", str(e.tmp / "no" / "r.json")],
        "n'existe pas",
    )
    add("diff-html-est-un-dossier", lambda e: ["diff", base, base, "--html", str(e.tmp)], "dossier")

    # --- check ----------------------------------------------------------------------------------
    add(
        "check-rules-absent",
        lambda e: ["check", "--snapshot", base, "--rules", str(e.tmp / "r.yml")],
        "introuvable",
    )
    add("check-rules-dossier", lambda e: ["check", "--snapshot", base, "--rules", str(e.tmp)], "dossier")
    add(
        "check-rules-yaml-invalide",
        lambda e: ["check", "--snapshot", base, "--rules", e.w("r.yml", bad_yaml)],
        "YAML invalide",
    )
    add(
        "check-rules-non-utf8",
        lambda e: ["check", "--snapshot", base, "--rules", _binary(e, "r.yml")],
        "UTF-8",
    )
    add(
        "check-rules-pas-une-liste",
        lambda e: ["check", "--snapshot", base, "--rules", e.w("r.yml", "rules: 3\n")],
        "liste",
    )
    add(
        "check-rules-vides",
        lambda e: ["check", "--snapshot", base, "--rules", e.w("r.yml", "rules: []\n")],
        "aucune règle",
    )
    add(
        "check-rules-fichier-vide",
        lambda e: ["check", "--snapshot", base, "--rules", e.w("r.yml", "")],
        "aucune règle",
    )
    add(
        "check-rules-kind-inconnu",
        lambda e: [
            "check",
            "--snapshot",
            base,
            "--rules",
            e.w(
                "r.yml",
                "rules:\n  - {id: a, description: d, severity: haute, applies_to: all, kind: nosuch}\n",
            ),
        ],
        "kind",
    )
    add(
        "check-regle-sans-parametre",
        lambda e: [
            "check",
            "--snapshot",
            base,
            "--rules",
            e.w(
                "r.yml",
                "rules:\n  - {id: a, description: d, severity: haute, applies_to: all, kind: line_present}\n",
            ),
        ],
        "pattern",
    )
    add(
        "check-derogations-absent",
        lambda e: ["check", "--snapshot", base, "--derogations", str(e.tmp / "d.yml")],
        "illisible",
    )
    add(
        "check-derogations-dossier",
        lambda e: ["check", "--snapshot", base, "--derogations", str(e.tmp)],
        "illisible",
    )
    add(
        "check-derogations-yaml-invalide",
        lambda e: ["check", "--snapshot", base, "--derogations", e.w("d.yml", bad_yaml)],
        "YAML invalide",
    )
    add(
        "check-today-format",
        lambda e: [
            "check",
            "--snapshot",
            base,
            "--derogations",
            e.w("d.yml", "version: 1\nderogations: []\n"),
            "--today",
            "demain",
        ],
        "--today",
    )
    add(
        "check-today-sans-derogations",
        lambda e: ["check", "--snapshot", base, "--today", "2026-01-01"],
        "--derogations",
    )
    add(
        "check-config-dir-et-snapshot",
        lambda e: ["check", "--config-dir", str(e.tmp), "--snapshot", base],
        "s'excluent",
    )
    add(
        "check-driver-sans-config-dir",
        lambda e: ["check", "--snapshot", base, "--driver", "frr"],
        "--config-dir",
    )
    add(
        "check-driver-inconnu",
        lambda e: ["check", "--config-dir", str(e.tmp), "--driver", "nosuch"],
        "driver",
    )
    add(
        "check-config-dir-absent",
        lambda e: ["check", "--config-dir", str(e.tmp / "no"), "--driver", "frr"],
        "pas un dossier",
    )
    add(
        "check-config-dir-est-un-fichier",
        lambda e: ["check", "--config-dir", e.w("f.txt", "x"), "--driver", "frr"],
        "pas un dossier",
    )
    add(
        "check-config-dir-vide",
        lambda e: [
            "check",
            "--config-dir",
            (e.tmp / "vide").mkdir() or str(e.tmp / "vide"),
            "--driver",
            "frr",
        ],
        "aucune configuration",
    )
    add(
        "check-config-dir-sans-inventaire-ni-driver",
        lambda e: ["check", "--config-dir", str(e.tmp), "-i", str(e.tmp / "no.yml")],
        "--driver",
    )
    add(
        "check-config-dir-inventaire-invalide-meme-avec-driver",
        lambda e: ["check", "--config-dir", str(e.tmp), "--driver", "frr", "-i", e.w("i.yml", bad_yaml)],
        "YAML invalide",
    )
    add("check-snapshot-absent", lambda e: ["check", "--snapshot", "nosuch"], "introuvable")
    add(
        "check-snapshot-corrompu",
        lambda e: e.w("snapshots/bad/r1.json", "{" + PASSWORD) and ["check", "--snapshot", "bad"],
        "corrompu",
    )
    add(
        "check-inventaire-invalide",
        lambda e: ["check", "--snapshot", base, "-i", e.w("i.yml", bad_yaml)],
        "YAML invalide",
    )
    add(
        "check-snapshot-et-host-keys",
        lambda e: ["check", "--snapshot", base, "--host-keys", "strict"],
        "collecte en direct",
    )
    add(
        "check-config-dir-et-known-hosts",
        lambda e: ["check", "--config-dir", str(e.tmp), "--driver", "frr", "--known-hosts", str(e.tmp / "k")],
        "collecte en direct",
    )
    add(
        "check-json-dossier-absent",
        lambda e: ["check", "--snapshot", base, "--json", str(e.tmp / "no" / "r.json")],
        "n'existe pas",
    )
    add("check-html-est-un-dossier", lambda e: ["check", "--snapshot", base, "--html", str(e.tmp)], "dossier")
    add(
        "check-direct-appareil-sans-host",
        lambda e: [
            "check",
            "-i",
            e.w(
                "i.yml",
                'defaults: {device_type: linux, username: u, password: "'
                + PASSWORD
                + '"}\nrouters:\n  r1: {}\n',
            ),
        ],
        "host",
    )

    # --- guard ----------------------------------------------------------------------------------
    sh = "true\n"
    add(
        "guard-change-absent",
        lambda e: ["guard", "--change", str(e.tmp / "c.sh"), "--yes", "-i", e.inv],
        "introuvable",
    )
    add(
        "guard-change-dossier",
        lambda e: ["guard", "--change", str(e.tmp), "--yes", "-i", e.inv],
        "introuvable",
    )
    add(
        "guard-rollback-absent",
        lambda e: [
            "guard",
            "--change",
            e.w("c.sh", sh),
            "--rollback",
            str(e.tmp / "r.sh"),
            "--yes",
            "-i",
            e.inv,
        ],
        "introuvable",
    )
    add(
        "guard-rollback-on-sans-rollback",
        lambda e: ["guard", "--change", e.w("c.sh", sh), "--rollback-on", "attention", "--yes", "-i", e.inv],
        "--rollback",
    )
    add(
        "guard-wait-zero",
        lambda e: ["guard", "--change", e.w("c.sh", sh), "--wait", "0", "--yes", "-i", e.inv],
        ">= 1",
    )
    add(
        "guard-timeout-zero",
        lambda e: ["guard", "--change", e.w("c.sh", sh), "--script-timeout", "0", "--yes", "-i", e.inv],
        ">= 1",
    )
    add(
        "guard-expect-absent",
        lambda e: [
            "guard",
            "--change",
            e.w("c.sh", sh),
            "--expect",
            str(e.tmp / "x.yml"),
            "--yes",
            "-i",
            e.inv,
        ],
        "introuvable",
    )
    add(
        "guard-expect-invalide",
        lambda e: [
            "guard",
            "--change",
            e.w("c.sh", sh),
            "--expect",
            e.w("x.yml", bad_yaml),
            "--yes",
            "-i",
            e.inv,
        ],
        "YAML invalide",
    )
    add(
        "guard-inventaire-absent",
        lambda e: ["guard", "--change", e.w("c.sh", sh), "--yes", "-i", str(e.tmp / "no.yml")],
        "introuvable",
    )
    add(
        "guard-json-dossier-absent",
        lambda e: [
            "guard",
            "--change",
            e.w("c.sh", sh),
            "--yes",
            "-i",
            e.inv,
            "--json",
            str(e.tmp / "no" / "r.json"),
        ],
        "n'existe pas",
    )
    add(
        "guard-html-est-un-dossier",
        lambda e: ["guard", "--change", e.w("c.sh", sh), "--yes", "-i", e.inv, "--html", str(e.tmp)],
        "dossier",
    )
    add(
        "guard-known-hosts-dossier",
        lambda e: ["guard", "--change", e.w("c.sh", sh), "--yes", "-i", e.inv, "--known-hosts", str(e.tmp)],
        "dossier",
    )

    # --- assert ---------------------------------------------------------------------------------
    ok = "assertions:\n  - {id: a, description: d, device: r1, type: ospf_neighbors, count: 1}\n"
    add(
        "assert-intent-absent",
        lambda e: ["assert", "--intent", str(e.tmp / "i.yml"), "--snapshot", base],
        "introuvable",
    )
    add("assert-intent-dossier", lambda e: ["assert", "--intent", str(e.tmp), "--snapshot", base], "dossier")
    add(
        "assert-intent-yaml-invalide",
        lambda e: ["assert", "--intent", e.w("i.yml", bad_yaml), "--snapshot", base],
        "YAML invalide",
    )
    add(
        "assert-intent-non-utf8",
        lambda e: ["assert", "--intent", _binary(e, "i.yml"), "--snapshot", base],
        "UTF-8",
    )
    add(
        "assert-intent-sans-assertions",
        lambda e: ["assert", "--intent", e.w("i.yml", "autre: 1\n"), "--snapshot", base],
        "assertions",
    )
    add(
        "assert-intent-vide",
        lambda e: ["assert", "--intent", e.w("i.yml", "assertions: []\n"), "--snapshot", base],
        "aucune assertion",
    )
    add(
        "assert-intent-parametre-manquant",
        lambda e: [
            "assert",
            "--intent",
            e.w("i.yml", "assertions:\n  - {id: a, description: d, device: r1, type: bgp_session}\n"),
            "--snapshot",
            base,
        ],
        "neighbor",
    )
    add(
        "assert-snapshot-absent",
        lambda e: ["assert", "--intent", e.w("i.yml", ok), "--snapshot", "nosuch"],
        "introuvable",
    )
    add(
        "assert-snapshot-corrompu",
        lambda e: (
            e.w("snapshots/bad/r1.json", "{" + PASSWORD)
            and ["assert", "--intent", e.w("i.yml", ok), "--snapshot", "bad"]
        ),
        "corrompu",
    )
    add(
        "assert-inventaire-invalide",
        lambda e: [
            "assert",
            "--intent",
            e.w("i.yml", ok),
            "--snapshot",
            base,
            "-i",
            e.w("inv2.yml", bad_yaml),
        ],
        "YAML invalide",
    )
    add(
        "assert-snapshot-et-host-keys",
        lambda e: ["assert", "--intent", e.w("i.yml", ok), "--snapshot", base, "--host-keys", "accept-new"],
        "collecte en direct",
    )
    add(
        "assert-json-dossier-absent",
        lambda e: [
            "assert",
            "--intent",
            e.w("i.yml", ok),
            "--snapshot",
            base,
            "--json",
            str(e.tmp / "no" / "r.json"),
        ],
        "n'existe pas",
    )
    add(
        "assert-html-est-un-dossier",
        lambda e: ["assert", "--intent", e.w("i.yml", ok), "--snapshot", base, "--html", str(e.tmp)],
        "dossier",
    )
    add(
        "assert-direct-driver-inconnu",
        lambda e: [
            "assert",
            "--intent",
            e.w("i.yml", ok),
            "-i",
            e.w(
                "i2.yml",
                'defaults: {device_type: linux, username: u, password: "'
                + PASSWORD
                + '"}\nrouters:\n  r1: {host: h, driver: nosuch}\n',
            ),
        ],
        "driver",
    )

    # --- monitor --------------------------------------------------------------------------------
    add("monitor-baseline-absente", lambda e: ["monitor", "--baseline", "nosuch", "-i", e.inv], "introuvable")
    add(
        "monitor-baseline-corrompue",
        lambda e: (
            e.w("snapshots/bad/r1.json", "{" + PASSWORD) and ["monitor", "--baseline", "bad", "-i", e.inv]
        ),
        "corrompu",
    )
    add(
        "monitor-confirm-zero",
        lambda e: ["monitor", "--baseline", base, "--confirm", "0", "-i", e.inv],
        ">= 1",
    )
    add(
        "monitor-rules-absent",
        lambda e: ["monitor", "--baseline", base, "--rules", str(e.tmp / "r.yml"), "-i", e.inv],
        "introuvable",
    )
    add(
        "monitor-rules-vides",
        lambda e: ["monitor", "--baseline", base, "--rules", e.w("r.yml", "rules: []\n"), "-i", e.inv],
        "aucune règle",
    )
    add(
        "monitor-intent-absent",
        lambda e: ["monitor", "--baseline", base, "--intent", str(e.tmp / "i.yml"), "-i", e.inv],
        "introuvable",
    )
    add(
        "monitor-intent-vide",
        lambda e: ["monitor", "--baseline", base, "--intent", e.w("i.yml", "assertions: []\n"), "-i", e.inv],
        "aucune assertion",
    )
    add(
        "monitor-derogations-sans-rules",
        lambda e: [
            "monitor",
            "--baseline",
            base,
            "--derogations",
            e.w("d.yml", "version: 1\nderogations: []\n"),
            "-i",
            e.inv,
        ],
        "--rules",
    )
    add(
        "monitor-state-file-est-un-dossier",
        lambda e: ["monitor", "--baseline", base, "--state-file", str(e.tmp), "-i", e.inv],
        "dossier",
    )
    add(
        "monitor-state-file-sous-un-fichier",
        lambda e: ["monitor", "--baseline", base, "--state-file", e.w("f", "x") + "/etat.json", "-i", e.inv],
        "n'existe pas",
    )
    add(
        "monitor-inventaire-absent",
        lambda e: ["monitor", "--baseline", base, "-i", str(e.tmp / "no.yml")],
        "introuvable",
    )
    add(
        "monitor-inventaire-invalide",
        lambda e: ["monitor", "--baseline", base, "-i", e.w("i.yml", bad_yaml)],
        "YAML invalide",
    )
    add(
        "monitor-known-hosts-dossier",
        lambda e: ["monitor", "--baseline", base, "--known-hosts", str(e.tmp), "-i", e.inv],
        "dossier",
    )
    return C


def _binary(e, name):
    path = e.tmp / name
    path.write_bytes(b"\xff\xfe\x00 pas de l'utf-8 \x80\x81")
    return str(path)


CASES = _cases()


@pytest.mark.parametrize(("make", "fragment"), CASES)
def test_usage_error_is_code_3_one_line_no_traceback_no_collection(make, fragment, env, capsys, monkeypatch):
    monkeypatch.setenv("NETCHECK_HOST_KEYS", "strict")
    _expect_usage_error(make(env), fragment, capsys)


def test_every_subcommand_has_usage_error_cases():
    subcommands = {p.id.split("-")[0] for p in CASES}
    assert {"snapshot", "list", "diff", "check", "guard", "assert", "monitor"} <= subcommands


def test_there_are_many_cases():
    # Garde-fou contre un balayage qui se viderait en silence.
    assert len(CASES) >= 85


# --- Cas qui ont besoin de plus qu'un argv ----------------------------------------------------------


def test_wrong_host_keys_environment_variable_is_a_usage_error(env, capsys, monkeypatch):
    monkeypatch.setenv("NETCHECK_HOST_KEYS", "ignore")
    _expect_usage_error(["snapshot", "s", "-i", env.inv], "ignore", capsys)


def test_a_refused_secret_file_is_a_usage_error_and_its_content_never_appears(env, capsys, monkeypatch):
    secret = env.w("pw", PASSWORD + "\n", 0o644)
    monkeypatch.setenv("NETCHECK_PASS_FILE", secret)
    out = _expect_usage_error(["snapshot", "s", "-i", env.inv], "droits", capsys)
    assert PASSWORD not in out.out + out.err


@pytest.mark.parametrize("mode", ["symlink", "multiline", "empty"])
def test_other_refused_secret_files_never_leak_their_content(mode, env, capsys, monkeypatch):
    content = {"symlink": PASSWORD, "multiline": PASSWORD + "\nsecond\n", "empty": ""}[mode]
    real = env.w("real", content, 0o600)
    target = real
    if mode == "symlink":
        link = env.tmp / "link"
        link.symlink_to(real)
        target = str(link)
    monkeypatch.setenv("NETCHECK_PASS_FILE", target)
    code = cli.main(["snapshot", "s", "-i", env.inv])
    captured = capsys.readouterr()
    assert code == 3 and "Traceback" not in captured.err
    assert PASSWORD not in captured.out + captured.err


def test_unusable_state_directory_makes_snapshot_a_usage_error(env, capsys, monkeypatch):
    state = DeviceState(name="r1", host="h", timestamp="t", reachable=True)
    monkeypatch.setattr(collector, "collect_all", lambda *_a, **_k: {"r1": (True, state)})
    blocker = env.tmp / "blocker"
    blocker.write_text("fichier, pas un dossier")
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", blocker)
    _expect_usage_error(["snapshot", "s", "-i", env.inv], "non écrit", capsys)


@pytest.mark.skipif(IS_ROOT, reason="root ignore les droits de fichier")
def test_unreadable_change_script_is_a_usage_error_before_any_action(env, capsys):
    script = env.w("c.sh", "true\n", 0o000)
    _expect_usage_error(["guard", "--change", script, "--yes", "-i", env.inv], "illisible", capsys)


@pytest.mark.skipif(IS_ROOT, reason="root ignore les droits de fichier")
def test_unwritable_output_directory_is_a_usage_error(env, capsys):
    locked = env.tmp / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        _expect_usage_error(
            ["diff", "base", "base", "--json", str(locked / "r.json")], "accessible en écriture", capsys
        )
    finally:
        locked.chmod(0o700)


def test_guard_without_confirmation_and_closed_stdin_is_a_usage_error(env, capsys, monkeypatch):
    marker = env.tmp / "marker"
    script = env.w("c.sh", f"touch {marker}\n")
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    code = cli.main(["guard", "--change", script, "-i", env.inv])
    err = capsys.readouterr().err
    assert code == 3 and "--yes" in err and "Traceback" not in err
    assert not marker.exists()


def test_guard_output_path_is_checked_before_the_change_script_runs(env, capsys):
    marker = env.tmp / "marker"
    script = env.w("c.sh", f"touch {marker}\n")
    code = cli.main(
        ["guard", "--change", script, "--yes", "-i", env.inv, "--json", str(env.tmp / "no" / "r.json")]
    )
    assert code == 3 and not marker.exists()
    assert "n'existe pas" in capsys.readouterr().err


def test_yaml_error_names_the_position_but_never_quotes_the_content(env, capsys):
    out = _expect_usage_error(
        ["snapshot", "s", "-i", env.w("i.yml", f"defaults: {{password: {PASSWORD}\n")], "ligne", capsys
    )
    assert PASSWORD not in out.err


def test_a_missing_default_inventory_with_driver_is_still_tolerated(env, capsys):
    # Comportement existant (--config-dir --driver sans inventaire) : seul un fichier ABSENT est toléré.
    cfg = env.tmp / "cfg"
    cfg.mkdir()
    (cfg / "edge1.conf").write_text("hostname edge1\n", encoding="utf-8")
    code = cli.main(["check", "--config-dir", str(cfg), "--driver", "frr", "-i", str(env.tmp / "absent.yml")])
    assert code in (0, 1, 2)  # audit fait ; pas une erreur d'usage
    capsys.readouterr()


# --- Le défaut interne reste distinct ---------------------------------------------------------------


def test_internal_defect_exits_70_with_a_trace(monkeypatch, capsys):
    def boom(_args):
        raise RuntimeError("défaut interne")

    monkeypatch.setattr(cli, "cmd_list", boom)
    code = cli.main(["list"])
    err = capsys.readouterr().err
    assert code == cli.EXIT_INTERNAL == 70
    assert code not in (0, 1, 2, 3, 4, 5, 6)
    assert "Traceback" in err and "RuntimeError" in err and "défaut interne" in err


def test_a_value_error_outside_the_loading_blocks_is_internal_not_usage(monkeypatch, capsys):
    def boom(_args):
        raise ValueError("incohérence interne")

    monkeypatch.setattr(cli, "cmd_list", boom)
    assert cli.main(["list"]) == 70
    capsys.readouterr()


def test_internal_trace_masks_registered_secrets(monkeypatch, capsys):
    secrets.SecretStr(PASSWORD, "test")  # inscrit la valeur dans le registre d'expurgation

    def boom(_args):
        raise RuntimeError(f"la bibliothèque a recopié {PASSWORD}")

    monkeypatch.setattr(cli, "cmd_list", boom)
    assert cli.main(["list"]) == 70
    err = capsys.readouterr().err
    assert PASSWORD not in err and "****" in err


def test_usage_errors_are_never_the_internal_code():
    assert cli.EXIT_USAGE == 3 != cli.EXIT_INTERNAL


# --- Processus réel ---------------------------------------------------------------------------------


def _run(*argv, cwd=None, env_extra=None):
    environ = {k: v for k, v in os.environ.items() if not k.startswith(("NETCHECK_", "LAB_"))}
    environ.update(env_extra or {})
    return subprocess.run(
        [sys.executable, "-m", "netcheck", *argv],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd or inventory.REPO_ROOT,
        env=environ,
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["snapshot", "x", "-d", "nosuch"],
        ["snapshot", "x", "-i", "/nonexistent/inventaire.yml"],
        ["check", "--rules", "/nonexistent/regles.yml", "--snapshot", "nosuch"],
        ["assert", "--intent", "/nonexistent/intent.yml", "--snapshot", "nosuch"],
        ["diff", "nosuch", "nosuch2", "--expect", "/nonexistent/x.yml"],
        ["monitor", "--baseline", "nosuch", "-i", "/nonexistent/inventaire.yml"],
        ["guard", "--change", "/nonexistent/c.sh", "--yes"],
    ],
    ids=lambda a: a[0] + "-" + (a[-1] if a[-1].startswith("/") else a[-2]),
)
def test_real_process_exits_3_with_one_line_and_no_traceback(argv):
    result = _run(*argv)
    assert result.returncode == 3, result.stderr
    assert "Traceback" not in result.stderr
    lines = [ln for ln in result.stderr.splitlines() if ln.strip()]
    assert len(lines) == 1 and lines[0].startswith("Erreur"), result.stderr


def test_real_process_internal_defect_exits_70():
    code = (
        "import sys\nfrom netcheck import cli\n"
        "cli.cmd_list = lambda args: 1 / 0\n"
        "sys.exit(cli.main(['list']))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=False, cwd=inventory.REPO_ROOT
    )
    assert result.returncode == 70
    assert "ZeroDivisionError" in result.stderr


# --- Messages d'erreur d'usage : une ligne, expurgés ------------------------------------------------


def test_a_usage_message_is_masked_and_on_one_line(monkeypatch, capsys):
    secrets.SecretStr(PASSWORD, "test")

    def boom(_args):
        raise cli.usage.UsageError(f"première ligne {PASSWORD}\nseconde ligne")

    monkeypatch.setattr(cli, "cmd_list", boom)
    assert cli.main(["list"]) == 3
    err = capsys.readouterr().err
    assert PASSWORD not in err and "****" in err
    assert len([ln for ln in err.splitlines() if ln.strip()]) == 1


@pytest.mark.skipif(IS_ROOT, reason="root ignore les droits de fichier")
def test_a_read_only_output_file_is_a_usage_error(env, capsys):
    target = env.w("r.json", "{}", 0o444)
    _expect_usage_error(["diff", "base", "base", "--json", target], "modifiable", capsys)


def test_an_assertion_that_fails_to_evaluate_is_a_usage_error(env, capsys, monkeypatch):
    def refuse(*_a, **_k):
        raise ValueError("assertion 'a' : paramètre manquant")

    monkeypatch.setattr(cli.assertions, "evaluate", refuse)
    intent = env.w(
        "i.yml", "assertions:\n  - {id: a, description: d, device: r1, type: ospf_neighbors, count: 1}\n"
    )
    _expect_usage_error(["assert", "--intent", intent, "--snapshot", "base"], "paramètre manquant", capsys)
