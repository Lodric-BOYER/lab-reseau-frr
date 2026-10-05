"""Gel de référence de la conformité (SPEC_v4, Phase A, étape A1).

Enregistre ce que le moteur de conformité de netcheck 0.3.0 répond sur des entrées RÉELLES, pour
prouver que la refonte de la Phase A (règles déplacées dans les drivers, configuration structurée,
peer groups) ne change aucun verdict là où il n'y a rien à corriger.

    python tests/tools/golden.py record      écrit tests/golden/compliance_<règles>.json
    python tests/tools/golden.py compare     recalcule et compare (c'est ce que fait pytest)
    python tests/tools/golden.py reference record|compare
                                             mêmes enregistrements sur les snapshots réels des trois
                                             labs (snapshots/ et reports/ restent hors Git)

`record` ne se rejoue qu'avec le code de référence (v0.3.0) ou pour une modification VOULUE des
entrées : régénérer après la refonte reviendrait à faire confiance à ce qu'on veut vérifier.

Entrées : (1) fixtures réelles, modèle complet, FRR, SR Linux et EOS ; (2) copies figées des
configurations de démarrage des labs (tests/golden/inputs/), configuration seule, telle que
`check --config-dir` la fournira ; (3) pour chaque équipement, une MUTATION par ligne de
configuration (la ligne est supprimée) et des SONDES nommées (ajout ou modification : mot de passe
en clair, route par défaut, voisin supplémentaire, limite à 0...) : un évaluateur qui change de
comportement sur une configuration voisine de la vraie est ainsi vu, pas seulement sur la
configuration nominale. Seules les mutations dont la réponse diffère de la base sont stockées.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
# Le code de netcheck évalué : le dépôt, sauf dans le sous-processus qui rejoue le code de référence
# (GOLDEN_CODE_ROOT = arbre extrait de git, voir evaluate_with_reference).
CODE_ROOT = Path(os.environ.get("GOLDEN_CODE_ROOT", REPO))
if str(CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(CODE_ROOT))

from netcheck import __version__, compliance, inventory, report, snapshot  # noqa: E402
from netcheck.drivers.eos import EosDriver  # noqa: E402
from netcheck.drivers.frr import FrrDriver  # noqa: E402
from netcheck.drivers.srlinux import SrlinuxDriver  # noqa: E402
from netcheck.model import DeviceState  # noqa: E402
from netcheck.secrets import mask_secrets  # noqa: E402

FIXTURES = REPO / "tests" / "fixtures"
GOLDEN_DIR = REPO / "tests" / "golden"
INPUTS = GOLDEN_DIR / "inputs"
RULE_FILES = {
    "default": REPO / "netcheck" / "rules" / "default.yml",
    "security": REPO / "netcheck" / "rules" / "security.yml",
    # Phase B3 : fichier NOUVEAU (règles OSPFv3). Aucun code de référence n'y répond : son gel est créé par
    # `record-new` avec le code courant commité, jamais par `record` (qui réécrirait les deux autres).
    "security-ipv6": REPO / "netcheck" / "rules" / "security-ipv6.yml",
}
# Fichiers de règles de la v0.3.0 : les seuls que `record` (code de référence) peut réécrire.
REFERENCE_RULE_FILES = ("default", "security")
# Union des interfaces de management des trois inventaires (une seule valeur pour les cas par
# équipement ; les cas « lab » utilisent celle de leur inventaire).
MGMT_ALL = {"eth0", "mgmt0", "Management0"}
LAB_MGMT = {"lab:frr": {"eth0"}, "lab:multivendor": {"eth0", "mgmt0"},
            "lab:ceos": {"eth0", "Management0"}, "lab:config-frr": {"eth0"},
            "lab:config-ceos": {"eth0", "Management0"},
            # Phase B3 : labs en double pile (configurations relevées en direct).
            "lab:dualstack-frr": {"eth0"}, "lab:dualstack-multivendor": {"eth0", "mgmt0"},
            "lab:dualstack-ceos": {"eth0", "Management0"}}
DUALSTACK = FIXTURES / "live_dualstack"

# Snapshots réels de référence (pris avec le code v0.3.0) -> inventaire du lab correspondant.
REFERENCES = {
    "v4a-ref-frr": "inventory.yml",
    "v4a-ref-mixte": "inventory-multivendor.yml",
    "v4a-ref-ceos": "inventory-ceos.yml",
}
REFERENCE_DIR = REPO / "reports" / "reference_v030"

# Commande logique -> fichier de fixture (mêmes commandes pour FRR et EOS ; SR Linux en a sept).
_FILES = {
    "show interface json": "interface.json",
    "show ip route json": "route.json",
    "show ip ospf neighbor json": "ospf_neighbor.json",
    "show bgp ipv4 unicast summary json": "bgp_summary.json",
    "show bgp ipv4 unicast json": "bgp_prefixes.json",
    "show running-config": "running_config.txt",
}
_SRLINUX_FILES = {
    "show interface json": "interface.json",
    "show ip route json": "route.json",
    "show ip ospf neighbor json": "ospf_neighbor.json",
    "show running-config": "running_config.txt",
    "show ospf running-config": "ospf_running_config.txt",
    "show system authentication": "system_authentication.txt",
    "show system banner": "system_banner.txt",
}


# ------------------------------------------------------------------------------------------
# Entrées
# ------------------------------------------------------------------------------------------

def _from_fixtures(driver_cls, driver_name: str, folder: Path, name: str, files: dict) -> DeviceState:
    raw = {command: (folder / filename).read_text(encoding="utf-8") for command, filename in files.items()}
    state = driver_cls().parse(raw, name, "-")
    state.driver = driver_name
    return state


def _from_state_file(path: Path) -> DeviceState:
    """État normalisé d'un snapshot réel (DeviceState tel que le driver l'a produit sur le lab)."""
    return DeviceState.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _config_text(name: str, driver_name: str, text: str) -> DeviceState:
    return DeviceState(name=name, host="-", timestamp="", reachable=True, running_config=text,
                       driver=driver_name)


def _config_only(name: str, driver_name: str, path: Path) -> DeviceState:
    """Configuration seule, sans aucun modèle : l'état que produira `check --config-dir`."""
    return _config_text(name, driver_name, path.read_text(encoding="utf-8"))


def devices() -> dict[str, DeviceState]:
    """Un état par cas « équipement » (c'est sur ceux-là que portent les mutations)."""
    out: dict[str, DeviceState] = {}
    for r in ("r1", "r3", "r4"):
        out[f"fixture:frr-{r}"] = _from_fixtures(FrrDriver, "frr", FIXTURES / r, r, _FILES)
    out["fixture:srlinux-r5"] = _from_fixtures(
        SrlinuxDriver, "srlinux", FIXTURES / "r5", "r5", _SRLINUX_FILES)
    # Ajouté après A1 (r5 durci, relevé sur le lab mixte : keychain OSPF en $aes1$, bannière).
    out["fixture:srlinux-r5-hardened"] = _from_state_file(FIXTURES / "r5_hardened" / "state.json")
    ceos = FIXTURES / "ceos"
    for scenario in sorted(p.name for p in ceos.iterdir() if p.is_dir()):
        out[f"fixture:eos-{scenario}"] = _from_fixtures(EosDriver, "eos", ceos / scenario, "r4", _FILES)
    for r in ("r1", "r2", "r3", "r4", "r5"):
        out[f"config:frr-{r}"] = _config_only(r, "frr", INPUTS / f"frr_{r}.conf")
    out["config:eos-r4"] = _config_only("r4", "eos", INPUTS / "eos_r4.startup-config")
    # Ajoutés en A4 (peer groups) : `running-config` relevées en direct sur r3 (FRR) et r4 (cEOS), sans
    # modèle (configuration seule). Capacité nouvelle : leur réponse est celle du code A4
    # (`add --current-code`).
    for path in sorted((FIXTURES / "peergroups").glob("*.txt")):
        vendor = path.stem.split("_")[0]
        out[f"peergroup:{path.stem}"] = _config_only("r3" if vendor == "frr" else "r4", vendor, path)
    # Ajoutés en B3 (double pile) : `running-config` relevées en direct sur les trois labs en double pile
    # (tests/fixtures/live_dualstack/), configuration seule. Capacité nouvelle (IPv6) : leur réponse est
    # celle du code B3 (`add --current-code`), vérifiée contre des attentes écrites à la main.
    for r in ("r1", "r2", "r3", "r4", "r5"):
        out[f"dualstack:frr-{r}"] = _config_only(r, "frr", DUALSTACK / f"frr_{r}.txt")
    out["dualstack:eos-r4"] = _config_only("r4", "eos", DUALSTACK / "eos_r4.txt")
    # Ajoutés en B4 : `running-config` de r4 (cEOS) relevées PENDANT le scénario d'intégration C6 (lecture
    # seule, sur le lab nominal modifié puis restauré) : listes d'entrée qui autorisent 0.0.0.0/0, ::/0 et
    # nos préfixes ; membre fictif d'un peer group dont la route-map d'entrée fait de même. Capacité
    # nouvelle (`add --current-code`).
    out["dualstack:eos-r4-inbound-lists"] = _config_only("r4", "eos", DUALSTACK / "eos_r4_inbound_lists.txt")
    out["dualstack:eos-r4-inbound-peergroup"] = _config_only(
        "r4", "eos", DUALSTACK / "eos_r4_inbound_peergroup.txt")
    out["dualstack:srlinux-r5"] = _config_only("r5", "srlinux", DUALSTACK / "srl_r5.txt")
    return out


def scenarios() -> dict[str, dict[str, DeviceState]]:
    """Cas « scénario » (réponse de base seulement) : une configuration réelle modifiée pour atteindre
    un chemin que ni les mutations ni les sondes n'atteignent. Leur réponse attendue est celle du CODE
    DE RÉFÉRENCE (`add --reference-code`), jamais celle du moteur courant."""
    r3 = (INPUTS / "frr_r3.conf").read_text(encoding="utf-8")
    anchor = "ip prefix-list PL-EBGP-IN seq 20 permit 192.168.2.0/24\n"
    assert r3.count(anchor) == 1
    # La politique d'entrée autorise 10.1.0.0/16, un préfixe que r3 annonce lui-même : réinjection.
    reinjection = r3.replace(anchor, anchor + "ip prefix-list PL-EBGP-IN seq 30 permit 10.1.0.0/16\n")
    # A4 : la limite d'un membre de peer group est posée à 0 (illimité sur EOS) alors que son groupe en a une.
    eos = (FIXTURES / "peergroups" / "eos_s2_override.txt").read_text(encoding="utf-8")
    assert eos.count("neighbor 192.0.2.4 maximum-routes 20") == 1
    unlimited = eos.replace("neighbor 192.0.2.4 maximum-routes 20", "neighbor 192.0.2.4 maximum-routes 0")
    return {"scenario:frr-r3-reinjection": {"r3": _config_text("r3", "frr", reinjection)},
            "scenario:eos-peergroup-member-maximum-routes-0": {"r4": _config_text("r4", "eos", unlimited)}}


def labs() -> dict[str, dict[str, DeviceState]]:
    """Cas « lab » : plusieurs équipements évalués ensemble (ordre des constats, non applicables)."""
    d = devices()
    frr = {r: d[f"fixture:frr-{r}"] for r in ("r1", "r3", "r4")}
    return {
        "lab:frr": frr,
        "lab:multivendor": {**frr, "r5": d["fixture:srlinux-r5"]},
        "lab:ceos": {"r1": frr["r1"], "r3": frr["r3"], "r4": d["fixture:eos-r4"]},
        "lab:config-frr": {r: d[f"config:frr-{r}"] for r in ("r1", "r2", "r3", "r4", "r5")},
        "lab:config-ceos": {**{r: d[f"config:frr-{r}"] for r in ("r1", "r2", "r3", "r5")},
                            "r4": d["config:eos-r4"]},
        "lab:dualstack-frr": {r: d[f"dualstack:frr-{r}"] for r in ("r1", "r2", "r3", "r4", "r5")},
        "lab:dualstack-multivendor": {**{r: d[f"dualstack:frr-{r}"] for r in ("r1", "r2", "r3", "r4")},
                                      "r5": d["dualstack:srlinux-r5"]},
        "lab:dualstack-ceos": {**{r: d[f"dualstack:frr-{r}"] for r in ("r1", "r2", "r3", "r5")},
                               "r4": d["dualstack:eos-r4"]},
    }


def mutants(state: DeviceState):
    """Une mutation par ligne non vide (hors « ! » seul) : (clé, état sans cette ligne). La clé
    porte le numéro de ligne ET une empreinte du texte : une entrée modifiée ne passe pas inaperçue."""
    lines = state.running_config.splitlines(keepends=True)
    for i, line in enumerate(lines):
        text = line.strip()
        if text in ("", "!"):
            continue
        key = f"{i + 1}:{hashlib.sha1(text.encode('utf-8')).hexdigest()[:8]}"
        yield key, replace(state, running_config="".join(lines[:i] + lines[i + 1:]))
    yield from probes(state)


def _with_config(state: DeviceState, lines: list[str]) -> DeviceState:
    return replace(state, running_config="".join(lines))


def _insert_after(state: DeviceState, lines: list[str], i: int, extra: str) -> DeviceState:
    return _with_config(state, lines[:i + 1] + [extra] + lines[i + 1:])


def _replace_line(state: DeviceState, lines: list[str], i: int, new: str) -> DeviceState:
    return _with_config(state, lines[:i] + [new] + lines[i + 1:])


def probes(state: DeviceState):
    """Sondes explicites (ajout ou modification, jamais une suppression) : elles atteignent les
    chemins « non conforme » que supprimer une ligne ne peut pas produire (mot de passe en clair,
    route par défaut, 0.0.0.0/0 dans une prefix-list, limite à 0, ip-mtu trop grand...). Chaque
    sonde ne s'applique que si l'entrée contient de quoi la poser ; clé = « probe:<nom>[@ligne] »."""
    cfg = state.running_config
    lines = cfg.splitlines(keepends=True)
    tail = lines[:] if (not lines or lines[-1].endswith("\n")) else lines[:-1] + [lines[-1] + "\n"]
    for name, text in (("clear-password", "password secret123\n"),
                       ("clear-enable-password", "enable password secret123\n"),
                       ("static-default-route", "ip route 0.0.0.0/0 10.0.0.1\n")):
        yield f"probe:{name}", _with_config(state, tail + [text])

    for i, line in enumerate(lines):
        # 0.0.0.0/0 ajouté à une prefix-list existante, avec et sans « le 32 ».
        m = re.match(r"^(ip prefix-list \S+ seq )\d+ (?:permit|deny) ", line)
        if m:
            for variant, suffix in (("default", ""), ("default-le32", " le 32")):
                extra = f"{m.group(1)}99 permit 0.0.0.0/0{suffix}\n"
                yield f"probe:prefix-list-{variant}@{i + 1}", _insert_after(state, lines, i, extra)
        # B3 : la route par défaut IPv6 ajoutée à une `ipv6 prefix-list` existante (FRR seulement : EOS
        # écrit ses listes IPv6 en sous-mode). Sans effet sur les entrées d'avant la double pile, qui n'en
        # ont aucune.
        m = re.match(r"^(ipv6 prefix-list \S+ seq )\d+ permit ", line)
        if m:
            for variant, suffix in (("default", ""), ("default-le128", " le 128")):
                extra = f"{m.group(1)}99 permit ::/0{suffix}\n"
                yield f"probe:ipv6-prefix-list-{variant}@{i + 1}", _insert_after(state, lines, i, extra)
        # Limite de préfixes/routes remplacée par 0 (illimité côté EOS).
        if re.search(r"\b(?:maximum-prefix|maximum-routes) \d+", line):
            zero = re.sub(r"\b(maximum-prefix|maximum-routes) \d+", r"\1 0", line)
            yield f"probe:limit-zero@{i + 1}", _replace_line(state, lines, i, zero)
        # SR Linux : ip-mtu égal à 1514 (marge nulle avec un mtu de 1514).
        if re.match(r"^\s*ip-mtu \d+\s*$", line):
            wide = re.sub(r"ip-mtu \d+", "ip-mtu 1514", line)
            yield f"probe:ip-mtu-1514@{i + 1}", _replace_line(state, lines, i, wide)
        # Un voisin eBGP, puis un voisin iBGP, de plus, sans rien d'autre (aucun mot de passe...).
        m = re.match(r"^router bgp (\d+)\s*$", line)
        if m and i + 1 < len(lines):
            indent = re.match(r"\s*", lines[i + 1]).group(0)
            for variant, asn in (("ebgp", int(m.group(1)) + 1), ("ibgp", int(m.group(1)))):
                extra = f"{indent}neighbor 10.9.9.9 remote-as {asn}\n"
                yield f"probe:bgp-extra-{variant}@{i + 1}", _insert_after(state, lines, i, extra)

    # Mutations du MODÈLE (la règle interface_description_required ne lit pas la configuration).
    for n, iface in enumerate(state.interfaces):
        if iface.description:
            ifaces = list(state.interfaces)
            ifaces[n] = replace(iface, description=None)
            yield f"probe:no-description@{iface.name}", replace(state, interfaces=ifaces)
    if any(i.is_loopback is not None for i in state.interfaces):
        yield "probe:loopback-unknown", replace(
            state, interfaces=[replace(i, is_loopback=None) for i in state.interfaces])


# ------------------------------------------------------------------------------------------
# Enregistrement
# ------------------------------------------------------------------------------------------

def record(rules, devs: dict[str, DeviceState], mgmt: set[str] = MGMT_ALL) -> dict:
    """Réponse du moteur sur ces équipements, par le chemin des vrais rapports (masquage compris).
    Colonnes : violations = [gravité, règle, équipement, détail, catégorie] ;
    not_applicable = [règle, équipement, raison]. Que des listes : le JSON relu est identique."""
    try:
        violations, not_applicable = compliance.evaluate(rules, devs, management_interfaces=set(mgmt))
        compliant, code = compliance.verdict(violations)
        data = report.compliance_to_dict(violations, compliant, not_applicable)
    except Exception as e:  # noqa: BLE001 -- un plantage du moteur fait partie du comportement gelé
        return {"error": mask_secrets(f"{type(e).__name__}: {e}")}
    return {
        "compliant": data["compliant"],
        "code": code,
        "violations": [[v["severity"], v["rule_id"], v["device"], v["detail"], v["category"]]
                       for v in data["violations"]],
        "not_applicable": [[n["rule_id"], n["device"], n["reason"]] for n in data["not_applicable"]],
    }


def _delta(base: dict, rec: dict) -> dict:
    """Les seuls champs de `rec` qui diffèrent de `base` (réponse complète si les clés diffèrent,
    ex. un plantage du moteur) : le fichier d'or reste lisible et compact."""
    if set(rec) != set(base):
        return rec
    return {k: v for k, v in rec.items() if base[k] != v}


def _build_device_case(rules, state: DeviceState) -> dict:
    base = record(rules, {state.name: state})
    changed, total = {}, 0
    for key, mutated in mutants(state):
        total += 1
        rec = record(rules, {state.name: mutated})
        if rec != base:
            changed[key] = _delta(base, rec)
    return {"base": base, "mutants_total": total, "mutants_changed": changed}


def build_cases(rules_name: str, only: list[str] | None = None) -> dict[str, dict]:
    """Tous les cas, ou seulement ceux de `only` (ajout d'un cas sans toucher aux autres)."""
    rules = compliance.load_rules(RULE_FILES[rules_name])
    cases: dict[str, dict] = {}
    for case_id, state in devices().items():
        if only is None or case_id in only:
            cases[case_id] = _build_device_case(rules, state)
    for case_id, devs in labs().items():
        if only is None or case_id in only:
            cases[case_id] = {"base": record(rules, devs, LAB_MGMT[case_id])}
    for case_id, devs in scenarios().items():
        if only is None or case_id in only:
            cases[case_id] = {"base": record(rules, devs)}
    unknown = set(only or ()) - set(cases)
    if unknown:
        raise SystemExit(f"cas inconnu(s) : {sorted(unknown)}")
    return cases


def build(rules_name: str) -> dict:
    cases = build_cases(rules_name)
    return {
        "meta": {
            "netcheck_version": __version__,
            "code_commit": _code_commit(),
            "rules": f"netcheck/rules/{rules_name}.yml",
            "mutation": "suppression d'une ligne non vide (hors '!') et sondes nommées (probe:*) ; "
                        "seules les mutations dont la réponse diffère de la base sont stockées, "
                        "et seulement les champs qui diffèrent",
            "columns": {"violations": ["gravité", "règle", "équipement", "détail", "catégorie"],
                        "not_applicable": ["règle", "équipement", "raison"]},
        },
        "cases": cases,
    }


def _code_commit() -> str:
    out = subprocess.run(["git", "-C", str(REPO), "log", "-1", "--format=%h", "--", "netcheck/"],
                         capture_output=True, text=True, check=False)
    return out.stdout.strip() or "inconnu"


def _write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def evaluate_with_reference(commit: str, rules_name: str, cases: dict[str, dict[str, DeviceState]]) -> dict:
    """Évalue ces cas avec le code de netcheck tel qu'il était à `commit` : l'arbre est extrait de git
    dans un dossier temporaire et exécuté dans un sous-processus. Rend {cas: réponse}. La preuve que
    c'est bien l'ancien moteur est vérifiée (il ne connaît pas `evaluate_config`, ajouté en A3)."""
    tree = Path(tempfile.mkdtemp(prefix="golden_reference_"))
    try:
        archive = subprocess.run(["git", "-C", str(REPO), "archive", commit, "netcheck", "automation"],
                                 capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", str(tree)], input=archive, check=True)
        payload = {cid: {name: s.to_dict() for name, s in devs.items()} for cid, devs in cases.items()}
        env = {**os.environ, "GOLDEN_CODE_ROOT": str(tree), "PYTHONPATH": str(tree)}
        out = subprocess.run([sys.executable, str(Path(__file__).resolve()), "_eval-reference", rules_name],
                             input=json.dumps(payload), capture_output=True, text=True, env=env, cwd=tree)
        if out.returncode:
            raise SystemExit(f"évaluation du code de référence en échec :\n{out.stderr}")
        result = json.loads(out.stdout)
        if result["engine_has_evaluate_config"]:
            raise SystemExit(f"{commit} contient déjà evaluate_config : ce n'est pas l'ancien moteur")
        return result["records"]
    finally:
        shutil.rmtree(tree, ignore_errors=True)


def _netcheck_dirty() -> str:
    """Ce que git voit de modifié ou de non suivi sous netcheck/ (vide = le code est dans l'historique)."""
    return subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--", "netcheck/"],
                          capture_output=True, text=True, check=False).stdout.strip()


def _netcheck_unstaged() -> str:
    """Ce qui, sous netcheck/, n'est pas (entièrement) indexé : modifié après l'indexation, ou non suivi."""
    out = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--", "netcheck/"],
                         capture_output=True, text=True, check=False).stdout.splitlines()
    return "\n".join(line for line in out if line[1] != " " or line.startswith("??"))


def _netcheck_tree() -> str:
    """L'empreinte de l'arbre netcheck/ tel qu'il est INDEXÉ : git la retrouvera dans le commit."""
    return subprocess.run(["git", "-C", str(REPO), "write-tree", "--prefix=netcheck/"], capture_output=True,
                          text=True, check=True).stdout.strip()


def add_cases(case_ids: list[str], reason: str, reference_commit: str | None = None,
              current_code: bool = False) -> None:
    """Ajoute des cas NOUVEAUX au gel, sans toucher aux autres. Refuse d'écraser un cas existant.

    Trois façons de produire la réponse gelée :
    - sans option : refuse de tourner si netcheck/ diffère du code de référence du gel : un ajout n'est
      légitime que tant que le moteur répond encore comme la v0.3.0 ;
    - `reference_commit` : les cas (des scénarios seulement) sont évalués par le code de ce commit, extrait
      de git : la réponse gelée est celle de la v0.3.0 même si le moteur courant a changé ;
    - `current_code` : pour une capacité NOUVELLE (aucune réponse de la v0.3.0 à préserver) : les cas sont
      évalués par le code courant, qui doit être commité (refus sinon : la réponse gelée vient d'un code qui
      existe dans l'historique, `meta.additions` en garde le commit). Réservé à des cas dont la réponse a été
      validée avant l'ajout.
    Les autres cas restent identiques à l'octet. Rien n'est écrit si un des fichiers refuse l'ajout."""
    if reference_commit is not None and current_code:
        raise SystemExit("--reference-code et --current-code s'excluent")
    if current_code and _netcheck_dirty():
        raise SystemExit("netcheck/ a des modifications non commitées : commitez le code d'abord, "
                         "le gel enregistre la réponse d'un code qui existe dans l'historique")
    updates: dict[str, dict] = {}
    for rules_name in RULE_FILES:
        if not golden_path(rules_name).exists():
            continue                      # gel pas encore créé (`record-new`) : il recevra tous les cas
        data = json.loads(golden_path(rules_name).read_text(encoding="utf-8"))
        reference = data["meta"]["code_commit"]
        if reference_commit is None and not current_code:
            diff_cmd = ["git", "-C", str(REPO), "diff", "--quiet", reference, "--", "netcheck/"]
            changed = subprocess.run(diff_cmd, check=False).returncode
            if changed:
                raise SystemExit(f"netcheck/ diffère du code de référence {reference} : ajout refusé "
                                 "(--reference-code pour un scénario, ou traitez l'écart cas par cas)")
        clash = [c for c in case_ids if c in data["cases"]]
        if clash:
            raise SystemExit(f"{rules_name} : cas déjà gelé(s) {clash}, jamais écrasés")
        if reference_commit is None:
            data["cases"].update(build_cases(rules_name, only=case_ids))
        else:
            wanted = {cid: scenarios()[cid] for cid in case_ids if cid in scenarios()}
            if set(wanted) != set(case_ids):
                raise SystemExit("--reference-code ne s'applique qu'aux cas « scenario: »")
            records = evaluate_with_reference(reference_commit, rules_name, wanted)
            data["cases"].update({cid: {"base": records[cid]} for cid in case_ids})
        code = reference_commit or (_code_commit() if current_code else reference)
        addition = {"cases": case_ids, "code_commit": code, "reason": reason}
        if current_code:
            addition["current_code"] = True
        data["meta"].setdefault("additions", []).append(addition)
        updates[rules_name] = data
    for rules_name, data in updates.items():
        _write(golden_path(rules_name), data)
        for case_id in case_ids:
            case = data["cases"][case_id]
            changed_count = len(case.get("mutants_changed", {}))
            detail = (f"{case['mutants_total']} mutations ({changed_count} changent la réponse)"
                      if "mutants_total" in case else "réponse de base")
            print(f"{rules_name} : + {case_id} : {detail}, conforme={case['base'].get('compliant')}")


def record_new(rules_name: str) -> None:
    """Crée le gel d'un fichier de règles ajouté APRÈS la v0.3.0 (Phase B3 : `security-ipv6`) avec le code
    courant, qui doit être commité (la réponse gelée vient d'un code qui existe dans l'historique). Tous
    les cas y entrent. Refuse d'écraser un gel existant, et ne touche à aucun autre fichier."""
    if rules_name in REFERENCE_RULE_FILES:
        raise SystemExit(f"{rules_name} fait partie des fichiers de la v0.3.0 : "
                         f"jamais réécrit par record-new")
    path = golden_path(rules_name)
    if path.exists():
        raise SystemExit(f"{path.name} existe déjà : jamais écrasé")
    if _netcheck_dirty():
        raise SystemExit("netcheck/ a des modifications non commitées : commitez le code d'abord")
    data = build(rules_name)
    data["meta"]["created_with"] = {"code_commit": _code_commit(), "current_code": True,
                                    "reason": "fichier de règles ajouté en B3 : aucune réponse de la v0.3.0"}
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    cases = data["cases"]
    print(f"{path.relative_to(REPO)} : {len(cases)} cas, "
          f"{sum(c.get('mutants_total', 0) for c in cases.values())} mutations")


def _base_now(rules, case_id: str) -> dict | None:
    """La réponse de base du moteur courant pour ce cas (équipement, lab ou scénario), ou None."""
    if case_id in (states := devices()):
        return record(rules, {states[case_id].name: states[case_id]})
    if case_id in (labs_ := labs()):
        return record(rules, labs_[case_id], LAB_MGMT[case_id])
    if case_id in (scenes := scenarios()):
        return record(rules, scenes[case_id])
    return None


def replace_mutants(rules_name: str, targets: list[str], reason: str, staged_code: bool = False) -> None:
    """Met à jour des entrées précises du gel après un écart voulu et validé. Jamais en bloc : chaque
    cible est nommée `<cas>@<clé de mutation>` (la clé = numéro de ligne:empreinte, telle que `compare`
    l'affiche) ou `<cas>@base` (la réponse de base du cas : équipement, lab ou scénario), doit être
    réellement en écart avec le moteur courant (sinon refus : rien à justifier), et n'est mise à jour
    qu'à cette seule entrée. Les autres entrées, bases et sondes restent identiques à l'octet. Quand une
    base et des mutations du même cas changent, la base se nomme EN PREMIER : les mutations sont des
    écarts par rapport à elle. Refuse de tourner si netcheck/ a des modifications non commitées : la
    réponse enregistrée doit venir d'un code qui existe dans l'historique.

    `staged_code` permet le commit ATOMIQUE (le code et le gel dans le même commit, donc jamais de gel
    rouge dans l'historique) : tout netcheck/ doit alors être indexé (`git add`), rien de plus, et la
    révision enregistre l'empreinte de l'arbre indexé (`code_tree`) au lieu d'un commit qui n'existe pas
    encore : `git rev-parse <commit>:netcheck` la retrouvera dans le commit qui suit."""
    if staged_code:
        if _netcheck_unstaged():
            raise SystemExit("--staged-code : netcheck/ a des modifications non indexées ou des fichiers non "
                             "suivis : indexez tout (git add), le gel garde l'empreinte de l'arbre indexé")
        if not _netcheck_dirty():
            raise SystemExit("--staged-code : rien d'indexé sous netcheck/ : utilisez replace sans l'option")
    elif _netcheck_dirty():
        raise SystemExit("netcheck/ a des modifications non commitées : commitez le code d'abord, "
                         "le gel enregistre la réponse d'un code qui existe dans l'historique")
    path = golden_path(rules_name)
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = compliance.load_rules(RULE_FILES[rules_name])
    states = devices()
    revisions = []
    for target in targets:
        case_id, _, key = target.partition("@")
        case = data["cases"].get(case_id)
        if case is not None and key == "base":
            before, after = case["base"], _base_now(rules, case_id)
            if after is None or json.loads(json.dumps(after)) == before:
                raise SystemExit(f"{target} : déjà identique au moteur courant (ou cas inconnu), "
                                 "rien à mettre à jour")
            case["base"] = after
            revisions.append({"case": case_id, "mutation": "base",
                              "rules_before": [v[1] for v in before.get("violations", [])],
                              "rules_after": [v[1] for v in after.get("violations", [])]})
            continue
        if case is None or case_id not in states or "mutants_changed" not in case:
            raise SystemExit(f"{target} : cas inconnu ou sans mutations")
        mutated = dict(mutants(states[case_id])).get(key)
        if mutated is None:
            raise SystemExit(f"{target} : mutation introuvable (clé {key})")
        record_now = record(rules, {mutated.name: mutated})
        before = case["mutants_changed"].get(key)
        after = None if record_now == case["base"] else _delta(case["base"], record_now)
        if json.loads(json.dumps(after)) == before:
            raise SystemExit(f"{target} : déjà identique au moteur courant, rien à mettre à jour")
        if after is None:
            case["mutants_changed"].pop(key)
        else:
            case["mutants_changed"][key] = after

        def ids(delta, base=case["base"]):
            return [v[1] for v in {**base, **(delta or {})}.get("violations", [])]
        revisions.append({"case": case_id, "mutation": key,
                          "rules_before": ids(before), "rules_after": ids(after)})
    code = ({"code_commit": None, "code_tree": _netcheck_tree()} if staged_code
            else {"code_commit": _code_commit()})
    data["meta"].setdefault("revisions", []).append(
        {"rules": rules_name, "reason": reason, **code, "targets": revisions})
    _write(path, data)
    print(f"{rules_name} : {len(revisions)} mutation(s) mise(s) à jour")


def _normalized(data) -> object:
    return json.loads(json.dumps(data, ensure_ascii=False))


def golden_path(rules_name: str) -> Path:
    return GOLDEN_DIR / f"compliance_{rules_name}.json"


def compare(rules_name: str) -> list[str]:
    """Recalcule avec le code actuel et liste les écarts avec le gel (liste vide = identique)."""
    expected = json.loads(golden_path(rules_name).read_text(encoding="utf-8"))["cases"]
    actual = _normalized(build(rules_name)["cases"])
    diffs: list[str] = []
    for case_id in sorted(set(expected) | set(actual)):
        if case_id not in expected or case_id not in actual:
            diffs.append(f"{case_id} : cas absent du gel ou du recalcul")
            continue
        e, a = expected[case_id], actual[case_id]
        if e["base"] != a["base"]:
            diffs.append(f"{case_id} : réponse de base différente\n    gel    : {e['base']}\n"
                         f"    actuel : {a['base']}")
        if e.get("mutants_total") != a.get("mutants_total"):
            diffs.append(f"{case_id} : {e.get('mutants_total')} mutations gelées, "
                         f"{a.get('mutants_total')} aujourd'hui (entrée modifiée ?)")
        for key in sorted(set(e.get("mutants_changed", {})) | set(a.get("mutants_changed", {}))):
            ev = e.get("mutants_changed", {}).get(key, "identique à la base")
            av = a.get("mutants_changed", {}).get(key, "identique à la base")
            if ev != av:
                diffs.append(f"{case_id} / ligne {key} : réponse différente\n    gel    : {ev}\n"
                             f"    actuel : {av}")
    return diffs


# ------------------------------------------------------------------------------------------
# Snapshots réels des trois labs (local, hors Git)
# ------------------------------------------------------------------------------------------

def reference_records() -> dict[str, dict]:
    out = {}
    for snap, inventory_file in REFERENCES.items():
        devs = snapshot.load(snap)
        mgmt = set(inventory.load(path=REPO / "automation" / inventory_file).management_interfaces)
        for rules_name, path in RULE_FILES.items():
            out[f"{snap}__{rules_name}"] = record(compliance.load_rules(path), devs, mgmt)
    return out


def _reference_file(name: str) -> Path:
    return REFERENCE_DIR / f"{name}.json"


EXIT_REFERENCE_MISSING = 3   # usage : une référence LOCALE (hors Git) manque : ni écart ni succès


def missing_references() -> list[Path]:
    """Fichiers de référence attendus (un par snapshot réel et par fichier de règles) mais absents."""
    return [_reference_file(f"{snap}__{rules}") for snap in REFERENCES for rules in RULE_FILES
            if not _reference_file(f"{snap}__{rules}").is_file()]


def _reference_missing_message(missing: list[Path]) -> str:
    names = ", ".join(str(p.relative_to(REPO)) if p.is_relative_to(REPO) else str(p) for p in missing)
    return (f"référence locale absente : {names} ; "
            "générer avec : python tests/tools/golden.py reference record "
            "(n'écrase pas les références existantes, --overwrite pour le faire exprès). "
            "Aucune comparaison n'a été faite : ce n'est pas un succès.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("record")
    new = sub.add_parser("record-new", help="crée le gel d'un fichier de règles NOUVEAU (refuse d'écraser)")
    new.add_argument("rules", choices=sorted(set(RULE_FILES) - set(REFERENCE_RULE_FILES)))
    sub.add_parser("compare")
    add = sub.add_parser("add", help="ajoute des cas nouveaux au gel (jamais d'écrasement)")
    add.add_argument("cases", nargs="+")
    add.add_argument("--reason", required=True)
    add.add_argument("--reference-code", help="commit dont le code évalue les scénarios (ex. b56a775)")
    add.add_argument("--current-code", action="store_true",
                     help="capacité nouvelle : évaluer par le code courant, qui doit être commité")
    sub.add_parser("_eval-reference", help=argparse.SUPPRESS).add_argument("rules")
    rep = sub.add_parser("replace", help="met à jour des mutations NOMMÉES après un écart voulu et validé")
    rep.add_argument("rules", choices=sorted(RULE_FILES))
    rep.add_argument("targets", nargs="+", help="<cas>@<clé de mutation>, une par écart validé")
    rep.add_argument("--reason", required=True)
    rep.add_argument("--staged-code", action="store_true",
                     help="commit atomique : netcheck/ entièrement indexé, la révision garde l'empreinte de "
                          "l'arbre indexé (retrouvée dans le commit qui suit)")
    ref = sub.add_parser("reference")
    ref.add_argument("action", choices=["record", "compare"])
    ref.add_argument("--overwrite", action="store_true",
                     help="record : réécrire aussi les références déjà présentes (jamais par défaut)")
    args = parser.parse_args(argv)

    if args.command == "record-new":
        record_new(args.rules)
        return 0

    if args.command == "record":
        GOLDEN_DIR.mkdir(exist_ok=True)
        for rules_name in REFERENCE_RULE_FILES:
            data = build(rules_name)
            golden_path(rules_name).write_text(
                json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            cases = data["cases"]
            mutants_total = sum(c.get("mutants_total", 0) for c in cases.values())
            mutants_changed = sum(len(c.get("mutants_changed", {})) for c in cases.values())
            print(f"{golden_path(rules_name).relative_to(REPO)} : {len(cases)} cas, "
                  f"{mutants_total} mutations ({mutants_changed} changent la réponse)")
        return 0

    if args.command == "add":
        add_cases(args.cases, args.reason, args.reference_code, args.current_code)
        return 0

    if args.command == "_eval-reference":     # exécuté dans le sous-processus, avec l'ancien code
        scene = json.loads(sys.stdin.read())
        rules = compliance.load_rules(RULE_FILES[args.rules])
        records = {cid: record(rules, {n: DeviceState.from_dict(d) for n, d in devs.items()})
                   for cid, devs in scene.items()}
        print(json.dumps({"engine_has_evaluate_config": hasattr(compliance, "evaluate_config"),
                          "records": records}))
        return 0

    if args.command == "replace":
        replace_mutants(args.rules, args.targets, args.reason, args.staged_code)
        return 0

    if args.command == "compare":
        failed = 0
        for rules_name in RULE_FILES:
            diffs = compare(rules_name)
            print(f"{rules_name} : {'identique au gel' if not diffs else f'{len(diffs)} écart(s)'}")
            for d in diffs[:20]:
                print("  -", d)
            failed += bool(diffs)
        return 1 if failed else 0

    if args.action == "compare":
        missing = missing_references()
        if missing:
            print(_reference_missing_message(missing), file=sys.stderr)
            return EXIT_REFERENCE_MISSING
    try:
        records = reference_records()
    except FileNotFoundError as exc:      # snapshot réel d'un lab absent (local, hors Git)
        print(f"référence locale absente : {exc} ; les snapshots v4a-ref-* se refont avec "
              "`netcheck snapshot <nom> -i <inventaire>` sur le lab concerné. "
              "Aucune comparaison n'a été faite.",
              file=sys.stderr)
        return EXIT_REFERENCE_MISSING
    if args.action == "record":
        REFERENCE_DIR.mkdir(parents=True, exist_ok=True)
        for name, rec in records.items():
            target = _reference_file(name)
            if target.exists() and not args.overwrite:
                print(f"{name} : référence existante conservée (--overwrite pour la réécrire)")
                continue
            target.write_text(json.dumps(rec, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"{name} : compliant={rec.get('compliant')} code={rec.get('code')} "
                  f"violations={len(rec.get('violations', []))} "
                  f"non applicables={len(rec.get('not_applicable', []))}")
        return 0
    failed = 0
    for name, rec in records.items():
        frozen = json.loads(_reference_file(name).read_text(encoding="utf-8"))
        same = frozen == _normalized(rec)
        print(f"{name} : {'identique' if same else 'DIFFÉRENT'}")
        failed += not same
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
