"""Connexion SSH générique et liste blanche des commandes (contrainte C1 : lecture seule).

Contrairement à automation/labtools.py, ce module ne connaît pas vtysh : c'est le driver qui
traduit une commande logique en commande CLI réelle (Driver.translate) et qui l'analyse
(Driver.parse). Un driver Cisco ou FortiGate n'a donc besoin de toucher qu'à drivers/.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from netmiko import ConnectHandler

from netcheck.drivers.base import Driver
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.model import DeviceState

# automation/ n'est pas un paquet Python (pas de __init__.py) : on réutilise run_parallel tel
# quel en ajoutant son dossier à sys.path, sans dupliquer sa logique (C2 : rien n'y est modifié).
AUTOMATION_DIR = Path(__file__).resolve().parent.parent / "automation"
if str(AUTOMATION_DIR) not in sys.path:
    sys.path.insert(0, str(AUTOMATION_DIR))
from labtools import run_parallel  # noqa: E402  (import après modification de sys.path)

# Commandes logiques autorisées (tableau §4 du cahier des charges, complété en Phase D2 pour
# le driver SR Linux : "show ospf running-config" récupère la config OSPF séparément, la
# syntaxe SR Linux ne permettant pas de la combiner avec "show running-config" en une seule
# requête -- voir drivers/srlinux.py). Un driver ne peut pas en demander d'autres : toute
# commande de configuration est refusée avant même la connexion SSH.
#
# Phase A (sécurité, O1) : deux commandes SR Linux supplémentaires, délibérément étroites.
# La règle d'authentification OSPF a besoin de vérifier qu'une keychain existe réellement
# (elle vit sous /system authentication, hors de la portée interface/OSPF déjà collectée) et
# la règle de bannière a besoin de /system banner. Vérifié en direct que "info from running
# system" (sans restriction) expose la clé privée TLS, le hash du mot de passe admin et la
# communauté SNMP en clair -- disproportionné pour ce qui est requis ici, donc jamais ajouté ;
# seules les deux sous-branches précises le sont.
ALLOWED_COMMANDS = {
    "show interface json",
    "show ip route json",
    "show ip ospf neighbor json",
    "show bgp ipv4 unicast summary json",
    "show bgp ipv4 unicast json",
    "show running-config",
    "show ospf running-config",
    "show system authentication",
    "show system banner",
}

# Le registre des drivers (champ "driver" de l'inventaire, Phase D1) vit dans drivers/registry.py
# depuis la Phase A3 de la v4 : le moteur de conformité le lit sans importer Netmiko. Le nom
# `collector.DRIVER_REGISTRY` reste valide (même objet).
__all__ = ["DRIVER_REGISTRY", "collect", "collect_all", "wait_for_convergence"]


def _resolve_driver(router: dict) -> Driver:
    """Instancie le driver du routeur d'après son champ "driver" (par défaut "frr").

    Lève ValueError avec un message explicite (nom du routeur, nom demandé, noms disponibles)
    si le nom ne correspond à aucun driver enregistré : mieux vaut échouer tout de suite et
    clairement qu'avec une erreur de connexion SSH incompréhensible plus loin.
    """
    name = router.get("driver", "frr")
    try:
        driver_cls = DRIVER_REGISTRY[name]
    except KeyError:
        raise ValueError(
            f"driver inconnu pour {router.get('name', '?')} : '{name}' "
            f"(disponibles : {sorted(DRIVER_REGISTRY)})"
        ) from None
    return driver_cls()


def _ensure_allowed(commands) -> None:
    """Lève PermissionError si une commande n'est pas dans la liste blanche (C1)."""
    unknown = set(commands) - ALLOWED_COMMANDS
    if unknown:
        raise PermissionError(f"commande(s) hors liste blanche : {sorted(unknown)}")


def collect(router: dict, driver: Driver | None = None) -> DeviceState:
    """Se connecte à un équipement, exécute les commandes du driver, renvoie l'état normalisé.

    `driver` est optionnel (Phase D1) : si omis, il est résolu automatiquement d'après le champ
    "driver" du routeur (_resolve_driver, registre DRIVER_REGISTRY). Le passer explicitement
    reste possible (utilisé par les tests, et par tout appelant qui veut forcer un driver
    unique pour tous les routeurs, comme avant la Phase D1).

    La liste blanche est vérifiée deux fois, *pour le driver réellement utilisé* : une première
    fois ici, sur tout REQUIRED_COMMANDS, *avant même d'ouvrir la connexion SSH* (un driver mal
    écrit ne contacte jamais l'équipement) ; une seconde fois juste avant l'envoi de chaque
    commande individuelle, au plus près de l'action sensible. La seconde ne peut pas être
    contournée par un futur appelant qui construirait sa propre liste de commandes sans
    repasser par ce premier contrôle.
    """
    driver = driver or _resolve_driver(router)
    _ensure_allowed(driver.REQUIRED_COMMANDS)
    # Phase F : second contrôle, sur la commande CLI RÉELLE que le driver fabrique (la liste
    # blanche logique ci-dessus ne voit pas le résultat de translate()). Un driver qui déclare
    # ALLOWED_CLI (EOS) est vérifié en correspondance exacte AVANT la connexion.
    for command in driver.REQUIRED_COMMANDS:
        driver.check_cli(driver.translate(command))

    conn = ConnectHandler(
        device_type=router["device_type"], host=router["host"],
        username=router["username"], password=router["password"],
        timeout=10, conn_timeout=10,
    )
    try:
        if driver.NEEDS_ENABLE:
            conn.enable()   # méthode Netmiko, jamais send_command("enable")
        raw = {}
        for command in driver.REQUIRED_COMMANDS:
            _ensure_allowed([command])
            cli = driver.translate(command)
            driver.check_cli(cli)
            out = conn.send_command(cli, read_timeout=30)
            raw[command] = driver.clean_output(out)
    finally:
        conn.disconnect()
    state = driver.parse(raw, router["name"], router["host"])
    # Champ lu par compliance.py pour filtrer les règles par driver (Phase D2). Le nom du
    # routeur dans l'inventaire fait foi (pas le type de l'instance `driver` reçue), pour que
    # ça marche aussi quand un appelant impose un driver explicite (tests, guard/wait_for_
    # convergence) sans passer par _resolve_driver.
    state.driver = router.get("driver", "frr")
    return state


def collect_all(routers: dict, driver: Driver | None = None, workers: int = 5) -> dict:
    """Collecte en parallèle ; renvoie {nom: (True, DeviceState) ou (False, message d'erreur)}.

    `driver` optionnel (Phase D1) : omis, chaque routeur utilise son propre driver résolu
    d'après l'inventaire (lab multi-constructeurs) ; fourni, il est imposé à tous les routeurs
    (comportement historique, lab mono-constructeur).

    Un équipement injoignable ne bloque pas les autres (réutilise run_parallel de labtools).
    """
    return run_parallel(lambda r: collect(r, driver), routers, workers=workers)


def _converged(results: dict, routers: dict) -> bool:
    """Vrai si chaque équipement a ses voisins OSPF Full et ses sessions BGP Established
    attendus (mêmes critères que health.py, portés sur le modèle normalisé de netcheck)."""
    for name, expected in routers.items():
        ok, state = results.get(name, (False, None))
        if not ok:
            return False
        full = sum(1 for n in state.ospf_neighbors if n.is_full)
        if full < expected.get("ospf_neighbors", 0):
            return False
        for ip, min_pfx in (expected.get("bgp_peers") or {}).items():
            peer = next((p for p in state.bgp_peers if p.neighbor == ip), None)
            if peer is None or peer.state != "Established" or peer.pfx_received < min_pfx:
                return False
    return True


def wait_for_convergence(
    routers: dict, driver: Driver | None = None, *, timeout: float, interval: float = 2.0
) -> bool:
    """Interroge l'état OSPF/BGP en boucle jusqu'à convergence ou expiration de `timeout`
    (jamais une pause fixe) -- utilisé par `guard --wait` (§5.5). Renvoie True si convergé
    avant l'expiration du délai, False sinon (le delai n'est pas une erreur en soi : le
    diff qui suit dira ce qui a réellement changé).

    `driver` optionnel (Phase D1), même sémantique que `collect_all` : résolu par routeur si
    omis (nécessaire sur le lab multi-constructeurs, où r5 n'a pas le même driver que r1-r4)."""
    deadline = time.monotonic() + timeout
    while True:
        if _converged(collect_all(routers, driver), routers):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)
