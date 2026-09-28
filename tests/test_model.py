"""Tests du modèle normalisé : ici, la compatibilité ascendante des snapshots (§4, v2 phase B).

DeviceState.from_dict() est le seul point d'entrée pour recharger un snapshot déjà écrit sur
disque (netcheck list / diff / check --snapshot) : un JSON créé par une version antérieure de
netcheck doit continuer à se charger, jamais planter juste parce qu'un champ a été ajouté.
"""
from netcheck.model import DeviceState

# Snapshot "ancien format" : tel qu'un netcheck d'avant l'ajout de is_loopback (v2 phase B)
# l'aurait écrit -- aucune clé "is_loopback" dans les interfaces.
OLD_FORMAT_SNAPSHOT = {
    "name": "r1",
    "host": "172.20.20.11",
    "timestamp": "2026-01-01T00:00:00+00:00",
    "reachable": True,
    "error": None,
    "interfaces": [
        {
            "name": "lo",
            "description": None,
            "admin_up": True,
            "oper_up": True,
            "addresses": ["10.1.255.1/32"],
            # pas de "is_loopback" ici : c'est le point testé.
        },
    ],
    "routes": [],
    "ospf_neighbors": [],
    "bgp_peers": [],
    "bgp_prefixes": [],
    "running_config": "",
}


def test_old_snapshot_without_is_loopback_key_still_loads():
    state = DeviceState.from_dict(OLD_FORMAT_SNAPSHOT)
    assert state.interfaces[0].name == "lo"
    assert state.interfaces[0].is_loopback is None  # inconnu, pas "faux"


def test_device_state_roundtrip_preserves_is_loopback():
    state = DeviceState.from_dict(OLD_FORMAT_SNAPSHOT)
    restored = DeviceState.from_dict(state.to_dict())
    assert restored.interfaces[0].is_loopback is None
