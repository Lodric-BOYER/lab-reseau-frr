"""Tests pour la règle 'interface_description_required' (§5.4) : toute interface avec une
adresse IP, hors loopback, doit avoir une description. Écrits avant l'implémentation de
netcheck.compliance._check_interface_description_required, pour la définir par l'exemple ;
elle est maintenant implémentée (loopback reconnu par le nom : "lo" exact, ou préfixe
"loopback") et ces tests passent.
"""
from netcheck.compliance import Rule, _check_interface_description_required
from netcheck.model import DeviceState, Interface


def _device(interfaces: list[Interface]) -> DeviceState:
    return DeviceState(name="r1", host="10.0.0.1", timestamp="2026-01-01T00:00:00+00:00",
                        reachable=True, interfaces=interfaces)


def _rule(**params) -> Rule:
    return Rule(id="test-description", description="test", severity="basse",
                applies_to="all", kind="interface_description_required", params=params)


def test_interface_with_ip_and_no_description_is_a_violation():
    device = _device([Interface("eth1", None, True, True, ["10.1.12.1/30"])])
    violations = _check_interface_description_required(_rule(), device)
    assert len(violations) == 1
    assert "eth1" in violations[0].detail


def test_interface_with_ip_and_description_is_conforme():
    device = _device([Interface("eth1", "vers-r2", True, True, ["10.1.12.1/30"])])
    assert _check_interface_description_required(_rule(), device) == []


def test_interface_without_ip_is_ignored_even_without_description():
    device = _device([Interface("eth9", None, False, False, [])])
    assert _check_interface_description_required(_rule(), device) == []


def test_loopback_without_description_is_not_a_violation():
    # Le loopback porte une adresse IP mais est explicitement exclu par la règle
    # (§5.4 : "hors loopback"). C'est le coeur de l'exercice : comment le reconnaître ?
    device = _device([Interface("lo", None, True, True, ["10.1.255.1/32"])])
    assert _check_interface_description_required(_rule(), device) == []


def test_exclude_param_ignores_listed_interfaces():
    device = _device([Interface("eth9", None, True, True, ["10.9.9.1/30"])])
    violations = _check_interface_description_required(_rule(exclude=["eth9"]), device)
    assert violations == []


def test_multiple_offending_interfaces_produce_one_violation_each():
    device = _device([
        Interface("eth1", None, True, True, ["10.1.12.1/30"]),
        Interface("eth2", None, True, True, ["10.1.13.1/30"]),
        Interface("eth3", "LAN-pc1", True, True, ["192.168.1.1/24"]),  # conforme, pas en cause
    ])
    violations = _check_interface_description_required(_rule(), device)
    details = "".join(v.detail for v in violations)
    assert len(violations) == 2
    assert "eth1" in details and "eth2" in details and "eth3" not in details
