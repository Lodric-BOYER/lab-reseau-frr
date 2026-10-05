"""Couverture et fraîcheur d'un snapshot lu hors ligne (`check --snapshot`, `assert --snapshot`, phase C6).

Ce que ces tests tiennent :
- le périmètre, la date et la version de netcheck du snapshot sont TOUJOURS affichés (terminal, JSON
  `snapshot_scope`, HTML) ;
- un équipement de l'inventaire absent sans avoir été demandé, ou présent mais injoignable, est une
  ATTENTION (ANALYSE INCOMPLÈTE pour `check`) ; un périmètre demandé (`-d`) est une information ;
- un snapshot sans `scope` est « périmètre inconnu » ;
- `--max-age` (sans valeur par défaut) rend un snapshot trop ancien ATTENTION ; une valeur invalide
  est le code 3.
Aucun test ne lit l'horloge : le temps est injecté (`at=`, ou `snapshotscope.now` remplacé).
"""

import json
from datetime import datetime, timedelta, timezone
from html import unescape
from pathlib import Path

import pytest
import yaml

from netcheck import cli, collector, hostkeys, inventory, snapshot, snapshotscope
from netcheck.model import DeviceState, Interface
from netcheck.snapshotscope import assess, describe, parse_max_age, scope_record
from netcheck.usage import UsageError

ROOT = Path(__file__).resolve().parent.parent
T0 = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)  # « maintenant » de tous les tests
TAKEN = "2026-02-20T10:00:00+00:00"  # 9 jours et 2 h avant T0 : 9,08 jours


def _state(name, reachable=True):
    up = Interface(name="eth1", description=None, admin_up=True, oper_up=True)
    return DeviceState(
        name=name,
        host="-",
        timestamp="t",
        reachable=reachable,
        running_config=f"hostname {name}\n",
        interfaces=[up] if reachable else [],
    )


def _devices(*names, down=()):
    return {n: _state(n, reachable=n not in down) for n in names}


def _meta(inventory_names=None, requested=None, timestamp=TAKEN, version="0.4.0", scope=True):
    meta = {"name": "s", "timestamp": timestamp, "netcheck_version": version}
    if scope:
        meta["scope"] = scope_record(inventory_names or [], requested)
    return meta


# ------------------------------------------------------------------------------------------
# assess : les règles de couverture
# ------------------------------------------------------------------------------------------


def test_a_complete_known_snapshot_has_no_attention_and_says_what_it_covers():
    cov = assess("s", _meta(["r1", "r2", "r3"]), _devices("r1", "r2", "r3"), ["r1", "r2", "r3"], at=T0)
    assert not cov.attention and cov.reasons == [] and cov.missing == [] and cov.known
    assert snapshotscope.as_dict(cov)["coverage"] == "3/3"
    assert "périmètre du snapshot : r1, r2, r3 (3/3 de l'inventaire)" in describe(cov)


def test_devices_of_the_inventory_missing_without_being_requested_are_attention():
    cov = assess("s", _meta(["r1", "r2", "r3"]), _devices("r1"), ["r1", "r2", "r3"], at=T0)
    assert cov.attention and cov.missing == ["r2", "r3"]
    assert cov.reasons == [
        "équipement(s) de l'inventaire absents du snapshot sans avoir été exclus volontairement (-d) : r2, r3"
    ]
    assert "périmètre du snapshot : r1 (1/3 de l'inventaire)" in describe(cov)


def test_a_requested_perimeter_is_information_without_effect_on_the_verdict():
    cov = assess(
        "s",
        _meta(["r1", "r2", "r3", "r4", "r5"], requested=["r5"]),
        _devices("r5"),
        ["r1", "r2", "r3", "r4", "r5"],
        at=T0,
    )
    assert not cov.attention and cov.requested == ["r5"]
    assert cov.notes == ["périmètre demandé (-d) : r5"]
    lines = describe(cov)
    assert "périmètre du snapshot : r5 (1/5 de l'inventaire)" in lines
    assert "information : périmètre demandé (-d) : r5" in lines


def test_a_requested_device_that_is_absent_is_attention():
    cov = assess("s", _meta(["r1", "r2"], requested=["r1", "r2"]), _devices("r1"), ["r1", "r2"], at=T0)
    assert cov.attention and cov.reasons == ["équipement(s) demandés mais absents du snapshot : r2"]


def test_a_present_but_unreachable_device_is_attention():
    cov = assess("s", _meta(["r1", "r2"]), _devices("r1", "r2", down=["r2"]), ["r1", "r2"], at=T0)
    assert cov.attention and cov.unreachable_expected == ["r2"]
    assert cov.reasons == ["équipement(s) de l'inventaire injoignable(s) lors du snapshot : r2"]


def test_an_unreachable_device_outside_the_requested_perimeter_is_not_attention():
    cov = assess(
        "s", _meta(["r1", "r2"], requested=["r1"]), _devices("r1", "r2", down=["r2"]), ["r1", "r2"], at=T0
    )
    assert not cov.attention and cov.unreachable == ["r2"] and cov.unreachable_expected == []


def test_a_device_added_to_the_inventory_after_the_snapshot_is_attention():
    cov = assess("s", _meta(["r1", "r2"]), _devices("r1", "r2"), ["r1", "r2", "r3"], at=T0)
    assert cov.attention and cov.missing == ["r3"] and cov.reference == ["r1", "r2", "r3"]


def test_a_device_in_the_inventory_at_the_time_but_not_collected_is_attention_even_if_since_removed():
    cov = assess("s", _meta(["r1", "r2", "r3"]), _devices("r1", "r2"), ["r1", "r2"], at=T0)
    assert cov.attention and cov.missing == ["r3"]
    assert snapshotscope.as_dict(cov)["coverage"] == "2/3"   # la référence compte l'inventaire d'alors


def test_devices_of_the_snapshot_that_are_not_in_the_inventory_are_listed_as_information():
    cov = assess("s", _meta(["r1"]), _devices("r1", "r9"), ["r1"], at=T0)
    assert not cov.attention and cov.extra == ["r9"]
    assert snapshotscope.as_dict(cov)["coverage"] == "1/1"   # r9 n'est pas de l'inventaire : jamais compté
    assert "équipement(s) du snapshot absents de l'inventaire : r9" in cov.notes
    assert "information : équipement(s) du snapshot absents de l'inventaire : r9" in describe(cov)


def test_a_requested_device_is_never_listed_as_extra():
    cov = assess("s", _meta(["r1"], requested=["r9"]), _devices("r9"), ["r1"], at=T0)
    assert cov.extra == [] and not cov.attention


# --- snapshot sans `scope` (pris avant la v0.4) -------------------------------


def test_an_old_snapshot_without_scope_that_covers_everything_is_information_only():
    cov = assess(
        "s", _meta(scope=False), _devices("r1", "r2", "r3", "r4", "r5"), ["r1", "r2", "r3", "r4", "r5"], at=T0
    )
    assert not cov.known and not cov.attention
    assert cov.notes == ["périmètre inconnu (snapshot sans métadonnée de périmètre), 5/5 présents"]


def test_an_old_snapshot_without_scope_that_misses_devices_is_attention():
    cov = assess("s", _meta(scope=False), _devices("r5"), ["r1", "r2", "r3", "r4", "r5"], at=T0)
    assert cov.attention and cov.missing == ["r1", "r2", "r3", "r4"]
    assert cov.reasons[0].startswith("périmètre inconnu (snapshot sans métadonnée de périmètre) et ")
    assert "r1, r2, r3, r4" in cov.reasons[0]


def test_an_old_snapshot_with_an_unreachable_device_is_attention():
    cov = assess("s", _meta(scope=False), _devices("r1", "r2", down=["r1"]), ["r1", "r2"], at=T0)
    assert cov.attention and "périmètre inconnu" in cov.reasons[0] and "r1" in cov.reasons[0]


def test_no_meta_at_all_is_an_unknown_perimeter_not_a_crash():
    cov = assess("s", None, _devices("r1"), ["r1", "r2"], at=T0)
    assert not cov.known and cov.attention and cov.timestamp is None and cov.age_days is None
    lines = describe(cov)
    assert "pris le date inconnue avec netcheck version inconnue" in lines[0]


@pytest.mark.parametrize(
    "scope",
    [
        {"inventory": "r1", "requested": None},
        {"inventory": ["r1"]},
        {"inventory": ["r1"], "requested": "r1"},
        {"inventory": [1], "requested": None},
        {"inventory": ["r1"], "requested": [2]},
        "r1",
        None,
    ],
)
def test_a_malformed_scope_is_unknown_never_guessed(scope):
    meta = {"timestamp": TAKEN, "netcheck_version": "0.4.0", "scope": scope}
    cov = assess("s", meta, _devices("r1"), ["r1", "r2"], at=T0)
    assert not cov.known and cov.attention


def test_the_scope_record_is_sorted_and_marks_a_full_snapshot_with_none():
    assert scope_record(["r3", "r1", "r2"], None) == {"inventory": ["r1", "r2", "r3"], "requested": None}
    assert scope_record(["r1", "r2"], ["r2", "r1"]) == {"inventory": ["r1", "r2"], "requested": ["r1", "r2"]}
    assert scope_record(["r1"], []) == {"inventory": ["r1"], "requested": None}


# --- date, version, âge, --max-age ----------------------------------------


def test_the_date_and_the_version_are_always_displayed_with_the_age():
    cov = assess("s", _meta(["r1"], version="0.3.0"), _devices("r1"), ["r1"], at=T0)
    assert (
        describe(cov)[0] == "Snapshot 's' : pris le 2026-02-20 10:00 UTC avec netcheck 0.3.0, âge 9.1 jour(s)"
    )
    assert cov.age_days == 9.08


def test_without_max_age_an_old_snapshot_is_not_attention():
    meta = _meta(["r1"], timestamp="2020-01-01T00:00:00+00:00")
    cov = assess("s", meta, _devices("r1"), ["r1"], at=T0)
    assert not cov.attention and not cov.too_old and cov.age_days > 2000


def test_max_age_makes_an_older_snapshot_attention_and_shows_the_age():
    cov = assess("s", _meta(["r1"]), _devices("r1"), ["r1"], max_age_days=7, at=T0)
    assert cov.attention and cov.too_old
    assert cov.reasons == ["snapshot trop ancien : 9.1 jour(s) pour une limite de 7 (--max-age)"]


def test_max_age_equal_to_the_age_is_not_too_old():
    cov = assess(
        "s",
        _meta(["r1"], timestamp=(T0 - timedelta(days=7)).isoformat()),
        _devices("r1"),
        ["r1"],
        max_age_days=7,
        at=T0,
    )
    assert not cov.attention and cov.age_days == 7.0


def test_max_age_just_over_the_limit_is_too_old():
    stamp = (T0 - timedelta(days=7, seconds=1)).isoformat()
    cov = assess("s", _meta(["r1"], timestamp=stamp), _devices("r1"), ["r1"], max_age_days=7, at=T0)
    assert cov.too_old


def test_a_fresh_snapshot_within_max_age_is_not_attention():
    cov = assess("s", _meta(["r1"]), _devices("r1"), ["r1"], max_age_days=30, at=T0)
    assert not cov.attention and cov.max_age_days == 30


@pytest.mark.parametrize("stamp", [None, "", "hier", "2026-13-45T00:00:00", 12345])
def test_an_unreadable_date_with_max_age_is_attention_not_a_pass(stamp):
    meta = {**_meta(["r1"]), "timestamp": stamp}
    cov = assess("s", meta, _devices("r1"), ["r1"], max_age_days=7, at=T0)
    assert cov.attention and cov.age_unreadable and "fraîcheur n'est pas vérifiable" in cov.reasons[0]


def test_an_unreadable_date_without_max_age_has_no_effect():
    meta = {**_meta(["r1"]), "timestamp": "hier"}
    assert not assess("s", meta, _devices("r1"), ["r1"], at=T0).attention


def test_a_date_in_the_future_with_max_age_is_attention():
    stamp = (T0 + timedelta(days=2)).isoformat()
    cov = assess("s", _meta(["r1"], timestamp=stamp), _devices("r1"), ["r1"], max_age_days=7, at=T0)
    assert cov.attention and cov.in_future and "dans le futur" in cov.reasons[0]


def test_a_date_a_few_hours_in_the_future_is_attention_beyond_the_one_hour_tolerance():
    stamp = (T0 + timedelta(hours=3)).isoformat()
    cov = assess("s", _meta(["r1"], timestamp=stamp), _devices("r1"), ["r1"], max_age_days=7, at=T0)
    assert cov.attention and cov.in_future


def test_a_small_clock_skew_is_tolerated():
    stamp = (T0 + timedelta(minutes=30)).isoformat()
    cov = assess("s", _meta(["r1"], timestamp=stamp), _devices("r1"), ["r1"], max_age_days=7, at=T0)
    assert not cov.attention and not cov.in_future


def test_a_naive_timestamp_is_read_as_utc():
    cov = assess("s", _meta(["r1"], timestamp="2026-02-20T10:00:00"), _devices("r1"), ["r1"], at=T0)
    assert cov.age_days == 9.08


@pytest.mark.parametrize(
    ("raw", "expected"), [("7", 7.0), ("0.5", 0.5), (" 3 ", 3.0), ("10.25", 10.25), ("1", 1.0)]
)
def test_a_valid_max_age_is_a_positive_number_of_days(raw, expected):
    assert parse_max_age(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " ",
        "0",
        "0.0",
        "-1",
        "-0.5",
        "abc",
        "1e3",
        "nan",
        "inf",
        "1,5",
        "1_0",
        "7 jours",
        "٣",
        "+7",
        ".5",
        "5.",
        None,
        7,
        7.5,
    ],
)
def test_an_invalid_max_age_is_a_usage_error(raw):
    with pytest.raises(UsageError, match="--max-age"):
        parse_max_age(raw)


def test_the_dict_for_the_json_has_every_field_and_no_secret():
    cov = assess(
        "s", _meta(["r1", "r2"], requested=["r1"]), _devices("r1"), ["r1", "r2"], max_age_days=30, at=T0
    )
    data = snapshotscope.as_dict(cov)
    assert data == {
        "snapshot": "s",
        "timestamp": TAKEN,
        "netcheck_version": "0.4.0",
        "age_days": 9.08,
        "max_age_days": 30,
        "devices": ["r1"],
        "reachable": ["r1"],
        "unreachable": [],
        "inventory": ["r1", "r2"],
        "recorded_inventory": ["r1", "r2"],
        "requested": ["r1"],
        "scope_known": True,
        "coverage": "1/2",
        "missing": [],
        "unreachable_expected": [],
        "extra": [],
        "too_old": False,
        "age_unreadable": False,
        "in_future": False,
        "attention": False,
        "reasons": [],
        "notes": ["périmètre demandé (-d) : r1"],
    }
    json.dumps(data)


def test_a_long_list_of_devices_is_truncated_not_dumped():
    names = [f"r{i:02d}" for i in range(40)]
    cov = assess("s", _meta(names), _devices("r00"), names, at=T0)
    assert "… (27 autre(s))" in cov.reasons[0] and "r39" not in cov.reasons[0]


# ------------------------------------------------------------------------------------------
# meta.json, inventaire
# ------------------------------------------------------------------------------------------


def test_save_writes_the_scope_and_without_it_the_meta_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    results = {"r1": (True, _state("r1"))}
    snapshot.save("avec", results, scope=scope_record(["r1", "r2"], ["r1"]))
    snapshot.save("sans", results)
    assert snapshot.load_meta("avec")["scope"] == {"inventory": ["r1", "r2"], "requested": ["r1"]}
    assert "scope" not in snapshot.load_meta("sans")
    assert snapshot.load_meta("avec")["netcheck_version"]


def _inventory_file(tmp_path, names=("r1", "r2")):
    path = tmp_path / "inv.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "lab": True,
                "defaults": {"device_type": "linux", "username": "u", "password": "mot-de-passe-1"},
                "routers": {
                    n: {"host": f"127.0.0.{i + 1}", "ospf_neighbors": 1} for i, n in enumerate(names)
                },
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def test_the_inventory_keeps_every_name_before_the_device_filter(tmp_path):
    path = _inventory_file(tmp_path, ("r1", "r2", "r3"))
    inv = inventory.load(["r2"], path=path, resolve_credentials=False)
    assert list(inv.routers) == ["r2"] and inv.all_names == ("r1", "r2", "r3")


def test_the_snapshot_command_records_the_full_inventory_and_the_requested_devices(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setattr(inventory, "REPO_ROOT", tmp_path)  # le message affiche le chemin relatif au dépôt
    monkeypatch.setenv("NETCHECK_KNOWN_HOSTS", str(tmp_path / "kh"))
    monkeypatch.setattr(hostkeys, "_policy", None)
    monkeypatch.setattr(
        collector, "collect_all", lambda routers, driver=None: {n: (True, _state(n)) for n in routers}
    )
    inv = _inventory_file(tmp_path, ("r1", "r2", "r3"))
    assert cli.main(["snapshot", "partiel", "-d", "r2", "-i", inv]) == 0
    assert cli.main(["snapshot", "complet", "-i", inv]) == 0
    assert snapshot.load_meta("partiel")["scope"] == {"inventory": ["r1", "r2", "r3"], "requested": ["r2"]}
    assert snapshot.load_meta("complet")["scope"] == {"inventory": ["r1", "r2", "r3"], "requested": None}
    assert sorted(snapshot.load("partiel")) == ["r2"]
    capsys.readouterr()


def test_guard_snapshots_record_the_full_inventory_too():
    source = (ROOT / "netcheck" / "cli.py").read_text(encoding="utf-8")
    assert "scope=snapshotscope.scope_record(inv.all_names, None)" in source
    assert "scope=snapshotscope.scope_record(inv.all_names, args.devices)" in source


# ------------------------------------------------------------------------------------------
# Les commandes : check --snapshot et assert --snapshot
# ------------------------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot, "SNAPSHOTS_DIR", tmp_path / "snaps")
    monkeypatch.setattr(snapshotscope, "now", lambda: T0)
    rules = tmp_path / "rules.yml"
    rules.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "hostname",
                        "description": "d",
                        "severity": "moyenne",
                        "applies_to": "all",
                        "kind": "line_present",
                        "pattern": "^hostname",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    intent = tmp_path / "intent.yml"
    intent.write_text(
        "assertions:\n  - {id: eth1-r1, description: x, device: r1, type: interface_up, interface: eth1}\n",
        encoding="utf-8",
    )
    return {"tmp": tmp_path, "rules": str(rules), "intent": str(intent), "inv": _inventory_file(tmp_path)}


def _take(name, results, scope=True, requested=None, inventory_names=("r1", "r2"), taken=TAKEN):
    snapshot.save(name, results, scope=scope_record(inventory_names, requested) if scope else None)
    meta_file = snapshot.SNAPSHOTS_DIR / name / "meta.json"
    meta = json.loads(meta_file.read_text(encoding="utf-8"))
    meta["timestamp"], meta["netcheck_version"] = taken, "0.4.0" if scope else "0.3.0"
    meta_file.write_text(json.dumps(meta), encoding="utf-8")


def _ok(*names, down=()):
    return {n: (n not in down, _state(n) if n not in down else "injoignable") for n in names}


def _check(env, capsys, *extra, snap="s"):
    out_json, out_html = env["tmp"] / "o.json", env["tmp"] / "o.html"
    for f in (out_json, out_html):
        f.unlink(missing_ok=True)
    code = cli.main(
        [
            "check",
            "--snapshot",
            snap,
            "--rules",
            env["rules"],
            "-i",
            env["inv"],
            "--json",
            str(out_json),
            "--html",
            str(out_html),
            *extra,
        ]
    )
    captured = capsys.readouterr()
    data = json.loads(out_json.read_text(encoding="utf-8")) if out_json.exists() else None
    html = out_html.read_text(encoding="utf-8") if out_html.exists() else ""
    return code, data, html, " ".join(captured.out.split()), captured.err


def _assert(env, capsys, *extra, snap="s"):
    out_json, out_html = env["tmp"] / "a.json", env["tmp"] / "a.html"
    for f in (out_json, out_html):
        f.unlink(missing_ok=True)
    code = cli.main(
        [
            "assert",
            "--snapshot",
            snap,
            "--intent",
            env["intent"],
            "-i",
            env["inv"],
            "--json",
            str(out_json),
            "--html",
            str(out_html),
            *extra,
        ]
    )
    captured = capsys.readouterr()
    data = json.loads(out_json.read_text(encoding="utf-8")) if out_json.exists() else None
    html = out_html.read_text(encoding="utf-8") if out_html.exists() else ""
    return code, data, html, " ".join(captured.out.split()), captured.err


def test_check_on_a_complete_snapshot_is_code_0_and_always_shows_the_scope_in_the_three_outputs(env, capsys):
    _take("s", _ok("r1", "r2"))
    code, data, html, out, _ = _check(env, capsys)
    assert code == 0 and data["status"] == "CONFORME"
    assert data["snapshot_scope"]["coverage"] == "2/2" and data["snapshot_scope"]["attention"] is False
    assert (
        data["snapshot_scope"]["timestamp"] == TAKEN and data["snapshot_scope"]["netcheck_version"] == "0.4.0"
    )
    assert "Snapshot 's' : pris le 2026-02-20 10:00 UTC avec netcheck 0.4.0, âge 9.1 jour(s)" in out
    assert "périmètre du snapshot : r1, r2 (2/2 de l'inventaire)" in out
    assert (
        "périmètre du snapshot : r1, r2 (2/2 de l'inventaire)" in unescape(html) and "netcheck 0.4.0" in html
    )


def test_check_on_a_partial_snapshot_not_requested_is_analyse_incomplete_code_1(env, capsys):
    _take("s", _ok("r1"))
    code, data, html, out, _ = _check(env, capsys)
    assert code == 1 and data["status"] == "ANALYSE INCOMPLÈTE" and data["compliant"] is False
    assert data["violations"] == [] and data["snapshot_scope"]["missing"] == ["r2"]
    assert "ATTENTION : équipement(s) de l'inventaire absents du snapshot" in out and "r2" in out
    assert "Conformité : ANALYSE INCOMPLÈTE" in out
    assert "ANALYSE INCOMPLÈTE" in html and "absents du snapshot" in html


def test_check_on_a_requested_partial_snapshot_stays_code_0_with_the_requested_perimeter_shown(env, capsys):
    _take("s", _ok("r2"), requested=["r2"])
    code, data, html, out, _ = _check(env, capsys)
    assert code == 0 and data["status"] == "CONFORME" and data["snapshot_scope"]["requested"] == ["r2"]
    assert "information : périmètre demandé (-d) : r2" in out and "(1/2 de l'inventaire)" in out
    assert "périmètre demandé (-d) : r2" in html


def test_check_on_an_unreachable_device_of_the_snapshot_is_code_1_twice_over(env, capsys):
    _take("s", _ok("r1", "r2", down=["r2"]))
    code, data, _, out, _ = _check(env, capsys)
    assert code == 1 and data["status"] == "ANALYSE INCOMPLÈTE"
    assert data["snapshot_scope"]["unreachable_expected"] == ["r2"]
    assert [n["cause"] for n in data["not_applicable"]] == ["unreachable"]
    assert "injoignable(s) lors du snapshot : r2" in out


def test_check_on_an_old_snapshot_without_scope_complete_is_code_0_and_says_unknown(env, capsys):
    _take("s", _ok("r1", "r2"), scope=False)
    code, data, _, out, _ = _check(env, capsys)
    assert code == 0 and data["snapshot_scope"]["scope_known"] is False
    assert "information : périmètre inconnu (snapshot sans métadonnée de périmètre), 2/2 présents" in out
    assert "netcheck 0.3.0" in out


def test_check_on_an_old_snapshot_without_scope_that_misses_a_device_is_code_1(env, capsys):
    _take("s", _ok("r1"), scope=False)
    code, data, _, out, _ = _check(env, capsys)
    assert code == 1 and data["status"] == "ANALYSE INCOMPLÈTE"
    assert "ATTENTION : périmètre inconnu (snapshot sans métadonnée de périmètre) et" in out


def test_check_on_a_snapshot_without_meta_json_is_an_unknown_perimeter_not_an_error(env, capsys):
    _take("s", _ok("r1", "r2"))
    (snapshot.SNAPSHOTS_DIR / "s" / "meta.json").unlink()
    code, data, _, out, _ = _check(env, capsys)
    assert (
        code == 0
        and data["snapshot_scope"]["scope_known"] is False
        and data["snapshot_scope"]["timestamp"] is None
    )
    assert "date inconnue" in out


def test_a_real_violation_keeps_code_2_with_a_partial_snapshot(env, capsys):
    _take("s", _ok("r1"))
    violating = env["tmp"] / "violating.yml"
    violating.write_text(
        yaml.safe_dump(
            {
                "rules": [
                    {
                        "id": "jamais",
                        "description": "d",
                        "severity": "haute",
                        "applies_to": "all",
                        "kind": "line_present",
                        "pattern": "^jamais$",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    env["rules"] = str(violating)
    code, data, _, _, _ = _check(env, capsys)
    assert code == 2 and data["status"] == "NON CONFORME" and data["snapshot_scope"]["attention"] is True


def test_max_age_makes_check_on_an_old_snapshot_code_1_with_the_age(env, capsys):
    _take("s", _ok("r1", "r2"))
    code, data, html, out, _ = _check(env, capsys, "--max-age", "7")
    assert code == 1 and data["status"] == "ANALYSE INCOMPLÈTE" and data["snapshot_scope"]["too_old"] is True
    assert "snapshot trop ancien : 9.1 jour(s) pour une limite de 7 (--max-age)" in out
    assert "snapshot trop ancien" in html
    code, data, _, _, _ = _check(env, capsys, "--max-age", "30")
    assert (
        code == 0
        and data["snapshot_scope"]["too_old"] is False
        and data["snapshot_scope"]["max_age_days"] == 30
    )


def test_without_max_age_there_is_no_default_limit_whatever_the_age(env, capsys):
    _take("s", _ok("r1", "r2"), taken="2001-01-01T00:00:00+00:00")
    code, data, _, out, _ = _check(env, capsys)
    assert code == 0 and data["snapshot_scope"]["max_age_days"] is None and "âge" in out


@pytest.mark.parametrize("value", ["abc", "0", "-3", "", "1e3", "nan", "inf", "7j"])
def test_an_invalid_max_age_is_code_3_and_writes_nothing(env, capsys, value):
    _take("s", _ok("r1", "r2"))
    code, data, _, _, err = _check(env, capsys, "--max-age", value)
    assert code == 3 and data is None and err.count("Erreur") == 1 and "--max-age" in err
    code, data, _, _, err = _assert(env, capsys, "--max-age", value)
    assert code == 3 and data is None and "--max-age" in err


def test_max_age_without_snapshot_is_code_3(env, capsys):
    out_json = env["tmp"] / "x.json"
    code = cli.main(
        ["check", "--rules", env["rules"], "-i", env["inv"], "--max-age", "7", "--json", str(out_json)]
    )
    err = capsys.readouterr().err
    assert code == 3 and "--max-age n'a de sens qu'avec --snapshot" in err and not out_json.exists()
    code = cli.main(["assert", "--intent", env["intent"], "-i", env["inv"], "--max-age", "7"])
    assert code == 3 and "--max-age n'a de sens qu'avec --snapshot" in capsys.readouterr().err


def test_max_age_with_config_dir_is_code_3(env, capsys):
    (env["tmp"] / "cfg").mkdir()
    (env["tmp"] / "cfg" / "r1.conf").write_text("hostname r1\n", encoding="utf-8")
    code = cli.main(
        [
            "check",
            "--rules",
            env["rules"],
            "-i",
            env["inv"],
            "--config-dir",
            str(env["tmp"] / "cfg"),
            "--max-age",
            "7",
        ]
    )
    assert code == 3 and "--max-age n'a de sens qu'avec --snapshot" in capsys.readouterr().err


def test_a_config_dir_check_has_no_snapshot_scope(env, capsys):
    (env["tmp"] / "cfg").mkdir()
    (env["tmp"] / "cfg" / "r1.conf").write_text("hostname r1\n", encoding="utf-8")
    out_json = env["tmp"] / "c.json"
    code = cli.main(
        [
            "check",
            "--rules",
            env["rules"],
            "-i",
            env["inv"],
            "--config-dir",
            str(env["tmp"] / "cfg"),
            "--json",
            str(out_json),
        ]
    )
    assert code == 0 and "snapshot_scope" not in json.loads(out_json.read_text(encoding="utf-8"))
    capsys.readouterr()


def test_assert_on_a_complete_snapshot_is_ok_and_shows_the_scope(env, capsys):
    _take("s", _ok("r1", "r2"))
    code, data, html, out, _ = _assert(env, capsys)
    assert code == 0 and data["verdict"] == "OK" and data["snapshot_scope"]["coverage"] == "2/2"
    assert "périmètre du snapshot : r1, r2 (2/2 de l'inventaire)" in out and "netcheck 0.4.0" in out
    assert "périmètre du snapshot : r1, r2 (2/2 de l'inventaire)" in unescape(html)


def test_assert_on_a_partial_snapshot_is_attention_even_if_every_assertion_passes(env, capsys):
    _take("s", _ok("r1"))
    code, data, html, out, _ = _assert(env, capsys)
    assert code == 1 and data["verdict"] == "ATTENTION" and [r["status"] for r in data["results"]] == ["OK"]
    assert data["snapshot_scope"]["missing"] == ["r2"]
    assert "Verdict : ATTENTION" in out and "ATTENTION : équipement(s) de l'inventaire absents" in out
    assert "ATTENTION" in html and "absents du snapshot" in html


def test_assert_on_a_requested_partial_snapshot_is_ok(env, capsys):
    _take("s", _ok("r1"), requested=["r1"])
    code, data, _, out, _ = _assert(env, capsys)
    assert code == 0 and data["verdict"] == "OK" and "information : périmètre demandé (-d) : r1" in out


def test_assert_max_age_on_an_old_snapshot_is_attention(env, capsys):
    _take("s", _ok("r1", "r2"))
    code, data, _, out, _ = _assert(env, capsys, "--max-age", "7")
    assert code == 1 and data["verdict"] == "ATTENTION" and data["snapshot_scope"]["too_old"] is True
    assert "snapshot trop ancien : 9.1 jour(s)" in out
    code, data, _, _, _ = _assert(env, capsys, "--max-age", "30")
    assert code == 0 and data["verdict"] == "OK"


def test_an_assert_failure_keeps_code_2_with_a_partial_snapshot(env, capsys):
    _take(
        "s",
        {
            "r1": (
                True,
                DeviceState(
                    name="r1",
                    host="-",
                    timestamp="t",
                    reachable=True,
                    interfaces=[Interface(name="eth1", description=None, admin_up=True, oper_up=False)],
                ),
            )
        },
    )
    code, data, _, _, _ = _assert(env, capsys)
    assert code == 2 and data["verdict"] == "ÉCHEC"


def test_a_live_check_has_no_snapshot_scope(env, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NETCHECK_KNOWN_HOSTS", str(tmp_path / "kh"))
    monkeypatch.setattr(hostkeys, "_policy", None)
    monkeypatch.setattr(
        collector, "collect_all", lambda routers, driver=None: {n: (True, _state(n)) for n in routers}
    )
    out_json = tmp_path / "live.json"
    code = cli.main(["check", "--rules", env["rules"], "-i", env["inv"], "--json", str(out_json)])
    assert code == 0 and "snapshot_scope" not in json.loads(out_json.read_text(encoding="utf-8"))
    capsys.readouterr()


def test_the_scope_lines_are_escaped_in_the_html(env, capsys):
    _take("s", _ok("r1", "r2"))
    meta_file = snapshot.SNAPSHOTS_DIR / "s" / "meta.json"
    meta = json.loads(meta_file.read_text(encoding="utf-8"))
    meta["netcheck_version"] = "<script>alert(1)</script>"
    meta_file.write_text(json.dumps(meta), encoding="utf-8")
    _, _, html, _, _ = _check(env, capsys)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
