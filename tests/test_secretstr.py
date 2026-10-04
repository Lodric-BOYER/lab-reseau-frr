"""SecretStr et registre des valeurs secrètes (phase C2, netcheck/secrets.py)."""
from __future__ import annotations

import copy
import json
import pickle

import pytest
import yaml

from netcheck import secrets
from netcheck.secrets import REDACTED, SecretStr

VALUE = "S3cr3t-V4lue-9f2c"


def test_every_textual_form_hides_the_value():
    s = SecretStr(VALUE, "variable NETCHECK_PASS")
    forms = [str(s), repr(s), f"{s}", f"{s!r}", f"{s:>20}", "%s" % s, "%r" % s, "{}".format(s),  # noqa: UP031
             format(s), f"{[s]}", f"{ {'k': s} }", repr({"password": s}), str((s,)), ascii(s)]
    for text in forms:
        assert VALUE not in text, text
    assert str(s) == REDACTED
    assert "variable NETCHECK_PASS" in repr(s)   # la source se lit, la valeur jamais


def test_serialisers_refuse_a_secret():
    s = SecretStr(VALUE)
    with pytest.raises(TypeError):
        json.dumps({"password": s})
    with pytest.raises(yaml.YAMLError):
        yaml.safe_dump({"password": s})
    with pytest.raises(TypeError):
        pickle.dumps(s)
    assert json.dumps({"password": s}, default=str) == '{"password": "****"}'   # le repli usuel masque


def test_copy_never_exposes_or_duplicates_the_value():
    s = SecretStr(VALUE)
    assert copy.copy(s) is s
    assert copy.deepcopy({"k": s})["k"] is s


def test_secret_is_immutable_and_unhashable():
    s = SecretStr(VALUE)
    with pytest.raises(AttributeError):
        s.source = "autre"
    with pytest.raises(AttributeError):
        s._value = "autre"
    with pytest.raises(TypeError):
        hash(s)
    assert not hasattr(s, "__dict__")


def test_equality_accepts_str_and_secretstr():
    s = SecretStr(VALUE)
    assert s == VALUE and s == SecretStr(VALUE)
    assert s != "autre" and s != SecretStr("autre")
    assert s != 12 and (s == None) is False  # noqa: E711
    assert bool(SecretStr("x")) and not bool(SecretStr(""))


def test_reveal_is_the_only_door_and_accepts_legacy_strings():
    assert SecretStr(VALUE).reveal() == VALUE
    assert secrets.reveal(SecretStr(VALUE)) == VALUE
    assert secrets.reveal("deja-une-str") == "deja-une-str"


# -- Registre des valeurs ----------------------------------------------------------------------

def test_creating_a_secret_registers_its_value_for_redaction():
    SecretStr(VALUE)
    redacted = secrets.redact_known(f"erreur : mot de passe {VALUE} refusé")
    assert redacted == "erreur : mot de passe **** refusé"
    assert VALUE not in secrets.mask_secrets(f"a {VALUE} b")


def test_short_values_are_not_redacted_from_text():
    # « admin » effacerait « network-admin » : le seuil protège le texte, SecretStr protège la valeur.
    SecretStr("admin")
    SecretStr("netops")
    assert secrets.redact_known("role network-admin, user netops") == "role network-admin, user netops"
    assert secrets.MIN_REGISTERED_LENGTH == 8
    SecretStr("1234567")                      # 7 caractères : en dessous du seuil
    assert secrets.redact_known("1234567") == "1234567"
    SecretStr("12345678")                     # 8 : au seuil
    assert secrets.redact_known("12345678") == REDACTED


def test_longest_registered_value_is_removed_first():
    SecretStr("abcdefgh-longer-value")
    SecretStr("abcdefgh")
    out = secrets.redact_known("x abcdefgh-longer-value y abcdefgh z")
    assert out == "x **** y **** z"
    assert "longer" not in out


def test_redaction_does_not_touch_text_without_secrets_and_forget_clears_it():
    SecretStr(VALUE)
    assert secrets.redact_known("rien à cacher ici") == "rien à cacher ici"
    secrets.forget_all_values()
    assert secrets.redact_known(VALUE) == VALUE


def test_the_registry_is_thread_safe_under_concurrent_registration():
    import threading
    values = [f"valeur-secrete-{i:04d}" for i in range(200)]
    threads = [threading.Thread(target=SecretStr, args=(v,)) for v in values]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    text = secrets.redact_known(" ".join(values))
    assert all(v not in text for v in values)


def test_configuration_secret_patterns_still_work_after_the_registry():
    # Les motifs de lignes de configuration (phase A) ne changent pas.
    assert secrets.mask_secrets("neighbor 10.0.0.1 password hunter2") == "neighbor 10.0.0.1 password ****"
