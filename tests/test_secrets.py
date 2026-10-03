"""Tests du masquage des secrets dans les rapports (netcheck.secrets), demandé avant la Phase B
qui introduit de vrais secrets de lab dans les configurations (clé OSPF, mot de passe BGP, clé
de keychain SR Linux)."""
import pytest

from netcheck.secrets import mask_secrets


def test_masks_local_password_line():
    assert mask_secrets("password secret123") == "password ****"


def test_masks_enable_password_line():
    assert mask_secrets("enable password secret123") == "enable password ****"


def test_masks_bgp_neighbor_password_inline():
    line = "neighbor 172.16.34.2 password SecretBgpEnClair"
    assert mask_secrets(line) == "neighbor 172.16.34.2 password ****"


def test_masks_ospf_message_digest_key():
    line = " ip ospf message-digest-key 1 md5 CleDeLabUniquement"
    assert mask_secrets(line) == " ip ospf message-digest-key 1 md5 ****"


def test_masks_key_string():
    assert mask_secrets("key-string SecretDeKeyChain") == "key-string ****"


def test_masks_srlinux_authentication_key():
    line = "            authentication-key $aes1$ATLlcEqv7bqoT28=$quwaA3HqquakFj2MYIQ7VQ=="
    assert mask_secrets(line) == "            authentication-key ****"


def test_masks_srlinux_snmp_community_only_when_obfuscated():
    line = "                community $aes1$AWAXONh1sdFRKm8=$ZnBl8dFkI0S5SX/JImlXiA=="
    assert mask_secrets(line) == "                community ****"


def test_does_not_mask_bgp_community_route_map_value():
    # "set community" (route-map BGP) n'est PAS un secret : une étiquette de politique de
    # routage ("65001:100"), à ne jamais confondre avec la communauté SNMP obscurcie.
    line = " set community 65001:100"
    assert mask_secrets(line) == line


def test_does_not_mask_unrelated_config_text():
    text = "interface eth1\n description vers-r2\n ip address 10.1.12.1/30\nexit"
    assert mask_secrets(text) == text


def test_masks_inside_a_quoted_violation_detail():
    # Format réel de compliance._check_line_absent : "ligne interdite trouvée : '...'"
    detail = "ligne interdite trouvée : 'password secret123'"
    assert mask_secrets(detail) == "ligne interdite trouvée : 'password ****'"


def test_masks_inside_a_multiline_config_diff():
    diff = (
        "--- avant\n+++ après\n@@ -1,2 +1,3 @@\n"
        " interface eth2\n+ ip ospf message-digest-key 1 md5 CleDeLabUniquement\nexit"
    )
    masked = mask_secrets(diff)
    assert "CleDeLabUniquement" not in masked
    assert "+ ip ospf message-digest-key 1 md5 ****" in masked


def test_masks_multiple_secrets_in_the_same_text():
    text = "neighbor 172.16.34.2 password X\n ip ospf message-digest-key 1 md5 Y"
    masked = mask_secrets(text)
    assert "X" not in masked and "Y" not in masked
    assert masked.count("****") == 2


def test_does_not_touch_text_without_secrets():
    text = "voisin eBGP 172.16.34.2 sans authentification TCP-MD5 (mot de passe)"
    assert mask_secrets(text) == text


# ------------------------------------------------------------------------------------------
# Phase F : Arista EOS. Lignes RÉELLES relevées sur cEOS 4.34.8M (lab-cEOS) : EOS écrit ses
# secrets en « type 7 » (réversible) ou « sha512 ». Avant la Phase F, ces trois lignes FUYAIENT :
# le motif « md5 X » prenait le « 7 » pour la valeur et laissait le hash.
# ------------------------------------------------------------------------------------------

_EOS_ADMIN_HASH = (
    "$6$BfyQeqMEAOYfFIFW$2TgamS6RUy/xvOEvKUwPWTVOBo3/XKjMOv0OJc1jq0e5avT1XGjkSpRvtprKpxM3u/HbtqsRiDweed98L7PYS."
)
EOS_REAL_LINES = [
    ("      ip ospf message-digest-key 1 md5 7 Xa3hY/loCKnuF1M4pSYh4fkunbQLFopl",
     "      ip ospf message-digest-key 1 md5 ****", ["Xa3hY/loCKnuF1M4pSYh4fkunbQLFopl"]),
    ("   neighbor 172.16.34.1 password 7 tYPpD4pAb7WtlAdSelrqsg==",
     "   neighbor 172.16.34.1 password ****", ["tYPpD4pAb7WtlAdSelrqsg=="]),
    (f"username admin privilege 15 role network-admin secret sha512 {_EOS_ADMIN_HASH}",
     "username admin privilege 15 role network-admin secret ****",
     ["$6$", "BfyQeqMEAOYfFIFW", "2TgamS6RUy", "sha512"]),
]

# (ligne, valeurs qui ne doivent PLUS apparaître), couvrant la liste demandée et les types EOS.
EOS_SECRET_CORPUS = [
    *[(line, values) for line, _expected, values in EOS_REAL_LINES],
    ("   ip ospf authentication-key 7 AbCdEf123456ghij", ["AbCdEf123456ghij"]),
    ("   ip ospf authentication-key 0 cleclair", ["cleclair"]),
    ("enable secret sha512 $6$salty$HashHashHashHash/xyz.", ["$6$", "HashHashHashHash"]),
    ("enable secret 5 $1$abcd$EfGhIjKlMnOpQrStUvWxY.", ["$1$", "EfGhIjKlMnOp"]),
    ("enable secret 8a $8a$salt$ZZZZhashvalueZZZZ", ["ZZZZhashvalueZZZZ"]),
    ("enable secret motdepasse-enable", ["motdepasse-enable"]),
    ("username bob secret 0 bobclair", ["bobclair"]),
    ("username bob privilege 1 secret bobclair2", ["bobclair2"]),
    ("username carl privilege 15 password 7 0822455D0A16", ["0822455D0A16"]),
    ("snmp-server community SuperCommunaute ro", ["SuperCommunaute"]),
    ("snmp-server community Ecriture rw SNMP-ACL", ["Ecriture"]),
    ("tacacs-server key 7 070E234F1B1A5B", ["070E234F1B1A5B"]),
    ("tacacs-server host 10.9.9.9 key 7 070E234F1B1A5B", ["070E234F1B1A5B"]),
    ("radius-server key 7 0207165218120E", ["0207165218120E"]),
    ("radius-server host 10.8.8.8 vrf MGMT key 7 0207165218120E", ["0207165218120E"]),
    ("ntp authentication-key 1 md5 7 15060E1F1D2B3A", ["15060E1F1D2B3A"]),
    ("ntp authentication-key 2 sha1 7 0A1B2C3D4E5F", ["0A1B2C3D4E5F"]),
    ("   key-string 7 12485744150B1C", ["12485744150B1C"]),
    ("neighbor 192.0.2.7 password 7 aGVsbG8gd29ybGQ=", ["aGVsbG8gd29ybGQ="]),
    ("neighbor 192.0.2.7 password 0 cleBGPclair", ["cleBGPclair"]),
]


@pytest.mark.parametrize(("line", "expected", "_values"), EOS_REAL_LINES)
def test_masks_the_three_real_eos_lines_exactly(line, expected, _values):
    assert mask_secrets(line) == expected


@pytest.mark.parametrize(("line", "values"), EOS_SECRET_CORPUS)
def test_no_secret_value_or_hash_survives_in_the_output(line, values):
    masked = mask_secrets(line)
    for value in values:
        assert value not in masked, f"FUITE : {value!r} apparaît encore dans {masked!r}"
    assert "****" in masked


def test_the_keyword_is_kept_so_the_report_stays_readable():
    assert mask_secrets("ip ospf authentication-key 7 AbCdEf123456ghij") == (
        "ip ospf authentication-key ****")
    assert mask_secrets("enable secret sha512 $6$salty$HashHash/xyz.") == "enable secret ****"
    assert mask_secrets("snmp-server community Public ro") == "snmp-server community **** ro"
    assert mask_secrets("tacacs-server host 10.9.9.9 key 7 070E234F") == (
        "tacacs-server host 10.9.9.9 key ****")
    assert mask_secrets("ntp authentication-key 1 md5 7 15060E1F") == "ntp authentication-key 1 md5 ****"


def test_a_whole_eos_running_config_leaks_nothing():
    secrets_in_config = [v for _line, values in EOS_SECRET_CORPUS for v in values if len(v) > 8]
    config = "\n".join(line for line, _values in EOS_SECRET_CORPUS)
    masked = mask_secrets("hostname r4\n" + config + "\nip routing\n")
    assert not [v for v in secrets_in_config if v in masked]
    assert "hostname r4" in masked and "ip routing" in masked


@pytest.mark.parametrize("line", [line for line, _e, _v in EOS_REAL_LINES])
def test_masking_is_idempotent(line):
    once = mask_secrets(line)
    assert mask_secrets(once) == once


@pytest.mark.parametrize("text", [
    # EOS / FRR : ce qui ressemble à un mot-clé mais n'en est pas un
    "   neighbor 172.16.34.1 maximum-routes 10",
    "   neighbor 172.16.34.1 ttl maximum-hops 1",
    "   ip ospf authentication message-digest",
    "   ip ospf network point-to-point",
    "key chain MA-CHAINE",                              # nom de key chain : pas un secret
    "snmp-server location Paris",
    "ip community-list standard COM1 permit 65001:100",
    " set community 65001:100",
    " match community 65001:100",
    "interface Management0\n   ip address 172.20.22.14/24",
    "tacacs-server timeout 5",
    "radius-server retransmit 3",
    "ntp server 192.0.2.1",
    "username admin privilege 15 role network-admin",   # sans secret
    # phrases françaises de netcheck
    "le secret en clair est interdit",
    "voisin eBGP sans mot de passe md5 configuré",
    "clé md5 absente sur l'interface",
])
def test_does_not_over_mask_non_secrets_and_prose(text):
    assert mask_secrets(text) == text


def test_frr_and_srlinux_masking_is_unchanged():
    # Non-régression : exactement les sorties d'avant la Phase F.
    assert mask_secrets("neighbor 172.16.34.1 password lab-bgp-r3r4") == (
        "neighbor 172.16.34.1 password ****")
    assert mask_secrets(" ip ospf message-digest-key 1 md5 lab-ospf-r4r5") == (
        " ip ospf message-digest-key 1 md5 ****")
    assert mask_secrets("authentication-key $aes1$ATLlcEqv7bqoT28=$quwaA3HqquakFj2MYIQ7VQ==") == (
        "authentication-key ****")
    assert mask_secrets("community $aes1$AWAXONh1sdFRKm8=$ZnBl8dFkI0S5SX/JImlXiA==") == "community ****"
