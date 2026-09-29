"""Tests du masquage des secrets dans les rapports (netcheck.secrets), demandé avant la Phase B
qui introduit de vrais secrets de lab dans les configurations (clé OSPF, mot de passe BGP, clé
de keychain SR Linux)."""
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
