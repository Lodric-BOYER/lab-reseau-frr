"""Masquage des secrets dans les rapports (terminal, JSON, HTML) -- Phase A (suite), avant la
Phase B qui va introduire de vrais secrets de lab dans les configurations (clé OSPF, mot de
passe BGP, clé de keychain SR Linux).

Portée volontairement limitée aux RAPPORTS (report.py), jamais au modèle ni aux snapshots : un
snapshot reste une donnée brute, déjà exclue de Git (C4) -- masquer à cet endroit casserait un
usage hors ligne légitime (`check --snapshot`, comparaison manuelle). Seul ce qui est destiné à
être lu, partagé ou publié (docs/audit/) passe par `mask_secrets`.

Chaque motif ne masque que la VALEUR du secret, jamais le mot-clé qui l'introduit : le rapport
reste lisible ("password ****") sans jamais exposer la valeur réelle.
"""
from __future__ import annotations

import re

# Un motif par famille de secret rencontrée dans les configurations FRR et SR Linux de ce
# projet (Phase A/B). Chaque motif capture le mot-clé (groupe 1) et remplace tout le motif par
# "<mot-clé> ****" -- jamais un simple "\1****" qui recollerait au mot-clé sans espace.
# Valeur d'un secret : tout sauf un espace ou un guillemet -- exclure les guillemets évite de
# happer la ponctuation d'un message qui cite la ligne entre apostrophes (ex.
# compliance._check_line_absent : "ligne interdite trouvée : 'password secret123'").
_VALUE = r"""[^\s'"]+"""

_SECRET_PATTERNS = [
    # FRR : mot de passe VTY/enable local ("password X", "enable password X") et mot de passe
    # TCP-MD5 d'un voisin BGP ("neighbor <ip> password X") -- même mot-clé final "password",
    # un seul motif suffit pour les deux.
    re.compile(rf"\b((?:enable )?password)\s+{_VALUE}"),
    # FRR : clé OSPF message-digest ("ip ospf message-digest-key <id> md5 X").
    re.compile(rf"\b(message-digest-key \d+ md5)\s+{_VALUE}"),
    # FRR : "key-string X" d'un key chain générique (RIP/EIGRP -- non utilisé dans ce lab
    # aujourd'hui, mais une commande FRR réelle qui porte un secret).
    re.compile(rf"\b(key-string)\s+{_VALUE}"),
    # SR Linux : clé d'une keychain ("authentication-key X", déjà obscurcie en "$aes1$..." par
    # la plateforme elle-même -- voir la vérification en direct dans le rapport de phase --
    # mais masquée quand même : ce n'est pas un chiffrement documenté comme sûr pour un rapport
    # public, seulement un stockage local protégé).
    re.compile(rf"\b(authentication-key)\s+{_VALUE}"),
    # SR Linux : communauté SNMP ("community $aes1$..."), UNIQUEMENT sous cette forme
    # obscurcie précise -- jamais un "set community"/"match community" de route-map BGP, qui
    # n'est pas un secret mais une étiquette de politique de routage (valeur "65001:100", pas
    # "$aes1$..."). Cette commande n'est pas collectée par netcheck aujourd'hui (voir
    # drivers/srlinux.py, "show system authentication"/"show system banner" seulement) ; le
    # motif reste prêt si cette section est collectée un jour.
    re.compile(rf"\b(community)\s+\$aes1\${_VALUE}"),
]


def mask_secrets(text: str) -> str:
    """Remplace la valeur de chaque secret reconnu par '****', partout où le motif apparaît
    (une ligne de config isolée, ou un bloc plus large comme un diff unifié multi-lignes)."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)} ****", text)
    return text
