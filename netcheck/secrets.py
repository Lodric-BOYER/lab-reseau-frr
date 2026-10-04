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

import hmac
import re
import threading

# Un motif par famille de secret rencontrée dans les configurations FRR et SR Linux de ce
# projet (Phase A/B). Chaque motif capture le mot-clé (groupe 1) et remplace tout le motif par
# "<mot-clé> ****" -- jamais un simple "\1****" qui recollerait au mot-clé sans espace.
# Valeur d'un secret : tout sauf un espace ou un guillemet -- exclure les guillemets évite de
# happer la ponctuation d'un message qui cite la ligne entre apostrophes (ex.
# compliance._check_line_absent : "ligne interdite trouvée : 'password secret123'").
_VALUE = r"""[^\s'"]+"""

# Phase F (3e constructeur, Arista EOS) : une règle GÉNÉRIQUE plutôt qu'un cas par ligne. Après un
# mot-clé, un TYPE facultatif puis la valeur ; tout est masqué sauf le mot-clé. EOS écrit ses
# secrets en « type 7 » (réversible), « sha512 » ou « 5 », et le hash ne ressemble à rien de connu :
#   ip ospf message-digest-key 1 md5 7 Xa3hY/lo...      neighbor 172.16.34.1 password 7 tYPpD4...==
#   username admin ... secret sha512 $6$salt$hash...
# Un motif écrit pour « md5 X » prenait le « 7 » pour la valeur et LAISSAIT FUIR le hash (constaté
# sur les trois lignes réelles de cEOS 4.34.8M). Les types ci-dessous sont ceux qu'EOS écrit.
_TYPE = r"(?:(?:0|5|7|8a|9|sha512|sha256|scrypt)\s+)?"
_STRICT_TYPE = r"(?:0|5|7|8a|9|sha512|sha256|scrypt)"
_DIGEST_ALGO = r"(?:md5|sha1|sha256|sha384|sha512)"

_SECRET_PATTERNS = [
    # Mot de passe VTY/enable local ("password X"), TCP-MD5 d'un voisin BGP ("neighbor <ip>
    # password X", FRR) et, sur EOS, "neighbor <ip> password 7 Y", "username U ... password 7 Y".
    re.compile(rf"\b((?:enable )?password)\s+{_TYPE}{_VALUE}"),
    # Clé OSPF message-digest ("ip ospf message-digest-key <id> md5 X", FRR et EOS) et clé NTP
    # ("ntp authentication-key <id> md5 7 X", EOS) : numéro de clé, algorithme, type, valeur.
    re.compile(rf"\b((?:message-digest-key|authentication-key)\s+\d+\s+{_DIGEST_ALGO})\s+{_TYPE}{_VALUE}"),
    # "key-string X" d'un key chain (FRR, EOS "key-string 7 X").
    re.compile(rf"\b(key-string)\s+{_TYPE}{_VALUE}"),
    # SR Linux : clé d'une keychain ("authentication-key X", déjà obscurcie en "$aes1$..." par
    # la plateforme elle-même -- voir la vérification en direct dans le rapport de phase --
    # mais masquée quand même : ce n'est pas un chiffrement documenté comme sûr pour un rapport
    # public, seulement un stockage local protégé). EOS : "ip ospf authentication-key 7 X".
    # Le lookahead laisse au motif précédent les formes "authentication-key <id> md5 ..." (sinon
    # le numéro de clé serait masqué à son tour).
    re.compile(rf"\b(authentication-key)\s+(?!\d+\s+{_DIGEST_ALGO}\b){_TYPE}{_VALUE}"),
    # EOS : "secret <type> <hash>" (username, enable). Le type est toujours écrit dans une
    # running-config ; une forme SANS type ("enable secret motdepasse", "username u secret x"),
    # possible dans un script de changement, n'est masquée que dans un contexte de configuration
    # (ligne qui commence par enable / username) : le mot « secret » d'une phrase française
    # ("secret en clair") ne doit pas être mangé.
    re.compile(rf"\b(secret)\s+{_STRICT_TYPE}\s+{_VALUE}"),
    re.compile(rf"(?m)^([ \t+\-]*(?:enable\s+|username\b[^\n]*?\s)secret)\s+{_VALUE}"),
    # EOS : "tacacs-server [host <ip>] key 7 X", "radius-server [host <ip>] key 7 X".
    re.compile(rf"\b((?:tacacs|radius)-server\b[^\n]*?\bkey)\s+{_TYPE}{_VALUE}"),
    # EOS : communauté SNMP en clair ("snmp-server community X ro") -- un secret d'accès, à ne
    # jamais confondre avec "set community" / "match community" des route-maps BGP.
    re.compile(rf"\b(snmp-server community)\s+{_VALUE}"),
    # SR Linux : communauté SNMP ("community $aes1$..."), UNIQUEMENT sous cette forme
    # obscurcie précise -- jamais un "set community"/"match community" de route-map BGP, qui
    # n'est pas un secret mais une étiquette de politique de routage (valeur "65001:100", pas
    # "$aes1$..."). Cette commande n'est pas collectée par netcheck aujourd'hui (voir
    # drivers/srlinux.py, "show system authentication"/"show system banner" seulement) ; le
    # motif reste prêt si cette section est collectée un jour.
    re.compile(rf"\b(community)\s+\$aes1\${_VALUE}"),
]


# Phase E : une URL de webhook EST un secret (quiconque la connaît peut poster dans le salon).
# Formats vérifiés dans la documentation de chaque service (Discord, Slack, Teams/Workflows) ;
# l'URL configurée est de plus remplacée à l'identique par webhook.redact(), quel que soit son
# format. Le masquage s'applique ici à tout texte destiné à un rapport ou à un message.
_URL_CHARS = r"""[^\s'"<>]+"""
_WEBHOOK_URL_PATTERNS = [
    re.compile(rf"https://(?:[\w-]+\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/{_URL_CHARS}"),
    re.compile(rf"https://hooks\.slack\.com/{_URL_CHARS}"),
    # Teams (Workflows) : le port est facultatif, mais fréquent (« :443 ») dans les URL Power Automate.
    re.compile(
        rf"""https://[^\s/'"<>]*(?:webhook\.office\.com|logic\.azure\.com|powerplatform\.com)"""
        rf"(?::\d+)?/{_URL_CHARS}"),
]
WEBHOOK_URL_MASK = "<url de webhook masquée>"


# Phase C2 : les secrets d'ACCÈS (mot de passe d'un équipement, phrase de passe d'une clé, jeton) ne sont
# pas des lignes de configuration : aucun motif ne les reconnaît. Ils sont donc portés par SecretStr, et
# leur valeur est inscrite dans un registre : tout texte publié (rapport, alerte, message d'erreur) en est
# débarrassé, même si une bibliothèque a recopié le mot de passe dans son message d'exception.
# Seuil : une valeur plus courte que MIN_REGISTERED_LENGTH n'est pas retirée des textes (« admin »,
# « netops » effaceraient ces mots partout, y compris dans « network-admin ») ; SecretStr la protège.
MIN_REGISTERED_LENGTH = 8
REDACTED = "****"
_known_values: set[str] = set()
_known_lock = threading.Lock()


def register_value(value: str) -> None:
    """Inscrit une valeur secrète : redact_known() la retirera de tout texte. Sans effet si trop courte."""
    if len(value) >= MIN_REGISTERED_LENGTH:
        with _known_lock:
            _known_values.add(value)


def forget_all_values() -> None:
    """Vide le registre (tests uniquement : un processus netcheck n'oublie jamais un secret)."""
    with _known_lock:
        _known_values.clear()


def redact_known(text: str) -> str:
    """Remplace chaque valeur inscrite par '****' (la plus longue d'abord : l'une peut contenir l'autre)."""
    with _known_lock:
        values = sorted(_known_values, key=len, reverse=True)
    for value in values:
        text = text.replace(value, REDACTED)
    return text


class SecretStr:
    """Une valeur secrète qui ne s'affiche, ne se formate et ne se sérialise jamais par accident.

    `str()`, `repr()`, f-string, `json.dumps`, `yaml.dump`, `pickle` et `copy` ne donnent jamais la valeur :
    la seule porte est `.reveal()`, appelée en un seul endroit (l'ouverture de la connexion). `source` dit
    d'où vient le secret (« variable NETCHECK_PASS », « fichier /chemin », « inventaire »), pas sa valeur."""
    __slots__ = ("_value", "source")

    def __init__(self, value: str, source: str = "?"):
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "source", source)
        register_value(value)

    def reveal(self) -> str:
        return self._value

    @property
    def redactable(self) -> bool:
        """Vrai si la valeur est assez longue (MIN_REGISTERED_LENGTH) pour être retirée des textes par valeur.
        Un booléen : ni la longueur ni la valeur ne sortent d'ici."""
        return len(self._value) >= MIN_REGISTERED_LENGTH

    def __setattr__(self, name, value):
        raise AttributeError("SecretStr est immuable")

    def __repr__(self) -> str:
        return f"SecretStr({REDACTED}, source={self.source!r})"

    def __str__(self) -> str:
        return REDACTED

    def __format__(self, spec: str) -> str:
        return format(REDACTED, spec)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other) -> bool:
        # Comparaison à temps constant ; accepte une str (tests et anciens appelants comparent des str).
        if isinstance(other, SecretStr):
            other = other._value
        if not isinstance(other, str):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other.encode())

    __hash__ = None  # type: ignore[assignment]  # modifiable par comparaison : jamais une clé de dictionnaire

    def __reduce__(self):
        raise TypeError("SecretStr ne se sérialise pas (pickle, copy)")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


def reveal(value) -> str:
    """La valeur en clair d'un SecretStr, ou la str telle quelle (anciens appelants et tests)."""
    return value.reveal() if isinstance(value, SecretStr) else value


def mask_secrets(text: str) -> str:
    """Remplace la valeur de chaque secret reconnu par '****', partout où le motif apparaît
    (une ligne de config isolée, ou un bloc plus large comme un diff unifié multi-lignes)."""
    text = redact_known(text)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda m: f"{m.group(1)} ****", text)
    for pattern in _WEBHOOK_URL_PATTERNS:
        text = pattern.sub(WEBHOOK_URL_MASK, text)
    return text
