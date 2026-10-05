"""Inventaire NetBox (phase C6.1, SPEC_v4 §6) : la LISTE des équipements vient de NetBox, rien d'autre.

netcheck LIRE dans NetBox ; il n'y écrit jamais. Exactement deux appels existent, (méthode, chemin) EXACTS :

    GET /api/status/                  (joignabilité, jeton accepté, version de NetBox)
    GET /api/dcim/devices/            (site, role, tag, status, limit, offset : validés)

Tout autre appel (une autre méthode, un autre chemin, un paramètre inconnu, une valeur douteuse) est refusé
AVANT d'ouvrir une connexion : c'est un défaut de netcheck (NetboxCallRefused), pas une erreur d'usage.

Client `urllib` : AUCUNE dépendance nouvelle. SPEC C26 prévoyait `pynetbox` en extra `[netbox]` ; il n'est pas
utilisé ici (une bibliothèque de plus, dont la surface d'écriture est large, pour deux GET). `pynetbox`
ne vit que dans le chargement du lab, hors du paquet netcheck.

Ce que NetBox fournit : le nom, l'adresse IP primaire (-> `host`) et la plateforme (-> `driver`, par la table
explicite `platforms:` de l'inventaire). Il ne fournit jamais `lab`, les identifiants, le bastion, les clés
d'hôte, `privilege_wrapper` ni les attendus (`ospf_neighbors`, `bgp_peers`) : tout cela reste dans
l'inventaire local.

Sécurité :
- jeton v2 seulement (`nbt_<clé>.<secret>`, en-tête `Authorization: Bearer`), par NETCHECK_NETBOX_TOKEN ou
  NETCHECK_NETBOX_TOKEN_FILE (mêmes règles que les mots de passe de C2 : 0600, propriétaire courant, une
  ligne) ; SecretStr, inscrit (en entier et par morceaux) dans le registre d'expurgation ; jamais en
  argument de commande ;
- TLS vérifié par défaut (nom d'hôte compris) ; `cacert:` / `--netbox-cacert` ajoute une autorité, jamais de
  désactivation ; `http://` seulement pour le bouclage ET sur un inventaire `lab: true` ;
- aucune redirection suivie, variables de proxy ignorées : le jeton ne sort que vers l'adresse configurée ;
- pagination : le lien `next` est contrôlé (même schéma, hôte, port et chemin ; mêmes filtres ; décalage qui
  avance), reconstruit à partir de paramètres validés, jamais suivi tel quel ; plafond de pages ; `count` doit
  égaler le nombre d'objets reçus.

Toute indisponibilité est une erreur d'usage (code 3) « inventaire NetBox indisponible (cause) » : aucun repli
sur le YAML, aucun résultat partiel, zéro équipement = erreur. Les messages ne reprennent jamais le texte
d'une exception de bibliothèque (un jeton pourrait y être recopié) : seulement une cause choisie ici.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from netcheck.credentials import read_secret_file
from netcheck.drivers.registry import DRIVER_REGISTRY
from netcheck.secrets import SecretStr, register_value
from netcheck.usage import UsageError

ENV_TOKEN = "NETCHECK_NETBOX_TOKEN"
ENV_TOKEN_FILE = "NETCHECK_NETBOX_TOKEN_FILE"
STATUS_PATH = "/api/status/"
DEVICES_PATH = "/api/dcim/devices/"
ALLOWED_PARAMS = {
    STATUS_PATH: frozenset(),
    DEVICES_PATH: frozenset({"site", "role", "tag", "status", "limit", "offset"}),
}
FILTER_KEYS = ("site", "role", "tag", "status")
TIMEOUT = 10  # secondes, connexion et lecture
PAGE_SIZE = 100
MAX_PAGES = 50  # 5000 équipements : au-delà, ce n'est plus un lab ni une zone d'audit raisonnable
MAX_BODY_BYTES = 16 * 1024 * 1024
BLOCK_KEYS = ("url", "site", "role", "tag", "status", "platforms", "cacert", "page_size")
# Type Netmiko par driver, comme dans les inventaires du dépôt (inventory*.yml).
DEVICE_TYPES = {"frr": "linux", "eos": "arista_eos", "srlinux": "nokia_srl"}

_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")
_VERSION = re.compile(r"[0-9][0-9A-Za-z.+_-]{0,39}")
_TOKEN_V2 = re.compile(r"nbt_([A-Za-z0-9]+)\.([A-Za-z0-9]+)")
_TOKEN_V1 = re.compile(r"[0-9a-f]{40}")
_LOOPBACK_NAMES = {"localhost"}


class NetboxConfigError(UsageError):
    """Bloc `netbox:` ou jeton invalide : message pour l'opérateur, jamais une valeur secrète."""


class NetboxUnavailable(UsageError):
    """NetBox ne peut pas fournir l'inventaire. Code 3, jamais de repli."""

    def __init__(self, cause: str):
        super().__init__(f"inventaire NetBox indisponible ({cause})")


class NetboxInventoryError(UsageError):
    """NetBox répond, mais ses équipements ne forment pas un inventaire utilisable, ou contredisent le fichier
    local. La liste de TOUS les équipements fautifs est dans le message."""


class NetboxCallRefused(PermissionError):
    """Un appel hors liste blanche a été demandé : défaut de netcheck, pas erreur d'usage (code 70)."""


# --- configuration (bloc `netbox:` de l'inventaire) ---------------------------------------------------


@dataclass(frozen=True)
class NetboxConfig:
    url: str  # schéma://hôte[:port], sans chemin
    platforms: dict
    filters: dict  # {"site": ("lab",), "status": ("active",), ...}
    cacert: str | None = None
    page_size: int | None = None  # `limit` demandé à NetBox ; None = PAGE_SIZE (lu à l'usage)

    @property
    def limit(self) -> int:
        return self.page_size or PAGE_SIZE

    @property
    def label(self) -> str:
        return urllib.parse.urlsplit(self.url).netloc

    @property
    def is_http(self) -> bool:
        return self.url.startswith("http://")


def describe_filters(filters: dict) -> str:
    return ", ".join(key + "=" + "/".join(values) for key, values in filters.items())


def _is_loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _check_url(url, lab: bool, where: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise NetboxConfigError(f"{where} : `url` manque (https://hôte:port)")
    parts = urllib.parse.urlsplit(url.strip())
    try:
        host, _port = parts.hostname, parts.port
    except ValueError:
        host = None
    if parts.scheme not in ("http", "https") or not host:
        raise NetboxConfigError(f"{where} : `url` invalide (https://hôte:port attendu)")
    if parts.username or parts.password:
        raise NetboxConfigError(
            f"{where} : des identifiants dans l'adresse sont refusés (le jeton va dans {ENV_TOKEN})"
        )
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise NetboxConfigError(f"{where} : l'adresse ne doit contenir ni chemin ni paramètre")
    if parts.scheme == "http":
        if not _is_loopback(host):
            raise NetboxConfigError(
                f"{where} : http:// n'est accepté que pour le bouclage (127.0.0.1, ::1, localhost) ; "
                "utilisez https:// pour un autre hôte"
            )
        if not lab:
            raise NetboxConfigError(
                f"{where} : http:// est réservé au lab : l'inventaire doit déclarer `lab: true` "
                "(le jeton circulerait en clair)"
            )
    return f"{parts.scheme}://{parts.netloc}"


def _slugs(key: str, value, where: str) -> tuple[str, ...]:
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or not all(isinstance(v, str) for v in values):
        raise NetboxConfigError(f"{where} : `{key}` doit être un nom (ou une liste de noms) NetBox")
    for item in values:
        if not _SLUG.fullmatch(item):
            raise NetboxConfigError(
                f"{where} : `{key}` : « {item} » n'est pas un identifiant NetBox "
                "(lettres, chiffres, « . », « - », « _ »)"
            )
    return tuple(values)


def parse_block(spec, path, lab: bool) -> NetboxConfig:
    """Valide la STRUCTURE du bloc `netbox:` (toujours, même hors ligne). Aucun réseau, aucun fichier lu."""
    where = f"Inventaire {path} : netbox"
    if not isinstance(spec, dict):
        raise NetboxConfigError(
            f"{where} doit être un objet (url, platforms, site, role, tag, status, cacert)"
        )
    unknown = sorted(set(spec) - set(BLOCK_KEYS))
    if unknown:
        raise NetboxConfigError(
            f"{where} : clé(s) inconnue(s) {unknown} (attendu : {', '.join(BLOCK_KEYS)} ; "
            "le jeton ne se met jamais dans l'inventaire)"
        )
    url = _check_url(spec.get("url"), lab, where)
    platforms = spec.get("platforms")
    if not isinstance(platforms, dict) or not platforms:
        raise NetboxConfigError(
            f"{where} : `platforms` manque : table « plateforme NetBox -> driver netcheck »"
        )
    for slug, driver in platforms.items():
        if not isinstance(slug, str) or not _SLUG.fullmatch(slug):
            raise NetboxConfigError(
                f"{where} : `platforms` : « {slug} » n'est pas un identifiant de plateforme NetBox"
            )
        if driver not in DRIVER_REGISTRY or driver not in DEVICE_TYPES:
            known = sorted(set(DRIVER_REGISTRY) & set(DEVICE_TYPES))
            raise NetboxConfigError(
                f"{where} : `platforms` : « {slug} » -> driver {driver!r} inconnu "
                f"(disponibles : {', '.join(known)})"
            )
    filters = {key: _slugs(key, spec[key], where) for key in FILTER_KEYS if key in spec}
    filters.setdefault("status", ("active",))
    cacert = spec.get("cacert")
    if cacert is not None and (not isinstance(cacert, str) or not cacert.strip()):
        raise NetboxConfigError(f"{where} : `cacert` doit être un chemin (texte)")
    page_size = spec.get("page_size")
    if page_size is not None:
        valid = isinstance(page_size, int) and not isinstance(page_size, bool) and 1 <= page_size <= 1000
        if not valid:
            raise NetboxConfigError(
                f"{where} : `page_size` doit être un entier de 1 à 1000 (reçu : {page_size!r})"
            )
    return NetboxConfig(
        url=url, platforms=dict(platforms), filters=filters, cacert=cacert, page_size=page_size
    )


def with_cacert(config: NetboxConfig, override: str | None) -> NetboxConfig:
    """`--netbox-cacert` l'emporte sur `cacert:` ; le fichier doit exister. Une autorité s'AJOUTE : le
    contrôle du certificat et du nom d'hôte reste actif."""
    chosen = override or config.cacert
    if chosen:
        resolved = Path(chosen).expanduser()
        if not resolved.is_file():
            raise NetboxConfigError(f"autorité de certification NetBox introuvable : {chosen}")
        chosen = str(resolved)
    return NetboxConfig(url=config.url, platforms=config.platforms, filters=config.filters, cacert=chosen,
                        page_size=config.page_size)


# --- jeton --------------------------------------------------------------------------------------------


def read_token(environ) -> SecretStr:
    """Jeton NetBox v2. Variable d'abord, puis fichier (0600) ; la source est portée par le SecretStr."""
    value = (environ.get(ENV_TOKEN) or "").strip()
    if value:
        source = f"variable {ENV_TOKEN}"
    elif environ.get(ENV_TOKEN_FILE):
        path = environ[ENV_TOKEN_FILE]
        value = read_secret_file(path, ENV_TOKEN_FILE).strip()
        source = f"fichier {Path(path).expanduser()} (droits 0600 vérifiés)"
    else:
        raise NetboxConfigError(
            f"jeton NetBox absent : définissez {ENV_TOKEN} ou {ENV_TOKEN_FILE} (fichier 0600)"
        )
    match = _TOKEN_V2.fullmatch(value)
    if not match:
        # Même une valeur refusée est inscrite : une exception de bibliothèque ne doit jamais la recopier.
        register_value(value)
        if _TOKEN_V1.fullmatch(value):
            raise NetboxConfigError(
                "jeton NetBox v1 refusé (format obsolète) : créez un jeton v2 (nbt_<clé>.<secret>)"
            )
        raise NetboxConfigError("jeton NetBox illisible : un jeton v2 (nbt_<clé>.<secret>) est attendu")
    for part in (value, *match.groups()):
        register_value(part)  # entier et par morceaux : une exception peut n'en recopier qu'une partie
    return SecretStr(value, source)


# --- liste blanche ------------------------------------------------------------------------------------


def _params_as_lists(params: dict) -> dict[str, list[str]]:
    return {k: [str(x) for x in (v if isinstance(v, (list, tuple)) else [v])] for k, v in params.items()}


def validate_call(method: str, path: str, params: dict) -> dict[str, list[str]]:
    """Refuse (NetboxCallRefused) tout ce qui n'est pas EXACTEMENT un des deux appels autorisés. Renvoie les
    paramètres normalisés (listes de textes)."""
    if method != "GET":
        raise NetboxCallRefused(f"appel NetBox hors liste blanche refusé : {method} {path}")
    allowed = ALLOWED_PARAMS.get(path)
    if allowed is None:
        raise NetboxCallRefused(f"appel NetBox hors liste blanche refusé : {method} {path}")
    normalised = _params_as_lists(params)
    for key, values in normalised.items():
        if key not in allowed:
            raise NetboxCallRefused(f"paramètre NetBox hors liste blanche refusé : {path}?{key}=")
        if not values:
            raise NetboxCallRefused(f"paramètre NetBox vide refusé : {key}")
        for value in values:
            if key in ("limit", "offset"):
                ok = len(values) == 1 and value.isascii() and value.isdigit() and len(value) <= 6
                ok = ok and (1 <= int(value) <= 1000 if key == "limit" else int(value) >= 0)
            else:
                ok = bool(_SLUG.fullmatch(value))
            if not ok:
                raise NetboxCallRefused(f"valeur de paramètre NetBox refusée : {key}")
    return normalised


# --- appels réseau ------------------------------------------------------------------------------------


# Raisons OpenSSL qui disent « en face, ce n'est pas du TLS » (https:// vers un port en clair), selon la
# version d'OpenSSL : mesuré, RECORD_LAYER_FAILURE avec OpenSSL 3.x récent, WRONG_VERSION_NUMBER avant.
_NOT_TLS_REASONS = frozenset(
    {"WRONG_VERSION_NUMBER", "RECORD_LAYER_FAILURE", "UNKNOWN_PROTOCOL", "HTTP_REQUEST", "WRONG_SSL_VERSION"}
)


def _tls_failure(where: str, error: BaseException) -> NetboxUnavailable:
    """Trois causes, jamais confondues, sans reprendre le texte de la bibliothèque : certificat refusé
    (l'autorité se donne par --netbox-cacert), serveur qui ne parle pas TLS sur ce port, autre échec de
    négociation."""
    if isinstance(error, ssl.SSLCertVerificationError):
        return NetboxUnavailable(
            f"{where} : certificat TLS refusé ; autorité à ajouter : --netbox-cacert ou `cacert:`"
        )
    if getattr(error, "reason", None) in _NOT_TLS_REASONS:
        return NetboxUnavailable(
            f"{where} : le serveur ne parle pas TLS sur ce port (https:// vers un service en clair ?) : "
            "vérifiez le schéma et le port de `url`"
        )
    return NetboxUnavailable(
        f"{where} : échec de la négociation TLS (ni certificat refusé, ni serveur sans TLS)"
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):  # noqa: D401 -- None : la redirection devient une HTTPError
        return None


def _build_opener(config: NetboxConfig) -> urllib.request.OpenerDirector:
    handlers: list = [urllib.request.ProxyHandler({}), _NoRedirect()]
    if not config.is_http:
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=config.cacert)))
    return urllib.request.build_opener(*handlers)


def _get(config: NetboxConfig, token: SecretStr, opener, path: str, params: dict) -> dict:
    query_params = validate_call("GET", path, params)  # AVANT toute connexion
    query = urllib.parse.urlencode([(k, v) for k in sorted(query_params) for v in query_params[k]])
    request = urllib.request.Request(
        config.url + path + (f"?{query}" if query else ""),
        method="GET",
        headers={
            "Authorization": f"Bearer {token.reveal()}",
            "Accept": "application/json",
            "User-Agent": "netcheck",
        },
    )
    where = config.label
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            body = response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as error:
        code = error.code
        if code in (401, 403):
            raise NetboxUnavailable(f"{where} : jeton refusé, HTTP {code}") from None
        if 300 <= code < 400:
            raise NetboxUnavailable(
                f"{where} : redirection refusée, HTTP {code} ; netcheck n'en suit aucune"
            ) from None
        if code == 404:
            raise NetboxUnavailable(
                f"{where} : {path} introuvable, HTTP 404 ; est-ce bien NetBox ?"
            ) from None
        if code >= 500:
            raise NetboxUnavailable(f"{where} : NetBox en erreur, HTTP {code}") from None
        raise NetboxUnavailable(f"{where} : réponse HTTP {code} inattendue") from None
    except (TimeoutError, socket.timeout):
        raise NetboxUnavailable(f"{where} : délai de {TIMEOUT} s dépassé") from None
    except ssl.SSLError as error:
        raise _tls_failure(where, error) from None
    except urllib.error.URLError as error:
        if isinstance(error.reason, ssl.SSLError):
            raise _tls_failure(where, error.reason) from None
        if isinstance(error.reason, (TimeoutError, socket.timeout)):
            raise NetboxUnavailable(f"{where} : délai de {TIMEOUT} s dépassé") from None
        raise NetboxUnavailable(f"{where} : injoignable") from None
    except OSError:
        raise NetboxUnavailable(f"{where} : injoignable ou connexion coupée") from None
    except Exception as error:  # noqa: BLE001 -- jamais le texte de la bibliothèque : il pourrait contenir le jeton
        raise NetboxUnavailable(f"{where} : erreur de communication ({type(error).__name__})") from None
    if len(body) > MAX_BODY_BYTES:
        raise NetboxUnavailable(f"{where} : réponse trop grande (plus de {MAX_BODY_BYTES // 1048576} Mio)")
    try:
        document = json.loads(body)
    except ValueError:
        raise NetboxUnavailable(f"{where} : réponse illisible (JSON attendu)") from None
    if not isinstance(document, dict):
        raise NetboxUnavailable(f"{where} : réponse inattendue (objet JSON attendu)")
    return document


def _origin(url: str) -> tuple[str, str, int]:
    parts = urllib.parse.urlsplit(url)
    default = 443 if parts.scheme == "https" else 80
    return parts.scheme.lower(), (parts.hostname or "").lower(), parts.port or default


def _next_params(config: NetboxConfig, link: str, previous_offset: int, sent: dict) -> dict[str, list[str]]:
    """Paramètres de la page suivante, tirés du lien `next` APRÈS contrôle : même schéma, hôte, port et
    chemin que le NetBox configuré, mêmes filtres que ceux envoyés, décalage strictement croissant. Le
    lien lui-même n'est jamais suivi : la requête est reconstruite par `_get`, donc ne peut partir que
    vers `config.url`."""
    if not isinstance(link, str):
        raise NetboxUnavailable(f"{config.label} : lien de pagination illisible")
    parts = urllib.parse.urlsplit(link)
    if _origin(link) != _origin(config.url) or parts.username or parts.password or parts.fragment:
        raise NetboxUnavailable(
            f"{config.label} : lien de pagination hors du NetBox configuré (refusé, jeton non envoyé)"
        )
    if parts.path != DEVICES_PATH:
        raise NetboxUnavailable(f"{config.label} : lien de pagination vers un autre chemin (refusé)")
    try:
        nxt = urllib.parse.parse_qs(parts.query, keep_blank_values=True, strict_parsing=bool(parts.query))
    except ValueError:
        raise NetboxUnavailable(f"{config.label} : lien de pagination illisible") from None
    try:
        validate_call("GET", DEVICES_PATH, nxt)
    except NetboxCallRefused:
        raise NetboxUnavailable(
            f"{config.label} : lien de pagination avec des paramètres non autorisés (refusé)"
        ) from None
    if not all(sorted(nxt.get(k, [])) == sorted(sent.get(k, [])) for k in FILTER_KEYS):
        raise NetboxUnavailable(f"{config.label} : lien de pagination avec d'autres filtres (refusé)")
    if "offset" not in nxt or int(nxt["offset"][0]) <= previous_offset:
        raise NetboxUnavailable(f"{config.label} : pagination qui n'avance pas (boucle évitée)")
    return nxt


@dataclass(frozen=True)
class Device:
    name: str
    host: str
    driver: str
    platform: str


@dataclass
class Fetched:
    version: str
    devices: list[Device]
    count: int
    pages: int


def fetch(config: NetboxConfig, token: SecretStr, opener=None) -> Fetched:
    """Les équipements de NetBox, ou une erreur (code 3). Jamais un résultat partiel."""
    where = config.label
    try:
        opener = opener or _build_opener(config)
    except (ssl.SSLError, OSError):
        raise NetboxConfigError("autorité de certification NetBox illisible (fichier PEM attendu)") from None
    status = _get(config, token, opener, STATUS_PATH, {})
    version = status.get("netbox-version")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise NetboxUnavailable(f"{where} : {STATUS_PATH} ne ressemble pas à NetBox (version absente)")
    params: dict = {
        **{k: list(v) for k, v in config.filters.items()},
        "limit": [str(config.limit)],
        "offset": ["0"],
    }
    raw: list = []
    count = None
    pages = 0
    while True:
        page = _get(config, token, opener, DEVICES_PATH, params)
        pages += 1
        results, total, link = page.get("results"), page.get("count"), page.get("next")
        if (
            not isinstance(results, list)
            or isinstance(total, bool)
            or not isinstance(total, int)
            or total < 0
        ):
            raise NetboxUnavailable(f"{where} : réponse de pagination inattendue")
        if count is None:
            count = total
        elif total != count:
            raise NetboxUnavailable(f"{where} : le total change pendant la lecture ({count} puis {total})")
        raw.extend(results)
        if not link:
            break
        if pages >= MAX_PAGES:
            raise NetboxUnavailable(
                f"{where} : plus de {MAX_PAGES} pages ({MAX_PAGES * config.limit} équipements) : "
                "affinez les filtres site, role ou tag"
            )
        params = _next_params(config, link, int(params["offset"][0]), params)
    if len(raw) != count:
        raise NetboxUnavailable(
            f"{where} : lecture incomplète ou incohérente (count={count}, objets reçus={len(raw)})"
        )
    if not raw:
        raise NetboxUnavailable(
            f"{where} : aucun équipement ne correspond aux filtres ({describe_filters(config.filters)})"
        )
    return Fetched(version=version, devices=to_devices(raw, config), count=count, pages=pages)


def to_devices(raw: list, config: NetboxConfig) -> list[Device]:
    """Équipements utilisables, ou NetboxInventoryError qui liste TOUS les équipements inutilisables."""
    faults: dict[str, list[str]] = {}
    seen: dict[str, int] = {}
    devices: list[Device] = []
    for index, item in enumerate(raw):
        label_id = item.get("id") if isinstance(item, dict) else None
        name = item.get("name") if isinstance(item, dict) else None
        usable = isinstance(name, str) and _SLUG.fullmatch(name)
        label = name if usable else f"(équipement n°{label_id if label_id is not None else index})"
        problems: list[str] = []
        if not isinstance(item, dict):
            faults[label] = ["entrée illisible"]
            continue
        if not usable:
            problems.append("nom inutilisable (lettres, chiffres, « . », « - », « _ » seulement)")
        else:
            seen[name] = seen.get(name, 0) + 1
        host = None
        primary = item.get("primary_ip")
        if not isinstance(primary, dict) or not primary.get("address"):
            problems.append("IP primaire absente")
        else:
            try:
                host = str(ipaddress.ip_interface(str(primary["address"])).ip)
            except ValueError:
                problems.append("IP primaire illisible")
        platform = item.get("platform")
        slug = platform.get("slug") if isinstance(platform, dict) else None
        if not isinstance(slug, str) or not slug:
            problems.append("plateforme absente")
            driver = None
        elif slug not in config.platforms:
            problems.append(f"plateforme « {slug} » sans correspondance dans `platforms`")
            driver = None
        else:
            driver = config.platforms[slug]
        if problems:
            faults.setdefault(label, []).extend(problems)
        elif host and driver:
            devices.append(Device(name=name, host=host, driver=driver, platform=slug))
    for name, count in seen.items():
        if count > 1:
            faults.setdefault(name, []).append("nom en double")
    if faults:
        listing = " ; ".join(f"{name} ({', '.join(why)})" for name, why in sorted(faults.items()))
        raise NetboxInventoryError(
            f"équipement(s) NetBox inutilisable(s), {len(faults)} sur {len(raw)} : {listing}"
        )
    return devices


# --- fusion avec l'inventaire local -------------------------------------------------------------------


@dataclass
class NetboxInfo:
    """Ce qu'il faut dire à l'opérateur d'une lecture NetBox (jamais de valeur secrète)."""

    url: str
    version: str
    token_source: str
    filters: dict
    count: int
    pages: int = 1
    page_size: int = PAGE_SIZE
    both: list[str] = field(default_factory=list)
    netbox_only: list[str] = field(default_factory=list)
    plain_http: bool = False  # http:// (bouclage d'un lab) : le jeton circule en clair, à dire à chaque usage

    def lines(self) -> list[str]:
        filters = describe_filters(self.filters)
        out = [
            f"Inventaire NetBox : {self.url} (NetBox {self.version}), filtres {filters}, "
            f"{self.count} équipement(s) en {self.pages} page(s) de {self.page_size} au plus "
            f"({len(self.both)} aussi dans l'inventaire local, "
            f"{len(self.netbox_only)} de NetBox seulement) ; "
            f"jeton : {self.token_source}"
        ]
        if self.netbox_only:
            out.append(
                "Attendus locaux absents pour : "
                + ", ".join(self.netbox_only)
                + " : audités avec les valeurs par défaut de l'inventaire ; leur convergence "
                "(guard --wait) est "
                "NON ÉVALUABLE (aucun attendu local), jamais comptée comme atteinte"
            )
        if self.plain_http:
            out.append(
                "Avertissement : NetBox en http:// (bouclage, inventaire `lab: true`) : "
                "le jeton circule en clair sur la boucle locale. Réservé au lab."
            )
        return out


def _same_host(local, netbox_host: str) -> bool:
    try:
        return ipaddress.ip_address(str(local)) == ipaddress.ip_address(netbox_host)
    except ValueError:
        return False  # un nom d'hôte local n'est pas démontrablement l'IP primaire de NetBox : conflit


def merge(local: dict, defaults: dict, fetched: Fetched, config: NetboxConfig, token_source: str):
    """Fusionne la liste de NetBox et les routeurs du fichier local (attributs propres à chaque routeur,
    sans les `defaults`). Renvoie ({nom: attributs}, NetboxInfo).

    - dans les deux : l'entrée locale est conservée (attendus, identifiants, bastion...) ; `host` et `driver`
      manquants viennent de NetBox ; un `host` ou un `driver` local DIFFÉRENT est un conflit (erreur, aucune
      priorité silencieuse) ;
    - NetBox seulement : audité avec les `defaults` (nom, IP primaire, driver, device_type viennent
      de NetBox) ;
    - local seulement : erreur. Tous les écarts sont listés ensemble."""
    conflicts: list[str] = []
    by_name = {d.name: d for d in fetched.devices}
    merged: dict[str, dict] = {}
    both: list[str] = []
    netbox_only: list[str] = []
    for name in sorted(by_name):
        device = by_name[name]
        if name in local:
            attrs = dict(local[name] or {})
            both.append(name)
            if "host" in attrs and not _same_host(attrs["host"], device.host):
                conflicts.append(f"{name} (adresse : NetBox {device.host}, local {attrs['host']})")
            wanted = attrs.get("driver", defaults.get("driver"))
            if wanted is not None and wanted != device.driver:
                conflicts.append(f"{name} (driver : NetBox {device.driver}, local {wanted})")
            attrs.setdefault("host", device.host)
            attrs.setdefault("driver", device.driver)
            attrs.setdefault("device_type", DEVICE_TYPES[device.driver])
        else:
            netbox_only.append(name)
            attrs = {"host": device.host, "driver": device.driver, "device_type": DEVICE_TYPES[device.driver]}
        merged[name] = attrs
    missing = sorted(set(local) - set(by_name))
    problems = []
    if conflicts:
        problems.append(
            f"conflit entre NetBox et l'inventaire local, {len(conflicts)} équipement(s) : "
            + " ; ".join(sorted(conflicts))
        )
    if missing:
        filters = describe_filters(config.filters)
        problems.append(
            f"présent(s) dans l'inventaire local mais absent(s) de NetBox (ou écartés par les filtres "
            f"{filters}) : {', '.join(missing)}"
        )
    if problems:
        raise NetboxInventoryError(" | ".join(problems))
    info = NetboxInfo(
        url=config.url,
        version=fetched.version,
        token_source=token_source,
        filters=config.filters,
        count=fetched.count,
        pages=fetched.pages,
        page_size=config.limit,
        both=both,
        netbox_only=netbox_only,
        plain_http=config.is_http,
    )
    return merged, info
