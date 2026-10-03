"""Analyse structurelle d'une configuration d'équipement (SPEC_v4, Phase A, étape A2).

Trois syntaxes, un seul résultat (`ParsedConfig`) :
  - `parse_indented` : blocs par indentation (FRR, EOS : « router bgp 65001 » puis lignes indentées) ;
  - `parse_braces`   : blocs entre accolades (SR Linux, sortie « info from running ») ;
  - `parse_set`      : lignes « set / chemin... » (SR Linux, fichier de démarrage), sans arbre : sans le
                       schéma de l'équipement on ne sait pas quels mots sont des clés, donc on garde
                       le chemin tel quel.
Les trois offrent la même vue plate (`ParsedConfig.flat` : un chemin de mots par ligne feuille), ce
qui permet d'écrire une règle une seule fois pour les deux syntaxes d'un même équipement.

Ce module est NEUTRE : il ne connaît aucun mot-clé constructeur (ni voisin, ni interface, ni
protocole). Tout ce qui est propre à un équipement (où commence une bannière, quel préfixe racine
donner à une section) est passé en paramètre par son driver.

Exigence de la Phase A : une ligne que l'analyse ne sait pas classer n'est JAMAIS ignorée en
silence. Chaque ligne de la source tombe dans exactement une classe (`counts` : blank, comment,
node, close, raw, skipped) et tout ce qui est douteux produit un `ParseWarning` :
  - `kept=False` : la ligne n'a pas pu être convertie et n'est PAS dans le résultat (classe skipped) ;
  - `kept=True`  : la ligne est dans le résultat mais ambiguë (dédentation partielle...) ;
  - `blocking=True` : l'avertissement empêche l'audit de conclure « conforme », même si la ligne est
    conservée (ex. une accolade fermante manque : la place de ce qui suit est incertaine). Par défaut,
    une ligne non conservée bloque et une ligne conservée ne bloque pas.
Le texte d'un avertissement passe par `mask_secrets` à sa création : une ligne qui porte un secret
ne fuit pas dans un rapport.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from netcheck.secrets import mask_secrets

Pattern = str | re.Pattern
ANY = "*"             # dans un motif : n'importe quel mot, un seul
_MAX_TEXT = 100       # longueur maximale de la ligne recopiée dans un avertissement
_TAB_WIDTH = 8


def _word_matches(word: str, pattern: Pattern) -> bool:
    if isinstance(pattern, re.Pattern):
        return pattern.fullmatch(word) is not None
    return pattern == ANY or pattern == word


def _prefix_matches(words: tuple[str, ...], pattern: tuple[Pattern, ...]) -> bool:
    """Vrai si `words` COMMENCE par le motif (« * » = n'importe quel mot, regex = correspondance
    complète du mot). Un motif plus court que les mots correspond (préfixe)."""
    return len(words) >= len(pattern) and all(_word_matches(w, p) for w, p in zip(words, pattern))


@dataclass(frozen=True)
class ParseWarning:
    line: int
    text: str         # la ligne, tronquée et secrets masqués
    reason: str
    kept: bool        # True : ligne conservée mais ambiguë ; False : ligne NON convertie
    blocking: bool | None = None   # None : bloque si et seulement si la ligne n'est pas conservée

    @property
    def blocks_verdict(self) -> bool:
        """Vrai si l'audit ne peut pas conclure « conforme » à cause de cette ligne."""
        return (not self.kept) if self.blocking is None else self.blocking

    def __str__(self) -> str:
        state = "conservée" if self.kept else "non convertie"
        if self.kept and self.blocks_verdict:
            state = "conservée, structure incertaine"
        return f"ligne {self.line} ({state}) : {self.reason} : {self.text}"


@dataclass(frozen=True)
class FlatLine:
    """Une ligne feuille sous forme de chemin : (mots depuis la racine, numéro de ligne source)."""
    path: tuple[str, ...]
    line: int


@dataclass(eq=False)
class ConfigNode:
    words: tuple[str, ...]
    text: str                                   # la ligne sans indentation ni accolade ouvrante
    line: int
    children: list[ConfigNode] = field(default_factory=list)
    parent: ConfigNode | None = field(default=None, repr=False)
    raw: list[str] = field(default_factory=list)  # lignes brutes d'un bloc brut déclaré

    def walk(self) -> Iterator[ConfigNode]:
        yield self
        for child in self.children:
            yield from child.walk()

    def children_matching(self, *pattern: Pattern) -> list[ConfigNode]:
        return [c for c in self.children if _prefix_matches(c.words, pattern)]

    def path(self) -> tuple[str, ...]:
        words: list[str] = []
        node: ConfigNode | None = self
        while node is not None and node.parent is not None:
            words = list(node.words) + words
            node = node.parent
        return tuple(words)


@dataclass
class ParsedConfig:
    syntax: str                                  # "indent", "braces" ou "set"
    lines_total: int
    counts: dict[str, int]
    warnings: list[ParseWarning]
    root: ConfigNode | None = None               # None pour la syntaxe « set » (pas d'arbre)
    prefix: tuple[str, ...] = ()
    _flat: list[FlatLine] | None = field(default=None, repr=False)

    @property
    def flat(self) -> list[FlatLine]:
        if self._flat is None:
            self._flat = list(_flatten(self.root, self.prefix)) if self.root is not None else []
        return self._flat

    def select(self, *pattern: Pattern) -> list[FlatLine]:
        """Lignes feuilles dont le chemin COMMENCE par le motif (« * » = un mot quelconque)."""
        return [f for f in self.flat if _prefix_matches(f.path, pattern)]

    def top(self, *pattern: Pattern) -> list[ConfigNode]:
        """Noeuds de premier niveau (arbres seulement) dont les mots commencent par le motif."""
        if self.root is None:
            return []
        return self.root.children_matching(*pattern)

    def unclassified(self) -> list[ParseWarning]:
        """Lignes de la source qui ne sont PAS dans le résultat."""
        return [w for w in self.warnings if not w.kept]

    def reject(self, node: ConfigNode, reason: str) -> None:
        """Retire ce noeud et ses descendants du résultat et les signale comme lignes NON conservées.

        C'est le moyen, pour un driver qui connaît la syntaxe de son équipement, de dire « cette ligne
        est à une place où je ne peux pas la lire correctement » (ex. une sous-commande que l'équipement
        appliquerait au bloc ouvert mais que l'indentation ne rattache à rien) : elle ne reste pas dans
        l'arbre, où une règle la prendrait pour une commande de premier niveau, et l'audit en est averti."""
        if node.parent is None:
            raise ValueError("le noeud racine ne peut pas être rejeté")
        node.parent.children.remove(node)
        for removed in node.walk():
            self.counts["node"] -= 1
            self.counts["skipped"] += 1
            _warn(self.warnings, removed.line, removed.text, reason, False)
        self.warnings.sort(key=lambda w: w.line)
        self._flat = None


def _flatten(root: ConfigNode, prefix: tuple[str, ...]) -> Iterator[FlatLine]:
    """Un chemin par noeud sans enfant (une ligne feuille, ou un bloc vide comme `address X {}`) ;
    un noeud qui porte des lignes brutes compte comme une feuille."""
    def visit(node: ConfigNode, path: tuple[str, ...]) -> Iterator[FlatLine]:
        here = path + node.words
        if not node.children:
            yield FlatLine(here, node.line)
        for child in node.children:
            yield from visit(child, here)

    for child in root.children:
        yield from visit(child, prefix)


# ------------------------------------------------------------------------------------------
# Découpage d'une ligne en mots (guillemets doubles reconnus)
# ------------------------------------------------------------------------------------------

def _tokenize(text: str) -> tuple[list[tuple[str, bool]], bool]:
    """([(mot, était_entre_guillemets)], guillemet_non_fermé). Un guillemet n'ouvre une chaîne qu'en
    début de mot ; \\" et \\\\ sont reconnus dans une chaîne. Guillemet non fermé : le reste de la
    ligne devient un mot simple et le drapeau est levé (la ligne est signalée par l'appelant)."""
    tokens: list[tuple[str, bool]] = []
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace():
            i += 1
        elif text[i] == '"':
            buf: list[str] = []
            j, closed = i + 1, False
            while j < n:
                if text[j] == "\\" and j + 1 < n and text[j + 1] in '"\\':
                    buf.append(text[j + 1])
                    j += 2
                elif text[j] == '"':
                    closed = True
                    break
                else:
                    buf.append(text[j])
                    j += 1
            if not closed:
                tokens.append((text[i:], False))
                return tokens, True
            tokens.append(("".join(buf), True))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace():
                j += 1
            tokens.append((text[i:j], False))
            i = j
    return tokens, False


def make_warning(line: int, raw: str, reason: str, kept: bool, blocking: bool | None = None) -> ParseWarning:
    """Un avertissement dont le texte est tronqué et dont les secrets sont masqués."""
    shown = raw.strip()
    if len(shown) > _MAX_TEXT:
        shown = shown[:_MAX_TEXT] + "..."
    return ParseWarning(line, mask_secrets(shown), reason, kept, blocking)


def _warn(warnings: list[ParseWarning], line: int, raw: str, reason: str, kept: bool,
          blocking: bool | None = None) -> None:
    warnings.append(make_warning(line, raw, reason, kept, blocking))


def _new_counts() -> dict[str, int]:
    return {"blank": 0, "comment": 0, "node": 0, "close": 0, "raw": 0, "skipped": 0}


# ------------------------------------------------------------------------------------------
# Syntaxe par indentation
# ------------------------------------------------------------------------------------------

def parse_indented(
    text: str,
    *,
    comment_prefixes: tuple[str, ...] = ("!",),
    raw_blocks: tuple[tuple[str, str], ...] = (),
) -> ParsedConfig:
    """Blocs par indentation. Un commentaire ne modifie jamais la structure (un « ! » peut se
    trouver à n'importe quelle profondeur). `raw_blocks` : [(regex de début, regex de fin)] sur la
    ligne sans indentation ; les lignes entre les deux sont du texte libre (ex. une bannière),
    conservé dans `node.raw` sans être analysé. Une tabulation compte pour 8 colonnes (signalé)."""
    lines = text.splitlines()
    counts, warnings = _new_counts(), []
    root = ConfigNode((), "", 0)
    stack: list[tuple[int, ConfigNode]] = [(-1, root)]
    raw_node: tuple[ConfigNode, re.Pattern] | None = None
    compiled = [(re.compile(s), re.compile(e)) for s, e in raw_blocks]

    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if raw_node is not None:
            counts["raw"] += 1
            if raw_node[1].fullmatch(stripped):
                raw_node = None
            else:
                raw_node[0].raw.append(line)
            continue
        if not stripped:
            counts["blank"] += 1
            continue
        if stripped.startswith(comment_prefixes):
            counts["comment"] += 1
            continue

        leading = line[: len(line) - len(line.lstrip())]
        if "\t" in leading:
            _warn(warnings, number, line,
                  f"tabulation dans l'indentation (comptée pour {_TAB_WIDTH} colonnes)", True)
        indent = len(leading.expandtabs(_TAB_WIDTH))
        # La colonne 0 est toujours un niveau valide (la racine), même sous une ligne mal indentée.
        if indent < stack[-1][0] and indent not in {0, *(level for level, _ in stack)}:
            _warn(warnings, number, line,
                  "dédentation partielle : ne correspond à aucun niveau ouvert", True)
        while stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if parent is root and indent > 0:
            _warn(warnings, number, line, "ligne indentée sans bloc parent", True)

        tokens, unclosed = _tokenize(stripped)
        if unclosed:
            _warn(warnings, number, line, "guillemet non fermé", True)
        words = tuple(t for t, _ in tokens)
        if words and (words[-1] == "{" or words[0] == "}"):
            _warn(warnings, number, line,
                  "accolade dans une configuration par indentation : mauvaise syntaxe ?", True)
        node = ConfigNode(words, stripped, number, parent=parent)
        parent.children.append(node)
        stack.append((indent, node))
        counts["node"] += 1
        for start, end in compiled:
            if start.fullmatch(stripped):
                raw_node = (node, end)
                break

    if raw_node is not None:
        _warn(warnings, raw_node[0].line, raw_node[0].text, "bloc brut jamais terminé", True)
    return ParsedConfig("indent", len(lines), counts, warnings, root=root)


# ------------------------------------------------------------------------------------------
# Syntaxe à accolades
# ------------------------------------------------------------------------------------------

def parse_braces(
    text: str,
    *,
    prefix: tuple[str, ...] = (),
    comment_prefixes: tuple[str, ...] = ("#",),
) -> ParsedConfig:
    """Blocs `entête {` ... `}`. `prefix` : mots du chemin sous lequel la sortie a été demandée (une
    commande « info » affiche le contenu RELATIVEMENT à son chemin) ; il préfixe la vue plate.
    Formes acceptées : entête se terminant par « { », « } » seul, ligne feuille. Toute autre forme
    (accolade au milieu d'une ligne, `{ }` sur une ligne, `}` sans bloc ouvert) est signalée et
    non convertie : seules les formes réellement observées sont reconnues, aucune n'est devinée. Un bloc
    jamais refermé est conservé mais bloque le verdict (voir la fin de la fonction)."""
    lines = text.splitlines()
    counts, warnings = _new_counts(), []
    root = ConfigNode((), "", 0)
    stack: list[ConfigNode] = [root]

    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            counts["blank"] += 1
            continue
        if stripped.startswith(comment_prefixes):
            counts["comment"] += 1
            continue
        tokens, unclosed = _tokenize(stripped)
        if unclosed:
            counts["skipped"] += 1
            _warn(warnings, number, line, "guillemet non fermé", False)
            continue

        words = tuple(t for t, _ in tokens)
        braces = [i for i, (t, quoted) in enumerate(tokens) if not quoted and ("{" in t or "}" in t)]
        if tokens == [("}", False)]:
            if len(stack) == 1:
                counts["skipped"] += 1
                _warn(warnings, number, line, "accolade fermante sans bloc ouvert", False)
            else:
                stack.pop()
                counts["close"] += 1
            continue
        is_open = len(tokens) > 1 and tokens[-1] == ("{", False) and braces == [len(tokens) - 1]
        if braces and not is_open:
            counts["skipped"] += 1
            _warn(warnings, number, line, "accolade dans une position non reconnue", False)
            continue

        header = is_open
        node_words = words[:-1] if header else words
        node_text = stripped[:-1].rstrip() if header else stripped
        node = ConfigNode(node_words, node_text, number, parent=stack[-1])
        stack[-1].children.append(node)
        counts["node"] += 1
        if header:
            stack.append(node)

    # Une accolade fermante manque : la place de TOUT ce qui suit l'entête est incertaine (une ligne peut
    # être lue sous le mauvais bloc, et cacher une violation). Les lignes restent dans le résultat, pour
    # que les règles continuent de trouver ce qu'elles trouvent, mais l'audit ne peut plus conclure
    # « conforme » (blocking). Les sorties d'un équipement sont toujours équilibrées.
    for node in stack[1:]:
        _warn(warnings, node.line, node.text,
              "bloc ouvert jamais fermé : l'accolade fermante manque, la place de ce qui suit est incertaine",
              True, blocking=True)
    return ParsedConfig("braces", len(lines), counts, warnings, root=root, prefix=prefix)


# ------------------------------------------------------------------------------------------
# Syntaxe « set / chemin »
# ------------------------------------------------------------------------------------------

_SET_RE = re.compile(r"set\s+/(?:\s+(?P<path>.*)|(?P<glued>\S.*))?")


def parse_set(text: str, *, comment_prefixes: tuple[str, ...] = ("#",)) -> ParsedConfig:
    """Lignes `set / mot mot ...`, chemin absolu. Toute autre ligne (`delete`, `commit`, un `set` sans
    chemin absolu, un guillemet non fermé...) est SIGNALÉE et non convertie : un fichier de démarrage
    qui fait autre chose que poser des valeurs ne doit pas être lu comme s'il n'en faisait pas."""
    lines = text.splitlines()
    counts, warnings = _new_counts(), []
    flat: list[FlatLine] = []

    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            counts["blank"] += 1
            continue
        if stripped.startswith(comment_prefixes):
            counts["comment"] += 1
            continue
        match = _SET_RE.fullmatch(stripped)
        if match is None:
            counts["skipped"] += 1
            reason = ("commande set sans chemin absolu (contexte de navigation inconnu)"
                      if stripped.split()[0] == "set" else "commande autre que « set / » : non convertie")
            _warn(warnings, number, line, reason, False)
            continue
        tokens, unclosed = _tokenize(match.group("path") or match.group("glued") or "")
        if unclosed:
            counts["skipped"] += 1
            _warn(warnings, number, line, "guillemet non fermé", False)
        elif not tokens:
            counts["skipped"] += 1
            _warn(warnings, number, line, "chemin vide après « set / »", False)
        else:
            flat.append(FlatLine(tuple(t for t, _ in tokens), number))
            counts["node"] += 1
    return ParsedConfig("set", len(lines), counts, warnings, root=None, _flat=flat)


def combine(
    parts: list[tuple[ParsedConfig, int]], *, lines_total: int, syntax: str = "braces",
    counts: dict[str, int] | None = None, warnings: list[ParseWarning] | None = None,
) -> ParsedConfig:
    """Assemble les analyses de plusieurs SECTIONS d'un même texte (ex. une sortie faite de plusieurs
    commandes, séparées par des lignes de marqueur) en une seule vue plate. Chaque partie est donnée
    avec son décalage : le nombre de lignes qui la précèdent dans le texte entier, pour que les numéros
    de ligne des chemins et des avertissements restent ceux du texte que lit l'utilisateur. `counts`
    et `warnings` apportent ce que les parties ne comptent pas (les lignes de marqueur elles-mêmes).
    Il n'y a pas d'arbre : `top()` rend [] et `reject()` n'est pas disponible."""
    total = _new_counts()
    for key, n in (counts or {}).items():
        total[key] += n
    flat: list[FlatLine] = []
    merged: list[ParseWarning] = list(warnings or [])
    for part, offset in parts:
        for key, n in part.counts.items():
            total[key] += n
        flat += [FlatLine(f.path, f.line + offset) for f in part.flat]
        merged += [ParseWarning(w.line + offset, w.text, w.reason, w.kept, w.blocking) for w in part.warnings]
    merged.sort(key=lambda w: w.line)
    return ParsedConfig(syntax, lines_total, total, merged, root=None, _flat=flat)


SYNTAXES = {"indent": parse_indented, "braces": parse_braces, "set": parse_set}


def parse(text: str, syntax: str, **options) -> ParsedConfig:
    try:
        parser = SYNTAXES[syntax]
    except KeyError:
        raise ValueError(
            f"syntaxe de configuration inconnue : {syntax!r} (attendu : {sorted(SYNTAXES)})") from None
    return parser(text, **options)
