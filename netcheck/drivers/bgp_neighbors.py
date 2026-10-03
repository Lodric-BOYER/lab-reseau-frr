"""Vue « voisin BGP effectif » des syntaxes de type IOS (FRR, EOS) -- SPEC_v4, Phase A4.

Un peer group porte des réglages que ses membres héritent : `neighbor PG remote-as 65099`,
`neighbor PG password ...`, puis `neighbor 192.0.2.1 peer-group PG`. Lire ces lignes comme des voisins
(ce que faisait la v0.3.0, qui cherchait `neighbor <x> remote-as N`) donne trois défauts, constatés sur
r3 (FRR 10.2.1) et r4 (cEOS 4.34.8M), configurations dans tests/fixtures/peergroups/ :
- le NOM du groupe est pris pour un voisin : une fausse violation « voisin eBGP PG-ORPHAN sans... » sur un
  groupe qui n'a aucun membre ;
- les MEMBRES, qui n'ont pas de `remote-as` à eux, ne sont jamais vus : un faux « conforme » silencieux,
  même quand le groupe n'a pas de mot de passe (le groupe étant jugé à leur place) ;
- (FRR) `remote-as external|internal` n'est pas un numéro d'AS : un voisin `external` n'était jamais vu.

Ce module lit chaque voisin avec ses réglages EFFECTIFS :
- un groupe (nom déclaré par `neighbor <nom> peer-group`, ou cité par un membre ou une plage) n'est pas un
  voisin : il n'est jamais évalué pour lui-même ;
- un membre est eBGP si son `remote-as` propre, à défaut celui de son groupe, désigne un autre AS que
  l'AS local (ou vaut `external`, FRR seulement : EOS répond « % Invalid input » à `external` et `internal`) ;
- un réglage posé sur le membre MASQUE celui du groupe (`lines`) : c'est la surcharge, relevée en direct
  sur les deux équipements (mot de passe, GTSM, limite de routes) ;
- une plage de voisins dynamiques (`bgp listen range <réseau> peer-group <groupe> [remote-as N]`) crée des
  sessions sans ligne `neighbor <ip>` : elle est un voisin à part entière, qui hérite des réglages de son
  groupe. Relevée en direct (fixtures `*_s6_*`, `*_s7_*`) : FRR l'écrit sans `remote-as` (celui du groupe
  s'applique), EOS l'exige sur la ligne même (`% Incomplete command` sinon, même si le groupe le porte) ;
- un membre dont aucun `remote-as` (propre ou du groupe) n'est connu n'ouvre pas de session : il n'est pas
  évalué, comme avant.

Limite connue : les voisins sans numéro (`neighbor <interface> interface remote-as ...`, FRR) ne sont pas
lus, comme avant (CHANGELOG, « Connu »).

Ce module ne dépend d'aucun constructeur : la syntaxe propre à un équipement est un paramètre (`Syntax`).
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from netcheck.confparse import ConfigNode

_DIGITS = re.compile(r"\d+")
Rest = tuple[str, ...]


@dataclass(frozen=True)
class Syntax:
    group_decl: Rest                  # ce qui suit le nom dans `neighbor <nom> ...` pour déclarer un groupe
    remote_as_words: dict[str, bool]  # valeurs de `remote-as` qui ne sont pas un numéro : mot -> eBGP ?


# `neighbor PG peer-group` / `neighbor <ip> peer-group PG` (FRR), `peer group` en deux mots (EOS).
FRR_SYNTAX = Syntax(("peer-group",), {"external": True, "internal": False})
EOS_SYNTAX = Syntax(("peer", "group"), {})


class BgpView:
    """Les voisins d'un bloc `router bgp <AS>`, avec leurs réglages effectifs."""

    def __init__(self, block: ConfigNode, syntax: Syntax):
        self.local_as = block.words[2]
        self.below = [n for n in block.walk() if n is not block]   # famille d'adresses comprise
        self._syntax = syntax
        self._lines: dict[str, list[ConfigNode]] = {}   # nom ou IP -> ses lignes `neighbor <clé> ...`
        self._group_of: dict[str, str] = {}             # membre (IP ou réseau de plage) -> son groupe
        self._groups: set[str] = set()
        self._ranges: dict[ConfigNode, tuple[str, str, str | None]] = {}   # ligne -> (réseau, groupe, AS)
        decl = syntax.group_decl
        for n in self.below:
            w = n.words
            if w[0] == "neighbor" and len(w) >= 3:
                self._lines.setdefault(w[1], []).append(n)
                if w[2:] == decl:
                    self._groups.add(w[1])
                elif len(w) == 3 + len(decl) and w[2:-1] == decl:
                    self._group_of[w[1]] = w[-1]
            elif w[:3] == ("bgp", "listen", "range") and len(w) >= 6 and w[4] == "peer-group":
                inline = w[7] if len(w) >= 8 and w[6] == "remote-as" else None
                self._ranges[n] = (w[3], w[5], inline)
                self._group_of[w[3]] = w[5]
        self._groups |= set(self._group_of.values())

    # -- lecture ------------------------------------------------------------------------------

    def _external(self, value: str) -> bool:
        number = _DIGITS.match(value)
        if number:
            return number.group() != self.local_as
        return self._syntax.remote_as_words.get(value, False)

    def _remote_as_lines(self, key: str) -> list[ConfigNode]:
        return [n for n in self._lines.get(key, ()) if n.words[2] == "remote-as" and len(n.words) >= 4]

    def _group_remote_as(self, group: str, inline: str | None = None) -> str | None:
        """L'AS du groupe : celui de la plage (EOS), sinon la dernière ligne `neighbor <groupe> remote-as`."""
        if inline is not None:
            return inline
        lines = self._remote_as_lines(group)
        return lines[-1].words[3] if lines else None

    @property
    def ebgp(self) -> list[str]:
        """Clés (IP, ou réseau d'une plage) des voisins eBGP, dans l'ordre de la configuration. Sans
        groupe, c'est exactement ce que lisait la v0.3.0 : une entrée par ligne
        `neighbor <ip> remote-as <AS autre>`."""
        out: list[str] = []
        derived: set[str] = set()
        for n in self.below:
            w = n.words
            if n in self._ranges:
                network, group, inline = self._ranges[n]
                value = self._group_remote_as(group, inline)
                if value is not None and self._external(value):
                    out.append(network)
            elif w[0] != "neighbor" or len(w) < 3 or w[1] in self._groups:
                continue
            elif w[2] == "remote-as" and len(w) >= 4:
                if self._external(w[3]):
                    out.append(w[1])
            elif w[1] in self._group_of and w[1] not in derived and not self._remote_as_lines(w[1]) \
                    and w[2:-1] == self._syntax.group_decl:
                derived.add(w[1])
                value = self._group_remote_as(self._group_of[w[1]])
                if value is not None and self._external(value):
                    out.append(w[1])
        return out

    def lines(self, key: str, selector: Callable[[Rest], bool]) -> list[ConfigNode]:
        """Les lignes `neighbor <clé> <suite>` dont la suite satisfait `selector`. S'il y en a sur le
        membre, ce sont les siennes (elles masquent celles du groupe) ; sinon celles de son groupe."""
        own = [n for n in self._lines.get(key, ()) if selector(n.words[2:])]
        if own:
            return own
        group = self._group_of.get(key)
        return [n for n in self._lines.get(group, ()) if selector(n.words[2:])] if group else []

    def label(self, key: str) -> str:
        """Comment nommer ce voisin dans un constat : l'IP seule s'il n'est pas dans un groupe."""
        group = self._group_of.get(key)
        if group is None:
            return key
        if key in {network for network, _, _ in self._ranges.values()}:
            return f"{key} (plage dynamique, peer group {group})"
        return f"{key} (peer group {group})"
