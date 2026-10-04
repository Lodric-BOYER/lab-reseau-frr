"""Suivi des sections relevées par un driver (phase B2) : une section peut être relevée (même vide), ou non.

Une section « obligatoire » (celles de la v0.3.0) garde le comportement historique : une sortie illisible
fait échouer le relevé de l'équipement, visiblement. Une section « facultative » (IPv6, OSPFv3, VRF), elle,
peut manquer sans faire échouer le relevé : elle est alors marquée NON RELEVÉE avec sa raison, jamais lue
comme « vide ».
"""
from __future__ import annotations

import json
from typing import Any, Callable


class SectionUnavailable(Exception):
    """La sortie de la commande n'est pas celle qu'on attend (commande inconnue du démon, démon arrêté...)."""


def json_object(text: str) -> Any:
    """json.loads, avec une raison lisible quand la sortie n'est pas du JSON (ex. `% Unknown command`)."""
    stripped = text.strip()
    if not stripped:
        raise SectionUnavailable("sortie vide")
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        first = stripped.splitlines()[0][:100]
        raise SectionUnavailable(f"sortie qui n'est pas du JSON : {first}") from None


class Sections:
    def __init__(self, raw: dict[str, str]):
        self.raw = raw
        self.collected: list[str] = []
        self.errors: dict[str, str] = {}

    def required(self, name: str, command: str, parse: Callable[[str], Any]) -> Any:
        value = parse(self.raw[command])
        self.collected.append(name)
        return value

    def optional(self, name: str, commands: str | tuple[str, ...], parse: Callable[..., Any],
                 empty: Any) -> Any:
        """`parse` reçoit le texte de chaque commande ; `empty` est rendu si la section n'est pas relevée."""
        commands = (commands,) if isinstance(commands, str) else commands
        missing = [c for c in commands if c not in self.raw]
        if missing:
            self.errors[name] = f"commande non exécutée : {missing[0]}"
            return empty
        try:
            value = parse(*(self.raw[c] for c in commands))
        except SectionUnavailable as e:
            self.errors[name] = str(e)
            return empty
        self.collected.append(name)
        return value

    def mark(self, name: str, ok: bool, reason: str = "") -> None:
        if ok:
            self.collected.append(name)
        else:
            self.errors[name] = reason
