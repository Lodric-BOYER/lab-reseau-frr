#!/usr/bin/env python3
"""Les lignes `role netcheck-ro` de r5/config.cli sont-elles dans la configuration COURANTE de r5 ?

Piège constaté (phase C5) : containerlab charge `config.cli` d'un bloc, et un commentaire contenant des
guillemets fait avorter les lignes qui suivent SANS message. Le déploiement réussit, le rôle n'existe pas.
Ce contrôle, rejoué après chaque déploiement par test_lab_multivendor.sh, compare ce que le fichier demande
à ce que `info flat from running system aaa authorization role netcheck-ro` répond.

    srl_role_check.py <config.cli>      (la réponse de l'équipement arrive sur l'entrée standard)

Code retour : 0 identique ; 1 écart (détail sur la sortie d'erreur) ; 2 usage.
"""

from __future__ import annotations

import re
import shlex
import sys
from pathlib import Path

PREFIX = "set / system aaa authorization role netcheck-ro "
_LINE = re.compile(re.escape(PREFIX) + r"(?P<key>.+?) \[ (?P<items>.*) \]\s*$")


def parse(text: str) -> dict[str, list[str]]:
    """{clé: éléments triés}. L'équipement double les antislashs et retire les guillemets inutiles :
    `shlex` (guillemets doubles, mode POSIX) défait le doublement, `\\\\*` redevient `\\*`."""
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        match = _LINE.match(line.strip())
        if match:
            found[match["key"]] = sorted(shlex.split(match["items"]))
    return found


def compare(wanted_text: str, live_text: str) -> list[str]:
    wanted, live = parse(wanted_text), parse(live_text)
    problems = []
    if not wanted:
        problems.append("config.cli ne contient aucune ligne « role netcheck-ro » : rien à comparer")
    for key in sorted(set(wanted) | set(live)):
        if key not in live:
            problems.append(f"« {key} » demandé par config.cli, absent de la configuration courante")
        elif key not in wanted:
            problems.append(f"« {key} » présent sur l'équipement, absent de config.cli")
        elif wanted[key] != live[key]:
            missing = sorted(set(wanted[key]) - set(live[key]))
            extra = sorted(set(live[key]) - set(wanted[key]))
            problems.append(f"« {key} » diffère : manque {missing}, en trop {extra}")
    return problems


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    problems = compare(Path(argv[0]).read_text(encoding="utf-8"), sys.stdin.read())
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print(f"{len(parse(Path(argv[0]).read_text(encoding='utf-8')))} lignes de rôle identiques")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
