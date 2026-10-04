"""Codes retour de la CLI pour une ligne de commande invalide.

argparse sort en code 2 par défaut ; pour netcheck, 2 = ÉCHEC (diff, check, assert, monitor) et 3 = erreur
d'usage. Une faute de frappe ne doit jamais ressembler à une panne : toute erreur d'analyse sort en 3,
pour chaque sous-commande, sans rien écrire sur la sortie standard.
"""
from __future__ import annotations

import argparse
import subprocess
import sys

import pytest

from netcheck import cli, guard, monitor

SUBCOMMANDS = ("snapshot", "list", "diff", "check", "guard", "assert", "monitor")

# (sous-commande, arguments invalides) : option inconnue, argument obligatoire manquant, valeur hors
# choix, valeur du mauvais type, argument en trop.
INVALID = [
    ("snapshot", ["--bogus"]),
    ("snapshot", []),
    ("snapshot", ["x", "--host-keys", "ignore"]),
    ("snapshot", ["x", "extra"]),
    ("list", ["--bogus"]),
    ("list", ["extra"]),
    ("diff", ["avant"]),
    ("diff", ["avant", "apres", "--bogus"]),
    ("check", ["--bogus"]),
    ("check", ["--host-keys", "ignore"]),
    ("guard", []),
    ("guard", ["--change", "c.sh", "--rollback-on", "jamais"]),
    ("guard", ["--change", "c.sh", "--wait", "beaucoup"]),
    ("assert", []),
    ("assert", ["--intent", "i.yml", "--bogus"]),
    ("monitor", []),
    ("monitor", ["--baseline", "b", "--webhook-format", "irc"]),
    ("monitor", ["--baseline", "b", "--confirm", "deux"]),
]


def test_every_subcommand_is_covered_by_the_invalid_cases():
    assert {sub for sub, _ in INVALID} == set(SUBCOMMANDS)


def test_usage_codes_agree_across_modules():
    assert cli.EXIT_USAGE == guard.EXIT_USAGE == monitor.EXIT_USAGE == 3


@pytest.mark.parametrize(("sub", "args"), INVALID)
def test_invalid_command_line_exits_3_with_a_message_on_stderr(sub, args, capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main([sub, *args])
    out = capsys.readouterr()
    assert exit_info.value.code == 3
    assert out.out == ""                      # rien sur la sortie standard
    assert "usage" in out.err and "erreur" in out.err


@pytest.mark.parametrize("argv", [[], ["--bogus"], ["nosuch"], ["nosuch", "--bogus"]])
def test_invalid_top_level_command_line_exits_3(argv, capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(argv)
    assert exit_info.value.code == 3
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("sub", SUBCOMMANDS)
def test_help_still_exits_0(sub, capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main([sub, "--help"])
    assert exit_info.value.code == 0
    assert "usage" in capsys.readouterr().out
    with pytest.raises(SystemExit) as top:
        cli.main(["--help"])
    assert top.value.code == 0


def test_every_subparser_uses_the_netcheck_parser():
    # Un futur `add_subparsers(parser_class=argparse.ArgumentParser)` rendrait le code 2 à ce sous-parseur.
    parser = cli.build_parser()
    action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    assert set(action.choices) == set(SUBCOMMANDS)
    for name, sub in action.choices.items():
        assert isinstance(sub, cli._Parser), name


def test_real_process_exits_3_on_an_invalid_option():
    # Le chemin complet : `python -m netcheck`, comme le lance un pipeline ou monitor.sh.
    result = subprocess.run([sys.executable, "-m", "netcheck", "snapshot", "x", "--bogus"],
                            capture_output=True, text=True, check=False, cwd=cli.inventory.REPO_ROOT)
    assert result.returncode == 3
    assert result.stdout == ""
    assert "erreur" in result.stderr
