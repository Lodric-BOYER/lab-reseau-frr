"""Permet d'importer le paquet netcheck/ pendant les tests, sans installation (pip install -e)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
# Récepteur de webhook local (tests/tools/webhook_recorder.py), partagé avec les scénarios shell.
TOOLS_DIR = Path(__file__).resolve().parent / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
