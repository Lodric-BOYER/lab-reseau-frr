"""Permet d'importer le paquet netcheck/ pendant les tests, sans installation (pip install -e)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
