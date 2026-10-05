#!/usr/bin/env python3
"""Lance une commande sous un pseudo-terminal, VTYSH_PAGER = premier argument (tests/lib_ro.sh, phase C5).

    ptyrun.py <valeur de VTYSH_PAGER> <commande> [arguments...]

vtysh ne lance son « pager » que si sa sortie va vers un terminal : pour prouver qu'une variable
d'environnement n'atteint pas vtysh à travers doas, il faut un vrai terminal (`os.forkpty`) et un témoin
positif (la même variable, sans doas, DOIT faire exécuter le script). Bibliothèque standard seulement ;
ce fichier ne s'appelle pas `pty.py` pour ne pas masquer le module standard.
"""

import os
import pty
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    os.environ["VTYSH_PAGER"] = sys.argv[1]
    argv = sys.argv[2:]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    out = b""
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    os.waitpid(pid, 0)
    sys.stdout.write(out.decode(errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
