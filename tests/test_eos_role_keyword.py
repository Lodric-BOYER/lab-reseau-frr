"""EOS : `role` est un mot-clé de premier niveau connu (phase C5, compte netcheck-ro).

Un bloc `role NOM` (permissions de commandes d'un compte) fait partie d'une configuration EOS normale.
Sans ce mot-clé, `check --config-dir` signalerait chaque `role` comme « mot-clé inconnu du driver eos ».
Ce changement est inoffensif seul : il ne dépend d'aucune configuration du dépôt (texte en ligne).
"""

from netcheck import configdir
from netcheck.drivers.eos import EosDriver

CONFIG = """hostname r9
!
interface Ethernet1
   no switchport
!
router ospf 1
   router-id 10.0.0.9
!
role lecture-seule
   10 permit command show interfaces
   150 deny command .*
"""


def _warned(tmp_path, text):
    (tmp_path / "r9.cfg").write_text(text, encoding="utf-8")
    loaded = configdir.load([tmp_path], {"r9": "eos"})
    return [w.warning.reason for w in loaded.warnings]


def test_role_is_a_known_eos_root_keyword():
    assert "role" in EosDriver.ROOT_KEYWORDS


def test_a_role_block_is_not_reported_as_an_unknown_keyword(tmp_path):
    assert _warned(tmp_path, CONFIG) == []


def test_the_unknown_keyword_report_still_works_for_other_words(tmp_path):
    reasons = _warned(tmp_path, CONFIG + "motinconnu quelque chose\n")
    assert len(reasons) == 1 and "motinconnu" in reasons[0] and "role" not in reasons[0]


def test_the_role_block_is_read_as_a_root_statement():
    statements = EosDriver().parse_config(CONFIG).root_statements()
    assert [word for _, _, word in statements].count("role") == 1
