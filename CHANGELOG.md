# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Versions : numérotation
sémantique (le numéro de version vit dans `netcheck/__init__.py`, lu par `pyproject.toml`).

## [0.4.0] — non publiée (en préparation, `SPEC_v4.md`)

Quatrième version de netcheck. Cette entrée suit la construction phase par phase et sera complétée.

### Ajouté

- **Licence Apache-2.0** (`LICENSE`, champ `license` du paquet).
- **Phase A, socle.** `netcheck/confparse.py` : analyse structurelle des configurations (indentation,
  accolades, lignes `set /`), en bibliothèque standard, neutre vis-à-vis des constructeurs. Aucune
  ligne n'est ignorée en silence : chaque ligne de la source tombe dans exactement une classe, et tout
  ce qui est douteux produit un avertissement (texte masqué).
- **Les règles de configuration vivent dans les drivers** : `Driver.CONFIG_CHECKS` et
  `Driver.parse_config()` ; les règles sont dans `drivers/frr_rules.py`, `srlinux_rules.py` et
  `eos_rules.py`. `compliance.py` ne garde que le moteur : **836 → 397 lignes** (542 → 245 lignes de code), et un test statique
  (`tests/test_compliance_neutrality.py`) échoue si une syntaxe de constructeur y revient.
- **SR Linux : une règle, deux syntaxes.** Les accolades de « info from running » et les lignes
  `set /` du fichier de démarrage donnent les mêmes chemins (vue plate de `confparse`). Les règles
  vérifient la présence et la référence d'une keychain, jamais la forme de la clé (en clair dans le
  fichier de démarrage, `$aes1$` sur l'équipement) : même verdict, test à l'appui.
- **EOS : bannières et sous-commandes non indentées.** Une bannière (`banner login|motd` jusqu'à
  `EOF`) est du texte libre ; une sous-commande non indentée est signalée, comme pour FRR. EOS, lui
  aussi, lit selon le contexte et ignore l'indentation : vérifié sur cEOS 4.34.8M en chargeant de vrais
  fichiers dans une session de configuration abandonnée.
- **Verdict « ANALYSE INCOMPLÈTE »** : une ligne de configuration que l'analyse n'a pas pu lire donne
  au minimum le code retour 1, dans les trois sorties (terminal, JSON `status`, HTML) et dans
  `monitor` (ATTENTION). « NON CONFORME » reste réservé aux violations réelles. Une ligne lue mais
  ambiguë n'est qu'une information, sans effet sur le code retour. Une accolade fermante manquante
  rend la **structure incertaine** : les lignes restent évaluées (les violations sont rapportées) mais
  le verdict ne peut pas être « conforme ».
- **FRR : sous-commande au premier niveau.** FRR lit selon le contexte et ignore l'indentation ; une
  sous-commande non indentée (`ip ospf …`, `neighbor …`) d'un fichier écrit à la main est signalée
  (liste vérifiée avec `vtysh -C`), au lieu de faire croire à une interface sans authentification.
- **« Non applicable » en deux causes**, comptées à part : « hors sujet » (la règle ne liste pas le
  driver) et « non implémenté par le driver X » (un trou de couverture).
- **Peer groups BGP (FRR et EOS).** Les règles BGP lisent chaque voisin avec ses réglages effectifs
  (`drivers/bgp_neighbors.py`) : un membre hérite du mot de passe, du GTSM, de la limite et des
  politiques de son groupe, et un réglage posé sur le membre masque celui du groupe. Un constat sur un
  membre le nomme avec son groupe (`192.0.2.5 (peer group PG-OPEN)`). Treize configurations relevées en
  direct (r3 FRR, r4 cEOS) servent de fixtures (`tests/fixtures/peergroups/`), avec la preuve du retour
  exact de chaque scénario.
- **Plages de voisins dynamiques (`bgp listen range … peer-group …`, FRR et EOS).** Elles créent des
  sessions eBGP sans aucune ligne `neighbor <ip>` : la plage est évaluée comme un voisin eBGP qui hérite
  des réglages de son groupe, et un constat la nomme (`192.0.2.64/26 (plage dynamique, peer group …)`).
  Avant, ces sessions n'étaient pas auditées du tout. Relevé en direct : FRR écrit la plage sans
  `remote-as` (celui du groupe s'applique), EOS exige le `remote-as` sur la ligne même.
- **`netcheck check --config-dir <dossier> [--driver …]`** : audit de fichiers de configuration, sans aucun
  équipement. Deux dispositions (`dossier/<équipement>.<ext>`, `dossier/<équipement>/<fichier>`), driver
  déduit de l'inventaire ou donné, option répétable (lab mixte : `configs` puis `configs-multivendor`).
  Même moteur, mêmes règles, mêmes trois sorties que le direct ; sur les trois labs, les fichiers de
  démarrage du dépôt donnent le même verdict que l'audit en direct (mêmes violations, mêmes causes de
  « non applicable », même code retour), avec des relevés réels comme preuve
  (`tests/fixtures/live_hardened/`).
- **Hors ligne, une règle qui lit l'état collecté est « non évaluable »** : cause **ÉTAT REQUIS (hors
  ligne)**, comptée à part dans la synthèse des trois sorties (JSON : `cause: "no_model"`,
  `summary.not_applicable_no_model`). Le rapport dit aussi d'où vient chaque équipement (JSON `source`).
- **Rien n'est ignoré en silence dans un dossier** : une entrée hors disposition (`daemons`, fichier caché)
  est une information ; un fichier qui ressemble à une configuration mais n'a pas pu être lu (équipement
  inconnu, plusieurs fichiers sans nom attendu, vide, trop gros, illisible en UTF-8) est « NON AUDITÉ » et
  bloque le verdict comme une ligne non lue (`summary.config_files_not_audited`). Aucun fichier lu : code 3.
- Gel de référence de la conformité (`tests/golden/`, `tests/tools/golden.py`) : les réponses de la
  v0.3.0 sur des configurations réelles, leurs mutations et des sondes ; les écarts voulus sont tracés
  dans `meta.revisions`.

### Modifié

- **Refus au chargement** d'une règle dont `drivers:` cite un driver qui n'implémente pas son `kind`
  (elle ne vérifierait rien sur cet équipement). Les règles de la v0.3.0 se chargent sans modification.
- **Verdict et structure incertaine.** Un avertissement d'analyse peut bloquer le verdict sans retirer
  la ligne (`ParseWarning.blocking`) : c'est le cas d'une accolade fermante manquante, qui rend
  incertaine la place de tout ce qui suit. La ligne reste lue et évaluée (ses violations sont
  rapportées), mais le verdict n'est jamais « conforme » : code 1 au minimum, ligne comptée avec les
  lignes non lues, affichée « STRUCTURE INCERTAINE ». Si une violation réelle existe en même temps, elle
  s'affiche (NON CONFORME) avec la mention de structure incertaine. JSON : `config_analysis[].blocks_verdict`.
- **Bannière SR Linux : un évaluateur sur les chemins.** La règle `srlinux-banniere-de-connexion` n'est
  plus un `line_present` sur le texte (`^\s*login-banner\s`, qui ne voyait pas la ligne
  `set / system banner login-banner …` du fichier de démarrage) mais le kind `srlinux_login_banner_present`,
  qui lit le chemin `login-banner <texte>` dans les deux syntaxes. Réponses identiques sur tout le gel et
  sur les snapshots réels. Le message ne cite plus l'expression régulière disparue : « aucune bannière
  de connexion (login-banner) configurée » (7 entrées du gel, tracées dans `meta.revisions` ; ni verdict ni
  code ne changent).
- API : `compliance.evaluate_config()` (violations, non applicables, avertissements d'analyse) ;
  `compliance.evaluate()` garde sa forme historique. `verdict()` accepte les avertissements.
- Rapports : JSON enrichi de `status`, `summary`, `config_analysis` et de `cause` par règle non
  applicable (champs ajoutés, aucun retiré). Le registre des drivers vit dans `drivers/registry.py`
  (`collector.DRIVER_REGISTRY` reste le même objet).

### Corrigé

Défauts des règles FRR de la v0.3.0, qui lisaient le texte de la configuration par expressions
régulières et sous-chaînes (validés sur 10 cas du gel et 4 entrées fabriquées) :

- **Blocs sans `exit`** : l'ancien code ne retrouvait un bloc d'interface que s'il se terminait par
  `exit`, et une route-map sans `exit` absorbait la suivante. Résultat : des interfaces qui
  disparaissaient du rapport (faux négatifs) et des violations de réinjection de préfixes inventées
  (faux positifs, jusqu'au code 2 sur une configuration durcie).
- **`no ip ospf passive`** était lu comme `ip ospf passive` (test de sous-chaîne) : interface active
  ignorée par l'audit d'authentification OSPF.
- **Une description contenant le texte `ip ospf passive`** était lue comme la commande.
- **Espaces multiples** dans `neighbor X password Y` : l'ancien code concluait « sans mot de passe ».

Défauts des règles EOS de la v0.3.0 :

- **Une bannière dont le texte ressemble à de la configuration** était lue comme de la configuration
  (par exemple une fausse interface sans authentification).
- **Un `!` en colonne 0 terminait le bloc** : les lignes indentées qui suivent étaient ignorées, alors
  qu'EOS les applique au bloc ouvert (vérifié sur cEOS).
- **Espaces multiples** dans `neighbor X maximum-routes N` : l'ancien code concluait « sans limite ».

Défauts communs à FRR et EOS, sur les peer groups (relevés sur r3 et r4, mesurés avec le code de la v0.3.0) :

- **Fausse violation sur un groupe** : `neighbor PG remote-as N` était lu comme un voisin nommé `PG`.
  Un groupe sans aucun membre (`PG-ORPHAN`) produisait des violations (`sans GTSM`, `sans limite`) sur un
  voisin qui n'existe pas ; un groupe sans mot de passe était signalé sous son nom au lieu de ses membres.
- **Faux « conforme » silencieux sur les membres** : un membre n'a pas de `remote-as` à lui
  (`neighbor 192.0.2.5 peer-group PG`), donc il n'était jamais vu. C'était le groupe, et non ses membres,
  qui était jugé : un groupe complet donnait « conforme » par hasard, et une surcharge dangereuse sur un
  membre (par exemple `maximum-routes 0`, illimité) passait inaperçue.
- **Un fichier de notes lu avec `--driver` était « conforme »** (`check --config-dir`, défaut de la
  construction de la 0.4.0, mesuré avant publication) : `--driver eos` (code 0) et `--driver srlinux` sous
  `default.yml` ; seul `--driver frr` échappait à « conforme », par hasard. Un fichier n'est maintenant audité
  que si au moins la moitié de ses lignes de premier niveau commencent par un mot-clé racine du driver
  (`Driver.ROOT_KEYWORDS`, vérifié contre les 52 configurations réelles du dépôt : aucune rejetée, aucun
  signalement), sinon il est NON AUDITÉ ; dans un fichier audité, une ligne de premier niveau inconnue du
  driver est listée en information (lue, ambiguë). Aucun fichier audité : code 3. Un fichier remplacé par un
  dossier ultérieur n'est plus lu avec le driver de l'inventaire (le r5 FRR de `configs` l'était avec le
  driver SR Linux du lab mixte).
- **`maximum-routes 0` posé sur un membre (EOS)** : sur EOS, 0 veut dire « pas de limite ». Sur un membre
  de peer group, cette surcharge masque la limite de son groupe et passait inaperçue (aucune violation,
  code 0) ; elle est maintenant signalée. Le changement est apparu avec le code des peer groups
  (commit `fe6b04e`) ; pour un voisin déclaré hors groupe, la v0.3.0 le signalait déjà.
- **`remote-as external|internal` ignoré (FRR)** : un voisin `external` n'était jamais audité. EOS refuse
  ces deux formes (`% Invalid input`, relevé sur cEOS 4.34.8M).

### Connu

- **Peer groups SR Linux hors périmètre** : r5 n'a pas de BGP dans ce lab, donc aucun relevé réel ; les
  règles SR Linux n'ont pas de règle BGP à adapter pour l'instant.
- Les voisins sans numéro (`neighbor <interface> interface remote-as …`, FRR) ne sont pas lus (comme
  avant) : leur rendu n'a pas été relevé sur un équipement.
- Un membre dont aucun `remote-as` (propre ou du groupe) n'est connu n'ouvre pas de session : il n'est
  pas évalué.

- Une keychain SR Linux sans aucune clé n'est pas détectée (comportement de la v0.3.0, conservé) :
  amélioration prévue en phase E.

## [0.3.0] — 2026-10-03

Troisième version de netcheck, construite en sept phases (A à G, `SPEC_v3.md`) : sécurité,
état attendu, changements prévus et retour arrière prouvé, surveillance planifiée, troisième
constructeur. **Valeurs de lab uniquement** : voir « Secrets du lab » dans le README.

### Ajouté

- **Phase A : audit de sécurité** (`netcheck/rules/security.yml`). Authentification OSPF
  message-digest (FRR) ou keychain (SR Linux), mot de passe TCP-MD5, GTSM (`ttl-security`),
  `maximum-prefix`, politique d'entrée sans route par défaut ni préfixe local, absence de mot de
  passe en clair, bannière SR Linux. Les règles qui s'appuient sur une source portent des
  références vérifiées (RFC 2328, 2385, 5082, 7454) ; les autres n'en inventent pas.
  **Masquage des secrets** (`netcheck/secrets.py`) dans les trois formats de rapport.
- **Phase B : durcissement des deux labs** (FRR, FRR + SR Linux), démarrage à froid prouvé, une
  clé distincte par lien. Rapports avant/après dans `docs/audit/` : FRR 14 non-conformités
  → 0, lab mixte 15 → 0.
- **Phase C : `netcheck assert`** : état attendu en YAML (`bgp_session`, `ospf_neighbors`,
  `route_present`, `route_absent`, `interface_up`, `path`), évalué sur le modèle normalisé, donc
  identique pour tous les constructeurs. `path` : longest prefix match, trou noir = ÉCHEC, ECMP
  `all|any`, NON ÉVALUABLE réservé aux limites de la méthode. Intents `intents/lab*.yml`.
- **Phase D : `--expect` et `guard --rollback`.** `--expect` : constats PRÉVUS avec garde-fous
  anti-masquage (plafond de gravité, motif trop large refusé, `count` exact, assertions `after`).
  `guard --rollback` : retour arrière **prouvé** par un diff sans aucun constat, délais par script
  avec arrêt du groupe de processus, journal JSON masqué (SHA-256 des scripts), interruption sans
  annulation automatique ; codes retour 0 à 6.
- **Phase E : `netcheck monitor`** : exécution unique pour cron ou timer systemd, statut global
  (diff, assertions, conformité), alerte webhook **seulement au changement de statut** (état
  `observed` / `notified`, `--confirm N`, verrou `flock`, retour à la normale), formats `generic`
  et `discord` (détection automatique), `--dry-run`, `automation/monitor.sh` (fichier d'environnement
  lu comme du texte, jamais exécuté). L'URL du webhook n'apparaît jamais.
- **Phase F : driver Arista EOS (cEOS)** : `drivers/eos.py`, lab `lab-cEOS.clab.yml` (r4 = cEOS
  4.34.8M, image importée localement, jamais commitée), cinq règles `drivers: [eos]`,
  `intents/lab-ceos.yml`, `test_lab_ceos.sh`, `tests/integration_ceos.sh` (tests négatifs rejoués).
  Mesures : démarrage à froid 23 à 27 s, +1 GiB de RAM.
- **Phase G : documentation et version** : sections assert, monitor, cEOS, « Secrets du lab »,
  « Limites connues et pistes v4 » ; formats intent et expect ; guide « ajouter un driver » mis à
  jour ; ce fichier.

### Modifié

- **Changement de comportement (Phase D2)** : un script `guard --change` qui se termine par un code
  non nul rend désormais au minimum le **code 2** (avant : simple avertissement).
- **Liste blanche à deux niveaux** : en plus de la liste des commandes logiques, un driver peut
  déclarer `ALLOWED_CLI` (commandes CLI réelles, correspondance exacte) ; `NEEDS_ENABLE` pour les
  équipements qui ouvrent la session en mode utilisateur.
- **Masquage des secrets généralisé** : règle « mot-clé, type facultatif, valeur ».
- `netcheck_version` des snapshots, journaux et alertes : 0.3.0.

### Corrigé

- **Fuite de secrets sur Arista EOS** (trouvée par les tests de la Phase F) : les trois formes de
  secret EOS (`md5 7`, `password 7`, `secret sha512`) laissaient fuir le hash dans les rapports ;
  corrigé par la règle générique, avec un test qui échoue si un hash survit.
- Masquage des URL de webhook avec port explicite (`:443`, Teams).
- `monitor --dry-run` ne déplace plus un fichier d'état corrompu.
- Scénarios d'intégration de `monitor` rendus déterministes (attente d'un réseau stable avant
  la référence, au lieu d'un `sleep` qui n'avait réussi que par chance).
- Phase D2 : le titre du cadre d'alarme de `guard` était tronqué à 80 colonnes et masquait
  « l'annulation n'a PAS été lancée ».

### Connu

- Voir « Limites connues et pistes v4 » dans le README : évaluateurs texte dans `compliance.py`,
  peer groups, adresses IPv4 secondaires, états OSPF autres que `full`, pas de TCP-AO.
- Les rapports de `docs/audit/` portent la mention « netcheck v0.2.0 » : ce sont des preuves
  datées, produites par cette version sur les labs de l'époque, volontairement non régénérées.

### Vérification de la version

695 tests unitaires ; lab FRR : `test_lab.sh` 28/28, `tests/integration.sh` 80/80 ; lab mixte :
`test_lab_multivendor.sh` 15/15, `tests/integration_multivendor.sh` 27/27 ; lab cEOS :
`test_lab_ceos.sh` 26/26, `tests/integration_ceos.sh` 38/38 ; ruff et shellcheck propres.
Chaque lab a été déployé à froid, un seul à la fois ; le lab FRR est remis en route à la fin.

## [0.2.0]

Lab multi-constructeurs FRR + Nokia SR Linux, registre de drivers, règles `drivers:`,
identifiants par driver (`SPEC_v2.md`).

## [0.1.0]

netcheck : snapshot, diff, check, guard, rapports HTML, sur le lab FRR (`SPEC_netcheck.md`).
