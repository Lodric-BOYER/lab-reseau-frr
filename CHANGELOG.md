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
  `eos_rules.py`. `compliance.py` ne garde que le moteur : **836 → 388 lignes**, et un test statique
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
- Gel de référence de la conformité (`tests/golden/`, `tests/tools/golden.py`) : les réponses de la
  v0.3.0 sur des configurations réelles, leurs mutations et des sondes ; les écarts voulus sont tracés
  dans `meta.revisions`.

### Modifié

- **Refus au chargement** d'une règle dont `drivers:` cite un driver qui n'implémente pas son `kind`
  (elle ne vérifierait rien sur cet équipement). Les règles de la v0.3.0 se chargent sans modification.
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

### Connu

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
