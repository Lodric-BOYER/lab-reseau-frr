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
- **Phase B1, labs en double pile IPv4 / IPv6 et VRF de démonstration.** Les trois labs convergent en double
  pile (`2001:db8::/32`, liens point à point en /127, OSPFv3 authentifié par RFC 7166 sur les liens FRR–FRR, session
  BGP IPv6 distincte avec le durcissement de l'IPv4) et r2 porte la VRF `DEMO`. `test_lab.sh` passe de 28 à 47
  contrôles, `test_lab_multivendor.sh` de 15 à 28, `test_lab_ceos.sh` de 26 à 44 ; les scénarios d'intégration
  restent verts. Mesures de convergence et de RAM (3 démarrages à froid par lab) dans le README.
- **Phase B2, modèle étendu : IPv6, VRF et sections collectées.** Le modèle contient les adresses IPv6 (globales
  et lien local), les routes IPv6, les voisins OSPFv3 et le BGP `ipv6 unicast`, et un champ `vrf` sur les interfaces,
  routes, sessions et préfixes BGP (identité d'une route = (vrf, préfixe)). Les trois drivers les lisent, sur les
  sorties réelles des trois labs en double pile (`tests/fixtures/dualstack/`, dont une VRF temporaire relevée sur
  cEOS puis retirée avec preuve). Six noms logiques de plus à la liste blanche et douze chaînes exactes pour EOS,
  chacune avec le refus de ses variantes.
- **Sections collectées** : chaque relevé dit ce qu'il contient ; une section relevée mais vide n'est pas une
  section non relevée. `assert` rend NON ÉVALUABLE (avec la raison) quand il lui manque une section, `diff` ne
  déclare jamais « aucun changement » sur une section relevée d'un seul côté. Un snapshot de la v0.3.0 se charge
  (lu comme la VRF `default`, sections de la v0.3.0), test sur un vrai snapshot.
- **`assert` en IPv6 et par VRF** : paramètres `family` et `vrf`, `path` en IPv6 dans la VRF de départ. Un next-hop
  de lien local est résolu par la paire (adresse, interface de sortie) sur le même lien, jamais par l'adresse seule ;
  introuvable ou ambigu : NON ÉVALUABLE. Dix-sept intents IPv6 et VRF de plus (`intents/*.yml`), un scénario de coupure
  de l'IPv6 seul (eBGP, OSPFv3) rouge en `diff` et en `assert` dans `tests/integration.sh`.
- **`management_vrfs`** (inventaire) : une VRF de management (`mgmt` sur SR Linux) est exclue comme `eth0` ou
  `Management0`, dans `diff`, `assert` et `check`.
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

- **Phase B4, l'IPv6 n'est jamais un silence.** Quand l'état relevé ou la configuration auditée contient de l'IPv6 et
  qu'aucune règle IPv6 ne s'applique à l'équipement, `check` (et `monitor`, dans ses rapports) le dit en information
  dans les trois sorties (« IPv6 configuré, aucune règle IPv6 chargée »), sans effet sur le code retour. Un évaluateur est
  « IPv6 » quand son driver le déclare (`Check.ipv6`).
- **Phase B4, EOS : les règles « pas de route par défaut en entrée » et « pas de réinjection de nos préfixes en entrée »**
  (IPv4 et IPv6, peer groups compris, famille par famille), mutations de vraies configurations, preuve en direct sur le
  lab cEOS (injection puis retour prouvé, `tests/integration_ceos.sh`, C6). Un seul texte de constat pour FRR et EOS
  (`drivers/ebgp_filters.py`).
- **Phase C1, clés d'hôte SSH vérifiées** (`netcheck/hostkeys.py`) : fichier `known_hosts` dédié
  (`~/.netcheck/known_hosts`, `--known-hosts`, `NETCHECK_KNOWN_HOSTS`), option `--host-keys strict|accept-new`
  (`NETCHECK_HOST_KEYS`) sur `snapshot`, `check`, `guard`, `assert` et `monitor`. Il n'existe aucun mode « ignorer » :
  `--host-keys ignore` est refusé par la CLI, et un test statique échoue si `AutoAddPolicy` ou `ssh_strict=False`
  reviennent. `accept-new` enregistre la clé d'un équipement inconnu au premier contact, puis se connecte en strict ;
  une clé changée reste refusée ; il est refusé (code 3, avant toute connexion) si l'inventaire ne déclare pas
  `lab: true`, et avertit à chaque usage. Un `known_hosts` modifiable par d'autres comptes est refusé.
  `lab-access/pin_hostkeys.sh <lab>` épingle les clés lues DANS les conteneurs (`docker exec`, jamais par le réseau)
  et refuse deux routeurs qui annoncent la même clé. Le champ `port` d'un routeur est lu (22 par défaut).
- **Image `frr-ssh` : clés d'hôte générées au démarrage du conteneur** (`docker/entrypoint-sshkeys.sh`), plus à la
  construction. Avant, tous les routeurs FRR d'un lab avaient la MÊME clé (relevé : même empreinte sur r1 et r2,
  cuite dans l'image) : l'épinglage ne distinguait pas r1 de r3 et en compromettre un permettait d'usurper les autres.
  Après : 5 empreintes différentes sur le lab FRR, et des clés nouvelles à chaque déploiement.

- **Phase C2, identifiants : fichiers 0600, `SecretStr`, source dans les rapports** (`netcheck/credentials.py`,
  `netcheck/secrets.py`). `NETCHECK_<DRIVER>_USER_FILE` / `_PASS_FILE` et `NETCHECK_USER_FILE` / `_PASS_FILE` désignent un
  fichier de secret (une ligne, droits 0600 ou 0400, propriétaire courant, pas de lien symbolique) ; un fichier désigné
  mais refusé est une erreur (code 3), jamais un repli. Ordre : variable de driver, fichier de driver, variable
  générique, fichier générique, `LAB_*`, inventaire (le niveau « driver » passe avant le générique, fichier ou non).
  Le mot de passe d'un routeur est un `SecretStr` (jamais affiché ni sérialisé) inscrit dans un registre qui expurge
  tout texte publié, y compris l'exception d'une bibliothèque qui le recopierait ; seuil de 8 caractères.
  La **source** de chaque identifiant (variable, fichier, inventaire, jamais la valeur) est dite sur le terminal, dans
  le JSON et le HTML de `check` et `assert`, dans `meta.json`, dans le journal de `guard` et dans `summary.json` de
  `monitor`. Test sentinelle sur toutes les sorties, tous les fichiers écrits, les journaux et les alertes.
  `inventory.load(resolve_credentials=False)` : les commandes hors ligne ne résolvent aucun identifiant.
- **Note d'information sur les mots de passe de moins de 8 caractères** (après C2) : « expurgation par valeur
  inactive pour ce secret (moins de 8 caractères), seule la protection `SecretStr` s'applique », avec les équipements
  concernés, à côté des sources (ligne `remarque` ; clé `remarque` des `credential_sources`). Ni avertissement ni effet
  sur le code retour ; jamais la longueur exacte ni la valeur. `SecretStr.redactable` (booléen).
- **Phase C3, identifiants lus dans Vault ou OpenBao** (`netcheck/vault.py`, extra optionnel `netcheck[vault]` =
  `hvac`, Apache-2.0). KV v2, authentification AppRole, configuration par `NETCHECK_VAULT_ADDR`, `_ROLE_ID`,
  `_SECRET_ID_FILE` (fichier 0600, mêmes règles que C2, jamais en argument de ligne de commande), `_PATH`, `_MOUNT`,
  `_CACERT`. Ordre de priorité : variable de driver, fichier de driver, variable générique, fichier générique,
  **Vault**, `LAB_*`, inventaire (un `LAB_PASS` ne masque jamais Vault ; si les quatre premiers niveaux fournissent
  l'identifiant, Vault n'est pas contacté). **Exactement deux appels réseau** (`POST /v1/auth/approle/login`, seule
  écriture, puis `GET` du chemin configuré), imposés par une liste blanche exacte dans l'adaptateur de `hvac` : tout
  autre appel est refusé avant envoi. Politique du rôle en lecture seule sur le seul chemin
  (`lab-access/vault/netcheck-ro.hcl`). Aucun repli silencieux : Vault injoignable, authentification refusée,
  secret introuvable, lecture refusée ou TLS refusé donnent le code 3 sur une ligne. Jeton et `secret_id` sont des
  `SecretStr` inscrits au registre d'expurgation ; source affichée « Vault (montage/chemin) ». `http://` refusé hors
  bouclage, TLS toujours vérifié, redirections et proxies d'environnement ignorés. Lab : `lab-access/vault_lab.sh`
  (`hashicorp/vault:2.1.1` et `openbao/openbao:2.7.1`, mode développement sur 127.0.0.1) et
  `tests/integration_vault.sh` (lab FRR réel, journal d'audit, refus 403 du rôle, priorité, pannes).
  **Rôle AppRole durci** (après C3, sans toucher à la liste blanche) : `token_num_uses=1`, `token_ttl=60s`,
  `token_max_ttl=120s`, `secret_id_num_uses=1`, `secret_id_ttl=15m`, `token_bound_cidrs` et `secret_id_bound_cidrs` au
  bouclage ; conséquence : chaque exécution consomme un `secret_id` (`vault_lab.sh secret-id`). Le conteneur de lab
  partage le réseau de l'hôte pour que Vault voie `127.0.0.1` (derrière une redirection Docker il voyait `172.x.0.1`).
  `tests/integration_vault.sh` : 76 contrôles, dont les réglages relus sur le serveur, jeton et `secret_id` à usage
  unique, liaison CIDR prouvée, rôle de sonde à usages illimités pour que les refus 403 viennent de la politique.
  Ressources (C24) : Vault ≈ 34-35 Mo de RAM et image de 744 Mo ; OpenBao ≈ 22 Mo et 275 Mo.

### Modifié

- **Phase C2 : le mot de passe d'un routeur de l'inventaire est un `SecretStr`** (compare égal à la `str`
  correspondante ; `.reveal()` donne la valeur). `inventory.load()` résout les identifiants avec la source de chacun
  (`credential_sources`) ; un identifiant absent partout est une erreur claire (code 3) au lieu d'une `KeyError`.
  Les messages d'erreur de collecte passent par `redact_known`.
- **INCOMPATIBLE, phase C1 : netcheck vérifie les clés d'hôte, strict par défaut.** Jusqu'ici netcheck acceptait
  n'importe quelle clé d'hôte (Netmiko `ssh_strict=False`, soit `AutoAddPolicy`, jamais surchargé) : une
  interposition sur le réseau de management était invisible. Maintenant, un équipement dont la clé est absente du
  `known_hosts` dédié est refusé (« clé d'hôte inconnue »), une clé changée aussi (« clé d'hôte CHANGÉE », avec les
  deux empreintes). **Migration** : voir la section du même nom dans le README (épingler les clés avec `ssh-keyscan`
  ou `lab-access/pin_hostkeys.sh`). `automation/labtools.py` (`health.py`, `backup.py`, `drift.py`, hors
  netcheck) n'est pas modifié et garde `AutoAddPolicy` : limite connue.
- Les trois inventaires de lab déclarent `lab: true` (seul moyen d'utiliser `--host-keys accept-new`).
- **Phase B3, règles IPv6 : les trois silences sont fermés.** L'authentification OSPFv3 (trois règles, une par
  driver, dans `netcheck/rules/security-ipv6.yml`), `::/0` autorisé en entrée et un préfixe IPv6 local autorisé en
  entrée (les deux règles existantes lisent maintenant l'IPv6). Mutations de vraies configurations des labs en double
  pile ; 35 mutations du code des règles et des dérogations, toutes détectées. `check` et `monitor` acceptent plusieurs
  `--rules`.
- **Objet des violations (`Violation.subject`)** : chaque règle dit sur quel objet (interface, voisin, API) porte sa
  violation, un test par kind de règle ; le champ `object` est dans le JSON.
- **Dérogations** (`check|monitor --derogations`, `netcheck/derogations.py`) : un défaut connu, documenté et daté. Paires
  (équipement, objet) en correspondance exacte, statut DÉROGATION dans les trois sorties (justification, validateur,
  expiration), compté à part, sans effet sur le code retour ; expirée : la violation redevient active et le dit ;
  moins de 30 jours : information ; orpheline : information ; règle critique, expiration absente ou à plus de 365 jours,
  doublon : refusés. L'horloge est un paramètre (`--today`), jamais appelée par le moteur. Chaque rapport indique le
  chemin et l'empreinte SHA-256 du fichier. Une dérogation par lab (`derogations/*.yml`) couvre le lien r4–r5.
- **Gel de référence : cas double pile ajoutés** (10 cas dans `default` et `security`, zéro ligne du gel existant
  modifiée) et gel du nouveau fichier de règles `security-ipv6` (`golden.py record-new`), vérifiés contre des
  attentes écrites à la main (`tests/test_golden_dualstack.py`).
- **Scénarios d'intégration IPv6 négatifs** : authentification OSPFv3 retirée, `::/0` et préfixe local autorisés en
  entrée (lab FRR, C3 à C5), dérogation en cours et expirée (les trois labs), retour prouvé par un diff à zéro constat.
- **`diff` : une section perdue est un constat ATTENTION.** Relevée avant et non relevée après (collecte échouée
  pendant l'intervention), elle donne un constat ATTENTION par section et par équipement : `guard` ne rend plus
  SUCCESS, `monitor` passe en ATTENTION. Relevée seulement après (ancien snapshot) : information.
- **Phase B2 : trois traductions élargies à toutes les VRF** (routes IPv4 de FRR, d'EOS et de SR Linux) ; l'ancienne
  chaîne EOS `show ip route | json` n'est plus autorisée. Le BGP de SR Linux, jamais relevé, est maintenant une
  section absente : une assertion `bgp_session` sur r5 est NON ÉVALUABLE (elle disait « aucune session »).
  Le périphérique d'une VRF FRR n'est plus une interface du modèle.
- **Phase B3 : SR Linux, une instance OSPF est jugée selon sa version.** Les règles OSPFv2 ne lisent plus les
  interfaces d'une instance `ospf-v3` (elles étaient fusionnées par nom : une keychain posée côté OSPFv3 aurait masqué
  son absence côté OSPFv2). FRR : `ipv6 ospf6 …` et `ospf6 router-id` non indentés sont signalés comme les autres
  sous-commandes de bloc (refusés à la racine par `vtysh -C`). EOS : `ospfv3 passive` (démarrage) et `ospfv3
  passive-interface` (running-config) sont tous deux « passif ».
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
- **Code 70 (EX_SOFTWARE) : défaut interne de netcheck, pour toutes les commandes.** Une exception Python non gérée
  sortait en code 1 (lu comme ATTENTION ou injoignable) ; elle sort en **70**, avec la trace expurgée des secrets connus.
  70 est distinct de 3 (erreur d'usage, que l'opérateur corrige), de 0 à 2 (statut), de 4 à 6 (`guard`) et de 4
  (verrou de `monitor`). **Changement de comportement pour `monitor`** : son erreur interne (« monitor n'a pas pu
  conclure ») sortait en **3** ; elle sort maintenant en **70**. Un planificateur qui testait `== 3` pour « refusé ou
  erreur interne » doit distinguer 3 (refus d'usage) et 70 (défaut interne). Tableau des codes retour du README mis à jour.
  **Où va la trace sous `monitor`** : jamais sur stderr (cron l'enverrait par courriel) ; dans
  `reports/monitor_latest/summary.json` (`status: DEFAUT_INTERNE`, `internal_error.type` et `.trace`, expurgée des secrets
  et de l'URL du webhook, droits 0600), les rapports d'une exécution précédente étant retirés ; une ligne sur la sortie
  standard. Une exception dans le chargement des fichiers n'est plus prise pour un refus d'usage (code 3) : seules
  `ValueError`, `OSError` et les erreurs d'identifiants le sont, tout le reste est un défaut interne (70).

### Sécurité

- **Traversée de chemin évitée à l'écriture d'un snapshot.** `snapshot ../x --force` (ou un nom contenant `/`) écrivait
  des fichiers hors de `snapshots/`. Le nom est désormais limité aux lettres, chiffres, `.`, `-` et `_` (100 caractères,
  commençant par une lettre ou un chiffre) et refusé en code 3 avant toute collecte. La lecture d'un snapshot par chemin
  reste permise (elle n'écrase rien).
- **Fuite d'un extrait de fichier par un message d'erreur YAML.** PyYAML recopie dans son message la ligne fautive ; sur
  un inventaire, cette ligne peut être un mot de passe, que `netcheck` affichait donc sur stderr. Les messages ne donnent
  plus que la ligne, la colonne et le type du problème, jamais un extrait (test qui met un mot de passe dans la ligne
  fautive et le cherche dans la sortie).

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

Erreurs d'usage hors argparse (après la phase C2) :

- **Une erreur d'usage sortait en code 1 (ATTENTION / injoignable) ou en traceback, jamais en code 3, depuis la
  v0.1.0.** Un balayage de chaque sous-commande les ramène toutes à : code 3, UNE ligne `Erreur : …` sur stderr, aucune
  trace, avant toute connexion. Cas : `-d` inconnu et inventaire absent, dossier, YAML invalide, sans `routers`, avec
  `host`/`device_type` manquant, driver inconnu, mot de passe numérique, `port` hors bornes ; `--rules`, `--intent`,
  `--derogations`, `--expect` absents, dossiers, non UTF-8 ou invalides ; snapshot absent ou corrompu ; `--today` mal
  formé ; options incohérentes ; `--json`/`--html`/`--state-file` impossibles à écrire (contrôlé **avant** le script de
  changement pour `guard`, qui le découvrait à la fin) ; `known_hosts` dossier ou modifiable par d'autres ; `guard`
  sans `--yes` et sans entrée standard (EOFError). `tests/test_cli_usage_errors.py` : un test paramétré par cas (141
  tests), plus le processus réel ; 67 mutations, toutes détectées.
- **Une exception Python non gérée sortait en code 1** (lu comme ATTENTION) : voir « Modifié » (code 70).
- **Refus d'un audit qui ne lit rien** : fichier de règles ou d'intent vide (zéro règle, zéro assertion) sort en code 3 au
  lieu d'un « conforme » sur rien, comme `--config-dir` sans configuration lisible l'était déjà.

Phase C1 :

- **Option invalide : code 3, plus le 2 d'argparse (depuis la v0.1.0).** `netcheck --bogus`, un argument manquant, une
  valeur hors choix (`--host-keys ignore`) sortaient en code 2, le code par défaut d'argparse, or 2 veut dire ÉCHEC
  (`diff`, `check`, `assert`, `monitor`) : un pipeline ou `monitor.sh` prenait une faute de frappe pour une panne.
  Toute erreur d'analyse de la ligne de commande sort maintenant en code 3 (erreur d'usage), sur la sortie d'erreur,
  pour chaque sous-commande ; `--help` reste à 0. Un test par sous-commande, plus un test sur le processus réel.
- **Mutations : le bytecode périmé ne peut plus fausser un résultat.** Le harnais de mutation (hors dépôt) positionne
  `PYTHONDONTWRITEBYTECODE=1`, purge les `__pycache__` après chaque mutation et exige un passage à vide vert avant et
  après ; les 39 mutations de C1 ont été rejouées ainsi : toutes détectées.

Phase B4 :

- **`deny` IPv4 d'une prefix-list lu comme une autorisation (FRR).** `ebgp-pas-de-route-par-defaut` et
  `ebgp-pas-de-reinjection-de-prefixes-locaux` comptaient toute entrée IPv4, `deny` compris : `deny 0.0.0.0/0` (le bon
  filtre) ou `deny <notre préfixe>` étaient signalés comme des autorisations (faux positifs, code 2). Seuls les `permit`
  comptent, comme en IPv6 depuis la phase B3. Aucune entrée du gel de référence ne contient de `deny` : zéro écart du gel.
- **FRR : une séquence `deny` de route-map signalée à tort, et un route-map d'entrée jamais lu (faux positif et faux
  négatif).** `ebgp-pas-de-route-par-defaut` et `ebgp-pas-de-reinjection-de-prefixes-locaux` lisaient toutes les
  séquences d'un route-map sans regarder leur action : `route-map X deny 5` + une liste qui contient `0.0.0.0/0` (la
  manière classique de refuser la route par défaut) donnait une violation. Elles ne lisaient aussi que le PREMIER
  route-map en entrée d'un voisin : un voisin actif en IPv4 et en IPv6 avec un route-map par famille, dont celui de la
  seconde famille laissait passer `::/0`, était « conforme ». Maintenant : séquences `deny` ignorées, tous les route-maps
  d'entrée lus par famille, un membre de peer group ne masque son groupe que dans sa famille (même lecture que pour EOS,
  `drivers/ebgp_filters.py`). Zéro écart du gel ; 14 mutations de cette lecture détectées.
- **EOS : deux règles qui ne lisaient pas EOS (silence depuis la v0.3.0).** Une route par défaut ou un préfixe local
  autorisé en entrée d'un voisin eBGP d'un routeur EOS n'était signalé par aucune règle (« non applicable » : `drivers:
  [frr]`). Les deux règles sont maintenant `drivers: [frr, eos]`. Écart du gel : les réponses des cas EOS perdent deux
  lignes « non applicable » et les sondes d'ajout de `0.0.0.0/0` à `PL-EBGP-IN` sont désormais signalées.

### Connu

- **Peer groups SR Linux hors périmètre** : r5 n'a pas de BGP dans ce lab, donc aucun relevé réel ; les
  règles SR Linux n'ont pas de règle BGP à adapter pour l'instant.
- Les voisins sans numéro (`neighbor <interface> interface remote-as …`, FRR) ne sont pas lus (comme
  avant) : leur rendu n'a pas été relevé sur un équipement.
- Un membre dont aucun `remote-as` (propre ou du groupe) n'est connu n'ouvre pas de session : il n'est
  pas évalué.

- **OSPFv3 sans authentification sur le lien r4–r5** des trois labs : défaut connu (SR Linux refuse l'authentification
  OSPFv3 par keychain, EOS n'a que l'IPsec, FRR utilise la RFC 7166), signalé par la règle d'audit et couvert par une
  dérogation datée par lab (`derogations/*.yml`, expire le 2027-01-04, à renouveler ou à retirer).
- Le BGP des VRF n'est relevé par aucun driver (section `bgp_vrf`) ; OSPF n'est relevé que pour la VRF `default` ; les
  routes de lien local ne sont pas comparées par `diff`.
- `validated_by` d'une dérogation est un texte libre non vérifiable (signature en phase J). `monitor --derogations`
  lit la date du jour (pas de `--today`).
- Règles de politique d'entrée : aucune des deux règles (FRR, EOS) ne simule l'ordre des séquences d'un route-map ni
  des entrées d'une prefix-list : un `permit` est signalé même précédé d'un `deny` plus large (faux positif). Ouverture
  prévue en phase E : simuler l'ordre (la première entrée ou séquence qui correspond décide), pour les prefix-lists et
  les route-maps, FRR et EOS.
- `automation/labtools.py` (utilisé par `health.py`, `backup.py`, `drift.py`) accepte toujours n'importe quelle clé
  d'hôte (`AutoAddPolicy`) : ces scripts de lab sont hors du périmètre de netcheck (C2). La vérification des clés
  d'hôte de la phase C1 ne concerne que `netcheck`.
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
