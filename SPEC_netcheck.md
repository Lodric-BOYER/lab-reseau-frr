# Cahier des charges : netcheck

Outil en ligne de commande qui **valide les changements réseau** (état avant/après) et **audite la conformité** des configurations.
Il est développé et testé sur le lab containerlab/FRR de ce dépôt, et conçu pour s'étendre à d'autres constructeurs.

---

## 1. Contexte et objectifs

Le dépôt contient déjà :
- un lab de 5 routeurs FRR 10.2.1 (OSPF dans 2 AS, eBGP filtré entre r3 et r4) décrit dans `lab.clab.yml` ;
- des scripts Netmiko dans `automation/` (`labtools.py`, `health.py`, `backup.py`, `drift.py`) ;
- un test de bout en bout, `test_lab.sh` (28 contrôles).

`netcheck` doit répondre à deux questions :
1. **« Mon intervention a-t-elle cassé quelque chose ? »** : capture de l'état avant et après, puis comparaison, avec un verdict clair.
2. **« Mes équipements respectent-ils les règles de sécurité et de conception ? »** : des règles écrites en YAML, appliquées aux configurations.

## 2. Contraintes impératives

| # | Contrainte |
|---|---|
| C1 | **Lecture seule.** L'outil n'envoie jamais de commande de configuration. Les commandes autorisées sont listées explicitement dans le code (liste blanche). Toute autre commande lève une erreur. |
| C2 | **Ne rien casser dans l'existant.** `automation/*.py` et `lab.clab.yml` ne changent pas de comportement, et `bash test_lab.sh --destroy` doit toujours donner 28/28. |
| C3 | **Identifiants hors du code** : variables d'environnement `NETCHECK_USER` et `NETCHECK_PASS`, avec repli sur `LAB_USER`/`LAB_PASS`, puis sur l'inventaire. |
| C4 | Les snapshots contiennent des configurations : `snapshots/` et `reports/` vont dans `.gitignore`. |
| C5 | Python ≥ 3.11. Dépendances limitées : netmiko, pyyaml, jinja2, rich, pytest (en dev). Pas de framework lourd. |
| C6 | Style : commentaires **en français, courts, au niveau des blocs** (pas de commentaire à chaque ligne). Docstrings en français. |
| C7 | Aucun `sudo`. Si une étape en demande un, s'arrêter et me donner la commande à taper. |
| C8 | Commits git petits et explicites, un par phase terminée. **Ne jamais faire de `git push` sans me demander.** |

## 3. Architecture attendue

```
netcheck/
├── __init__.py
├── __main__.py            # permet : python -m netcheck ...
├── cli.py                 # argparse : sous-commandes snapshot, list, diff, check, guard
├── inventory.py           # lecture de l'inventaire (réutilise automation/inventory.yml)
├── collector.py           # connexion SSH en parallèle + liste blanche des commandes
├── drivers/
│   ├── base.py            # interface commune d'un constructeur
│   └── frr.py             # FRR : commandes vtysh "... json" -> modèle normalisé
├── model.py               # dataclasses normalisées : Interface, Route, OspfNeighbor, BgpPeer, DeviceState
├── snapshot.py            # sauvegarde et chargement JSON des snapshots
├── diff.py                # comparaison de deux snapshots -> liste de Finding
├── compliance.py          # moteur de règles de conformité
├── report.py              # sorties : terminal (rich), JSON, HTML autonome (jinja2)
├── templates/report.html.j2
└── rules/default.yml      # règles de conformité par défaut
tests/
├── fixtures/              # vraies sorties JSON de FRR capturées sur le lab
├── test_drivers_frr.py
├── test_diff.py
├── test_compliance.py
└── integration.sh         # scénarios de bout en bout sur le lab déployé
```

Le driver FRR est le seul à implémenter. `drivers/base.py` doit rendre l'ajout d'un driver Cisco IOS ou FortiGate évident : documente dans la docstring ce qu'un nouveau driver doit fournir.

## 4. Données collectées (driver FRR)

| Donnée | Commande vtysh | Champs normalisés |
|---|---|---|
| Interfaces | `show interface json` | nom, état admin, état opérationnel, adresses IPv4 |
| Routes | `show ip route json` | préfixe, protocole, métrique, liste des next-hops (IP + interface), sélectionnée ou non |
| Voisins OSPF | `show ip ospf neighbor json` | router-id, état, interface |
| Sessions BGP | `show bgp ipv4 unicast summary json` | voisin, AS distant, état, préfixes reçus et envoyés |
| Préfixes BGP | `show bgp ipv4 unicast json` | préfixe, AS-path, next-hop, meilleur chemin |
| Configuration | `show running-config` | texte brut (pour l'audit de conformité) |

Attention aux variations de format JSON entre versions de FRR (ex. `nbrState` ou `state`) : gère les deux, et teste-les avec des fixtures.

## 5. Fonctionnalités

### 5.1 `netcheck snapshot <nom> [-d r1 r3]`
- Interroge tous les équipements (ou ceux listés) **en parallèle**. Un équipement injoignable est noté comme tel sans bloquer les autres.
- Écrit `snapshots/<nom>/<equipement>.json`, ainsi que `snapshots/<nom>/meta.json` (horodatage, équipements, erreurs, version de netcheck).
- Refuse d'écraser un snapshot existant, sauf avec `--force`.

### 5.2 `netcheck list`
Liste les snapshots, avec leur date et le nombre d'équipements.

### 5.3 `netcheck diff <avant> <apres> [--html fichier] [--json fichier]`
Compare les deux snapshots et produit une liste de constats, classés par gravité :

| Gravité | Exemples |
|---|---|
| **CRITIQUE** | session BGP qui n'est plus Established ; voisin OSPF perdu ; préfixe qui n'est plus joignable depuis un équipement qui l'avait ; interface passée à l'état down |
| **ATTENTION** | next-hop modifié ; métrique modifiée ; nombre de préfixes BGP reçus modifié ; protocole de la route modifié ; AS-path modifié |
| **INFO** | nouvelle route ; nouveau voisin ; lignes de configuration ajoutées ou retirées (diff unifié, en ignorant le bruit : version, bannières, lignes `!`) |

- Verdict global : **OK** (rien, ou uniquement INFO), **ATTENTION** ou **ÉCHEC** (au moins un CRITIQUE).
- Codes retour : 0 = OK, 1 = ATTENTION, 2 = ÉCHEC, 3 = erreur d'utilisation ou snapshot manquant.
- Sortie terminal lisible (tableau rich, couleurs par gravité), plus un résumé en une ligne.

### 5.4 `netcheck check [--snapshot <nom>] [--rules fichier] [--html fichier] [--json fichier]`
- Audite les configurations, soit en direct, soit **hors ligne** depuis un snapshot (sans connexion aux équipements).
- Règles en YAML. Chaque règle a : `id`, `description`, `severity` (critique, haute, moyenne, basse), `applies_to` (liste d'équipements, ou `all`), `kind`, et des paramètres propres au type.
- Types de règles (`kind`) à implémenter :

| kind | Rôle |
|---|---|
| `line_present` | une ligne (regex) doit exister dans la config |
| `line_absent` | une ligne (regex) ne doit pas exister |
| `bgp_neighbor_inbound_policy` | chaque voisin eBGP doit avoir une route-map (ou une prefix-list) en entrée |
| `bgp_neighbor_outbound_policy` | idem en sortie |
| `ospf_passive_on_interfaces` | les interfaces dont la description correspond à une regex (ex. `LAN`) doivent être en `ip ospf passive` |
| `interface_description_required` | toute interface avec une adresse IP (hors loopback) doit avoir une description |

- `rules/default.yml` contient au moins 8 règles cohérentes avec les bonnes pratiques et **toutes respectées par le lab dans son état initial**.
- Codes retour : 0 = conforme, 1 = non-conformités de gravité moyenne ou basse uniquement, 2 = au moins une non-conformité critique ou haute.

### 5.5 `netcheck guard --change <script.sh> [--wait 30]`
Encadre automatiquement une intervention : snapshot `avant`, exécution du script de changement, attente de convergence, snapshot `apres`, puis diff. Le nom des snapshots est horodaté. C'est la seule commande qui exécute quelque chose de modifiant, **et c'est le script fourni par l'utilisateur qui le fait, pas netcheck**. Affiche clairement ce qui va être exécuté.

### 5.6 Rapport HTML
Fichier **autonome** (CSS intégré, aucun appel externe) : en-tête avec le verdict en couleur, compteurs par gravité, tableau des constats filtrable par gravité et par équipement, diff de configuration repliable.

## 6. Tests et critères d'acceptation

### Tests unitaires (sans lab) : `pytest` doit être au vert
- Fixtures JSON **capturées sur le vrai lab** (pas inventées).
- Driver FRR : normalisation correcte des 5 types de données.
- Diff : un cas par type de constat, plus le verdict et le code retour.
- Conformité : chaque type de règle, en cas conforme et non conforme.

### Tests d'intégration sur le lab : `tests/integration.sh`
Chaque scénario : snapshot avant, changement, attente, snapshot après, diff, vérification du verdict, puis retour à l'état initial.

| # | Changement | Verdict attendu | Constats attendus |
|---|---|---|---|
| S1 | aucun | OK (code 0) | aucun constat CRITIQUE ni ATTENTION |
| S2 | `ip ospf cost 100` sur r1 eth2 | ATTENTION (code 1) | next-hop de r1 vers 10.2.0.0/16 et 192.168.2.0/24 modifié (via r2) ; ligne de config ajoutée |
| S3 | `ip link set eth2 down` sur r1 | ÉCHEC (code 2) | voisin OSPF r3 perdu sur r1, interface eth2 down |
| S4 | `neighbor 172.16.34.1 shutdown` sur r4 | ÉCHEC (code 2) | session BGP perdue sur r3 et r4, préfixes 192.168.x perdus |
| S5 | retrait de `192.168.1.0/24` de `PL-EBGP-OUT` sur r3 | ÉCHEC (code 2) | 192.168.1.0/24 perdu sur r4 et r5 ; préfixes reçus 2 → 1 |
| C1 | aucun (conformité) | conforme (code 0) | 0 non-conformité |
| C2 | suppression de `neighbor ... route-map RM-EBGP-IN in` sur r3 | code 2 | règle `bgp_neighbor_inbound_policy` violée sur r3 |

- Le script affiche un bilan `X/Y scénarios réussis` et sort avec le code 0 seulement si tout passe.
- `bash test_lab.sh --destroy` donne toujours 28/28.

## 7. Documentation
- Section « netcheck » dans le README : installation, les 5 commandes avec un exemple de sortie réelle, les codes retour, et comment écrire une règle.
- `netcheck/README.md` : architecture et **guide pour ajouter un driver constructeur**.
- Un avertissement clair : n'utiliser l'outil sur un réseau réel qu'avec une autorisation écrite.

## 8. Méthode de travail demandée
1. **Commence par lire le dépôt**, puis propose-moi un plan détaillé (fichiers, étapes, choix techniques) **avant d'écrire du code**. Attends ma validation.
2. Travaille par phases, en validant chacune avant de passer à la suivante :
   - Phase 1 : `model`, `collector`, driver FRR, `snapshot`, `list`, et les fixtures capturées sur le lab
   - Phase 2 : `diff`, sortie terminal et JSON, scénarios S1 à S5
   - Phase 3 : rapport HTML
   - Phase 4 : conformité (`check`, règles par défaut), scénarios C1 et C2
   - Phase 5 : `guard`, documentation, vérification finale (pytest, integration.sh, test_lab.sh)
3. À la fin de chaque phase : un résumé de ce qui a été fait, les tests passés, **et une explication pédagogique du code principal de la phase** (je dois pouvoir l'expliquer en entretien).
4. Si une spécification est ambiguë ou irréalisable, dis-le et propose une alternative au lieu de deviner.
