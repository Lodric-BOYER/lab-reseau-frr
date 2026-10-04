"""Interface en ligne de commande : `python -m netcheck <sous-commande> ...`.

Sept sous-commandes : snapshot, list, diff, check, guard, assert, monitor.
"""
from __future__ import annotations

import argparse
import sys
from datetime import date, datetime
from pathlib import Path

import yaml

from netcheck import (
    assertions,
    collector,
    compliance,
    configdir,
    derogations,
    diff,
    expect,
    guard,
    hostkeys,
    inventory,
    monitor,
    report,
    snapshot,
    webhook,
)

DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "rules" / "default.yml"
REPORTS_DIR = inventory.REPO_ROOT / "reports"  # journaux de guard ; ignoré par Git (C4)


def _load_expectation(path: str | None) -> expect.Expectation | None:
    """Charge --expect s'il est fourni. Lève ValueError/OSError : l'appelant renvoie le code 3,
    avant toute action sur le réseau (un fichier d'attentes invalide ne doit jamais être
    découvert après l'exécution d'un script de changement)."""
    return expect.load_expect(path) if path else None


def _setup_host_keys(args: argparse.Namespace, inv: inventory.Inventory) -> bool:
    """Pose la politique de clés d'hôte du processus (phase C1), AVANT toute connexion. Renvoie False
    (message sur stderr) si elle est refusée : accept-new sur un inventaire non marqué `lab: true`,
    ou mode inconnu dans NETCHECK_HOST_KEYS. accept-new prévient à chaque usage."""
    try:
        policy = hostkeys.configure(getattr(args, "host_keys", None), getattr(args, "known_hosts", None),
                                    inv.lab)
    except hostkeys.HostKeyError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return False
    if policy.mode == "accept-new":
        print("Avertissement : --host-keys accept-new enregistre sans la vérifier la clé de tout équipement "
              "inconnu (premier contact). Réservé au lab.", file=sys.stderr)
    hostkeys.set_policy(policy)
    return True


def cmd_snapshot(args: argparse.Namespace) -> int:
    inv = inventory.load(args.devices, path=args.inventory)
    if not _setup_host_keys(args, inv):
        return 3
    results = collector.collect_all(inv.routers)

    try:
        out_dir = snapshot.save(args.name, results, force=args.force)
    except FileExistsError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 3

    print(f"Snapshot '{args.name}' écrit dans {out_dir.relative_to(inventory.REPO_ROOT)}")
    failed = 0
    for name, (ok, value) in sorted(results.items()):
        if ok:
            print(f"  {name:<8} OK")
        else:
            failed += 1
            print(f"  {name:<8} INJOIGNABLE : {value}")
    return 1 if failed else 0


def cmd_diff(args: argparse.Namespace) -> int:
    try:
        expectation = _load_expectation(args.expect)
        before = snapshot.load(args.before)
        after = snapshot.load(args.after)
    except (FileNotFoundError, ValueError, OSError) as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 3

    inv = inventory.load(path=args.inventory)
    mgmt = set(inv.management_interfaces)
    mgmt_vrfs = set(inv.management_vrfs)
    findings = diff.compare(before, after, management_interfaces=mgmt, management_vrfs=mgmt_vrfs)
    after_results = None
    if expectation:
        findings, after_results = expect.apply(findings, expectation, after, mgmt, mgmt_vrfs)
    verdict_label, code = diff.verdict(findings)

    report.print_terminal(findings, verdict_label, after_results=after_results)
    if args.json:
        report.write_json(findings, verdict_label, args.json, after_results)
        print(f"Constats écrits (JSON) : {args.json}")
    if args.html:
        report.write_html(findings, verdict_label, args.before, args.after, args.html, after_results)
        print(f"Rapport HTML écrit : {args.html}")
    return code


def _today(value: str | None) -> date:
    """La date du jour pour les dérogations : `--today AAAA-MM-JJ` (audit « à la date du », reproductible) ou
    l'horloge. C'est le SEUL endroit qui appelle l'horloge ; le moteur reçoit la date en paramètre."""
    return date.fromisoformat(value) if value else date.today()


def cmd_check(args: argparse.Namespace) -> int:
    rule_files = [args.rules] if isinstance(args.rules, str) else (args.rules or [DEFAULT_RULES_PATH])
    rules_path = ", ".join(str(p) for p in rule_files)
    try:
        rules = compliance.load_rule_files(rule_files)
        today = _today(getattr(args, "today", None))
        derogation_file = getattr(args, "derogations", None)
        derogation_set = derogations.load(derogation_file, rules, today) if derogation_file else None
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 3
    if getattr(args, "today", None) and not derogation_file:
        print("Erreur : --today n'a de sens qu'avec --derogations", file=sys.stderr)
        return 3

    if args.config_dir and args.snapshot:
        print("Erreur : --config-dir et --snapshot s'excluent (deux sources différentes)", file=sys.stderr)
        return 3
    if args.driver and not args.config_dir:
        print("Erreur : --driver n'a de sens qu'avec --config-dir", file=sys.stderr)
        return 3

    source = None
    file_warnings: list[compliance.ConfigWarning] = []
    if args.config_dir:
        # Hors ligne : on ne lit que des fichiers. L'inventaire sert à déduire le driver de chaque
        # équipement ; sans lui, --driver est obligatoire.
        try:
            inv = inventory.load(path=args.inventory)
        except (OSError, KeyError, TypeError, yaml.YAMLError) as e:
            if not args.driver:
                print(f"Erreur : inventaire illisible ({e.__class__.__name__}) : donnez --driver",
                      file=sys.stderr)
                return 3
            inv = inventory.Inventory(routers={})
        try:
            drivers = {n: r.get("driver", "frr") for n, r in inv.routers.items()}
            loaded = configdir.load(args.config_dir, drivers, args.driver)
        except configdir.ConfigDirError as e:
            print(f"Erreur : {e}", file=sys.stderr)
            return 3
        if not loaded.devices:
            for w in loaded.warnings:
                print(f"  {w.device}: {w.warning.reason}", file=sys.stderr)
            print("Erreur : aucune configuration lue : rien n'a été audité", file=sys.stderr)
            return 3
        devices, file_warnings = loaded.devices, loaded.warnings
        source = loaded.source_info(args.config_dir, args.driver)
    elif args.snapshot:
        inv = inventory.load(path=args.inventory)
        try:
            devices = snapshot.load(args.snapshot)
        except FileNotFoundError as e:
            print(f"Erreur : {e}", file=sys.stderr)
            return 3
    else:
        inv = inventory.load(path=args.inventory)
        if not _setup_host_keys(args, inv):
            return 3
        results = collector.collect_all(inv.routers)
        devices = {}
        for name, (ok, value) in results.items():
            if ok:
                devices[name] = value
            else:
                print(f"  {name:<8} INJOIGNABLE : {value}", file=sys.stderr)

    result = compliance.evaluate_config(
        rules, devices, management_interfaces=set(inv.management_interfaces), offline=bool(args.config_dir),
        management_vrfs=set(inv.management_vrfs), derogations=derogation_set, today=today)
    derogation_info = report.derogation_data(result)
    coverage = report.coverage_data(result)
    # Une ligne de configuration non lue (ou un fichier non audité) donne au minimum le code 1 : jamais
    # « conforme » sur une configuration que l'audit n'a pas entièrement lue.
    warnings = result.config_warnings + file_warnings
    compliant, code = compliance.verdict(result.violations, warnings)

    report.print_compliance_terminal(result.violations, compliant, result.not_applicable,
                                     config_warnings=warnings, source=source, derogations=derogation_info,
                                     coverage=coverage)
    if args.json:
        report.write_compliance_json(result.violations, compliant, args.json, result.not_applicable,
                                     warnings, source=source, derogations=derogation_info,
                                     coverage=coverage)
        print(f"Constats écrits (JSON) : {args.json}")
    if args.html:
        report.write_compliance_html(result.violations, compliant, rules_path, args.html,
                                     result.not_applicable, warnings, source=source,
                                     derogations=derogation_info, coverage=coverage)
        print(f"Rapport HTML écrit : {args.html}")
    return code


def cmd_guard(args: argparse.Namespace) -> int:
    """Encadre une intervention : ce sont les scripts --change / --rollback, fournis par
    l'utilisateur, qui modifient -- jamais netcheck lui-même (§5.5, C13). Voir netcheck/guard.py
    pour le déroulé et les codes retour (0 à 6)."""
    change_script = Path(args.change)
    rollback_script = Path(args.rollback) if args.rollback else None

    # --- Tout ce qui peut être refusé l'est ICI, avant la moindre action (code 3) -----------
    for label, script in (("changement", change_script), ("annulation", rollback_script)):
        if script is not None and not script.is_file():
            print(f"Erreur : script de {label} introuvable : {script}", file=sys.stderr)
            return guard.EXIT_USAGE
    if args.rollback_on is not None and rollback_script is None:
        print("Erreur : --rollback-on n'a de sens qu'avec --rollback", file=sys.stderr)
        return guard.EXIT_USAGE
    if args.script_timeout < 1 or args.wait < 1:
        print("Erreur : --script-timeout et --wait doivent être >= 1 seconde", file=sys.stderr)
        return guard.EXIT_USAGE
    rollback_on = args.rollback_on or "echec"
    try:
        expectation = _load_expectation(args.expect)
    except (ValueError, OSError) as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return guard.EXIT_USAGE
    inv = inventory.load(path=args.inventory)
    if not _setup_host_keys(args, inv):
        return guard.EXIT_USAGE

    # --- Les deux scripts sont affichés ENSEMBLE, une seule confirmation, rien d'exécuté avant.
    print("Scripts qui vont être exécutés (contenu affiché en clair : c'est votre fichier local) :")
    to_show = (("CHANGEMENT", change_script), ("ANNULATION", rollback_script))
    for number, (label, script) in enumerate(to_show, 1):
        print(f"\n[{number}/2] {label}" + (f" : {script}" if script else ""))
        if script is None:
            print("      (aucun --rollback : pas de retour arrière automatique)")
            continue
        print("--- contenu ---")
        print(script.read_text(encoding="utf-8", errors="replace").rstrip())
        print("---------------")
    if rollback_script is not None:
        print(f"\nRetour arrière si : verdict >= {rollback_on.upper()} (--rollback-on), ou script de "
              f"changement en échec/bloqué. Délai par script : {args.script_timeout}s.")
    if not args.yes:
        reply = input("\nConfirmer l'exécution de ces scripts ? [o/N] ").strip().lower()
        if reply not in ("o", "oui", "y", "yes"):
            print("Annulé : rien n'a été exécuté.")
            return guard.EXIT_USAGE

    mgmt = set(inv.management_interfaces)
    mgmt_vrfs = set(inv.management_vrfs)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    names = guard.SnapshotNames(f"guard_{stamp}_avant", f"guard_{stamp}_apres", f"guard_{stamp}_retour")

    def do_diff(before_name: str, after_name: str, use_expect: bool) -> guard.DiffResult:
        before, after = snapshot.load(before_name), snapshot.load(after_name)
        findings = diff.compare(before, after, management_interfaces=mgmt, management_vrfs=mgmt_vrfs)
        after_results = None
        if use_expect and expectation:
            findings, after_results = expect.apply(findings, expectation, after, mgmt, mgmt_vrfs)
        verdict_label, code = diff.verdict(findings)
        return guard.DiffResult(findings, verdict_label, code, after_results)

    ui = guard.UI()
    io = guard.GuardIO(
        snapshot=lambda name: snapshot.save(name, collector.collect_all(inv.routers), force=True),
        wait_convergence=lambda t: collector.wait_for_convergence(inv.routers, timeout=t),
        diff=do_diff,
        run_script=lambda path, timeout: guard.run_script(path, timeout, echo=ui.script_output),
    )
    journal = guard.Journal(
        REPORTS_DIR / f"guard_{stamp}.json",
        {
            "change_script": guard.script_record(change_script),
            "rollback_script": guard.script_record(rollback_script) if rollback_script else None,
            "options": {"rollback_on": rollback_on, "script_timeout": args.script_timeout,
                        "wait": args.wait, "expect": args.expect, "inventory": args.inventory},
            "snapshots": {"avant": names.before, "apres": names.after,
                          "retour": names.back if rollback_script else None},
        },
    )
    journal.write()

    with guard.sigterm_as_interrupt():
        result = guard.run_guard(
            change=change_script, rollback=rollback_script, rollback_on=rollback_on,
            wait=args.wait, script_timeout=args.script_timeout, io=io, ui=ui, journal=journal, names=names,
        )

    # Rapports --json/--html : le diff après changement (avec --expect), comme avant la phase D2.
    if result.diff_after is not None:
        d = result.diff_after
        if args.json:
            report.write_json(d.findings, d.verdict_label, args.json, d.after_results)
            print(f"Constats écrits (JSON) : {args.json}")
        if args.html:
            report.write_html(d.findings, d.verdict_label, names.before, names.after, args.html,
                              d.after_results)
            print(f"Rapport HTML écrit : {args.html}")
    return result.code


def cmd_assert(args: argparse.Namespace) -> int:
    """Vérifie l'état attendu (Phase C, SPEC_v3 §6, O2) : en direct ou hors ligne (--snapshot),
    identique aux autres sous-commandes de collecte/lecture."""
    try:
        intent = assertions.load_intent(args.intent)
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 3

    inv = inventory.load(path=args.inventory)
    if args.snapshot:
        try:
            devices = snapshot.load(args.snapshot)
        except FileNotFoundError as e:
            print(f"Erreur : {e}", file=sys.stderr)
            return 3
    else:
        if not _setup_host_keys(args, inv):
            return 3
        results = collector.collect_all(inv.routers)
        devices = {}
        for name, (ok, value) in results.items():
            if ok:
                devices[name] = value
            else:
                print(f"  {name:<8} INJOIGNABLE : {value}", file=sys.stderr)

    try:
        results = assertions.evaluate(intent, devices, management_interfaces=set(inv.management_interfaces),
                                  management_vrfs=set(inv.management_vrfs))
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 3
    verdict_label, code = assertions.verdict(results)

    report.print_assert_terminal(results, verdict_label)
    if args.json:
        report.write_assert_json(results, verdict_label, args.json)
        print(f"Constats écrits (JSON) : {args.json}")
    if args.html:
        report.write_assert_html(results, verdict_label, args.intent, args.html)
        print(f"Rapport HTML écrit : {args.html}")
    return code


def cmd_monitor(args: argparse.Namespace) -> int:
    """Surveillance planifiée, exécution unique (Phase E, SPEC_v3 §8). Lecture seule stricte :
    ni guard, ni script, ni rollback. Voir netcheck/monitor.py pour le statut, l'anti-bruit
    (--confirm) et les codes retour (0/1/2 = statut, 3 = refusé, 4 = verrou tenu)."""
    # --- Tout ce qui peut être refusé l'est ICI, avant la moindre collecte (code 3) -----------
    if args.confirm < 1:
        print("Erreur : --confirm doit être >= 1", file=sys.stderr)
        return monitor.EXIT_USAGE
    url = None
    try:
        url = webhook.from_environment()   # ne cite jamais l'URL dans ses erreurs
        baseline = snapshot.load(args.baseline)
        intent = assertions.load_intent(args.intent) if args.intent else None
        rules = compliance.load_rule_files(args.rules) if args.rules else None
        derogation_set = None
        if args.derogations:
            if rules is None:
                raise ValueError("--derogations n'a de sens qu'avec --rules")
            derogation_set = derogations.load(args.derogations, rules, date.today())
        inv = inventory.load(path=args.inventory)
    except Exception as e:  # noqa: BLE001 -- toute erreur de chargement est un refus, code 3
        print(f"Erreur : {webhook.redact(str(e), url)}", file=sys.stderr)
        return monitor.EXIT_USAGE
    if not _setup_host_keys(args, inv):
        return monitor.EXIT_USAGE

    webhook_format, format_warning = webhook.resolve_format(url, args.webhook_format)
    if format_warning:
        print(format_warning, file=sys.stderr)

    cfg = monitor.MonitorConfig(
        baseline_name=args.baseline, baseline=baseline, inventory=inv,
        state_file=Path(args.state_file) if args.state_file else REPORTS_DIR / monitor.STATE_FILENAME,
        reports_dir=REPORTS_DIR, intent=intent, intent_path=args.intent, rules=rules,
        rules_path=", ".join(args.rules) if args.rules else None, derogations=derogation_set,
        webhook_url=url, webhook_format=webhook_format,
        confirm=args.confirm, dry_run=args.dry_run, repo_root=inventory.REPO_ROOT,
    )
    io = monitor.MonitorIO(
        collect=lambda: collector.collect_all(inv.routers),
        send=webhook.post,
        now=lambda: datetime.now().astimezone(),
    )
    try:
        return monitor.run_monitor(cfg, io)
    except Exception as e:  # noqa: BLE001
        # Une exception Python non gérée sortirait en code 1, lu à tort comme « ATTENTION » par un
        # planificateur : un monitor qui n'a pas pu conclure doit le dire (code 3), sans alerte.
        print(f"Erreur interne : monitor n'a pas pu conclure ({type(e).__name__}) : "
              f"{webhook.redact(str(e), url)}", file=sys.stderr)
        return monitor.EXIT_USAGE


def cmd_list(_args: argparse.Namespace) -> int:
    snaps = snapshot.list_snapshots()
    if not snaps:
        print("Aucun snapshot.")
        return 0
    print(f"{'Nom':<20} {'Horodatage':<22} Équipements")
    for meta in snaps:
        print(f"{meta['name']:<20} {meta['timestamp']:<22} {len(meta['devices'])}")
    return 0


def _add_inventory_arg(sub_parser: argparse.ArgumentParser) -> None:
    """-i/--inventory : fichier d'inventaire (défaut : automation/inventory.yml). Ajouté à
    toute sous-commande qui contacte les équipements ou lit management_interfaces (Phase D1,
    nécessaire pour cibler automation/inventory-multivendor.yml sur le lab mixte)."""
    sub_parser.add_argument(
        "-i", "--inventory",
        help="fichier d'inventaire YAML (défaut : automation/inventory.yml)",
    )


def _add_host_keys_args(sub_parser: argparse.ArgumentParser) -> None:
    """--host-keys / --known-hosts (phase C1) : à toute sous-commande qui ouvre une connexion SSH.
    Il n'existe pas de valeur « ignore » : argparse la refuse."""
    sub_parser.add_argument(
        "--host-keys", choices=hostkeys.MODES, default=None,
        help="vérification des clés d'hôte SSH : strict (défaut ; la clé doit figurer dans le known_hosts "
             "dédié) ou accept-new (premier contact enregistré ; RÉSERVÉ au lab, refusé si l'inventaire ne "
             f"déclare pas `lab: true`) ; défaut aussi via {hostkeys.ENV_MODE}")
    sub_parser.add_argument(
        "--known-hosts", metavar="FICHIER", default=None,
        help=f"fichier known_hosts dédié (défaut : {hostkeys.ENV_KNOWN_HOSTS}, sinon "
             "~/.netcheck/known_hosts) ; le ~/.ssh/known_hosts de l'utilisateur n'est jamais lu")


def _add_expect_arg(sub_parser: argparse.ArgumentParser) -> None:
    """--expect : changements prévus (Phase D1) -- un constat prévu n'est plus une alerte, un
    changement prévu mais absent en devient une. Voir netcheck/expect.py pour le format."""
    sub_parser.add_argument(
        "--expect", help="fichier YAML des changements attendus (constats prévus, états attendus)",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m netcheck", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    p_snap = sub.add_parser("snapshot", help="capture l'état de tous les équipements (ou -d)")
    p_snap.add_argument("name", help="nom du snapshot (dossier snapshots/<name>/)")
    p_snap.add_argument("-d", "--devices", nargs="+", help="équipements ciblés (défaut : tous)")
    p_snap.add_argument("--force", action="store_true", help="écraser un snapshot existant")
    _add_inventory_arg(p_snap)
    _add_host_keys_args(p_snap)
    p_snap.set_defaults(func=cmd_snapshot)

    p_list = sub.add_parser("list", help="liste les snapshots existants")
    p_list.set_defaults(func=cmd_list)

    p_diff = sub.add_parser("diff", help="compare deux snapshots")
    p_diff.add_argument("before", help="nom du snapshot avant")
    p_diff.add_argument("after", help="nom du snapshot après")
    p_diff.add_argument("--json", help="écrire les constats au format JSON dans ce fichier")
    p_diff.add_argument("--html", help="écrire un rapport HTML autonome dans ce fichier")
    _add_expect_arg(p_diff)
    _add_inventory_arg(p_diff)
    p_diff.set_defaults(func=cmd_diff)

    p_check = sub.add_parser("check", help="audite la conformité des configurations")
    p_check.add_argument("--snapshot", help="auditer un snapshot existant (hors ligne, sans connexion)")
    p_check.add_argument(
        "--config-dir", action="append", metavar="DOSSIER",
        help="auditer des fichiers de configuration, sans aucun équipement : `DOSSIER/<équipement>.<ext>` ou "
             "`DOSSIER/<équipement>/<fichier>` ; répétable (un dossier ultérieur remplace un équipement "
             "du précédent). Les règles qui lisent l'état collecté sont alors non évaluables")
    p_check.add_argument(
        "--driver",
        help="avec --config-dir : driver de TOUS les fichiers (défaut : celui de l'inventaire, -i)")
    p_check.add_argument("--rules", action="append",
                         help=f"fichier de règles YAML (défaut : {DEFAULT_RULES_PATH.name}) ; répétable : "
                              "les règles de tous les fichiers s'appliquent (un identifiant en double "
                              "est refusé)")
    p_check.add_argument("--derogations", metavar="FICHIER",
                         help="fichier de dérogations YAML (voir netcheck/derogations.py) : les violations "
                              "qu'une dérogation en cours couvre gardent le statut DÉROGATION, sans effet "
                              "sur le code retour ; le rapport indique le chemin et l'empreinte SHA-256 "
                              "du fichier")
    p_check.add_argument("--today", metavar="AAAA-MM-JJ",
                         help="avec --derogations : date du jour à utiliser (audit à une date donnée, "
                              "reproductible) ; défaut : l'horloge")
    p_check.add_argument("--json", help="écrire les non-conformités au format JSON dans ce fichier")
    p_check.add_argument("--html", help="écrire un rapport HTML autonome dans ce fichier")
    _add_inventory_arg(p_check)
    _add_host_keys_args(p_check)
    p_check.set_defaults(func=cmd_check)

    p_guard = sub.add_parser(
        "guard", help="encadre une intervention (snapshot avant/après + diff, retour arrière optionnel)")
    p_guard.add_argument(
        "--change", required=True,
        help="script exécuté par guard (lui seul modifie, pas netcheck)",
    )
    p_guard.add_argument(
        "--rollback", help="script d'annulation, lancé UNE fois si le seuil est atteint ou si le "
                           "script de changement échoue ; le retour est ensuite prouvé par un diff vide",
    )
    p_guard.add_argument(
        "--rollback-on", choices=("echec", "attention"), default=None,
        help="verdict qui déclenche l'annulation (défaut : echec ; exige --rollback)",
    )
    p_guard.add_argument(
        "--script-timeout", type=int, default=guard.DEFAULT_SCRIPT_TIMEOUT,
        help=f"délai maximum par script, en secondes (défaut : {guard.DEFAULT_SCRIPT_TIMEOUT}) ; "
             "un script bloqué est arrêté et compte comme un échec",
    )
    p_guard.add_argument(
        "--wait", type=int, default=30,
        help="délai maximum de convergence, en secondes (défaut : 30)",
    )
    p_guard.add_argument(
        "--yes", action="store_true",
        help="ne pas demander de confirmation avant d'exécuter le script",
    )
    p_guard.add_argument("--json", help="écrire les constats au format JSON dans ce fichier")
    p_guard.add_argument("--html", help="écrire un rapport HTML autonome dans ce fichier")
    _add_expect_arg(p_guard)
    _add_inventory_arg(p_guard)
    _add_host_keys_args(p_guard)
    p_guard.set_defaults(func=cmd_guard)

    p_assert = sub.add_parser("assert", help="vérifie l'état attendu (Phase C, --intent)")
    p_assert.add_argument("--intent", required=True, help="fichier d'intent YAML (intents/*.yml)")
    p_assert.add_argument("--snapshot", help="vérifier un snapshot existant (hors ligne, sans connexion)")
    p_assert.add_argument("--json", help="écrire les résultats au format JSON dans ce fichier")
    p_assert.add_argument("--html", help="écrire un rapport HTML autonome dans ce fichier")
    _add_inventory_arg(p_assert)
    _add_host_keys_args(p_assert)
    p_assert.set_defaults(func=cmd_assert)

    p_monitor = sub.add_parser(
        "monitor", help="surveillance planifiée à exécution unique (cron/systemd) + alertes webhook")
    p_monitor.add_argument(
        "--baseline", required=True,
        help="snapshot de référence : l'état nominal, à refaire après un changement légitime")
    p_monitor.add_argument("--intent", help="fichier d'intent YAML (assertions) ; absent : non exécuté")
    p_monitor.add_argument("--rules", action="append",
                           help="fichier de règles de conformité YAML (répétable) ; absent : non exécuté")
    p_monitor.add_argument("--derogations", metavar="FICHIER",
                           help="fichier de dérogations YAML : les violations couvertes ne comptent pas dans "
                                "le statut (voir `check --derogations`)")
    p_monitor.add_argument("--state-file", help="fichier d'état (défaut : reports/monitor_state.json)")
    p_monitor.add_argument(
        "--webhook-format", choices=webhook.FORMATS, default=None,
        help="format du message (défaut : discord si l'URL est un webhook Discord, sinon generic ; "
             "l'URL vient de NETCHECK_WEBHOOK_URL)")
    p_monitor.add_argument(
        "--confirm", type=int, default=1, metavar="N",
        help="un nouveau statut doit être observé N fois de suite avant d'alerter, dans les deux sens "
             "(défaut : 1)")
    p_monitor.add_argument(
        "--dry-run", action="store_true",
        help="affiche le message qui serait envoyé ; n'envoie rien, n'écrit ni état ni rapport")
    _add_inventory_arg(p_monitor)
    _add_host_keys_args(p_monitor)
    p_monitor.set_defaults(func=cmd_monitor)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
