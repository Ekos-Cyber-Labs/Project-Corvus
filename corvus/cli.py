"""Corvus command line interface."""

import argparse
import os

from corvus import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(prog="corvus", description="Corvus CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("version", help="Print the Corvus version.")

    db = sub.add_parser("db", help="Database commands.")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    migrate = db_sub.add_parser("migrate", help="Apply pending SQL migrations.")
    migrate.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )

    attack = sub.add_parser("attack", help="ATT&CK dictionary commands.")
    attack_sub = attack.add_subparsers(dest="attack_command", required=True)
    build = attack_sub.add_parser(
        "build", help="Build the compact ATT&CK dictionary from the STIX bundle."
    )
    build.add_argument(
        "--bundle",
        default="data/mitre-cti/enterprise-attack/enterprise-attack.json",
        help="Pinned STIX bundle path (default: %(default)s).",
    )
    build.add_argument(
        "--out",
        default="data/attack/enterprise.json",
        help="Compact dictionary output path (default: %(default)s).",
    )

    replay = sub.add_parser("replay", help="Replay dataset commands.")
    replay_sub = replay.add_subparsers(dest="replay_command", required=True)
    load = replay_sub.add_parser(
        "load", help="Normalize dataset files into Parquet under data/replay/."
    )
    load.add_argument("path", help="Dataset file or directory to load.")
    load.add_argument(
        "--replay-dir",
        default="data/replay",
        help="Replay Parquet store directory (default: data/replay).",
    )
    load.add_argument(
        "--data-dir",
        default="data",
        help="Dataset root for data-relative provenance paths (default: data).",
    )
    load.add_argument(
        "--batch-size",
        type=int,
        default=5000,
        help="Rows buffered before one Parquet write (default: 5000).",
    )
    detect = replay_sub.add_parser(
        "detect",
        help="Evaluate Sigma rules over the replay store into findings.",
    )
    detect.add_argument(
        "--rules-dir",
        default="data/sigma/rules",
        help="Sigma rules directory (default: data/sigma/rules).",
    )
    detect.add_argument(
        "--replay-dir",
        default="data/replay",
        help="Replay Parquet store directory (default: data/replay).",
    )
    detect.add_argument(
        "--attack",
        default="data/attack/enterprise.json",
        help="Compact ATT&CK dictionary (default: data/attack/enterprise.json).",
    )

    correlate = sub.add_parser("correlate", help="Deterministic correlation commands.")
    correlate_sub = correlate.add_subparsers(dest="correlate_command", required=True)
    replay_corr = correlate_sub.add_parser(
        "replay",
        help="Correlate replay findings into Postgres incidents (upsert by "
        "correlation_key; measurements with different settings should "
        "use a fresh database).",
    )
    replay_corr.add_argument(
        "--replay-dir",
        default="data/replay",
        help="Replay Parquet store directory (default: data/replay).",
    )
    replay_corr.add_argument(
        "--attack",
        default="data/attack/enterprise.json",
        help="Compact ATT&CK dictionary (default: data/attack/enterprise.json).",
    )
    replay_corr.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )

    triage = sub.add_parser("triage", help="Glimmer triage queue commands.")
    triage_sub = triage.add_subparsers(dest="triage_command", required=True)
    triage_enqueue = triage_sub.add_parser(
        "enqueue",
        help="Enqueue one triage job per incident lacking a triage analysis.",
    )
    triage_enqueue.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    triage_enqueue.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Enqueue at most this many incidents (default: all).",
    )
    triage_run = triage_sub.add_parser(
        "run",
        help="Claim and run triage jobs (Glimmer condenses raw evidence).",
    )
    triage_run.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process at most this many jobs (default: until empty).",
    )
    triage_run.add_argument(
        "--purpose",
        default="triage",
        choices=["triage"],
        help="Model-call purpose and analysis stage (default: %(default)s).",
    )
    triage_run.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    triage_run.add_argument(
        "--replay-dir",
        default="data/replay",
        help="Replay Parquet store for incident evidence (default: data/replay).",
    )
    triage_run.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="Max in-flight jobs (default: the backend TRIAGE_CONCURRENCY).",
    )
    triage_run.add_argument(
        "--lease-seconds",
        type=float,
        default=None,
        help=(
            "Queue lease per claim in seconds"
            " (default: the purpose read timeout"
            " TRIAGE_READ_TIMEOUT_SECONDS)."
        ),
    )

    analyze = sub.add_parser(
        "analyze",
        help="Run Glimmer triage when missing, then the Spark agent loop.",
    )
    analyze.add_argument(
        "--incident",
        type=int,
        required=True,
        help="Incident id to analyze.",
    )
    analyze.add_argument(
        "--lang",
        default="en",
        choices=["en", "es"],
        help="Answer language for the verdict (default: %(default)s).",
    )
    analyze.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    analyze.add_argument(
        "--replay-dir",
        default="data/replay",
        help="Replay Parquet store for incident evidence (default: data/replay).",
    )

    evaluation = sub.add_parser("eval", help="Evaluation harness commands.")
    eval_sub = evaluation.add_subparsers(dest="eval_command", required=True)
    eval_run = eval_sub.add_parser(
        "run",
        help="Run load -> detect -> correlate over the replay store and "
        "write eval/reports/latest.md and latest.json.",
    )
    eval_run.add_argument(
        "--replay-dir",
        default="data/replay",
        help="Replay Parquet store directory (default: data/replay).",
    )
    eval_run.add_argument(
        "--rules-dir",
        default="data/sigma/rules",
        help="Sigma rules directory (default: data/sigma/rules).",
    )
    eval_run.add_argument(
        "--attack",
        default="data/attack/enterprise.json",
        help="Compact ATT&CK dictionary (default: data/attack/enterprise.json).",
    )
    eval_run.add_argument(
        "--ground-truth",
        default="data/ground_truth.json",
        help="Ground-truth mapping (default: data/ground_truth.json).",
    )
    eval_run.add_argument(
        "--benign-hosts", type=int, default=4, help="Benign hosts (default: 4)."
    )
    eval_run.add_argument(
        "--benign-hours", type=int, default=24, help="Benign hours (default: 24)."
    )
    eval_run.add_argument(
        "--benign-seed", type=int, default=7, help="Benign seed (default: 7)."
    )
    eval_run.add_argument(
        "--report-md",
        default="eval/reports/latest.md",
        help="Markdown report path (default: eval/reports/latest.md).",
    )
    eval_run.add_argument(
        "--report-json",
        default="eval/reports/latest.json",
        help="JSON report path (default: eval/reports/latest.json).",
    )
    eval_run.add_argument(
        "--baseline",
        default="eval/reports/latest.json",
        help=(
            "Committed baseline for deltas (the git HEAD version is used "
            "for in-repo paths; default: eval/reports/latest.json)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "db" and args.db_command == "migrate":
        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        from corvus.state.migrate import migrate

        applied = migrate(args.database_url)
        if applied:
            for name in applied:
                print(f"applied {name}")
        else:
            print("up to date")
        return 0
    if args.command == "attack" and args.attack_command == "build":
        from corvus.attack import build as attack_build

        stats = attack_build.build_from_files(args.bundle, args.out)
        print(attack_build.format_summary(stats))
        return 0
    if args.command == "replay" and args.replay_command == "load":
        from corvus.adapters.replay import format_summary, load_path

        try:
            summary = load_path(
                args.path,
                replay_dir=args.replay_dir,
                data_dir=args.data_dir,
                batch_size=args.batch_size,
            )
        except ValueError as exc:
            parser.error(str(exc))
        print(format_summary(summary, args.replay_dir))
        return 0
    if args.command == "replay" and args.replay_command == "detect":
        import json

        from corvus.adapters.replay import format_write_summary, write_findings
        from corvus.attack import load_dictionary
        from corvus.detect import load_rules
        from corvus.detect.engine import evaluate

        attack = load_dictionary(args.attack)
        with open(args.attack, encoding="utf-8") as handle:
            attack_version = str(
                json.loads(handle.read()).get("attack_version", "v20.0")
            ).removeprefix("v")
        compiled, load_stats = load_rules(args.rules_dir)
        print(
            f"rules: {load_stats.parsed_rules} parsed from "
            f"{load_stats.files} files, {len(compiled)} evaluate, "
            f"{sum(load_stats.skipped.values())} skipped"
        )
        matches, infos, eval_stats = evaluate(args.replay_dir, compiled)
        write_summary = write_findings(
            args.replay_dir, compiled, matches, infos, attack, attack_version
        )
        print(format_write_summary(write_summary, args.replay_dir))
        print(
            f"detect: {eval_stats.rules_run} rules run, "
            f"{eval_stats.matches} matches on {eval_stats.events_matched} events "
            f"({eval_stats.events_scanned} scanned) in {eval_stats.seconds:.1f}s, "
            f"peak {eval_stats.peak_rss_mb:.0f} MiB; "
            f"{len(eval_stats.rules_errored)} runtime errors"
        )
        for rule_id in sorted(eval_stats.rules_errored):
            print(f"  error {rule_id}: {eval_stats.rules_errored[rule_id]}")
        return 0
    if args.command == "correlate" and args.correlate_command == "replay":
        from collections import Counter

        from corvus.correlate.replay import correlate_replay_store
        from corvus.settings import get_settings
        from corvus.state.incidents import (
            stored_correlation_keys,
            stored_incident_count,
            upsert_incidents,
        )
        from corvus.state.migrate import migrate

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        settings = get_settings()
        migrate(args.database_url)
        incidents = correlate_replay_store(
            replay_dir=args.replay_dir,
            attack_path=args.attack,
            settings=settings,
        )
        upsert_incidents(args.database_url, incidents)
        floors = Counter(incident["severity_floor"] for incident in incidents)
        factor4 = sum(
            1
            for incident in incidents
            if incident["severity_factors"]["factor_4_success_vs_attempt"].get("fired")
        )
        print(
            f"correlated {len(incidents)} incidents "
            f"(floors {dict(sorted(floors.items()))}, "
            f"factor 4 fired on {factor4})"
        )
        print(f"stored {stored_incident_count(args.database_url)} incidents")
        stale = len(
            stored_correlation_keys(args.database_url)
            - {incident["correlation_key"] for incident in incidents}
        )
        print(
            f"{stale} stored incidents were not produced by this run "
            "(stale keys from earlier settings are kept; use a fresh "
            "database when settings change)"
        )
        return 0
    if args.command == "triage" and args.triage_command == "enqueue":
        from corvus.llm.triage_worker import enqueue_triage_jobs

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        job_ids = enqueue_triage_jobs(args.database_url, limit=args.limit)
        print(f"enqueued {len(job_ids)} triage jobs")
        return 0
    if args.command == "triage" and args.triage_command == "run":
        from corvus.llm.triage_worker import run_loop

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        counts = run_loop(
            args.database_url,
            purpose=args.purpose,
            limit=args.limit,
            concurrency=args.concurrency,
            lease_seconds=args.lease_seconds,
            replay_dir=args.replay_dir,
        )
        done = counts.get("resolved", 0)
        print(f"triage run: {done} resolved, counts {counts}")
        return 0
    if args.command == "analyze":
        from corvus.adapters.replay import ReplayAdapter
        from corvus.llm.agent import TriageMissingError, read_analysis, run_analysis
        from corvus.llm.config import LlmConfigError, get_backend

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        database_url = args.database_url
        try:
            analysis_backend = get_backend("analysis")
        except LlmConfigError as exc:
            # No cloud key (or other backend misconfiguration): say
            # so and end pending_ai instead of crashing.
            print(f"analysis backend unavailable ({exc}); ending pending_ai")
            return 0
        triage = read_analysis(database_url, args.incident, "triage")
        if triage is None or triage["status"] != "resolved":
            from corvus.llm.triage_worker import process_incident_triage

            try:
                # Scoped to the requested incident only: no other
                # incident is enqueued, claimed, or spent on.
                process_incident_triage(
                    database_url, args.incident, replay_dir=args.replay_dir
                )
            except LlmConfigError as exc:
                print(f"triage backend unavailable ({exc}); ending pending_ai")
                return 0
        try:
            outcome = run_analysis(
                args.incident,
                lang=args.lang,
                database_url=database_url,
                adapter=ReplayAdapter(args.replay_dir),
                replay_dir=args.replay_dir,
                backend=analysis_backend,
            )
        except TriageMissingError as exc:
            print(f"{exc}; ending pending_ai")
            return 0
        except ValueError as exc:
            parser.error(str(exc))
        print(f"status: {outcome.status}")
        if outcome.verdict is not None:
            print(
                f"verdict: {outcome.verdict.verdict}"
                f" (severity {outcome.verdict.severity_id},"
                f" confidence {outcome.verdict.confidence:.2f})"
            )
        elif outcome.payload is not None:
            print(f"detail: {outcome.payload}")
        for error in outcome.errors:
            print(f"error: {error.get('code')}: {error.get('message')}")
        print("trace:")
        print(f"  {'step':>4}  {'tool':<22}  {'tokens':>6}")
        for step in outcome.steps:
            print(f"  {step.step_number:>4}  {step.tool:<22}  {step.tokens:>6}")
        print(
            f"tries: {outcome.attempts} (attempts),"
            f" tool calls: {outcome.tool_calls_used},"
            f" loop tokens: {outcome.loop_tokens}"
        )
        return 0
    if args.command == "eval" and args.eval_command == "run":
        from eval.harness import main as harness_main

        return harness_main(
            [
                "--replay-dir",
                args.replay_dir,
                "--rules-dir",
                args.rules_dir,
                "--attack",
                args.attack,
                "--ground-truth",
                args.ground_truth,
                "--benign-hosts",
                str(args.benign_hosts),
                "--benign-hours",
                str(args.benign_hours),
                "--benign-seed",
                str(args.benign_seed),
                "--report-md",
                args.report_md,
                "--report-json",
                args.report_json,
                "--baseline",
                args.baseline,
            ]
        )
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
