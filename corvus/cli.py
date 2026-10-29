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

        summary = load_path(
            args.path,
            replay_dir=args.replay_dir,
            data_dir=args.data_dir,
            batch_size=args.batch_size,
        )
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
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
