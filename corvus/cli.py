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
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
