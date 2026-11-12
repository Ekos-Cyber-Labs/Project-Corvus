"""Corvus command line interface."""

import argparse
import os
from typing import Any

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
    clean_pseudo = db_sub.add_parser(
        "clean-pseudonyms",
        help="Report (and with --apply, delete) unreferenced file-like "
        "pseudonym rows; counts only, never values.",
    )
    clean_pseudo.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    clean_pseudo.add_argument(
        "--apply",
        action="store_true",
        help="Delete the unreferenced candidate rows (default: dry run).",
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
    load_linux = replay_sub.add_parser(
        "load-linux",
        help="Normalize Wazuh Linux archives into Parquet under data/replay-linux/.",
    )
    load_linux.add_argument("path", help="Archive file or directory to load.")
    load_linux.add_argument(
        "--replay-dir",
        default="data/replay-linux",
        help="Linux replay store directory (default: data/replay-linux).",
    )
    load_linux.add_argument(
        "--data-dir",
        default="data",
        help="Dataset root for data-relative provenance paths (default: data).",
    )
    load_linux.add_argument(
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

    sweep = sub.add_parser(
        "sweep",
        help="Loop poll-then-analyze: poll Wazuh, select pending incidents "
        "by policy, run triage plus Spark analysis on them.",
    )
    sweep.add_argument(
        "--once",
        action="store_true",
        help="Run a single cycle and stop (default: loop every interval).",
    )
    sweep.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Seconds between cycles; loop until SIGINT/SIGTERM "
        "(default: 300, env SWEEP_INTERVAL_SECONDS, minimum 30).",
    )
    sweep.add_argument(
        "--min-floor",
        default=None,
        choices=["low", "medium", "high", "critical"],
        help="Analyze incidents at or above this floor "
        "(default: high, env SWEEP_MIN_FLOOR).",
    )
    sweep.add_argument(
        "--max-analyses",
        type=int,
        default=None,
        help="Analyses per cycle, at most (default: 5, env SWEEP_MAX_ANALYSES, 0..50).",
    )
    sweep.add_argument(
        "--triage-workers",
        type=int,
        default=None,
        help="Concurrent analysis threads per cycle "
        "(default: 4, env SWEEP_TRIAGE_WORKERS, 1..16; 1 is sequential).",
    )
    sweep.add_argument(
        "--always-analyze-injection",
        dest="always_analyze_injection",
        action="store_true",
        default=None,
        help="Always analyze incidents with an injection signal "
        "(default on, env SWEEP_ALWAYS_INJECTION).",
    )
    sweep.add_argument(
        "--no-always-analyze-injection",
        dest="always_analyze_injection",
        action="store_false",
        help="Do not prefer injection-signal incidents.",
    )
    sweep.add_argument(
        "--spend-cap-usd",
        type=float,
        default=None,
        help="USD spend cap for this sweep (default: $SPEND_CAP_USD).",
    )
    sweep.add_argument(
        "--lang",
        default="en",
        choices=["en", "es"],
        help="Answer language for verdicts (default: %(default)s).",
    )
    sweep.add_argument(
        "--store",
        default="data/live",
        help="Live replay-format store directory (default: data/live).",
    )
    sweep.add_argument(
        "--replay-dir",
        default=None,
        help="Replay Parquet store for incident evidence"
        " (default: the --store directory).",
    )
    sweep.add_argument(
        "--since",
        default=None,
        help="Seed cursor when no checkpoint is stored (ISO-8601).",
    )
    sweep.add_argument(
        "--with-archives",
        action="store_true",
        help="Fetch surrounding archive events for each new incident.",
    )
    sweep.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )

    rules = sub.add_parser("rules", help="Learned-rule commands.")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    bt = rules_sub.add_parser(
        "backtest",
        help="Backtest one candidate Sigma rule file against a target.",
    )
    bt.add_argument("file", help="Candidate Sigma YAML file.")
    bt.add_argument(
        "--event-uid",
        action="append",
        default=[],
        help="Target event uid (repeatable; or use --host/--start/--end).",
    )
    bt.add_argument("--host", default=None, help="Target host for a time window.")
    bt.add_argument("--start", default=None, help="Window start (ISO-8601 or ms).")
    bt.add_argument("--end", default=None, help="Window end (ISO-8601 or ms).")
    bt.add_argument(
        "--baseline-dir",
        default="data/replay-linux-baseline",
        help="Benign baseline store (default: %(default)s).",
    )
    bt.add_argument(
        "--chain-dir",
        default="data/replay-linux-chain1",
        help="Attack-chain store (default: %(default)s).",
    )
    add = rules_sub.add_parser(
        "add", help="Backtest and store a candidate rule (refused when rejected)."
    )
    add.add_argument("file", help="Candidate Sigma YAML file.")
    add.add_argument(
        "--event-uid",
        action="append",
        default=[],
        help="Cited target event uid (repeatable).",
    )
    add.add_argument(
        "--incident",
        type=int,
        required=True,
        help="Incident id the rule was learned from (required: the store "
        "re-runs the backtest against this incident's stored events).",
    )
    add.add_argument("--producer", required=True, help="Producer name (free field).")
    add.add_argument(
        "--producer-version", required=True, help="Producer version (free field)."
    )
    add.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    add.add_argument(
        "--baseline-dir",
        default="data/replay-linux-baseline",
        help="Benign baseline store (default: %(default)s).",
    )
    add.add_argument(
        "--chain-dir",
        default="data/replay-linux-chain1",
        help="Attack-chain store (default: %(default)s).",
    )
    lst = rules_sub.add_parser("list", help="List stored rules (newest first).")
    lst.add_argument("--status", default=None, help="Filter by status (optional).")
    lst.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    show = rules_sub.add_parser("show", help="Show one stored rule as JSON.")
    show.add_argument("rule_id", type=int, help="Stored rule id.")
    show.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    propose = rules_sub.add_parser(
        "propose",
        help="Propose one Sigma rule for an incident (Muse Spark loop).",
    )
    propose.add_argument("--incident", type=int, required=True, help="Incident id.")
    propose.add_argument(
        "--max-usd",
        type=float,
        default=None,
        help="Per-proposal USD cap on top of SPEND_CAP_USD (default: none).",
    )
    propose.add_argument(
        "--lang",
        default="en",
        choices=["en", "es"],
        help="Answer language for the rationale (default: %(default)s).",
    )
    propose.add_argument(
        "--replay-dir",
        default="data/replay-linux-chain1",
        help="Replay store holding the incident events.",
    )
    propose.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    approve = rules_sub.add_parser(
        "approve", help="Move a stored rule to a new status (approver required)."
    )
    approve.add_argument("rule_id", type=int, help="Stored rule id.")
    approve.add_argument(
        "--to",
        required=True,
        choices=["shadow", "active", "archived"],
        help="Target status (allowed moves only).",
    )
    approve.add_argument(
        "--approver",
        required=True,
        help="Approver name (must be in $CORVUS_RULE_APPROVERS when set).",
    )
    approve.add_argument("--reason", required=True, help="Approval reason.")
    approve.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    rollback = rules_sub.add_parser(
        "rollback", help="Roll a shadow or active rule back instantly."
    )
    rollback.add_argument("rule_id", type=int, help="Stored rule id.")
    rollback.add_argument(
        "--approver",
        required=True,
        help="Approver name (must be in $CORVUS_RULE_APPROVERS when set).",
    )
    rollback.add_argument("--reason", required=True, help="Rollback reason.")
    rollback.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    shadow_eval = rules_sub.add_parser(
        "shadow-eval",
        help="Evaluate shadow rules over a replay store (no model calls).",
    )
    shadow_eval.add_argument(
        "--replay-dir",
        default="data/replay-linux-chain1-off",
        help="Replay store to evaluate over.",
    )
    shadow_eval.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    export_wazuh = rules_sub.add_parser(
        "export-wazuh",
        help="Translate a stored rule to Wazuh XML plus an offline parity bundle.",
    )
    export_wazuh.add_argument("rule_id", type=int, help="Stored rule id.")
    export_wazuh.add_argument("--out", required=True, help="Bundle directory to write.")
    export_wazuh.add_argument(
        "--mode",
        default="shadow",
        choices=["shadow", "active"],
        help="Wazuh rule mode (default: %(default)s).",
    )
    export_wazuh.add_argument(
        "--chain-dir",
        default="data/replay-linux-chain1",
        help="Attack-chain store (default: %(default)s).",
    )
    export_wazuh.add_argument(
        "--baseline-dir",
        default="data/replay-linux-baseline",
        help="Benign baseline store (default: %(default)s).",
    )
    export_wazuh.add_argument(
        "--data-dir",
        default="data",
        help=(
            "Dataset root for replay provenance files; live stores read each"
            " event's stored raw_data instead (default: %(default)s)."
        ),
    )
    export_wazuh.add_argument(
        "--ruleset-dir",
        default="data/wazuh-ruleset",
        help="Wazuh ruleset directory (default: %(default)s).",
    )
    export_wazuh.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    logtest = rules_sub.add_parser(
        "logtest",
        help="Run bundle lines through wazuh-logtest and write a parity report.",
    )
    logtest.add_argument("rule_id", type=int, help="Stored rule id.")
    logtest.add_argument("--bundle", required=True, help="Bundle directory.")
    logtest.add_argument(
        "--out",
        default=None,
        help="Parity report path (default: <bundle>/parity_report.json).",
    )
    logtest.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Logtest wall-clock budget in seconds (default: %(default)s).",
    )
    logtest.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    ledger_check = rules_sub.add_parser(
        "ledger-check",
        help="Print llm_attempts and spend rows in a window grouped by "
        "purpose and model (with --expect-zero, exit non-zero if any).",
    )
    ledger_check.add_argument("--start", required=True, help="Window start (ISO-8601).")
    ledger_check.add_argument("--end", required=True, help="Window end (ISO-8601).")
    ledger_check.add_argument(
        "--expect-zero",
        action="store_true",
        help="Exit non-zero when any ledger row exists in the window.",
    )
    ledger_check.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    prove = rules_sub.add_parser(
        "prove",
        help="Learning proof: stored rule fires on the control store, "
        "detection spends nothing, rollback silences it.",
    )
    prove.add_argument(
        "--chain-dir",
        default="data/replay-linux-chain1",
        help="Attack-chain store the rule is stored from.",
    )
    prove.add_argument(
        "--control-dir",
        default="data/replay-linux-chain1-off",
        help="Control-variant store the rule must fire on.",
    )
    prove.add_argument(
        "--baseline-dir",
        default="data/replay-linux-baseline",
        help="Benign baseline store.",
    )
    prove.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )

    wazuh = sub.add_parser("wazuh", help="Live Wazuh indexer commands.")
    wazuh_sub = wazuh.add_subparsers(dest="wazuh_command", required=True)
    poll = wazuh_sub.add_parser(
        "poll",
        help="Poll new alerts from the Wazuh indexer into findings and "
        "incidents (no model calls; resumable via the checkpoints table).",
    )
    poll.add_argument(
        "--once",
        action="store_true",
        help="Run a single cycle and stop (default when --interval is absent).",
    )
    poll.add_argument(
        "--interval",
        type=float,
        default=None,
        help="Seconds between cycles; loop until SIGINT (default: run once).",
    )
    poll.add_argument(
        "--store",
        default="data/live",
        help="Live replay-format store directory (default: data/live).",
    )
    poll.add_argument(
        "--since",
        default=None,
        help="Seed cursor when no checkpoint is stored (ISO-8601).",
    )
    poll.add_argument(
        "--with-archives",
        action="store_true",
        help="Fetch surrounding archive events for each new incident.",
    )
    poll.add_argument(
        "--archives-limit",
        type=int,
        default=200,
        help="Archive events per incident, at most (default: 200).",
    )
    poll.add_argument(
        "--page-size",
        type=int,
        default=500,
        help="Alerts per indexer page, at most 1000 (default: 500).",
    )
    poll.add_argument(
        "--max-docs",
        type=int,
        default=5000,
        help="Documents per cycle, at most (default: 5000).",
    )
    poll.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    poll.add_argument(
        "--attack",
        default="data/attack/enterprise.json",
        help="Compact ATT&CK dictionary (default: data/attack/enterprise.json).",
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
    eval_gate2 = eval_sub.add_parser(
        "gate2",
        help="Gate-2 learning evidence: a stored rule fires on an unseen "
        "variant run (positive) and stays silent on the rule-absent "
        "control (negative), with anti-leak checks first.",
    )
    eval_gate2.add_argument("--rule", type=int, required=True, help="Stored rule id.")
    eval_gate2.add_argument(
        "--train-gt", required=True, help="Training-run ground truth file."
    )
    eval_gate2.add_argument(
        "--positive", required=True, help="Variant export directory (rule present)."
    )
    eval_gate2.add_argument(
        "--positive-gt", required=True, help="Variant ground truth for --positive."
    )
    eval_gate2.add_argument(
        "--negative", required=True, help="Variant export directory (rule absent)."
    )
    eval_gate2.add_argument(
        "--negative-gt", required=True, help="Variant ground truth for --negative."
    )
    eval_gate2.add_argument(
        "--baseline-dir",
        default="data/replay-linux-baseline",
        help="Benign baseline store or export (default: %(default)s).",
    )
    eval_gate2.add_argument(
        "--train-dir",
        default="data/replay-linux-chain1",
        help="Training replay store holding the cited events (default: %(default)s).",
    )
    eval_gate2.add_argument(
        "--out",
        default="eval/reports/gate2.md",
        help="Markdown report path (default: %(default)s).",
    )
    eval_gate2.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
    )
    eval_llm = eval_sub.add_parser(
        "llm",
        help="Run the paid model-path eval (Glimmer triage + Spark analysis) "
        "and write eval/reports/llm_latest.md and llm_latest.json.",
    )
    eval_llm.add_argument(
        "--min-floor",
        type=int,
        default=4,
        help="Only incidents at or above this severity floor (default: 4).",
    )
    eval_llm.add_argument(
        "--analyze",
        type=int,
        default=1,
        help="Spark-analyze the first N selected incidents (default: 1).",
    )
    eval_llm.add_argument(
        "--lang",
        default="en",
        choices=["en", "es"],
        help="Answer language for the verdict (default: %(default)s).",
    )
    eval_llm.add_argument(
        "--labels",
        default="blind",
        choices=["visible", "blind"],
        help="Detector-label mode for model payloads (default: %(default)s).",
    )
    eval_llm.add_argument(
        "--max-usd",
        type=float,
        default=None,
        help="Hard USD cap on top of SPEND_CAP_USD; the run stops when reached.",
    )
    eval_llm.add_argument(
        "--concurrency",
        type=int,
        default=None,
        help="Max in-flight triage jobs (default: the TRIAGE_CONCURRENCY).",
    )
    eval_llm.add_argument(
        "--adversarial",
        action="store_true",
        help="Also run the eval/adversarial/ injection fixtures.",
    )
    eval_llm.add_argument(
        "--replay-dir",
        default="data/replay",
        help="Replay Parquet store directory (default: data/replay).",
    )
    eval_llm.add_argument(
        "--report-md",
        default="eval/reports/llm_latest.md",
        help="Markdown report path (default: eval/reports/llm_latest.md).",
    )
    eval_llm.add_argument(
        "--report-json",
        default="eval/reports/llm_latest.json",
        help="JSON report path (default: eval/reports/llm_latest.json).",
    )
    eval_llm.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="Postgres URL (default: $DATABASE_URL).",
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
    if args.command == "db" and args.db_command == "clean-pseudonyms":
        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        from corvus.guardrails.pseudonymizer import purge_file_pseudonyms

        counts = purge_file_pseudonyms(args.database_url, apply=args.apply)
        mode = "applied" if args.apply else "dry run"
        print(
            f"clean-pseudonyms ({mode}): {counts['candidates']} candidates, "
            f"{counts['referenced_kept']} referenced kept, "
            f"{counts['deleted']} deleted"
        )
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
    if args.command == "replay" and args.replay_command == "load-linux":
        from corvus.adapters.replay.linux_loader import (
            format_linux_summary,
            load_linux_path,
        )

        try:
            linux_summary = load_linux_path(
                args.path,
                replay_dir=args.replay_dir,
                data_dir=args.data_dir,
                batch_size=args.batch_size,
            )
        except ValueError as exc:
            parser.error(str(exc))
        print(format_linux_summary(linux_summary, args.replay_dir))
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
    if args.command == "sweep":
        from corvus.live.sweep import (
            effective_policy,
            run_sweep_loop,
            try_acquire_sweep_lock,
        )
        from corvus.normalize.wazuh import parse_wazuh_time

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        if args.once and args.interval is not None:
            parser.error("pass --once or --interval, not both")
        try:
            policy = effective_policy(
                min_floor=args.min_floor,
                max_analyses=args.max_analyses,
                always_analyze_injection=args.always_analyze_injection,
                spend_cap_usd=args.spend_cap_usd,
                lang=args.lang,
                interval_seconds=args.interval,
                triage_workers=args.triage_workers,
            )
        except ValueError as exc:
            parser.error(str(exc))
        sweep_since_ms: int | None = None
        if args.since is not None:
            try:
                sweep_since_ms = parse_wazuh_time(args.since)
            except ValueError as exc:
                parser.error(f"--since is not a time: {exc}")
        missing = [
            name
            for name in (
                "WAZUH_INDEXER_URL",
                "WAZUH_INDEXER_USER",
                "WAZUH_INDEXER_PASSWORD",
            )
            if not os.environ.get(name)
        ]
        if missing:
            # Names only: values (credentials) never appear in errors.
            parser.error("sweep needs from the environment: " + ", ".join(missing))
        lock_conn: Any = None
        try:
            lock_conn = try_acquire_sweep_lock(args.database_url)
            if lock_conn is None:
                print("another sweep is already running; exiting")
                return 0
            return run_sweep_loop(
                database_url=args.database_url,
                store_dir=args.store,
                replay_dir=args.replay_dir,
                policy=policy,
                once=args.once,
                since_ms=sweep_since_ms,
                with_archives=args.with_archives,
            )
        finally:
            try:
                if lock_conn is not None:
                    lock_conn.close()
            except Exception:
                pass
    if args.command == "rules" and args.rules_command == "ledger-check":
        from corvus.learning.ledger import ledger_check

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        try:
            return ledger_check(
                args.database_url,
                args.start,
                args.end,
                expect_zero=args.expect_zero,
            )
        except ValueError as exc:
            parser.error(str(exc))
        return 2
    if args.command == "wazuh" and args.wazuh_command == "poll":
        import random
        import signal
        import time

        import httpx2

        from corvus.adapters.wazuh.adapter import WazuhAdapter
        from corvus.adapters.wazuh.client import IndexerError, ReadOnlyIndexerClient
        from corvus.live.poll import run_poll_cycle
        from corvus.normalize.wazuh import parse_wazuh_time

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        if args.once and args.interval is not None:
            parser.error("pass --once or --interval, not both")
        if args.interval is not None and args.interval <= 0:
            parser.error("--interval must be positive seconds")
        since_ms: int | None = None
        if args.since is not None:
            try:
                since_ms = parse_wazuh_time(args.since)
            except ValueError as exc:
                parser.error(f"--since is not a time: {exc}")
        missing = [
            name
            for name in (
                "WAZUH_INDEXER_URL",
                "WAZUH_INDEXER_USER",
                "WAZUH_INDEXER_PASSWORD",
            )
            if not os.environ.get(name)
        ]
        if missing:
            # Names only: values (credentials) never appear in errors.
            parser.error("wazuh poll needs from the environment: " + ", ".join(missing))
        url = os.environ["WAZUH_INDEXER_URL"]
        user = os.environ["WAZUH_INDEXER_USER"]
        password = os.environ["WAZUH_INDEXER_PASSWORD"]
        ca_path = os.environ.get("WAZUH_INDEXER_CA") or None
        try:
            client = ReadOnlyIndexerClient(
                url,
                user,
                password,
                ca_path=ca_path,
                timeout=httpx2.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0),
            )
        except (ValueError, FileNotFoundError) as exc:
            parser.error(f"wazuh indexer misconfigured: {exc}")
        adapter = WazuhAdapter(client, database_url=args.database_url)
        stop = False

        def _request_stop(signum: int, frame: object) -> None:
            nonlocal stop
            stop = True

        signal.signal(signal.SIGINT, _request_stop)
        signal.signal(signal.SIGTERM, _request_stop)

        def _sleep(seconds: float) -> None:
            deadline = time.monotonic() + seconds
            while not stop and time.monotonic() < deadline:
                time.sleep(min(0.2, deadline - time.monotonic()))

        failures = 0
        while True:
            try:
                cycle = run_poll_cycle(
                    adapter=adapter,
                    database_url=args.database_url,
                    store_dir=args.store,
                    attack_path=args.attack,
                    page_size=args.page_size,
                    max_docs=args.max_docs,
                    since_ms=since_ms,
                    with_archives=args.with_archives,
                    archives_limit=args.archives_limit,
                )
            except IndexerError as exc:
                failures += 1
                print(f"poll failed ({exc}); backing off")
                if args.interval is None and failures > 3:
                    return 1
                _sleep(min(2.0**failures, 30.0) + random.uniform(0, 1.0))
                if args.interval is None:
                    continue
                if stop:
                    return 1
                continue
            except ValueError as exc:
                parser.error(str(exc))
            failures = 0
            print(
                f"poll cycle: alerts={cycle.alerts_seen}"
                f" events={cycle.events_written}"
                f" findings={cycle.findings_written}"
                f" learned={cycle.learned_findings}"
                f" shadow={cycle.shadow_findings}"
                f" unknown={cycle.unknown_learned}"
                f" future_dated={cycle.future_dated}"
                f" incidents={cycle.incidents_upserted}"
                f" (total {cycle.incidents_total})"
                f" archives={cycle.archives_added}"
            )
            if args.with_archives and cycle.archives_empty:
                print("archives index returned nothing for this cycle")
            if args.interval is None or stop:
                break
            _sleep(args.interval)
        try:
            client.close()
        except Exception:
            pass
        return 0
    if args.command == "eval" and args.eval_command == "llm":
        from eval.llm_harness import main as llm_harness_main

        return llm_harness_main(
            [
                "--min-floor",
                str(args.min_floor),
                "--analyze",
                str(args.analyze),
                "--lang",
                args.lang,
                "--labels",
                args.labels,
                *(["--max-usd", str(args.max_usd)] if args.max_usd is not None else []),
                *(
                    ["--concurrency", str(args.concurrency)]
                    if args.concurrency is not None
                    else []
                ),
                *([] if not args.adversarial else ["--adversarial"]),
                "--replay-dir",
                args.replay_dir,
                "--report-md",
                args.report_md,
                "--report-json",
                args.report_json,
                "--database-url",
                args.database_url or "",
            ]
        )
    if args.command == "eval" and args.eval_command == "gate2":
        from eval.gate2 import main as gate2_main

        return gate2_main(
            [
                "--rule",
                str(args.rule),
                "--train-gt",
                args.train_gt,
                "--positive",
                args.positive,
                "--positive-gt",
                args.positive_gt,
                "--negative",
                args.negative,
                "--negative-gt",
                args.negative_gt,
                "--baseline-dir",
                args.baseline_dir,
                "--train-dir",
                args.train_dir,
                "--out",
                args.out,
                "--database-url",
                args.database_url or "",
            ]
        )
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
    if args.command == "rules" and args.rules_command == "backtest":
        import json
        from pathlib import Path

        from corvus.learning.backtest import backtest

        try:
            sigma_text = Path(args.file).read_text(encoding="utf-8")
        except OSError as exc:
            parser.error(f"cannot read rule file: {exc}")
        if args.event_uid:
            target: dict[str, object] = {"event_uids": list(args.event_uid)}
        elif args.host is not None or args.start is not None or args.end is not None:
            target = {"host": args.host, "start": args.start, "end": args.end}
        else:
            parser.error("give --event-uid (repeatable) or --host/--start/--end")
        result = backtest(
            sigma_text,
            target,  # type: ignore[arg-type]
            baseline_dir=args.baseline_dir,
            chain_dir=args.chain_dir,
        )
        print(json.dumps(result.to_dict(), indent=2))
        print(f"verdict: {'accepted' if result.accepted else 'rejected'}")
        return 0 if result.accepted else 1
    if args.command == "rules" and args.rules_command == "add":
        from pathlib import Path

        from corvus.learning.rules import add_candidate
        from corvus.state.migrate import migrate

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        if not args.event_uid:
            parser.error("give at least one --event-uid citing the target event")
        try:
            sigma_text = Path(args.file).read_text(encoding="utf-8")
        except OSError as exc:
            parser.error(f"cannot read rule file: {exc}")
        migrate(args.database_url)
        # No caller-side backtest here: the store re-runs the verifier
        # itself against the incident's stored events and refuses when
        # the fresh result is not accepted.
        try:
            row = add_candidate(
                args.database_url,
                sigma_text,
                args.incident,
                list(args.event_uid),
                None,
                args.producer,
                args.producer_version,
                chain_dir=args.chain_dir,
                baseline_dir=args.baseline_dir,
            )
        except ValueError as exc:
            print(f"rejected: {exc}")
            return 1
        print(
            f"stored candidate id={row['id']} "
            f"native_rule_id={row['native_rule_id']} version={row['version']}"
        )
        return 0
    if args.command == "rules" and args.rules_command == "list":
        from corvus.learning.rules import list_rules

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        for row in list_rules(args.database_url, status=args.status):
            lineage = row["lineage"] or {}
            print(
                f"{row['id']:>6}  {row['status']:<11}  v{row['version']}  "
                f"native={row['native_rule_id']}  "
                f"{lineage.get('sigma_rule_id')}  {row['title']}"
            )
        return 0
    if args.command == "rules" and args.rules_command == "show":
        import json

        from corvus.learning.rules import get_rule

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        stored = get_rule(args.database_url, args.rule_id)
        if stored is None:
            parser.error(f"unknown rule id {args.rule_id}")
        assert stored is not None
        print(json.dumps(stored, indent=2, sort_keys=True, default=str))
        return 0
    if args.command == "rules" and args.rules_command == "propose":
        import tempfile
        import zipfile
        from pathlib import Path as _Path

        from corvus.learning.propose import propose_rule, spark_model_fn
        from corvus.learning.rule_tools import build_search_index
        from corvus.llm.config import LlmConfigError, get_backend
        from corvus.state.migrate import migrate

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        try:
            backend = get_backend("analysis")
        except LlmConfigError as exc:
            parser.error(f"analysis backend unavailable ({exc})")
        migrate(args.database_url)
        index: list = []
        zip_path = _Path("data/sigma/sigma_all_rules.zip")
        if zip_path.is_file():
            tmpdir = tempfile.TemporaryDirectory(prefix="lnx-corpus")
            with zipfile.ZipFile(zip_path) as bundle:
                names = [
                    name
                    for name in bundle.namelist()
                    if name.startswith("rules/linux/")
                ]
                for name in names:
                    rule_path = _Path(tmpdir.name) / name
                    rule_path.parent.mkdir(parents=True, exist_ok=True)
                    rule_path.write_bytes(bundle.read(name))
            index = build_search_index(_Path(tmpdir.name) / "rules" / "linux")
        try:
            proposal_outcome = propose_rule(
                incident_id=args.incident,
                database_url=args.database_url,
                replay_dir=args.replay_dir,
                backend=backend,
                model_fn=spark_model_fn(backend),
                max_usd=args.max_usd,
                lang=args.lang,
                rules_index=index,
            )
        except ValueError as exc:
            parser.error(str(exc))
        print(f"status: {proposal_outcome.status}")
        print(
            f"rounds: {len(proposal_outcome.rounds)}"
            f" (attempts: {proposal_outcome.attempts},"
            f" tool calls: {proposal_outcome.tool_calls_used},"
            f" loop tokens: {proposal_outcome.loop_tokens},"
            f" spend: ${proposal_outcome.spend_usd:.6f})"
        )
        for item in proposal_outcome.rounds:
            print(f"  round {item.round_number}: {list(item.codes)}")
        if proposal_outcome.rule_db_id is not None:
            print(
                f"stored candidate id={proposal_outcome.rule_db_id}"
                f" sigma={proposal_outcome.sigma_rule_id}"
            )
        for error in proposal_outcome.errors:
            print(f"error: {error.get('code')}: {error.get('message')}")
        return 0 if proposal_outcome.status == "accepted" else 1
    if args.command == "rules" and args.rules_command == "approve":
        from corvus.learning.rules import transition_rule
        from corvus.state.migrate import migrate

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        migrate(args.database_url)
        try:
            row = transition_rule(
                args.database_url,
                args.rule_id,
                args.to,
                approver=args.approver,
                reason=args.reason,
            )
        except ValueError as exc:
            parser.error(str(exc))
        print(f"rule {row['id']} is now {row['status']}")
        return 0
    if args.command == "rules" and args.rules_command == "rollback":
        from corvus.learning.rules import roll_back_rule
        from corvus.state.migrate import migrate

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        migrate(args.database_url)
        try:
            row = roll_back_rule(
                args.database_url,
                args.rule_id,
                approver=args.approver,
                reason=args.reason,
            )
        except ValueError as exc:
            parser.error(str(exc))
        print(f"rule {row['id']} is now {row['status']}")
        return 0
    if args.command == "rules" and args.rules_command == "shadow-eval":
        from corvus.learning.shadow import evaluate_shadow
        from corvus.state.migrate import migrate

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        migrate(args.database_url)
        shadow_report = evaluate_shadow(args.replay_dir, args.database_url)
        print(
            f"shadow eval: enabled={shadow_report.enabled},"
            f" rules={shadow_report.rules_evaluated},"
            f" findings={len(shadow_report.findings)}"
        )
        for rule_db_id in sorted(shadow_report.hits_by_rule):
            print(f"  rule {rule_db_id}: {shadow_report.hits_by_rule[rule_db_id]} hits")
        if shadow_report.skipped:
            print(f"  skipped: {shadow_report.skipped}")
        return 0
    if args.command == "rules" and args.rules_command == "export-wazuh":
        import json

        from corvus.learning.export_wazuh import (
            EXPECTED_NAME,
            ExportError,
            build_bundle,
            write_bundle,
        )
        from corvus.learning.rules import get_rule, list_rules
        from corvus.state.migrate import migrate

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        migrate(args.database_url)
        stored = get_rule(args.database_url, args.rule_id)
        if stored is None:
            parser.error(f"unknown rule id {args.rule_id}")
        assert stored is not None
        store_ids = [
            row["native_rule_id"]
            for row in list_rules(args.database_url)
            if isinstance(row["native_rule_id"], int)
        ]
        try:
            from corvus.attack import load_dictionary

            attack_dict = load_dictionary()
        except Exception:
            attack_dict = None
        try:
            wazuh_bundle = build_bundle(
                row=stored,
                mode=args.mode,
                chain_dir=args.chain_dir,
                baseline_dir=args.baseline_dir,
                data_dir=args.data_dir,
                ruleset_dir=args.ruleset_dir,
                store_ids=store_ids,
                attack=attack_dict,
            )
        except ExportError as exc:
            print(f"export refused: {exc}")
            return 1
        try:
            out = write_bundle(wazuh_bundle, args.out)
        except ExportError as exc:
            print(f"export refused: {exc}")
            return 1
        expected = json.loads(wazuh_bundle[EXPECTED_NAME])
        print(f"bundle written to {out}")
        for name in sorted(wazuh_bundle):
            print(f"  {name}")
        print(
            f"inputs={expected['counts']['inputs']}"
            f" target={expected['counts']['target']}"
            f" baseline={expected['counts']['baseline']}"
            f" must_fire={expected['counts']['must_fire']}"
        )
        return 0
    if args.command == "rules" and args.rules_command == "logtest":
        import json
        from pathlib import Path as _Path

        from corvus.learning.export_wazuh import EXPECTED_NAME, INPUTS_NAME
        from corvus.learning.logtest import (
            LogtestError,
            SubprocessLogtestRunner,
            compare_parity,
            parse_logtest_result,
        )
        from corvus.learning.rules import get_rule
        from corvus.state.migrate import migrate

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        migrate(args.database_url)
        stored = get_rule(args.database_url, args.rule_id)
        if stored is None:
            parser.error(f"unknown rule id {args.rule_id}")
        assert stored is not None
        bundle_dir = _Path(args.bundle)
        try:
            expected = json.loads((bundle_dir / EXPECTED_NAME).read_text())
            inputs = [
                json.loads(line)
                for line in (bundle_dir / INPUTS_NAME).read_text().splitlines()
                if line.strip()
            ]
        except OSError as exc:
            parser.error(f"cannot read bundle: {exc}")
        if expected.get("sigma_rule_id") != stored["lineage"].get("sigma_rule_id"):
            parser.error("bundle is for a different stored rule (sigma id mismatch)")
        if not expected.get("native_rule_ids", [stored["native_rule_id"]])[:1] == [
            stored["native_rule_id"]
        ]:
            parser.error("bundle is for a different stored rule (native id mismatch)")
        try:
            runner = SubprocessLogtestRunner()
            answers = runner.run(inputs, timeout_s=args.timeout)
            verdicts = [
                parse_logtest_result(answer, rule_ids=set(expected["native_rule_ids"]))
                for answer in answers
            ]
            report = compare_parity(expected["lines"], verdicts)
        except LogtestError as exc:
            print(f"logtest failed: {exc}")
            return 1
        out_path = _Path(args.out) if args.out else bundle_dir / "parity_report.json"
        payload = {
            "rule_db_id": stored["id"],
            "sigma_rule_id": stored["lineage"].get("sigma_rule_id"),
            "native_rule_ids": expected["native_rule_ids"],
            "bundle": str(bundle_dir),
            **report.to_dict(),
        }
        try:
            out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        except OSError as exc:
            parser.error(f"cannot write parity report: {exc}")
        print(f"parity: {report.agreement}/{len(report.lines)} agree")
        for line in report.disagreements:
            print(
                f"  disagree key={line.key} uid={line.event_uid}"
                f" must_fire={line.must_fire} fired={line.fired}"
            )
        return 0 if not report.disagreements else 1
    if args.command == "rules" and args.rules_command == "prove":
        import json

        from corvus.learning.proof import run_proof
        from corvus.state.migrate import migrate

        if not args.database_url:
            parser.error("DATABASE_URL is not set (or pass --database-url).")
        migrate(args.database_url)
        try:
            proof_report = run_proof(
                args.database_url,
                chain_dir=args.chain_dir,
                control_dir=args.control_dir,
                baseline_dir=args.baseline_dir,
            )
        except ValueError as exc:
            print(f"proof FAILED: {exc}")
            return 1
        print(json.dumps(proof_report.to_dict(), indent=2))
        print(
            f"proof passed: rule {proof_report.rule_db_id} fires"
            f" {proof_report.control_hits} times on the control store"
            f" (n={proof_report.control_n}), silent after rollback,"
            " detection added"
            f" {proof_report.attempts_after - proof_report.attempts_before}"
            " attempts and"
            f" {proof_report.spend_after - proof_report.spend_before} spend rows"
        )
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
