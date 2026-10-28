"""Download pinned public evaluation datasets into data/ (stdlib only).

Usage (from the repo root):
    python3 scripts/fetch_datasets.py
    python3 scripts/fetch_datasets.py --update-checksums  # first run only

The script enumerates files at the pinned revision via the GitHub API,
downloads missing files via raw.githubusercontent.com, and verifies the
SHA-256 of every file against datasets/checksums.txt. Re-running skips
files that already verify (idempotent). With --update-checksums the
checksums file is rewritten from the downloaded files instead of being
enforced; inspect the diff and commit it.

Inputs: pinned revisions in DATASETS below. No dataset content is
committed; data/ is git ignored. No secrets are logged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parent.parent

DATASETS: list[dict[str, object]] = [
    {
        "name": "evtx-attack-samples",
        "repo": "sbousseaden/EVTX-ATTACK-SAMPLES",
        "rev": "4ceed2f4706daf601c212a8f91c113dd85349a2c",
        # Windows atomic samples: tactic folders + loose top-level samples.
        "prefixes": [
            "AutomatedTestingTools",
            "Command and Control",
            "Credential Access",
            "Defense Evasion",
            "Discovery",
            "Execution",
            "Lateral Movement",
            "Other",
            "Persistence",
            "Privilege Escalation",
        ],
        "include_root_samples": True,
        # Sample files only: tactic folders also hold .pcap/.log/.md/.txt.
        "extensions": [".evtx", ".etl"],
        # Relative to the data directory (not the repo root).
        "dest": "evtx-attack-samples",
    },
    {
        "name": "security-datasets",
        "repo": "OTRF/Security-Datasets",
        "rev": "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87",
        # Windows atomic datasets + their metadata, plus the single
        # APT29 day-1 compound host file (exact path, so the day-1
        # pcaps/zeek and all of day 2 stay unfetched).
        "prefixes": [
            "datasets/atomic/windows",
            "datasets/atomic/_metadata",
            "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip",
        ],
        "include_root_samples": False,
        # Relative to the data directory (not the repo root).
        "dest": "security-datasets",
    },
    {
        "name": "mitre-cti",
        "repo": "mitre/cti",
        "rev": "50be388e93819a5d20e71cbaaeccfda157abc846",
        # ATT&CK v20.0 Enterprise STIX bundle plus the license text.
        # Exact file paths (matched by equality in wanted()); no
        # directory prefix, so nothing else in the repo is fetched.
        "prefixes": [
            "enterprise-attack/enterprise-attack.json",
            "LICENSE.txt",
        ],
        "include_root_samples": False,
        # Relative to the data directory (not the repo root).
        "dest": "mitre-cti",
    },
]

MARKER = ".fetch_rev"
CHUNK = 1024 * 1024


def _request(url: str) -> urllib.request.Request:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "corvus-eval-fetch",
            "Accept": "application/vnd.github+json",
        },
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    return req


def list_files(repo: str, rev: str) -> list[str]:
    """List blob paths at a pinned revision via the Git trees API."""
    url = f"https://api.github.com/repos/{repo}/git/trees/{rev}?recursive=1"
    with urllib.request.urlopen(_request(url), timeout=60) as resp:
        tree = json.load(resp)
    if tree.get("truncated"):
        raise RuntimeError(f"file tree for {repo}@{rev} is truncated; aborting")
    return sorted(
        item["path"] for item in tree.get("tree", []) if item.get("type") == "blob"
    )


def wanted(
    paths: list[str],
    prefixes: list[str],
    root_samples: bool,
    extensions: list[str] | None = None,
) -> list[str]:
    """Filter a repo file list down to the Windows atomic subset we fetch."""
    wanted_suffixes = tuple(ext.lower() for ext in extensions) if extensions else None
    selected: list[str] = []
    for path in paths:
        if wanted_suffixes is not None and not path.lower().endswith(wanted_suffixes):
            continue
        if any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes):
            selected.append(path)
        elif root_samples and _is_root_sample(path):
            selected.append(path)
    return sorted(selected)


def _is_root_sample(path: str) -> bool:
    """Check for a loose top-level Windows sample (no directory prefix)."""
    return "/" not in path and path.lower().endswith((".evtx", ".etl"))


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(repo: str, rev: str, path: str, dest: Path) -> None:
    """Download one file at a pinned revision, atomically replacing dest."""
    url = f"https://raw.githubusercontent.com/{repo}/{rev}/{quote(path, safe='/')}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(_request(url), timeout=120) as resp:
        with open(tmp, "wb") as handle:
            for chunk in iter(lambda: resp.read(CHUNK), b""):
                handle.write(chunk)
    os.replace(tmp, dest)


def read_checksums(path: Path) -> dict[str, str]:
    """Read a checksums file into {posix rel path: hex digest}."""
    mapping: dict[str, str] = {}
    if not path.exists():
        return mapping
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, rel = line.partition("  ")
        if digest and rel:
            mapping[rel.strip()] = digest.strip()
    return mapping


def write_checksums(path: Path, mapping: dict[str, str]) -> None:
    header = (
        "# SHA-256 checksums for files under data/ (see README.md).\n"
        '# Format: "<hex>  <posix path relative to the repo root'
        ', e.g. data/...>".\n'
        "# Generated by: python3 scripts/fetch_datasets.py --update-checksums\n"
    )
    body = "".join(f"{mapping[key]}  {key}\n" for key in sorted(mapping))
    path.write_text(header + body, encoding="utf-8")


def fetch_dataset(
    dataset: dict[str, object],
    data_dir: Path,
    checks: dict[str, str],
    update: bool,
) -> tuple[dict[str, str], list[str]]:
    """Ensure one dataset is on disk.

    Returns ({rel path: sha256} entries, [rel paths with no recorded
    checksum]). In verify mode a checksum mismatch triggers one
    re-download; a second mismatch raises.
    """
    repo = str(dataset["repo"])
    rev = str(dataset["rev"])
    dest = data_dir / str(dataset["dest"])
    rel_dest = dest.relative_to(REPO_ROOT).as_posix()
    prefixes = list(dataset["prefixes"])  # type: ignore[union-attr]
    root_samples = bool(dataset.get("include_root_samples"))
    raw_extensions = dataset.get("extensions")
    extensions = (
        [str(suffix) for suffix in raw_extensions]  # type: ignore[union-attr]
        if raw_extensions is not None
        else None
    )

    expected = wanted(list_files(repo, rev), prefixes, root_samples, extensions)
    if not expected:
        raise RuntimeError(f"no files selected for {repo}@{rev}; aborting")

    entries: dict[str, str] = {}
    unverified: list[str] = []
    for path in expected:
        target = dest / path
        rel = f"{rel_dest}/{path}"
        if target.is_file():
            actual = sha256_of(target)
            if update or checks.get(rel) == actual:
                entries[rel] = actual
                continue
            if rel not in checks:
                entries[rel] = actual
                unverified.append(rel)
                continue
            print(f"re-downloading (checksum mismatch): {rel}", file=sys.stderr)
            target.unlink()
        print(f"downloading: {repo}@{rev[:12]} {path}")
        download(repo, rev, path, target)
        entries[rel] = sha256_of(target)
        if update:
            continue
        if rel not in checks:
            unverified.append(rel)
        elif entries[rel] != checks[rel]:
            raise RuntimeError(f"checksum mismatch after re-download: {rel}")

    marker = dest / MARKER
    if marker.is_file() and marker.read_text(encoding="utf-8").strip() != rev:
        print(
            f"warning: {dest} fetched at another revision; refreshed", file=sys.stderr
        )
    marker.write_text(rev + "\n", encoding="utf-8")
    return entries, unverified


def verify_extra_files(dest: Path, expected_rels: set[str]) -> list[str]:
    """Find files under dest that are neither expected nor dotfiles."""
    rel_dest = dest.relative_to(REPO_ROOT).as_posix()
    extras: list[str] = []
    for file in sorted(dest.rglob("*")):
        if not file.is_file() or file.name.startswith("."):
            continue
        rel = f"{rel_dest}/{file.relative_to(dest).as_posix()}"
        if rel not in expected_rels:
            extras.append(rel)
    return extras


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--checksums", default="datasets/checksums.txt")
    parser.add_argument(
        "--update-checksums",
        action="store_true",
        help="rewrite the checksums file from downloaded files",
    )
    args = parser.parse_args(argv)

    data_dir = (REPO_ROOT / args.data_dir).resolve()
    checks_path = (REPO_ROOT / args.checksums).resolve()
    if data_dir != (REPO_ROOT / "data").resolve():
        print("refusing: --data-dir must resolve to the repo data/ directory")
        return 2
    checks = read_checksums(checks_path)

    # In update mode the checksums file is rebuilt from exactly what the
    # pinned revisions contain, so stale keys from older layouts vanish.
    merged = {} if args.update_checksums else dict(checks)
    pending: list[str] = []
    try:
        for dataset in DATASETS:
            entries, unverified = fetch_dataset(
                dataset, data_dir, checks, args.update_checksums
            )
            pending.extend(unverified)
            rel_data = data_dir.relative_to(REPO_ROOT).as_posix()
            dest_prefix = f"{rel_data}/{dataset['dest']}/"
            for key in [key for key in merged if key.startswith(dest_prefix)]:
                del merged[key]
            merged.update(entries)
            if not args.update_checksums:
                dest_dir = data_dir / str(dataset["dest"])
                extras = verify_extra_files(dest_dir, set(entries))
                if extras:
                    print("unlisted files under data/:")
                    for extra in extras:
                        print(f"  {extra}")
                    print("re-run with --update-checksums or remove them.")
                    return 1
        if args.update_checksums:
            write_checksums(checks_path, merged)
            print(f"wrote {len(merged)} checksums to {checks_path}")
            return 0
        if pending:
            print(f"no checksums recorded for {len(pending)} file(s); first 10:")
            for rel in pending[:10]:
                print(f"  {rel}")
            print("re-run with --update-checksums, review the diff, and commit it.")
            return 1
        print(f"verified {len(merged)} files against {checks_path}")
    except (OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
