"""Derive ATT&CK ground truth per dataset file (stdlib only).

Usage (from the repo root, after fetching):
    python3 eval/ground_truth.py --out data/ground_truth.json

Reads the fetched datasets under data/ (see datasets/README.md) and
writes a JSON mapping of posix paths relative to data/ to per-file
objects: {"dataset": ..., "techniques": [...], "tactics": [...],
"label_source": "otrf-metadata" | "otrf-folder" | "evtx-folder" |
"evtx-filename"}. OTRF files no metadata file links map to empty
techniques with "otrf-folder" (tactic only).
Files whose ground truth cannot be determined map to empty lists
(unknown is never guessed).

Sources:
- EVTX-ATTACK-SAMPLES: tactic-level ground truth from the top-level
  folder name; filename technique tokens (T####[.###]) are kept when
  present. At the pinned revision only a handful of file names carry
  a technique token; evtx_data.csv and EVTX_ATT&CK_Metadata give the
  tactic only.
- OTRF Security-Datasets: technique-level ground truth from
  datasets/atomic/_metadata/SDWIN-*.yaml attack_mappings (technique +
  optional sub-technique) joined to the dataset zips via the
  files[].link URLs; tactics come from the folder under
  datasets/atomic/windows/. The YAML subset used here is parsed
  line-wise (no PyYAML dependency); only id, attack_mappings
  entries, and files link URLs are read.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EVTX_DEST = "evtx-attack-samples"
OTRF_DEST = "security-datasets"
OTRF_METADATA = "datasets/atomic/_metadata"
OTRF_WINDOWS = "datasets/atomic/windows"

TECHNIQUE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])T(\d{4})(?:\.(\d{3}))?(?![0-9])", re.IGNORECASE
)
BASE_TECHNIQUE = re.compile(r"T\d{4}$")

SOURCE_OTRF_METADATA = "otrf-metadata"
SOURCE_OTRF_FOLDER = "otrf-folder"
SOURCE_EVTX_FOLDER = "evtx-folder"
SOURCE_EVTX_FILENAME = "evtx-filename"

ATTACK_TACTICS = {
    "collection": "Collection",
    "command and control": "Command and Control",
    "credential access": "Credential Access",
    "defense evasion": "Defense Evasion",
    "discovery": "Discovery",
    "execution": "Execution",
    "lateral movement": "Lateral Movement",
    "persistence": "Persistence",
    "privilege escalation": "Privilege Escalation",
    # "automatedtestingtools" and "other" deliberately map to no tactic.
}


def tactics_for_folder(folder: str) -> list[str]:
    """Map a dataset folder name to ATT&CK tactic names (possibly none)."""
    key = re.sub(r"[\s_]+", " ", folder.strip().lower())
    name = ATTACK_TACTICS.get(key)
    return [name] if name is not None else []


def normalize_technique(base: str, sub: str | None) -> str | None:
    """Combine a T#### base id with an optional 3-digit sub-technique."""
    base = base.strip().upper()
    if not BASE_TECHNIQUE.fullmatch(base):
        return None
    if sub is None:
        return base
    sub = sub.strip().strip("'\"")
    if not sub:
        return base
    if not re.fullmatch(r"\d{3}", sub):
        return None
    return f"{base}.{sub}"


def evtx_techniques_for_filename(name: str) -> list[str]:
    """Extract sorted ATT&CK technique ids from an EVTX sample file name."""
    found: set[str] = set()
    for match in TECHNIQUE_TOKEN.finditer(name):
        technique = normalize_technique(f"T{match.group(1)}", match.group(2))
        if technique is not None:
            found.add(technique)
    return sorted(found)


@dataclass
class OtrfMetadata:
    """Parsed subset of one OTRF SDWIN-*.yaml file."""

    dataset_id: str | None = None
    techniques: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


def parse_otrf_metadata(text: str) -> OtrfMetadata:
    """Parse the id, attack_mappings, and files links from OTRF metadata YAML."""
    meta = OtrfMetadata()
    section: str | None = None
    pending_base: str | None = None

    def flush_pending() -> None:
        nonlocal pending_base
        if pending_base is not None:
            technique = normalize_technique(pending_base, pending_sub[0])
            if technique is not None and technique not in meta.techniques:
                meta.techniques.append(technique)
        pending_base = None
        pending_sub[0] = None

    pending_sub: list[str | None] = [None]
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0 and stripped.endswith(":"):
            flush_pending()
            key = stripped[:-1]
            section = key if key in ("attack_mappings", "files") else None
            continue
        if indent == 0 and stripped.startswith("id:"):
            meta.dataset_id = stripped[3:].strip().strip("'\"") or None
            continue
        if section == "attack_mappings":
            item = stripped[2:].strip() if stripped.startswith("- ") else stripped
            if item.startswith("technique:"):
                flush_pending()
                pending_base = item[len("technique:") :].strip().strip("'\"")
            elif item.startswith("sub-technique:") and pending_base is not None:
                pending_sub[0] = item[len("sub-technique:") :].strip().strip("'\"")
        elif section == "files":
            item = stripped[2:].strip() if stripped.startswith("- ") else stripped
            if item.startswith("link:"):
                link = item[len("link:") :].strip().strip("'\"")
                if link:
                    meta.links.append(link)
    flush_pending()
    return meta


def otrf_key_for_link(link: str) -> str:
    """Reduce a metadata files[].link URL to a matchable path suffix."""
    marker = "datasets/atomic/windows/"
    if marker in link:
        return link.split(marker, 1)[1]
    return link.rsplit("/", 1)[-1]


def build_otrf_index(metadata_dir: Path) -> dict[str, set[str]]:
    """Map dataset path suffix (or basename) to the union of technique ids."""
    index: dict[str, set[str]] = {}
    if not metadata_dir.is_dir():
        return index
    for path in sorted(metadata_dir.glob("SDWIN-*.yaml")):
        meta = parse_otrf_metadata(path.read_text(encoding="utf-8"))
        for link in meta.links:
            index.setdefault(otrf_key_for_link(link), set()).update(meta.techniques)
    return index


@dataclass
class FileLabel:
    """Ground truth for one fetched dataset file."""

    dataset: str
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    label_source: str = SOURCE_EVTX_FOLDER

    def to_jsonable(self) -> dict[str, object]:
        """Convert to a JSON-serializable per-file object."""
        return {
            "dataset": self.dataset,
            "techniques": self.techniques,
            "tactics": self.tactics,
            "label_source": self.label_source,
        }


def build_ground_truth(data_dir: Path) -> dict[str, FileLabel]:
    """Map every fetched dataset file (data-relative) to its ground truth."""
    mapping: dict[str, FileLabel] = {}

    evtx_root = data_dir / EVTX_DEST
    if evtx_root.is_dir():
        for file in sorted(evtx_root.rglob("*")):
            if file.is_file() and file.suffix.lower() in (".evtx", ".etl"):
                parts = file.relative_to(evtx_root).parts
                tactics = tactics_for_folder(parts[0]) if len(parts) > 1 else []
                techniques = evtx_techniques_for_filename(file.name)
                source = SOURCE_EVTX_FILENAME if techniques else SOURCE_EVTX_FOLDER
                rel = file.relative_to(data_dir).as_posix()
                mapping[rel] = FileLabel(
                    dataset=EVTX_DEST,
                    techniques=techniques,
                    tactics=tactics,
                    label_source=source,
                )
    else:
        print(f"warning: {evtx_root} missing; skipping EVTX source", file=sys.stderr)

    otrf_root = data_dir / OTRF_DEST
    otrf_windows = otrf_root / OTRF_WINDOWS
    if otrf_windows.is_dir():
        index = build_otrf_index(otrf_root / OTRF_METADATA)
        for file in sorted(otrf_windows.rglob("*")):
            if not file.is_file() or file.name.startswith("."):
                continue
            repo_rel = file.relative_to(otrf_root).as_posix()
            suffix = repo_rel.split(OTRF_WINDOWS + "/", 1)[1]
            tactics = tactics_for_folder(suffix.split("/", 1)[0])
            techniques = sorted(
                set(index.get(suffix, set()) or index.get(file.name, set()))
            )
            rel = file.relative_to(data_dir).as_posix()
            source = SOURCE_OTRF_METADATA if techniques else SOURCE_OTRF_FOLDER
            mapping[rel] = FileLabel(
                dataset=OTRF_DEST,
                techniques=techniques,
                tactics=tactics,
                label_source=source,
            )
    else:
        print(f"warning: {otrf_windows} missing; skipping OTRF source", file=sys.stderr)

    return dict(sorted(mapping.items()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--out", default="data/ground_truth.json")
    args = parser.parse_args(argv)

    data_dir = (REPO_ROOT / args.data_dir).resolve()
    if not data_dir.is_dir():
        print(f"error: data directory missing: {data_dir}", file=sys.stderr)
        return 1
    out_path = (REPO_ROOT / args.out).resolve()
    try:
        data_dir.relative_to(REPO_ROOT)
        out_path.relative_to(REPO_ROOT)
    except ValueError:
        print("error: --data-dir and --out must stay inside the repository")
        return 2

    mapping = build_ground_truth(data_dir)
    if not mapping:
        print("error: no dataset files found; fetch datasets first", file=sys.stderr)
        return 1
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(
            {rel: label.to_jsonable() for rel, label in mapping.items()}, indent=2
        )
        + "\n",
        encoding="utf-8",
    )
    for name in (EVTX_DEST, OTRF_DEST):
        labels = [label for label in mapping.values() if label.dataset == name]
        with_techniques = sum(1 for label in labels if label.techniques)
        with_tactics = sum(1 for label in labels if label.tactics)
        print(
            f"{name}: {len(labels)} files, "
            f"{with_techniques} with techniques, {with_tactics} with tactics"
        )
    print(f"wrote {len(mapping)} files to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
