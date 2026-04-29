"""
Prepare raw external mail corpora for evaluation and future ML work.

The downloader stores raw source corpora under data/corpora/. This module
turns those sources into a flat directory of .eml files plus labels and a
manifest that the eval harness can consume directly.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mailbox
import random
import shutil
from dataclasses import asdict, dataclass
from email import policy
from pathlib import Path
from typing import Iterable, Iterator, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPORA_DIR = PROJECT_ROOT / "data" / "corpora"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "eval_corpus"

ENRON_HAM_FOLDERS = {"sent", "sent_items", "_sent_mail"}
SPAMASSASSIN_HAM_FOLDERS = ("easy_ham", "easy_ham_2", "hard_ham")
SKIP_SOURCE_NAMES = {"README.txt", "README.md", "LICENSE.txt"}
SKIP_RAW_NAMES = {"cmds"}
DEFAULT_MAX_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class CorpusCandidate:
    """A candidate email selected from one of the raw corpora."""

    source_corpus: str
    source_path: str
    label: str
    path: Optional[Path] = None
    payload: Optional[bytes] = None

    def read_bytes(self) -> bytes:
        if self.payload is not None:
            return self.payload
        if self.path is None:
            raise ValueError(f"candidate has no path or payload: {self.source_path}")
        return self.path.read_bytes()


@dataclass(frozen=True)
class PreparedCorpus:
    """Summary of a prepared corpus directory."""

    output_dir: Path
    labels_path: Path
    labels_csv_path: Path
    manifest_path: Path
    summary_path: Path
    labels: dict[str, str]
    written_counts: dict[str, int]
    available_counts: dict[str, int]
    warnings: list[str]


def _rng_for(seed: int, name: str) -> random.Random:
    digest = hashlib.sha256(f"{seed}:{name}".encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iter_files_sorted(root: Path) -> Iterator[Path]:
    if not root.exists():
        return
    for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if child.is_dir() and not child.is_symlink():
            yield from _iter_files_sorted(child)
        elif child.is_file():
            yield child


def _reservoir_sample(
    candidates: Iterable[CorpusCandidate],
    count: int,
    rng: random.Random,
) -> tuple[list[CorpusCandidate], int]:
    if count <= 0:
        return [], 0

    sample: list[CorpusCandidate] = []
    seen = 0
    for candidate in candidates:
        seen += 1
        if len(sample) < count:
            sample.append(candidate)
            continue
        replace_at = rng.randrange(seen)
        if replace_at < count:
            sample[replace_at] = candidate
    return sample, seen


def _message_as_bytes(message: mailbox.mboxMessage) -> bytes:
    utf8_policy = policy.default.clone(utf8=True)
    for email_policy in (policy.SMTPUTF8, utf8_policy, policy.compat32):
        try:
            return message.as_bytes(policy=email_policy)
        except (AttributeError, TypeError, UnicodeEncodeError):
            continue
    try:
        return message.as_bytes()
    except (AttributeError, TypeError, UnicodeEncodeError):
        return _fallback_message_bytes(message)


def _fallback_message_bytes(message: mailbox.mboxMessage) -> bytes:
    lines = [f"{key}: {value}" for key, value in message.items()]
    lines.append("")
    payload = message.get_payload()
    if isinstance(payload, list):
        for part in payload:
            if hasattr(part, "as_bytes"):
                try:
                    lines.append(part.as_bytes(policy=policy.SMTPUTF8).decode("utf-8", "replace"))
                except Exception:
                    lines.append(str(part.get_payload() if hasattr(part, "get_payload") else part))
            else:
                lines.append(str(part))
    elif payload is not None:
        lines.append(str(payload))
    return "\n".join(lines).encode("utf-8", "surrogateescape")


def iter_nazario_candidates(corpora_dir: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> Iterator[CorpusCandidate]:
    """Yield PHISHING candidates from Nazario mbox files."""

    nazario_dir = corpora_dir / "nazario"
    if not nazario_dir.exists():
        return

    for mbox_path in _iter_files_sorted(nazario_dir):
        if mbox_path.name in SKIP_SOURCE_NAMES:
            continue

        try:
            mbox = mailbox.mbox(str(mbox_path), create=False)
        except (OSError, mailbox.Error):
            continue

        try:
            for index, message in enumerate(mbox):
                payload = _message_as_bytes(message)
                if not payload or len(payload) > max_bytes:
                    continue
                relative = mbox_path.relative_to(corpora_dir).as_posix()
                yield CorpusCandidate(
                    source_corpus="nazario",
                    source_path=f"{relative}#{index}",
                    label="PHISHING",
                    payload=payload,
                )
        finally:
            mbox.close()


def _is_reasonable_raw_message(path: Path, max_bytes: int) -> bool:
    if path.name.startswith(".") or path.name in SKIP_RAW_NAMES:
        return False
    if path.suffix.lower() in {".gz", ".bz2", ".tar", ".zip"}:
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return False
    return 0 < size <= max_bytes


def iter_enron_ham_candidates(corpora_dir: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> Iterator[CorpusCandidate]:
    """Yield CLEAN candidates from Enron sent-mail folders."""

    enron_dir = corpora_dir / "enron"
    if not enron_dir.exists():
        return

    for path in _iter_files_sorted(enron_dir):
        if not _is_reasonable_raw_message(path, max_bytes):
            continue
        rel_parts = tuple(part.lower() for part in path.relative_to(enron_dir).parts[:-1])
        if not any(part in ENRON_HAM_FOLDERS for part in rel_parts):
            continue
        yield CorpusCandidate(
            source_corpus="enron_ham",
            source_path=path.relative_to(corpora_dir).as_posix(),
            label="CLEAN",
            path=path,
        )


def iter_spamassassin_ham_candidates(
    corpora_dir: Path,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Iterator[CorpusCandidate]:
    """Yield CLEAN candidates from SpamAssassin ham folders."""

    sa_dir = corpora_dir / "spamassassin"
    if not sa_dir.exists():
        return

    for folder in SPAMASSASSIN_HAM_FOLDERS:
        root = sa_dir / folder
        for path in _iter_files_sorted(root):
            if not _is_reasonable_raw_message(path, max_bytes):
                continue
            yield CorpusCandidate(
                source_corpus="spamassassin_ham",
                source_path=path.relative_to(corpora_dir).as_posix(),
                label="CLEAN",
                path=path,
            )


def _assert_safe_clean_target(output_dir: Path) -> None:
    resolved = output_dir.resolve()
    if resolved == Path(resolved.anchor):
        raise ValueError(f"refusing to clean filesystem root: {resolved}")
    if resolved == Path.home().resolve():
        raise ValueError(f"refusing to clean home directory: {resolved}")
    if resolved.name.lower() in {
        ".git",
        "config",
        "corpora",
        "data",
        "docs",
        "models",
        "scripts",
        "src",
        "tests",
    }:
        raise ValueError(f"refusing to clean broad project directory: {resolved}")
    if len(resolved.parts) < 3:
        raise ValueError(f"refusing to clean shallow path: {resolved}")


def _prepare_output_dir(output_dir: Path, clean_output: bool) -> None:
    if output_dir.exists() and clean_output:
        _assert_safe_clean_target(output_dir)
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)


def _write_metadata(
    output_dir: Path,
    labels: dict[str, str],
    manifest_rows: list[dict],
    summary: dict,
) -> tuple[Path, Path, Path, Path]:
    labels_path = output_dir / "labels.json"
    labels_csv_path = output_dir / "labels.csv"
    manifest_path = output_dir / "manifest.jsonl"
    summary_path = output_dir / "summary.json"

    labels_path.write_text(json.dumps(labels, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with labels_csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["filename", "label", "source_corpus", "source_path", "sha256", "size_bytes"],
        )
        writer.writeheader()
        writer.writerows(manifest_rows)

    with manifest_path.open("w", encoding="utf-8", newline="\n") as fh:
        for row in manifest_rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return labels_path, labels_csv_path, manifest_path, summary_path


def prepare_corpus(
    corpora_dir: Path = DEFAULT_CORPORA_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    phishing: int = 200,
    enron_ham: int = 200,
    spamassassin_ham: int = 100,
    seed: int = 1337,
    max_bytes: int = DEFAULT_MAX_BYTES,
    clean_output: bool = False,
) -> PreparedCorpus:
    """
    Build a flat labeled .eml corpus from raw Nazario, Enron, and SpamAssassin data.
    """

    corpora_dir = Path(corpora_dir)
    output_dir = Path(output_dir)
    if not corpora_dir.exists():
        raise FileNotFoundError(f"corpora directory not found: {corpora_dir}")

    requested = {
        "nazario": phishing,
        "enron_ham": enron_ham,
        "spamassassin_ham": spamassassin_ham,
    }

    selections: dict[str, list[CorpusCandidate]] = {}
    available_counts: dict[str, int] = {}
    warnings: list[str] = []

    source_iterators = {
        "nazario": iter_nazario_candidates(corpora_dir, max_bytes),
        "enron_ham": iter_enron_ham_candidates(corpora_dir, max_bytes),
        "spamassassin_ham": iter_spamassassin_ham_candidates(corpora_dir, max_bytes),
    }

    for source, iterator in source_iterators.items():
        selected, available = _reservoir_sample(iterator, requested[source], _rng_for(seed, source))
        selections[source] = sorted(selected, key=lambda c: c.source_path)
        available_counts[source] = available
        if available < requested[source]:
            warnings.append(
                f"requested {requested[source]} {source} samples but only {available} were available"
            )

    _prepare_output_dir(output_dir, clean_output)

    labels: dict[str, str] = {}
    manifest_rows: list[dict] = []
    written_counts = {"PHISHING": 0, "CLEAN": 0}
    source_written_counts = {source: 0 for source in selections}

    for source in ("nazario", "enron_ham", "spamassassin_ham"):
        for index, candidate in enumerate(selections[source], start=1):
            payload = candidate.read_bytes()
            digest = _sha256(payload)
            filename = f"{source}_{index:04d}_{digest[:12]}.eml"
            (output_dir / filename).write_bytes(payload)

            labels[filename] = candidate.label
            written_counts[candidate.label] += 1
            source_written_counts[source] += 1
            manifest_rows.append(
                {
                    "filename": filename,
                    "label": candidate.label,
                    "source_corpus": candidate.source_corpus,
                    "source_path": candidate.source_path,
                    "sha256": digest,
                    "size_bytes": len(payload),
                }
            )

    summary = {
        "corpora_dir": str(corpora_dir),
        "output_dir": str(output_dir),
        "seed": seed,
        "max_bytes": max_bytes,
        "requested_counts": requested,
        "available_counts": available_counts,
        "written_counts": written_counts,
        "source_written_counts": source_written_counts,
        "sample_count": len(labels),
        "warnings": warnings,
    }
    labels_path, labels_csv_path, manifest_path, summary_path = _write_metadata(
        output_dir,
        labels,
        manifest_rows,
        summary,
    )

    return PreparedCorpus(
        output_dir=output_dir,
        labels_path=labels_path,
        labels_csv_path=labels_csv_path,
        manifest_path=manifest_path,
        summary_path=summary_path,
        labels=labels,
        written_counts=written_counts,
        available_counts=available_counts,
        warnings=warnings,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare raw phishing/ham corpora into a labeled .eml eval corpus.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--corpora-dir", type=Path, default=DEFAULT_CORPORA_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--phishing", type=int, default=200, help="Nazario phishing samples to write")
    parser.add_argument("--enron-ham", type=int, default=200, help="Enron sent-mail ham samples to write")
    parser.add_argument(
        "--spamassassin-ham",
        type=int,
        default=100,
        help="SpamAssassin ham samples to write",
    )
    parser.add_argument("--seed", type=int, default=1337, help="Deterministic sampling seed")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="Skip source emails larger than this many bytes",
    )
    parser.add_argument(
        "--clean-output",
        action="store_true",
        help="Remove the output directory before writing new samples",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    prepared = prepare_corpus(
        corpora_dir=args.corpora_dir,
        output_dir=args.output,
        phishing=args.phishing,
        enron_ham=args.enron_ham,
        spamassassin_ham=args.spamassassin_ham,
        seed=args.seed,
        max_bytes=args.max_bytes,
        clean_output=args.clean_output,
    )

    print(f"Wrote {len(prepared.labels)} samples to {prepared.output_dir}")
    print(f"  labels:   {prepared.labels_path}")
    print(f"  csv:      {prepared.labels_csv_path}")
    print(f"  manifest: {prepared.manifest_path}")
    print(f"  summary:  {prepared.summary_path}")
    print("")
    print("Counts:")
    for label, count in sorted(prepared.written_counts.items()):
        print(f"  {label}: {count}")
    if prepared.warnings:
        print("")
        print("Warnings:")
        for warning in prepared.warnings:
            print(f"  - {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
