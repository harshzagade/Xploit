"""Scan checkpointing for Xploit — resume an interrupted scan.

Mirrors the DurbX pattern: a checkpoint is a JSON file written via a
temporary file plus rename, so a kill mid-write never leaves a corrupt
checkpoint behind. The payload records everything a resumed scan needs
to pick up where the killed one stopped:

- ``target`` — the scan's normalized root URL. ``--resume`` refuses a
  checkpoint whose target differs from the URL on the command line.
- ``crawled`` — page URLs the crawl had already discovered. A resumed
  scan seeds its crawl from this list instead of re-running the
  robots.txt/sitemap discovery round-trips.
- ``forms`` — discovered forms (serializable, unlike page responses), so
  form entry points survive the restart.
- ``completed_modules`` — scan-module names that already ran. A resumed
  scan skips them entirely; module probe traffic is the expensive part
  of a long scan, so this is where the time is saved.
- ``findings`` — findings from completed modules, serialized with
  ``Finding.to_dict()``. Without these, skipping a module would also
  silently drop its findings from the final report.
- ``finished`` — True only for a scan that ran to completion.
  ``--resume`` refuses a finished checkpoint (nothing left to resume),
  exactly like DurbX.

Honest limitation, stated here and in the README: page *responses* are
not persisted (bodies can be megabytes and modules read live response
objects), so a resumed scan re-fetches crawled pages to rebuild the
in-memory page table. What resume saves is the discovery phase, all
completed modules' probe traffic, and every finding already recorded.
"""

from __future__ import annotations

import json
from dataclasses import asdict, fields
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import Finding, FormTarget

CHECKPOINT_VERSION = 1

_REQUIRED_KEYS = (
    "target",
    "crawled",
    "forms",
    "completed_modules",
    "findings",
    "finished",
)


def write_checkpoint(
    path: str,
    *,
    target: str,
    crawled: list[str],
    forms: list[dict],
    completed_modules: list[str],
    findings: list[dict],
    finished: bool,
) -> None:
    """Write a resume checkpoint as JSON (temp file + rename).

    ``forms``/``findings`` are already-serialized dicts (see
    :func:`serialize_forms` / :func:`serialize_findings`); keeping this
    function data-only means it never imports the scanner module and
    stays trivially unit-testable.
    """
    payload = {
        "tool": "xploit",
        "checkpoint_version": CHECKPOINT_VERSION,
        "target": target,
        "crawled": list(crawled),
        "forms": list(forms),
        "completed_modules": list(completed_modules),
        "findings": list(findings),
        "finished": bool(finished),
    }
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_checkpoint(path: str) -> dict:
    """Read and validate a checkpoint written by :func:`write_checkpoint`.

    Raises ``FileNotFoundError`` for a missing file and ``ValueError``
    for anything that is not an Xploit checkpoint of the supported
    version, or that is missing a required key.
    """
    source = Path(path).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"Checkpoint not found: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Checkpoint is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Checkpoint is not a JSON object")
    if payload.get("tool") != "xploit":
        raise ValueError("Checkpoint was not written by Xploit")
    if payload.get("checkpoint_version") != CHECKPOINT_VERSION:
        raise ValueError(
            f"Unsupported checkpoint version: "
            f"{payload.get('checkpoint_version')!r}"
        )
    for key in _REQUIRED_KEYS:
        if key not in payload:
            raise ValueError(f"Checkpoint is missing {key!r}")
    if not isinstance(payload["crawled"], list):
        raise ValueError("Checkpoint 'crawled' must be a list")
    if not isinstance(payload["forms"], list):
        raise ValueError("Checkpoint 'forms' must be a list")
    if not isinstance(payload["completed_modules"], list):
        raise ValueError("Checkpoint 'completed_modules' must be a list")
    if not isinstance(payload["findings"], list):
        raise ValueError("Checkpoint 'findings' must be a list")
    return payload


def serialize_forms(forms: list["FormTarget"]) -> list[dict]:
    """Serialize FormTarget objects for a checkpoint payload."""
    return [asdict(form) for form in forms]


def deserialize_forms(raw_forms: list) -> list["FormTarget"]:
    """Rebuild FormTarget objects from a checkpoint payload.

    Unknown keys are dropped so a checkpoint written by a newer minor
    version (with an extra form field) still loads instead of crashing
    the resumed scan.
    """
    from .scanner import FormTarget

    known = {f.name for f in fields(FormTarget)}
    forms: list[FormTarget] = []
    for raw in raw_forms:
        if not isinstance(raw, dict):
            continue
        forms.append(FormTarget(**{k: v for k, v in raw.items() if k in known}))
    return forms


def serialize_findings(findings: list["Finding"]) -> list[dict]:
    """Serialize Finding objects for a checkpoint payload."""
    return [finding.to_dict() for finding in findings]


def deserialize_findings(raw_findings: list) -> list["Finding"]:
    """Rebuild Finding objects from a checkpoint payload.

    Unknown keys are dropped (same forward-compat rationale as
    :func:`deserialize_forms`); entries missing a required field are
    skipped rather than crashing the resumed scan.
    """
    from .scanner import Finding

    known = {f.name for f in fields(Finding)}
    required = {
        "id", "name", "category", "severity", "confidence", "url",
        "evidence", "impact", "remediation",
    }
    findings: list[Finding] = []
    for raw in raw_findings:
        if not isinstance(raw, dict) or not required.issubset(raw):
            continue
        findings.append(Finding(**{k: v for k, v in raw.items() if k in known}))
    return findings
