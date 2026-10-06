from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..scanner import WebScanner, Finding

class BaseModule:
    name: str = "Base Module"
    category: str = "General"

    def __init__(self, scanner: WebScanner):
        self.scanner = scanner
        # Initialize deduplication set within the module's scope
        self._dedupe = set()
        # Scanner-level dedup key set shared across ALL modules, created lazily
        # here so base.py doesn't require changes to scanner.py. Prevents the
        # same finding (id + url + parameter) from being reported twice when
        # two modules cover the same check (e.g. cookie flags in general.py
        # and auth_advanced.py).
        if not hasattr(scanner, "_finding_keys"):
            scanner._finding_keys = set()

    def run(self):
        """Execute the module's detection logic."""
        raise NotImplementedError("Modules must implement run()")

    def add_finding(self, finding: Finding):
        # Every finding passes the provenance gate before it is recorded:
        # verified only with replayable proof, never on prose alone.
        from ..scanner import gate_finding
        gate_finding(finding)
        key = (finding.category, finding.url, finding.parameter, finding.name)
        if key not in self._dedupe:
            self._dedupe.add(key)
            # Scanner-level dedup across modules: skip if another module already
            # reported this exact finding (same id, url, parameter).
            xkey = (finding.id, finding.url, finding.parameter or "")
            if xkey in self.scanner._finding_keys:
                return
            self.scanner._finding_keys.add(xkey)
            self.scanner.findings.append(finding)
            if self.scanner.on_finding:
                self.scanner.on_finding(finding)

    def attach_proof(self, finding: "Finding", *, method: str, url: str,
                     marker: str = "", data: str = "",
                     kind: str = "marker", delay_s: float = 0.0) -> "Finding":
        """Attach replayable proof to a finding before add_finding().

        method/url describe the exact request demonstrating the vulnerability;
        data is the urlencoded POST body ("" for GET); marker is the response
        substring (case-insensitive) that confirmed it. An empty marker means
        the confirmation was behavioral, not substring-replayable.

        kind="timing" with delay_s>0 attaches a timing proof instead: the
        confirmation was a reproducible response delay of at least delay_s
        seconds, re-measurable on replay.
        """
        finding.proof_method = method.upper()
        finding.proof_url = url
        finding.proof_data = data
        finding.proof_marker = (marker or "").lower()
        finding.proof_kind = kind
        finding.proof_delay_s = delay_s
        return finding
