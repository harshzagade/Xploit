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

    def run(self):
        """Execute the module's detection logic."""
        raise NotImplementedError("Modules must implement run()")

    def add_finding(self, finding: Finding):
        key = (finding.category, finding.url, finding.parameter, finding.name)
        if key not in self._dedupe:
            self._dedupe.add(key)
            self.scanner.findings.append(finding)
            if self.scanner.on_finding:
                self.scanner.on_finding(finding)
