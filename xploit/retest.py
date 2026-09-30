"""Evidence-gated retest: re-fire each finding's proof request.

A finding is only as strong as its provenance. The retest pass replays the
exact proof request attached to every verified finding and checks whether the
confirming response marker is still present:

  confirmed    — the vulnerability reproduces (marker still present)
  fixed        — the proof request no longer triggers the marker
  unverifiable — the request failed, or the finding never had replayable proof
  skipped      — retest refused in passive mode (retest is active traffic)

Retest never runs in passive mode: replaying attack payloads is active
traffic by definition, so a passive scan's findings are marked `skipped`.
"""
from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qsl

if TYPE_CHECKING:
    from .scanner import Finding, WebScanner

RETEST_CONFIRMED = "confirmed"
RETEST_FIXED = "fixed"
RETEST_UNVERIFIABLE = "unverifiable"
RETEST_SKIPPED = "skipped"
RETEST_NOT_RUN = "not_run"

# A replay that comes back blocked or errored is NOT evidence the
# vulnerability is fixed — we simply never got a clean answer.
BLOCKED_BODY_SIGNS = (
    "access denied", "request blocked", "blocked by", "waf",
    "captcha", "cloudflare", "incapsula", "akamai",
    "rate limit", "too many requests",
)
LOGIN_HINTS = ("login", "signin", "sign-in", "auth")


def _replay_blocked(res) -> str | None:
    """Return a reason if the replay response can't be trusted, else None."""
    if res.status_code >= 400:
        return f"HTTP {res.status_code}"
    if res.status_code in (301, 302, 303, 307, 308):
        loc = (res.headers.get("Location") or "").lower()
        if any(h in loc for h in LOGIN_HINTS):
            return f"redirected to login ({res.headers.get('Location')})"
    body = res.text.lower()
    hit = next((s for s in BLOCKED_BODY_SIGNS if s in body), None)
    if hit:
        return f"block page ({hit})"
    return None


def _note(finding, text: str) -> None:
    finding.verification_note = (
        f"{finding.verification_note} [{text}]" if finding.verification_note else text
    )


def retest_findings(scanner: "WebScanner", findings: "list[Finding]") -> dict[str, int]:
    """Re-fire proof requests for verified findings. Mutates findings in place.

    Returns a tally of {confirmed, fixed, unverifiable, skipped}.
    """
    from .scanner import PASSIVE

    stats = {
        RETEST_CONFIRMED: 0,
        RETEST_FIXED: 0,
        RETEST_UNVERIFIABLE: 0,
        RETEST_SKIPPED: 0,
    }

    if scanner.mode == PASSIVE:
        for finding in findings:
            finding.retest_status = RETEST_SKIPPED
            stats[RETEST_SKIPPED] += 1
        return stats

    for finding in findings:
        if not finding.has_replayable_proof():
            finding.retest_status = RETEST_UNVERIFIABLE
            stats[RETEST_UNVERIFIABLE] += 1
            continue

        kwargs: dict = {}
        if finding.proof_method == "POST" and finding.proof_data:
            kwargs["data"] = dict(parse_qsl(finding.proof_data, keep_blank_values=True))

        try:
            res = scanner._request(finding.proof_method, finding.proof_url,
                                   quiet=True, **kwargs)
        except Exception:
            res = None

        if res is None:
            finding.retest_status = RETEST_UNVERIFIABLE
            _note(finding, "retest inconclusive: replay request failed")
            stats[RETEST_UNVERIFIABLE] += 1
        elif finding.proof_marker.lower() in res.text.lower():
            finding.retest_status = RETEST_CONFIRMED
            stats[RETEST_CONFIRMED] += 1
        else:
            blocked_reason = _replay_blocked(res)
            if blocked_reason:
                # 403 WAF page, 429, 500, login redirect, ... — the replay was
                # blocked or errored, so absence of the marker proves nothing.
                finding.retest_status = RETEST_UNVERIFIABLE
                _note(finding, f"retest inconclusive: replay {blocked_reason}")
                stats[RETEST_UNVERIFIABLE] += 1
            else:
                finding.retest_status = RETEST_FIXED
                stats[RETEST_FIXED] += 1

    return stats


def retest_summary_line(stats: dict[str, int]) -> str:
    parts = []
    if stats.get(RETEST_CONFIRMED):
        parts.append(f"{stats[RETEST_CONFIRMED]} confirmed")
    if stats.get(RETEST_FIXED):
        parts.append(f"{stats[RETEST_FIXED]} fixed")
    if stats.get(RETEST_UNVERIFIABLE):
        parts.append(f"{stats[RETEST_UNVERIFIABLE]} unverifiable")
    if stats.get(RETEST_SKIPPED):
        parts.append(f"{stats[RETEST_SKIPPED]} skipped (passive mode)")
    return "retest: " + (", ".join(parts) if parts else "no findings")
