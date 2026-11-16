"""WAF-bypass payload encodings and per-host rotation.

A WAF that keys on the literal bytes of a known payload misses the same
probe when its encoding changes — ``' OR 1=1--`` sent as ``%27%20OR...``
(double-decoded by the app, single-decoded by the WAF) is the classic
case. :class:`PayloadRotator` cycles the encoding per host so the same
probe never repeats the same encoding twice in a row against one host,
while different hosts rotate independently (a shared counter would let
one host's traffic dictate another's encoding).

Encodings (applied to the payload *value* before the request layer
URL-encodes it once more for the wire — the server's single decode
yields the encoded form, the app's own decoding yields the raw
payload, which is exactly the layering a bypass relies on):

- ``plain``: the payload unchanged.
- ``url``: percent-encode every byte (``quote`` with no safe chars).
- ``double-url``: percent-encode twice — the wire carries ``%2527``,
  the server decodes it once to ``%27``.
- ``unicode``: IIS-style ``%u00XX`` per character.

Rotation is opt-in (``WebScanner(waf_rotation=True)`` / ``--waf-rotation``):
off means every probe is ``plain``, which is the historical behaviour
and what the existing test suite pins down.
"""
from __future__ import annotations

import threading
from urllib.parse import quote, urlparse

ENCODINGS: tuple[str, ...] = ("plain", "url", "double-url", "unicode")


def encode_payload(payload: str, encoding: str) -> str:
    """Encode `payload` with one of the :data:`ENCODINGS` schemes.

    Raises ValueError on an unknown encoding name so a typo fails fast
    instead of silently sending a plain payload.
    """
    if encoding == "plain":
        return payload
    if encoding == "url":
        return quote(payload, safe="")
    if encoding == "double-url":
        return quote(quote(payload, safe=""), safe="")
    if encoding == "unicode":
        # IIS %u encoding: every character as %uXXXX. Non-ASCII characters
        # use their code point directly (e.g. U+00E9 -> %u00e9).
        return "".join(f"%u{ord(ch):04x}" for ch in payload)
    raise ValueError(f"unknown payload encoding {encoding!r}; "
                     f"expected one of {', '.join(ENCODINGS)}")


class PayloadRotator:
    """Per-host round-robin over :data:`ENCODINGS`.

    Thread-safe: scan modules fan probes out over worker threads, so the
    per-host counter advance is locked — two threads can never draw the
    same encoding for the same host in a row.
    """

    def __init__(self, encodings: tuple[str, ...] = ENCODINGS) -> None:
        if not encodings:
            raise ValueError("PayloadRotator needs at least one encoding")
        for name in encodings:
            if name not in ENCODINGS:
                raise ValueError(f"unknown payload encoding {name!r}; "
                                 f"expected one of {', '.join(ENCODINGS)}")
        self._encodings = tuple(encodings)
        self._next: dict[str, int] = {}
        self._lock = threading.Lock()

    def next_encoding(self, host: str) -> str:
        """The next encoding for `host`, advancing its round-robin."""
        with self._lock:
            index = self._next.get(host, 0)
            self._next[host] = (index + 1) % len(self._encodings)
            return self._encodings[index]

    def encode_for_host(self, payload: str, host: str) -> tuple[str, str]:
        """Encode `payload` with the next encoding for `host`.

        Returns ``(encoded_payload, encoding_name)`` so callers can log
        which layer a probe went out on.
        """
        encoding = self.next_encoding(host)
        return encode_payload(payload, encoding), encoding

    def reset(self, host: str | None = None) -> None:
        """Restart the rotation for one host, or for all hosts."""
        with self._lock:
            if host is None:
                self._next.clear()
            else:
                self._next.pop(host, None)


def host_of(url: str) -> str:
    """Lowercased host (with port when present) of a URL, for rotation keys."""
    return (urlparse(url).netloc or "").lower()
