"""Rate-limit jitter tests (round 4).

`--jitter N` adds up to N extra random seconds to each request's spacing so
scan traffic isn't metronomic. These tests pin the scanner-side contract
(validation, delay math) and the CLI surface (default + parsing).
"""
import random

import pytest

import xploit.scanner as scanner_mod
from xploit.cli import build_parser
from xploit.scanner import WebScanner


def parse(*argv):
    return build_parser().parse_args(list(argv))


def make_scanner(**kw):
    kw.setdefault("mode", "passive")
    return WebScanner("http://x/", **kw)


# --- validation ------------------------------------------------------------

def test_negative_jitter_rejected():
    with pytest.raises(ValueError):
        make_scanner(jitter=-0.1)


def test_jitter_defaults_to_zero():
    assert make_scanner().jitter == 0.0


# --- delay math (deterministic via monkeypatched uniform/sleep) ------------

def _recorded_sleeps(monkeypatch, uniform_value):
    calls = []
    monkeypatch.setattr(random, "uniform", lambda a, b: uniform_value)
    monkeypatch.setattr(scanner_mod, "sleep", calls.append)
    return calls


def test_jitter_adds_random_delay_between_requests(monkeypatch):
    calls = _recorded_sleeps(monkeypatch, 0.25)
    s = make_scanner(rate_limit=0.0, jitter=1.0)
    s._respect_rate_limit()  # first call: no prior slot, no sleep
    assert calls == []
    s._respect_rate_limit()  # second call: must wait out the jittered gap
    assert len(calls) == 1
    assert 0.24 < calls[0] <= 0.25


def test_jitter_stacks_on_rate_limit(monkeypatch):
    calls = _recorded_sleeps(monkeypatch, 0.25)
    s = make_scanner(rate_limit=0.5, jitter=1.0)
    s._respect_rate_limit()
    s._respect_rate_limit()
    assert len(calls) == 1
    assert 0.74 < calls[0] <= 0.75


def test_no_jitter_no_rate_limit_never_sleeps(monkeypatch):
    calls = _recorded_sleeps(monkeypatch, 0.25)
    s = make_scanner()
    s._respect_rate_limit()
    s._respect_rate_limit()
    assert calls == []


def test_zero_jitter_keeps_fixed_rate_limit(monkeypatch):
    calls = _recorded_sleeps(monkeypatch, 0.25)
    s = make_scanner(rate_limit=0.5, jitter=0.0)
    s._respect_rate_limit()
    s._respect_rate_limit()
    assert len(calls) == 1
    assert 0.49 < calls[0] <= 0.5


# --- CLI surface -----------------------------------------------------------

def test_parser_default_jitter_is_0():
    assert parse("http://x/").jitter == 0.0


def test_parser_jitter_value():
    assert parse("http://x/", "--jitter", "1.5").jitter == 1.5
