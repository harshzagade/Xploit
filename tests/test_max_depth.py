"""`--max-depth` as an alias for `--depth` (crawl depth).

`--depth` already bounded the crawl, but the flag name users reach for
first is `--max-depth` (dirb/gobuster-style). The alias takes precedence
when both are given, so there is exactly one effective depth per run.
"""
from xploit.cli import _build_scanner, build_parser, effective_depth


def parse(*argv):
    return build_parser().parse_args(list(argv))


def test_max_depth_defaults_to_none():
    args = parse("http://x/")
    assert args.max_depth is None
    assert effective_depth(args) == 4


def test_max_depth_alone_sets_effective_depth():
    args = parse("http://x/", "--max-depth", "2")
    assert args.depth == 4  # --depth untouched
    assert effective_depth(args) == 2
    assert _build_scanner(args, "http://x/").depth == 2


def test_max_depth_overrides_depth_when_both_given():
    args = parse("http://x/", "--depth", "5", "--max-depth", "1")
    assert effective_depth(args) == 1
    assert _build_scanner(args, "http://x/").depth == 1


def test_depth_alone_still_works():
    args = parse("http://x/", "--depth", "3")
    assert effective_depth(args) == 3
    assert _build_scanner(args, "http://x/").depth == 3


def test_namespace_without_max_depth_falls_back_to_depth():
    # Hand-built namespaces (interactive prompt, embedders) predate the flag.
    args = parse("http://x/", "--depth", "2")
    del args.max_depth
    assert effective_depth(args) == 2
    assert _build_scanner(args, "http://x/").depth == 2
