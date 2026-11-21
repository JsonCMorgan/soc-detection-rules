"""Load Sigma rules and prove Splunk + Sentinel backends convert without error."""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.backends.microsoft365defender import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


@pytest.fixture(scope="module")
def rule_collection() -> SigmaCollection:
    """All YAML rules in rules/."""
    paths = sorted(RULES_DIR.glob("*.yml"))
    assert len(paths) >= 10, "Expected at least 10 rules for portfolio pack"
    return SigmaCollection.load_ruleset(paths)


def test_rule_count(rule_collection: SigmaCollection) -> None:
    """Pack ships 12 SOC-oriented rules."""
    assert len(rule_collection.rules) == 12


def test_unique_rule_ids(rule_collection: SigmaCollection) -> None:
    ids = [str(r.id) for r in rule_collection.rules]
    assert len(ids) == len(set(ids))


def test_splunk_conversion(rule_collection: SigmaCollection) -> None:
    backend = SplunkBackend()
    for rule in rule_collection.rules:
        lines = backend.convert_rule(rule)
        assert lines, f"Splunk output empty for {rule.title}"
        assert any(line.strip() for line in lines)


def test_sentinel_conversion(rule_collection: SigmaCollection) -> None:
    backend = KustoBackend()
    for rule in rule_collection.rules:
        lines = backend.convert_rule(rule)
        assert lines, f"KQL output empty for {rule.title}"