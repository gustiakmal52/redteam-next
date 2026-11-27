"""Integrity tests for the October 2026 fresh-intel section of offensive_intel_db.

Every entry is hypothesis + version-gate guidance sourced from the CISA KEV
catalog (2026.10.16) and published advisories; these tests lock the schema so a
future edit cannot sneak in an entry without provenance or a valid CVE shape.
"""

import re

from redteam_agent.core import offensive_intel_db as db

REQUIRED_KEYS = {
    "name",
    "vulnerability_class",
    "pattern",
    "description",
    "technique",
    "detection",
    "sources",
}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
RUN_TAG = "run_20261017T122621Z"


def _all_entries():
    entries = []
    for section in (
        db.AUTHORIZATION_BYPASS_PATTERNS,
        db.SQL_INJECTION_PATTERNS,
        db.XSS_BYPASS_PATTERNS,
        db.SSRF_PATTERNS,
        db.GRAPHQL_PATTERNS,
        db.CISA_KEV_PATTERNS,
        db.FILE_UPLOAD_BYPASS_PATTERNS,
        db.RACE_CONDITION_PATTERNS,
        db.MODERN_ATTACK_SURFACE_PATTERNS,
        db.FRESH_INTEL_2026_10_PATTERNS,
    ):
        entries.extend(section)
    return entries


def test_fresh_section_exists_and_nonempty():
    assert len(db.FRESH_INTEL_2026_10_PATTERNS) >= 19


def test_every_fresh_entry_has_required_schema():
    for entry in db.FRESH_INTEL_2026_10_PATTERNS:
        missing = REQUIRED_KEYS - set(entry)
        assert not missing, f"{entry.get('name')} missing keys: {sorted(missing)}"
        assert isinstance(entry["technique"], list) and entry["technique"]
        assert entry["sources"], "anti-halu: every entry must cite its source"


def test_fresh_cve_entries_are_wellformed_and_unique():
    cves = [e["cve"] for e in db.FRESH_INTEL_2026_10_PATTERNS if "cve" in e]
    assert len(cves) >= 17
    for cve in cves:
        assert CVE_RE.match(cve), f"malformed CVE id: {cve}"
    assert len(cves) == len(set(cves)), "duplicate cve in fresh section"


def test_kev_entries_cite_the_2026_10_17_intel_run():
    for entry in db.FRESH_INTEL_2026_10_PATTERNS:
        if entry["pattern"].startswith("kev_"):
            assert RUN_TAG in entry["sources"], entry["name"]


def test_aggregator_includes_fresh_section():
    all_patterns = db.get_all_patterns()
    for entry in db.FRESH_INTEL_2026_10_PATTERNS:
        assert entry in all_patterns


def test_component_lookup_finds_ckan_bundle():
    hits = db.get_patterns_by_component("ckan")
    names = {h["name"] for h in hits}
    assert any("datastore_search_sql" in n for n in names)
    assert any("markdown_extract" in n for n in names)


def test_cve_lookup_spans_kev_and_fresh_sections():
    assert db.get_cve_pattern("CVE-2026-42032")["pattern"] == "ckan_sqlsearch_authz_bypass"
    assert db.get_cve_pattern("cve-2026-0322")["pattern"] == "kev_pan_os_code_injection"
    assert db.get_cve_pattern("CVE-2021-44228")["name"] == "Log4Shell"
    assert db.get_cve_pattern("CVE-0000-0000") == {}


def test_class_lookup_serves_the_new_classes():
    assert any(e.get("cve") == "CVE-2026-42032" for e in db.get_patterns_by_class("authorization"))
    assert any(e.get("cve") == "CVE-2026-0322" for e in db.get_patterns_by_class("rce"))
    assert any(e.get("cve") == "CVE-2025-54384" for e in db.get_patterns_by_class("xss"))
