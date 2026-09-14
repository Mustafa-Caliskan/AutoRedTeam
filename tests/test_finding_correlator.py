"""FindingCorrelator ve CVSS Scorer unit testleri."""
from core.finding_correlator import FindingCorrelator
from core.cvss_scorer import score_finding, severity_from_cvss


def _findings():
    return [
        {"finding_id": "F1", "category": "Privilege Escalation", "target": "m2",
         "tool": "privesc", "evidence_snippet": "uid=0(root)"},
        {"finding_id": "F2", "category": "Privilege Escalation", "target": "m2",
         "tool": "privesc", "evidence_snippet": "sudoers (ALL) ALL"},
        {"finding_id": "F3", "category": "Weak Default Credentials", "target": "m2",
         "tool": "exploit", "evidence_snippet": "msfadmin:msfadmin"},
    ]


def test_deduplicate_merges_privesc():
    c = FindingCorrelator()
    result = c.deduplicate(_findings())
    privesc = [f for f in result if f["category"] == "Privilege Escalation"]
    assert len(privesc) == 1
    assert privesc[0]["merged_count"] == 2


def test_build_chains_privesc():
    c = FindingCorrelator()
    chains = c.build_chains(_findings())
    names = [ch.name for ch in chains]
    assert "Privilege Escalation Chain" in names
    assert "Initial Access Chain" in names


def test_correlate_counts():
    c = FindingCorrelator()
    result = c.correlate(_findings())
    assert result["original_count"] == 3
    assert result["deduped_count"] == 2


def test_cvss_score_known_category():
    f = score_finding({"category": "SQL Injection"})
    assert f["cvss_score"] == 9.8
    assert "CVSS:3.1" in f["cvss_vector"]


def test_cvss_score_default():
    f = score_finding({"category": "Unknown Category"})
    assert f["cvss_score"] == 5.0


def test_severity_from_cvss():
    assert severity_from_cvss(9.8) == "Critical"
    assert severity_from_cvss(7.5) == "High"
    assert severity_from_cvss(5.0) == "Medium"
    assert severity_from_cvss(2.0) == "Low"
    assert severity_from_cvss(0.0) == "Informational"
