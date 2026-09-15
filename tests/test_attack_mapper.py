"""MITRE ATT&CK mapper + remediation testleri."""
from core.attack_mapper import get_attack, get_remediation, ATTACK_MAP, REMEDIATION_MAP
from core.cvss_scorer import score_finding, _lookup_cvss, severity_from_cvss


def test_attack_known_category():
    atk = get_attack("SQL Injection")
    assert atk["technique_id"] == "T1190"
    assert atk["tactic"] == "Initial Access"


def test_attack_default_fallback():
    atk = get_attack("Some Unknown Category")
    assert atk["technique_id"] == "T1190"


def test_attack_privilege_escalation():
    atk = get_attack("Privilege Escalation")
    assert atk["technique_id"] == "T1548"


def test_remediation_known_category():
    rem = get_remediation("SQL Injection")
    assert "parametreli" in rem.lower() or "prepared" in rem.lower()


def test_remediation_default():
    rem = get_remediation("Unknown Category")
    assert len(rem) > 0


def test_cvss_exact_match():
    score, vec = _lookup_cvss("SQL Injection")
    assert score == 9.8


def test_cvss_substring_match():
    # CVE ekli kategori tam eslesmese de alt-dize ile bulunmali
    score, vec = _lookup_cvss("Backdoor Exploitation (CVE-2011-2523)")
    assert score == 9.8


def test_cvss_rce_substring():
    score, vec = _lookup_cvss("Remote Code Execution (CVE-2004-2687)")
    assert score == 9.8


def test_score_finding_adds_fields():
    f = score_finding({"category": "Command Injection"})
    assert f["cvss_score"] == 9.8
    assert "CVSS:3.1" in f["cvss_vector"]
    assert f["cvss_rating"] == "Critical"


def test_severity_from_cvss():
    assert severity_from_cvss(9.8) == "Critical"
    assert severity_from_cvss(7.5) == "High"
    assert severity_from_cvss(5.0) == "Medium"


def test_all_attack_categories_have_valid_ids():
    for cat, (tid, name, tactic) in ATTACK_MAP.items():
        assert tid.startswith("T"), f"{cat}: {tid}"


def test_all_remediations_nonempty():
    for cat, rem in REMEDIATION_MAP.items():
        assert len(rem) > 20, f"{cat} remediation too short"
