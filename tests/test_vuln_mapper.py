"""VulnerabilityMapper unit testleri."""
from unittest.mock import patch

from core.vuln_mapper import VulnerabilityMapper, Vulnerability


def test_map_known_service():
    mapper = VulnerabilityMapper()
    with patch("core.vuln_mapper.run_command", return_value="{}"):
        vulns = mapper.map_service("vsftpd", "2.3.4", 21)
    assert len(vulns) >= 1
    assert vulns[0].exploit_module == "vsftpd_backdoor"
    assert "CVE-2011-2523" in vulns[0].cves


def test_score_high_for_known_exploit():
    mapper = VulnerabilityMapper()
    vuln = Vulnerability(
        service="vsftpd", version="2.3.4", port=21,
        cves=["CVE-2011-2523"], exploit_module="vsftpd_backdoor",
    )
    score = mapper.score_exploitability(vuln)
    assert score >= 0.9


def test_score_low_for_unknown():
    mapper = VulnerabilityMapper()
    vuln = Vulnerability(service="unknown-svc", version="", port=9999)
    score = mapper.score_exploitability(vuln)
    assert score <= 0.3


def test_map_all_from_dicts():
    mapper = VulnerabilityMapper()
    services = [
        {"service": "vsftpd", "version": "2.3.4", "port": 21},
        {"service": "ssh", "version": "OpenSSH 4.7", "port": 22},
    ]
    with patch("core.vuln_mapper.run_command", return_value="{}"):
        vulns = mapper.map_all(services)
    assert len(vulns) >= 2


def test_map_all_from_serviceinfo_objects():
    from core.recon_engine import ServiceInfo
    mapper = VulnerabilityMapper()
    services = [ServiceInfo(port=21, service="vsftpd", version="2.3.4")]
    with patch("core.vuln_mapper.run_command", return_value="{}"):
        vulns = mapper.map_all(services)
    assert len(vulns) >= 1
    assert vulns[0].port == 21


def test_searchsploit_parses_cve():
    mapper = VulnerabilityMapper()
    fake_json = (
        '{"RESULTS_EXPLOIT": [{"Title": "vsftpd 2.3.4 - Backdoor (CVE-2011-2523)",'
        ' "Path": "linux/remote/17491.rb"}]}'
    )
    with patch("core.vuln_mapper.run_command", return_value=fake_json):
        results = mapper._searchsploit("vsftpd", "2.3.4")
    assert len(results) == 1
    assert results[0]["cve"] == "CVE-2011-2523"


def test_searchsploit_handles_bad_json():
    mapper = VulnerabilityMapper()
    with patch("core.vuln_mapper.run_command", return_value="not json"):
        results = mapper._searchsploit("foo", "1.0")
    assert results == []
