"""
Deterministik degerlendirme akisi (run_deterministic) entegrasyon testleri.

Gercek ag erisimi yapmaz; recon ve exploit cagrilari mock'lanir.
"""
from unittest.mock import patch, MagicMock

from core.assessment_assistant import AssessmentAssistant
from core.recon_engine import ReconResult, ServiceInfo


def _fake_recon():
    result = ReconResult(target="metasploitable2")
    result.services = [
        ServiceInfo(port=21, service="ftp", version="vsftpd 2.3.4"),
        ServiceInfo(port=22, service="ssh", version="OpenSSH 4.7"),
        ServiceInfo(port=80, service="http", version="Apache 2.2.8"),
    ]
    return result


def test_run_deterministic_builds_plan_and_runs():
    assistant = AssessmentAssistant(llm_client=None, target="metasploitable2")

    with patch.object(assistant, "run_recon", return_value=_fake_recon()), \
         patch("core.assessment_assistant.vuln_mapper") as mock_mapper, \
         patch.object(assistant, "_run_planned_exploit",
                      return_value={"success": False, "output": "no", "exploit": "x"}), \
         patch.object(assistant, "_record_exploit_finding"):
        from core.vuln_mapper import Vulnerability
        mock_mapper.map_all.return_value = [
            Vulnerability(service="vsftpd", version="2.3.4", port=21,
                          cves=["CVE-2011-2523"], exploit_module="vsftpd_backdoor",
                          exploitability=0.95),
        ]
        findings = assistant.run_deterministic()

    assert isinstance(findings, list)
    assert hasattr(assistant, "_correlated")
    assert assistant._correlated["original_count"] >= 0


def test_run_deterministic_handles_recon_failure():
    assistant = AssessmentAssistant(llm_client=None, target="metasploitable2")
    with patch.object(assistant, "run_recon", return_value=None):
        findings = assistant.run_deterministic()
    assert findings == assistant.findings


def test_run_planned_exploit_alternative_returns_failure():
    assistant = AssessmentAssistant(llm_client=None, target="metasploitable2")
    step = MagicMock()
    step.exploit_module = "credential_spray"
    result = assistant._run_planned_exploit(step)
    assert result["success"] is False
