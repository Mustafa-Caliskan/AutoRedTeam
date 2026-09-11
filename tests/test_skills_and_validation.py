# tests/test_skills_and_validation.py
"""
Unit tests for AutoRedTeam's new capabilities:
1. SkillLoader (818 structured skills progressive index)
2. ValidationGate (7-Question quality check & anti-hallucination)
3. ChainEngine (Exploit chaining walk algorithm & attack narratives)
4. X64DbgMCPClient (Binary debugger MCP tools)
"""

import pytest
from pathlib import Path
from core.skill_loader import SkillLoader, skill_loader
from core.validation_gate import ValidationGate, validation_gate
from core.chain_engine import ChainEngine, chain_engine
from core.debugger_mcp import X64DbgMCPClient, debugger_mcp
from core.assessment_assistant import AssessmentAssistant


class TestSkillLoader:
    def test_index_loaded(self):
        assert skill_loader.total_skills >= 800, f"Expected 800+ skills, found {skill_loader.total_skills}"

    def test_search_skills(self):
        results = skill_loader.search("sql injection", limit=3)
        assert len(results) > 0
        names = [r["name"].lower() for r in results]
        assert any("sql" in n or "injection" in n for n in names)

    def test_suggest_skills_web(self):
        results = skill_loader.suggest_skills_for_target("localhost:3000", open_ports=[80, 3000], services=["http"])
        assert len(results) > 0
        desc = " ".join([r["description"].lower() for r in results])
        assert any(term in desc for term in ["api", "bola", "injection", "web", "access"])

    def test_suggest_skills_ftp_samba(self):
        results = skill_loader.suggest_skills_for_target("metasploitable2", open_ports=[21, 139], services=["ftp", "samba"])
        assert len(results) > 0
        desc = " ".join([r["description"].lower() for r in results])
        assert any(term in desc for term in ["ftp", "smb", "samba", "active directory", "credential"])

    def test_format_for_prompt(self):
        results = skill_loader.search("prompt injection", limit=2)
        formatted = skill_loader.format_for_prompt(results)
        assert "1. [" in formatted
        assert len(formatted) > 20


class TestValidationGate:
    def test_reject_empty_evidence(self):
        finding = {
            "category": "SQL Injection",
            "severity": "High",
            "evidence_snippet": ""
        }
        res = validation_gate.evaluate(finding)
        assert not res.passed
        assert "concrete evidence" in res.reason.lower()

    def test_reject_speculative_evidence(self):
        finding = {
            "category": "Remote Code Execution",
            "severity": "Critical",
            "evidence_snippet": "This endpoint could be vulnerable and might allow RCE"
        }
        res = validation_gate.evaluate(finding)
        assert not res.passed
        assert "speculative" in res.reason.lower()

    def test_instant_kill_missing_headers(self):
        finding = {
            "category": "Security Misconfiguration",
            "severity": "Medium",
            "evidence_snippet": "Missing Content-Security-Policy and HSTS headers on response"
        }
        res = validation_gate.evaluate(finding)
        assert not res.passed
        assert "Instant-Kill" in res.reason or "headers" in res.reason.lower()
        assert res.instant_kill_id == "NK-01"

    def test_instant_kill_banner_without_cve(self):
        finding = {
            "category": "Information Disclosure",
            "severity": "Low",
            "evidence_snippet": "Server banner disclosure: Apache/2.2.8 found on port 80"
        }
        res = validation_gate.evaluate(finding)
        assert not res.passed
        assert "NK-03" in res.reason or "cve" in res.reason.lower()

    def test_pass_banner_with_verified_cve(self):
        finding = {
            "category": "Backdoor",
            "severity": "Critical",
            "evidence_snippet": "vsftpd 2.3.4 backdoor identified with verified CVE-2011-2523"
        }
        res = validation_gate.evaluate(finding)
        assert res.passed
        assert res.suggested_action == "record"

    def test_pass_genuine_sqli(self):
        finding = {
            "category": "SQL Injection",
            "severity": "Critical",
            "evidence_snippet": "Parameter 'q' vulnerable: sqlmap confirmed boolean-based blind SQLi (UNION SELECT 1,2,3)"
        }
        res = validation_gate.evaluate(finding)
        assert res.passed
        assert res.suggested_action == "record"

    def test_conditionally_valid_open_redirect_requires_chain(self):
        finding = {
            "category": "Open Redirect",
            "severity": "Medium",
            "evidence_snippet": "Target redirects to evil.com via ?redirect=https://evil.com"
        }
        res = validation_gate.evaluate(finding)
        assert not res.passed
        assert res.requires_chain
        assert "chain" in res.reason.lower()


class TestChainEngine:
    def test_suggest_ssrf_next_hops(self):
        finding = {
            "category": "Server-Side Request Forgery",
            "evidence_snippet": "SSRF verified on /api/proxy endpoint"
        }
        hops = chain_engine.suggest_next_hops(finding)
        assert len(hops) > 0
        targets = [h["target"] for h in hops]
        assert any("metadata" in t.lower() or "internal" in t.lower() for t in targets)

    def test_suggest_sqli_next_hops(self):
        finding = {
            "category": "SQL Injection",
            "evidence_snippet": "SQLi confirmed on parameter id"
        }
        hops = chain_engine.suggest_next_hops(finding)
        assert len(hops) > 0
        techniques = [h["technique"].lower() for h in hops]
        assert any("hash" in t or "password" in t or "shell" in t or "host" in t for t in techniques)

    def test_build_chain_narrative(self):
        findings = [
            {
                "finding_id": "FIND-001",
                "tool": "nmap",
                "category": "Service Enumeration",
                "severity": "Low",
                "evidence_snippet": "Port 21 open running vsftpd 2.3.4"
            },
            {
                "finding_id": "FIND-002",
                "tool": "cve_search",
                "category": "Backdoor",
                "severity": "Critical",
                "evidence_snippet": "vsftpd 2.3.4 verified backdoor CVE-2011-2523 execution payload"
            }
        ]
        chains = chain_engine.build_chain_narrative(findings)
        assert len(chains) == 1
        assert chains[0]["severity"] == "Critical"
        assert len(chains[0]["steps"]) == 3
        summary = chain_engine.format_chain_summary(chains)
        assert "Terminal Impact" in summary


class TestX64DbgMCPClient:
    def test_mock_registers(self):
        client = X64DbgMCPClient(mock_mode=True)
        res = client.get_all_registers()
        assert "registers" in res
        assert "RAX" in res["registers"]
        assert "RIP" in res["registers"]

    def test_mock_disassemble(self):
        client = X64DbgMCPClient(mock_mode=True)
        res = client.disassemble("0x00007FF7ABCD1050", count=5)
        assert "instructions" in res
        assert len(res["instructions"]) > 0

    def test_mock_oep(self):
        client = X64DbgMCPClient(mock_mode=True)
        res = client.detect_oep()
        assert res["status"] == "success"
        assert "detected_oep" in res


class TestAssistantIntegration:
    def test_record_finding_filters_instant_kill(self, tmp_path):
        findings_file = tmp_path / "test_findings.jsonl"
        assistant = AssessmentAssistant(
            target="localhost:3000",
            findings_file=findings_file,
            auto_approve_findings=True
        )
        # Attempt to record missing header alone
        fid = assistant.record_finding(
            tool="nikto",
            category="Security Misconfiguration",
            severity="Low",
            cwe_reference="CWE-16",
            evidence_snippet="Missing X-Frame-Options and CSP headers alone"
        )
        assert fid == "", "Instant-kill finding should return empty string (rejected)"
        assert len(assistant.findings) == 0

    def test_record_finding_passes_verified(self, tmp_path):
        findings_file = tmp_path / "test_findings.jsonl"
        assistant = AssessmentAssistant(
            target="metasploitable2",
            findings_file=findings_file,
            auto_approve_findings=True
        )
        fid = assistant.record_finding(
            tool="cve_search",
            category="Backdoor",
            severity="Critical",
            cwe_reference="CWE-78",
            evidence_snippet="vsftpd 2.3.4 confirmed backdoor CVE-2011-2523 root shell"
        )
        assert fid.startswith("FIND-")
        assert len(assistant.findings) == 1

    def test_report_contains_exploit_chaining(self, tmp_path):
        findings_file = tmp_path / "test_findings.jsonl"
        report_file = tmp_path / "test_report.md"
        assistant = AssessmentAssistant(
            target="metasploitable2",
            findings_file=findings_file,
            report_file=report_file,
            auto_approve_findings=True
        )
        assistant.record_finding(
            tool="nmap",
            category="Service Enumeration",
            severity="Low",
            cwe_reference="CWE-200",
            evidence_snippet="Port 21 open running vsftpd 2.3.4 service"
        )
        assistant.record_finding(
            tool="cve_search",
            category="Backdoor",
            severity="Critical",
            cwe_reference="CWE-78",
            evidence_snippet="vsftpd 2.3.4 verified backdoor CVE-2011-2523"
        )
        rep = assistant.generate_report()
        assert rep.exists()
        content = rep.read_text(encoding="utf-8")
        assert "## 🔗 6. Exploit Zincirleme Analizi" in content
        assert "Terminal Impact" in content
