"""
Tests for core/context_engine.py (Headroom CCR + L0/L1/L2 Hierarchical Context Compression).
"""

import os
import pytest
from core.context_engine import ContextEngine, CCRNode, TargetAttackSurface, context_engine
from core.assessment_assistant import AssessmentAssistant
from core.orchestrator import OrchestratorAgent
from core.llm_client import BaseLLMClient, LLMResponse


@pytest.fixture
def tmp_engine(tmp_path):
    return ContextEngine(base_dir=tmp_path / "vfs")


def test_ccr_raw_cache_and_retrieve(tmp_engine):
    raw_nmap = (
        "PORT     STATE SERVICE     VERSION\n"
        "21/tcp   open  ftp         vsftpd 2.3.4\n"
        "22/tcp   open  ssh         OpenSSH 4.7p1\n"
        "445/tcp  open  netbios-ssn Samba 3.0.20\n"
        "1524/tcp open  ingreslock  Ingreslock\n"
    )
    node = tmp_engine.ingest(
        target="metasploitable2",
        tool="nmap",
        step=1,
        raw_output=raw_nmap,
        command="nmap -sV metasploitable2"
    )

    assert isinstance(node, CCRNode)
    assert node.tool == "nmap"
    assert node.step == 1
    assert os.path.exists(node.l2_raw_path)

    # CCR Retrieve
    retrieved = tmp_engine.retrieve_raw(node.node_id)
    assert retrieved == raw_nmap

    # Check L0 and L1
    assert "Discovered 4 open ports" in node.l0_abstract
    assert "21/tcp" in node.l1_tactical["open_ports"]
    assert node.l1_tactical["open_ports"]["21/tcp"]["exploit"] == "vsftpd_backdoor"


def test_gobuster_parsing(tmp_engine):
    raw_gobuster = (
        "/admin                (Status: 200)\n"
        "/login                (Status: 200)\n"
        "/api/v1               (Status: 403)\n"
    )
    node = tmp_engine.ingest(
        target="localhost:3000",
        tool="gobuster",
        step=2,
        raw_output=raw_gobuster,
        command="gobuster dir -u http://localhost:3000"
    )

    assert "Discovered 3 endpoints" in node.l0_abstract
    surface = tmp_engine.get_or_create_target("localhost:3000")
    assert len(surface.web_endpoints) == 3
    paths = [ep["path"] for ep in surface.web_endpoints]
    assert "/admin" in paths
    assert "/login" in paths


def test_exploit_lifecycle_and_root_tracking(tmp_engine):
    nmap_out = "21/tcp open ftp vsftpd 2.3.4\n1524/tcp open ingreslock Ingreslock"
    tmp_engine.ingest(target="metasploitable2", tool="nmap", step=1, raw_output=nmap_out)

    surface = tmp_engine.get_or_create_target("metasploitable2")
    assert surface.access_level == "none"
    assert surface.ports["21/tcp"]["status"] == "UNTESTED"

    # Failed exploit
    failed_out = "[-] Connection refused on port 6200. Exploit failed."
    node_failed = tmp_engine.ingest(
        target="metasploitable2",
        tool="exploit",
        step=2,
        raw_output=failed_out,
        suggestion={"tool": "exploit", "exploit": "vsftpd_backdoor"}
    )
    assert "EXPLOIT FAILED" in node_failed.l0_abstract
    assert surface.ports["21/tcp"]["status"] == "FAILED"
    assert surface.access_level == "none"

    # Successful exploit with root
    success_out = "uid=0(root) gid=0(root) groups=0(root)\nLinux metasploitable2 2.6.24"
    node_success = tmp_engine.ingest(
        target="metasploitable2",
        tool="exploit",
        step=3,
        raw_output=success_out,
        suggestion={"tool": "exploit", "exploit": "ingreslock_backdoor"}
    )
    assert "ROOT access (uid=0)" in node_success.l0_abstract
    assert surface.access_level == "root (uid=0)"
    assert surface.ports["1524/tcp"]["status"] == "ROOT_OBTAINED"


def test_render_attack_surface_tree(tmp_engine):
    nmap_out = (
        "21/tcp open ftp vsftpd 2.3.4\n"
        "22/tcp open ssh OpenSSH 4.7p1\n"
        "1524/tcp open ingreslock Ingreslock"
    )
    tmp_engine.ingest(target="metasploitable2", tool="nmap", step=1, raw_output=nmap_out)

    tmp_engine.ingest(
        target="metasploitable2",
        tool="exploit",
        step=2,
        raw_output="uid=0(root)",
        suggestion={"tool": "exploit", "exploit": "ingreslock_backdoor"}
    )

    tree = tmp_engine.render_attack_surface_tree("metasploitable2")
    assert "Target Attack Surface: metasploitable2 [Access: ROOT (UID=0)]" in tree
    assert "[21/tcp] ftp vsftpd 2.3.4 [EXPLOIT: vsftpd_backdoor] -> STATUS: UNTESTED" in tree
    assert "[1524/tcp] ingreslock Ingreslock [EXPLOIT: ingreslock_backdoor] -> STATUS: ROOT SHELL OBTAINED" in tree


def test_render_compact_context_and_token_savings(tmp_engine):
    verbose_filler = (
        "| _ssl-cert: Subject: commonName=metasploitable2\n"
        "| _http-title: Site doesn't have a title (text/html).\n"
        "| _smb-os-discovery: OS: Unix (Samba 3.0.20-Debian)\n"
        "| Host script results: 10 hosts up, latency 0.0002s\n"
    ) * 50
    large_nmap = (
        "Starting Nmap 7.80 scan at 2026-09-11 12:00:00\n"
        "PORT     STATE SERVICE     VERSION\n"
        "21/tcp   open  ftp         vsftpd 2.3.4\n"
        "22/tcp   open  ssh         OpenSSH 4.7p1\n"
        "80/tcp   open  http        Apache httpd 2.2.8\n"
        "445/tcp  open  netbios-ssn Samba smbd 3.X\n"
        + verbose_filler
    )

    tmp_engine.ingest(target="metasploitable2", tool="nmap", step=1, raw_output=large_nmap)
    compact_ctx = tmp_engine.render_compact_context("metasploitable2", current_step=1, max_steps=20)

    assert "Target Attack Surface: metasploitable2" in compact_ctx
    assert "Recent Activity" in compact_ctx
    assert "Step: 1/20" in compact_ctx

    savings = tmp_engine.get_token_savings()
    assert savings["total_raw_chars"] > savings["total_compressed_chars"]
    assert savings["savings_percent"] > 50.0
    assert savings["estimated_tokens_saved"] > 0


def test_reset_functionality(tmp_engine):
    tmp_engine.ingest(target="target_a", tool="nmap", step=1, raw_output="21/tcp open ftp")
    tmp_engine.ingest(target="target_b", tool="nmap", step=1, raw_output="80/tcp open http")

    tmp_engine.reset(target="target_a")
    assert "target_a" not in tmp_engine.targets
    assert "target_b" in tmp_engine.targets

    tmp_engine.reset()
    assert len(tmp_engine.targets) == 0
    assert len(tmp_engine.nodes) == 0


class DummyLLM(BaseLLMClient):
    def __init__(self, response_text: str = '{"thought":"recon","tool":"nmap","target":"localhost:3000","rationale":"scan"}'):
        self.response_text = response_text

    def generate(self, messages, **kwargs):
        return LLMResponse(content=self.response_text)


def test_assistant_and_orchestrator_integration(tmp_path):
    assistant = AssessmentAssistant(
        llm_client=DummyLLM(),
        target="test_target",
        max_steps=5,
        findings_file=tmp_path / "findings.jsonl",
        report_file=tmp_path / "report.md",
    )

    assistant.execute_step(
        tool="nmap",
        target="test_target",
        suggestion={"tool": "nmap", "target": "test_target", "thought": "scan", "rationale": "test"},
        approved=True
    )

    ctx = assistant._build_context()
    assert "Target Attack Surface: test_target" in ctx
    assert "Recent Activity" in ctx

    orch = OrchestratorAgent(client=DummyLLM("Directive: focus on web"))
    directive = orch.plan_next_step(
        current_findings=[],
        recent_worker_output="raw",
        step_number=1,
        target="test_target"
    )
    assert directive == "Directive: focus on web"
