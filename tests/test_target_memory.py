"""
Tests for core/target_memory.py (Cross-Session Experience Distillation & Target Memory).
"""

import json
from pathlib import Path
import pytest

from core.target_memory import TargetMemoryStore, TargetMemoryData, target_memory
from core.context_engine import ContextEngine, TargetAttackSurface
from core.assessment_assistant import AssessmentAssistant
from core.llm_client import BaseLLMClient, LLMResponse


@pytest.fixture
def tmp_store(tmp_path):
    return TargetMemoryStore(base_dir=tmp_path / "memories")


def test_distill_session_saves_data(tmp_store):
    findings = [
        {
            "category": "Backdoor Access",
            "severity": "Critical",
            "tool": "exploit",
            "cwe_reference": "CWE-78",
            "evidence_snippet": "uid=0(root) gid=0(root)"
        }
    ]
    decision_chain = [
        {"step": 1, "tool": "nmap", "target": "metasploitable2"},
        {"step": 2, "tool": "exploit", "exploit": "vsftpd_backdoor", "exploit_succeeded": False},
        {"step": 3, "tool": "exploit", "exploit": "ingreslock_backdoor", "exploit_succeeded": True},
    ]
    surface = TargetAttackSurface(
        target="metasploitable2",
        access_level="root (uid=0)",
        ports={
            "21/tcp": {"service": "ftp", "version": "vsftpd 2.3.4", "status": "FAILED"},
            "1524/tcp": {"service": "ingreslock", "version": "Ingreslock", "status": "ROOT_OBTAINED"},
        }
    )

    mem = tmp_store.distill_session(
        target="metasploitable2",
        findings=findings,
        decision_chain=decision_chain,
        surface=surface
    )

    assert isinstance(mem, TargetMemoryData)
    assert mem.target == "metasploitable2"
    assert mem.access_level == "root (uid=0)"
    assert "ingreslock_backdoor" in mem.successful_exploits
    assert "vsftpd_backdoor" in mem.failed_exploits
    assert len(mem.open_ports) == 2
    assert any("uid=0" in i.lower() for i in mem.learned_insights)

    # Check file on disk
    path = tmp_store._get_target_path("metasploitable2")
    assert path.exists()
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["target"] == "metasploitable2"
    assert saved["access_level"] == "root (uid=0)"


def test_recall_target_across_sessions(tmp_store):
    # Session 1: Distill
    tmp_store.distill_session(
        target="metasploitable2",
        findings=[],
        decision_chain=[
            {"step": 1, "tool": "exploit", "exploit": "ingreslock_backdoor", "exploit_succeeded": True}
        ],
        surface=TargetAttackSurface(
            target="metasploitable2",
            access_level="root (uid=0)",
            ports={"1524/tcp": {"service": "ingreslock", "status": "ROOT_OBTAINED"}}
        )
    )

    # Session 2: Fresh store instance reading the same directory
    session2_store = TargetMemoryStore(base_dir=tmp_store.base_dir)
    recalled = session2_store.recall_target("metasploitable2")

    assert recalled is not None
    assert recalled.target == "metasploitable2"
    assert recalled.access_level == "root (uid=0)"
    assert "ingreslock_backdoor" in recalled.successful_exploits

    brief = session2_store.render_memory_brief("metasploitable2")
    assert "Target Memory Recalled" in brief
    assert "ROOT (UID=0)" in brief
    assert "ingreslock_backdoor" in brief
    assert "Skip duplicate Nmap scans" in brief


def test_clear_memory(tmp_store):
    tmp_store.distill_session(target="t1", findings=[], decision_chain=[], surface=None)
    tmp_store.distill_session(target="t2", findings=[], decision_chain=[], surface=None)

    assert tmp_store.recall_target("t1") is not None
    assert tmp_store.recall_target("t2") is not None

    # Clear single target
    tmp_store.clear_memory("t1")
    assert tmp_store.recall_target("t1") is None
    assert tmp_store.recall_target("t2") is not None

    # Clear all
    tmp_store.clear_memory()
    assert tmp_store.recall_target("t2") is None


class DummyLLM(BaseLLMClient):
    def __init__(self, response_text: str = '{"thought":"done","tool":"done","target":"test_target","rationale":"finish"}'):
        self.response_text = response_text

    def generate(self, messages, **kwargs):
        return LLMResponse(content=self.response_text)


def test_assistant_cross_session_recall(tmp_path, monkeypatch):
    # Setup isolated memory store for assistant
    custom_store = TargetMemoryStore(base_dir=tmp_path / "memories")
    monkeypatch.setattr("core.assessment_assistant.target_memory", custom_store)

    # Pre-populate memory for target
    custom_store.distill_session(
        target="recalled_target",
        findings=[],
        decision_chain=[
            {"step": 1, "tool": "exploit", "exploit": "samba_usermap", "exploit_succeeded": False}
        ],
        surface=TargetAttackSurface(
            target="recalled_target",
            access_level="none",
            ports={"445/tcp": {"service": "samba", "status": "FAILED"}}
        )
    )

    assistant = AssessmentAssistant(
        llm_client=DummyLLM(),
        target="recalled_target",
        max_steps=2,
        findings_file=tmp_path / "findings.jsonl",
        report_file=tmp_path / "report.md",
    )

    # Verify assistant recalled target memory and injected into conversation
    assert "samba_usermap" in assistant._failed_exploits
    assert 445 in assistant._discovered_ports
    
    # Check that brief was injected into conversation
    user_msgs = [m["content"] for m in assistant.conversation if m.get("role") == "user"]
    assert any("Target Memory Recalled" in m for m in user_msgs)
    assert any("Skip duplicate Nmap scans" in m for m in user_msgs)
