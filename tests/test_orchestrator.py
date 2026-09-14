"""
Unit tests for DeepSeek Orchestrator and Web Search tool.
"""

import pytest
from core.web_search import WEB_SEARCH_TOOL_SCHEMA, execute_tool_call
from core.orchestrator import OrchestratorAgent, create_orchestrator, ORCHESTRATOR_SYSTEM_PROMPT
from core.llm_client import MockLLMClient, LLMResponse


def test_web_search_tool_schema():
    """Verify tool schema is formatted correctly for OpenAI/DeepSeek function calling."""
    assert WEB_SEARCH_TOOL_SCHEMA["type"] == "function"
    assert WEB_SEARCH_TOOL_SCHEMA["function"]["name"] == "web_search"
    assert "query" in WEB_SEARCH_TOOL_SCHEMA["function"]["parameters"]["properties"]
    assert "query" in WEB_SEARCH_TOOL_SCHEMA["function"]["parameters"]["required"]


def test_execute_tool_call_unknown():
    """Verify unknown tool returns error message gracefully."""
    res = execute_tool_call("unknown_tool", {})
    assert "TOOL ERROR" in res or "Bilinmeyen" in res


def test_create_orchestrator_without_key(monkeypatch):
    """When DEEPSEEK_API_KEY is empty, create_orchestrator should return None."""
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    orch = create_orchestrator(api_key="")
    assert orch is None


def test_orchestrator_plan_next_step():
    """Orchestrator should produce strategic directive using LLM client."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    # Mock LLM client returns a basic mock response
    orch = OrchestratorAgent(client=mock_client)
    
    directive = orch.plan_next_step(
        current_findings=[{"tool": "nmap", "severity": "info", "finding": "Port 21 open vsftpd 2.3.4"}],
        recent_worker_output="Discovered port 21",
        step_number=1,
        target="metasploitable2"
    )
    assert directive is not None
    assert len(directive) > 0


def test_orchestrator_fallback_correction():
    """Orchestrator should generate a correction directive when worker output is invalid."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    orch = OrchestratorAgent(client=mock_client)
    
    correction = orch.fallback_correction(
        failed_output="Invalid non-json output from worker",
        step_number=3,
        target="metasploitable2"
    )
    assert correction is not None
    assert len(correction) > 0


def test_orchestrator_system_prompt_structure():
    """System prompt must contain the 4-wave methodology keywords."""
    assert "WAVE 1" in ORCHESTRATOR_SYSTEM_PROMPT
    assert "WAVE 2" in ORCHESTRATOR_SYSTEM_PROMPT
    assert "WAVE 3" in ORCHESTRATOR_SYSTEM_PROMPT
    assert "WAVE 4" in ORCHESTRATOR_SYSTEM_PROMPT
    assert "web_search" in ORCHESTRATOR_SYSTEM_PROMPT


def test_orchestrator_analyze_and_rescue():
    """Orchestrator should produce a rescue directive when worker is stuck."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    orch = OrchestratorAgent(client=mock_client)

    rescue = orch.analyze_and_rescue(
        worker_activity=(
            "  Adim 1: nmap vsftpd (metasploitable2)\n"
            "  Adim 2: nmap vsftpd (metasploitable2)\n"
            "  TEKRAR TESPITI (worker ayni islemi tekrarliyor):\n"
            "    - nmap/vsftpd: 2 kez\n"
            "  NOT: Worker HIC exploit denemedi (sadece kesif yapti)."
        ),
        recent_worker_output="nmap captured vsftpd 2.3.4",
        current_findings=[{"tool": "nmap", "severity": "High", "category": "Known vulnerable service version"}],
        step_number=5,
        target="metasploitable2",
    )
    assert rescue is not None
    assert len(rescue) > 0



def test_orchestrator_plan_next_step_accepts_worker_activity():
    """plan_next_step should accept the worker_activity parameter without error."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    orch = OrchestratorAgent(client=mock_client)

    directive = orch.plan_next_step(
        current_findings=[],
        recent_worker_output="",
        step_number=5,
        target="metasploitable2",
        worker_activity="  TEKRAR TESPITI: nmap/vsftpd 3 kez",
    )
    assert directive is not None
    assert len(directive) > 0


def test_orchestrator_summarize_findings_empty():
    """Empty findings list should return friendly message."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    orch = OrchestratorAgent(client=mock_client)
    res = orch._summarize_findings([])
    assert res == "No findings recorded yet."


def test_orchestrator_summarize_findings_formatting():
    """Findings should be formatted with index, uppercase severity, tool, category and evidence."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    orch = OrchestratorAgent(client=mock_client)
    findings = [
        {
            "tool": "nmap",
            "severity": "medium",
            "category": "Open Port",
            "evidence_snippet": "Port 21/tcp open vsftpd 2.3.4"
        },
        {
            "tool": "exploit",
            "severity": "critical",
            "category": "Root Shell",
            "evidence_snippet": "uid=0(root) gid=0(root)"
        }
    ]
    res = orch._summarize_findings(findings)
    assert "[1] [MEDIUM] nmap: Open Port — Port 21/tcp open vsftpd 2.3.4" in res
    assert "[2] [CRITICAL] exploit: Root Shell — uid=0(root) gid=0(root)" in res


def test_orchestrator_summarize_findings_truncation():
    """More than 10 findings should be truncated with a header note."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    orch = OrchestratorAgent(client=mock_client)
    findings = [
        {"tool": "nmap", "severity": "low", "category": f"Port {p}", "evidence_snippet": f"port {p} open"}
        for p in range(1, 16)
    ]
    res = orch._summarize_findings(findings)
    assert "showing last 10 of 15 findings" in res
    assert "[10]" in res
    # Should only show the last 10
    assert "Port 15" in res
    assert "Port 6" in res


def test_orchestrator_summarize_findings_none_resilience():
    """Findings with None or missing values should be handled safely without crashing."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    orch = OrchestratorAgent(client=mock_client)
    findings = [
        {"tool": None, "severity": None, "category": None, "evidence_snippet": None},
        {}
    ]
    res = orch._summarize_findings(findings)
    assert "[?]" in res
    assert "unknown" in res


def test_orchestrator_research():
    """Verify research() utility method returns search results string."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    orch = OrchestratorAgent(client=mock_client)
    res = orch.research("vsftpd 2.3.4 exploit")
    assert isinstance(res, str)
    assert len(res) > 0


def test_orchestrator_triage_returns_string():
    """v3.0 Triage Advisor rolu calismali."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    orch = OrchestratorAgent(client=mock_client)
    result = orch.triage(
        findings=[{"category": "Weak Default Credentials", "severity": "Critical"}],
        untested=["mysql", "tomcat"],
        credentials=["msfadmin:msfadmin"],
        target="metasploitable2",
    )
    assert isinstance(result, str)


def test_orchestrator_escalate_returns_string():
    """v3.0 Escalation Oracle rolu calismali."""
    mock_client = MockLLMClient(model_name="mock-deepseek")
    orch = OrchestratorAgent(client=mock_client)
    result = orch.escalate(
        target="metasploitable2",
        attempted_steps=["vsftpd_backdoor", "samba_usermap"],
        findings=[{"category": "Known vulnerable service version"}],
    )
    assert isinstance(result, str)

