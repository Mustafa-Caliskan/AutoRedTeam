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
