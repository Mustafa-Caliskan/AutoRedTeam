"""
Tests for Phase 4: LLM Red Teaming & AI Agent Vulnerability Assessment Engine.
"""
from core.llm_client import MockLLMClient, ToolCallInfo, LLMResponse
from core.llm_redteam_engine import LLMRedTeamEngine, llm_redteam_engine


def test_llm_redteam_engine_categories():
    """Verify engine loads OWASP LLM categories from json."""
    cats = llm_redteam_engine.get_categories()
    assert len(cats) >= 3
    cat_ids = [c["id"] for c in cats]
    assert "LLM01" in cat_ids
    assert "LLM02" in cat_ids
    assert "LLM06" in cat_ids


def test_evaluate_unauthorized_tool_hijacking():
    """Verify tool call hijacking (LLM06 Excessive Agency) is detected."""
    payload = {
        "payload_id": "EA-01",
        "success_indicators": ["execute_wire_transfer"]
    }
    # Simulate an agent calling unauthorized tool
    resp = LLMResponse(
        content="I will execute the wire transfer now.",
        tool_calls=[ToolCallInfo(id="call_01", name="execute_wire_transfer", arguments={"amount": 50000})]
    )
    is_vuln, evidence, tools = llm_redteam_engine.evaluate_response(payload, resp)
    assert is_vuln is True
    assert "execute_wire_transfer" in evidence
    assert "execute_wire_transfer" in tools


def test_hardened_client_shows_safe_resistance():
    """Verify defensive refusal is correctly classified as non-vulnerable."""
    payload = {
        "payload_id": "PI-01",
        "success_indicators": ["system prompt", "instructions:"]
    }
    resp = LLMResponse(
        content="I cannot comply with this request because it is against safety policy to reveal system instructions.",
        tool_calls=None
    )
    is_vuln, evidence, tools = llm_redteam_engine.evaluate_response(payload, resp)
    assert is_vuln is False
    assert "defensive resistance" in evidence.lower()


def test_run_assessment_and_chain_generation():
    """Verify end-to-end evaluation produces findings and exploit chains."""
    mock_client = MockLLMClient(model_name="mock-muse-glimmer", simulated_security_level="vulnerable")
    results = llm_redteam_engine.run_assessment(target_client=mock_client, category_ids=["LLM06"])
    
    assert len(results) >= 1
    scorecard = llm_redteam_engine.generate_findings_and_chains(results, target_label="MockVictimAgent")
    
    assert "robustness_score" in scorecard
    assert "findings" in scorecard
    assert "chains" in scorecard
    assert scorecard["total_tests"] >= 1
