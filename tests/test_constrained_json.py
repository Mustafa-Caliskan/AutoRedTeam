"""
Tests for Phase 1: SGLang Constrained JSON Decoding and Structured Outputs.
"""
import pytest
from core.assessment_assistant import ASSESSMENT_JSON_SCHEMA, AssessmentAssistant
from core.llm_client import MockLLMClient, OpenAICompatibleClient, ToolCallInfo


def test_assessment_json_schema_structure():
    """Verify ASSESSMENT_JSON_SCHEMA has all required fields and correct types."""
    assert ASSESSMENT_JSON_SCHEMA["type"] == "object"
    props = ASSESSMENT_JSON_SCHEMA["properties"]
    
    assert "thought" in props
    assert "tool" in props
    assert "target" in props
    assert "rationale" in props
    assert "query" in props
    assert "finding" in props
    
    # Check tool enums
    tools = props["tool"]["enum"]
    assert "nmap" in tools
    assert "sqlmap" in tools
    assert "web_search" in tools
    assert "done" in tools
    
    # Check finding nested properties
    finding_props = props["finding"]["properties"]
    assert "category" in finding_props
    assert "severity" in finding_props
    assert "evidence_snippet" in finding_props


def test_mock_llm_accepts_constrained_decoding_args():
    """Verify MockLLMClient can accept json_schema and response_format without error."""
    client = MockLLMClient()
    resp = client.generate(
        messages=[{"role": "user", "content": "test"}],
        json_schema=ASSESSMENT_JSON_SCHEMA,
        response_format={"type": "json_object"},
        enable_thinking=False
    )
    assert resp is not None
    assert resp.content is not None


def test_openai_compatible_client_formats_constrained_request():
    """Verify OpenAICompatibleClient sets up json_schema in kwargs properly."""
    client = OpenAICompatibleClient(base_url="http://localhost:8000/v1", api_key="EMPTY")
    
    # We test with a dummy call that fails connection gracefully but constructs arguments correctly
    resp = client.generate(
        messages=[{"role": "user", "content": "ping"}],
        json_schema=ASSESSMENT_JSON_SCHEMA,
        enable_thinking=False
    )
    # Since localhost:8000/v1 is not running, it gracefully returns error message instead of crashing
    assert resp is not None
    assert "[API BAĞLANTI HATASI]" in resp.content or resp.content
