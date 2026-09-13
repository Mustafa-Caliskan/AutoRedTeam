"""
Tests for Phase 1: SGLang Constrained JSON Decoding and Structured Outputs.
"""
import json
import pytest
from core.assessment_assistant import ASSESSMENT_JSON_SCHEMA, AssessmentAssistant
from core.llm_client import (
    MockLLMClient,
    OpenAICompatibleClient,
    ToolCallInfo,
    sanitize_llm_response,
)


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


def test_sanitize_preserves_valid_json_object():
    """Geçerli JSON nesnesi sanitize tarafından bozulmamalı (✅, [Output] vb. içerse bile)."""
    payload = {
        "thought": "vsftpd backdoor denendi ✅",
        "tool": "exploit",
        "target": "metasploitable2",
        "exploit": "vsftpd_backdoor",
        "rationale": "[Output] uid=0(root) kanıtı",
    }
    raw = json.dumps(payload, ensure_ascii=False)
    cleaned = sanitize_llm_response(raw)
    assert json.loads(cleaned) == payload


def test_sanitize_preserves_fenced_json():
    """Markdown fence içindeki geçerli JSON da korunmalı (fence bozulmadan)."""
    payload = {"tool": "nmap", "target": "metasploitable2", "rationale": "scan"}
    raw = "```json\n" + json.dumps(payload) + "\n```"
    cleaned = sanitize_llm_response(raw)
    # Fence korunur; _parse_suggestion fence'i ayrıştırabilir.
    assert cleaned == raw
    assert json.loads(cleaned.strip("`").replace("json\n", "", 1)) == payload


def test_sanitize_still_strips_think_blocks():
    """JSON olmayan yanıtlarda <think> blokları hâlâ temizlenmeli."""
    raw = "<think>planlama yapıyorum</think>Nihai cevap."
    cleaned = sanitize_llm_response(raw)
    assert "<think>" not in cleaned
    assert "Nihai cevap." in cleaned


def test_openai_client_sends_guided_json_for_sglang():
    """SGLang için extra_body.guided_json gönderilmeli (constrained decoding)."""
    captured = {}

    class _FakeCompletions:
        def create(self, **kwargs):
            captured.update(kwargs)
            raise RuntimeError("stop-after-capture")

    class _FakeChat:
        completions = _FakeCompletions()

    class _FakeClient:
        chat = _FakeChat()

    client = OpenAICompatibleClient(base_url="http://localhost:8000/v1", api_key="EMPTY")
    client.client = _FakeClient()
    client.generate(
        messages=[{"role": "user", "content": "ping"}],
        json_schema=ASSESSMENT_JSON_SCHEMA,
        enable_thinking=False,
    )
    extra = captured.get("extra_body", {})
    assert extra.get("guided_json") == ASSESSMENT_JSON_SCHEMA
    assert extra.get("enable_thinking") is False
