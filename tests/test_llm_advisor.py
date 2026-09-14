"""LLMAdvisor unit testleri (mock client ile)."""
from core.llm_advisor import LLMAdvisor, AdvisorResult
from core.llm_client import MockLLMClient


class _FakeClient:
    """Basit sahte LLM client."""
    def __init__(self, content="", error=None):
        self._content = content
        self._error = error

    def generate(self, messages, **kwargs):
        from core.llm_client import LLMResponse
        return LLMResponse(content=self._content, error=self._error)


def test_payload_crafter_no_client():
    advisor = LLMAdvisor()
    result = advisor.craft_payload("m2", "vsftpd", "2.3.4", 21, "vsftpd_backdoor", "fail")
    assert result.available is False
    assert result.role == "payload_crafter"


def test_payload_crafter_with_client():
    advisor = LLMAdvisor(worker_client=_FakeClient(content="python3 -c 'exploit'"))
    result = advisor.craft_payload("m2", "vsftpd", "2.3.4", 21, "vsftpd_backdoor", "fail")
    assert result.available is True
    assert "exploit" in result.content


def test_triage_parses_json():
    client = _FakeClient(content='{"priority_target": "mysql", "reason": "creds", "confidence": 0.9}')
    advisor = LLMAdvisor(orchestrator_client=client)
    result = advisor.triage([{"category": "X", "severity": "High"}], ["mysql"], ["msfadmin:msfadmin"])
    assert result.available is True
    assert result.parsed["priority_target"] == "mysql"


def test_triage_handles_bad_json():
    client = _FakeClient(content="not json at all")
    advisor = LLMAdvisor(orchestrator_client=client)
    result = advisor.triage([], [], [])
    assert result.available is True
    assert result.parsed is None


def test_escalation_no_client():
    advisor = LLMAdvisor()
    result = advisor.escalate("m2", ["step1"], [])
    assert result.available is False


def test_escalation_with_client():
    advisor = LLMAdvisor(escalation_client=_FakeClient(content="Try lateral movement via SMB"))
    result = advisor.escalate("m2", ["step1"], [])
    assert result.available is True
    assert "SMB" in result.content


def test_error_response_returns_unavailable():
    advisor = LLMAdvisor(worker_client=_FakeClient(error="connection refused"))
    result = advisor.craft_payload("m2", "ssh", "", 22, "x", "fail")
    assert result.available is False


def test_is_available():
    assert LLMAdvisor().is_available() is False
    assert LLMAdvisor(worker_client=_FakeClient()).is_available() is True


def test_extract_json_with_fence():
    advisor = LLMAdvisor()
    parsed = advisor._extract_json('```json\n{"a": 1}\n```')
    assert parsed == {"a": 1}


def test_strip_thinking_block():
    advisor = LLMAdvisor()
    text = (
        "Thinking Process:\n"
        "1. Analyze the request\n"
        "2. Identify the target\n\n"
        "Use the Samba usermap exploit with a reverse shell payload."
    )
    cleaned = advisor._strip_thinking(text)
    assert "Thinking Process" not in cleaned
    assert "Samba" in cleaned


def test_strip_thinking_no_marker():
    advisor = LLMAdvisor()
    assert advisor._strip_thinking("plain payload") == "plain payload"
