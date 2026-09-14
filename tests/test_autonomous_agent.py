"""AutonomousAgent unit testleri (mock LLM ile)."""
from unittest.mock import patch

from core.autonomous_agent import (
    AutonomousAgent, AgentAction, AgentContext, is_dangerous_command,
)


class _FakeLLM:
    """Sirali JSON cevaplari donduren sahte LLM."""
    def __init__(self, responses):
        self._responses = list(responses)
        self._i = 0

    def generate(self, messages, **kwargs):
        from core.llm_client import LLMResponse
        if self._i < len(self._responses):
            content = self._responses[self._i]
            self._i += 1
        else:
            content = '{"thought": "done", "tool": "done", "params": {}}'
        return LLMResponse(content=content)


def test_dangerous_command_detection():
    assert is_dangerous_command("rm -rf /")
    assert is_dangerous_command("mkfs.ext4 /dev/sda")
    assert is_dangerous_command(":(){ :|:& };:")
    assert not is_dangerous_command("id")
    assert not is_dangerous_command("sudo -l")


def test_parse_action_valid_json():
    agent = AutonomousAgent("metasploitable2", llm_client=None)
    action = agent._parse_action('{"thought": "test", "tool": "nmap", "params": {"ports": "22"}}')
    assert action is not None
    assert action.tool == "nmap"
    assert action.params["ports"] == "22"


def test_parse_action_with_thinking():
    agent = AutonomousAgent("metasploitable2", llm_client=None)
    content = (
        "Thinking Process:\n1. Analyze\n2. Decide\n\n"
        '{"thought": "run privesc", "tool": "privesc", "params": {"technique": "sudoers_audit"}}'
    )
    action = agent._parse_action(content)
    assert action is not None
    assert action.tool == "privesc"


def test_parse_action_invalid():
    agent = AutonomousAgent("metasploitable2", llm_client=None)
    assert agent._parse_action("no json here") is None
    assert agent._parse_action("") is None


def test_context_extract_credential():
    ctx = AgentContext(target="metasploitable2")
    cred = ctx._extract_credential("Valid credentials: msfadmin:msfadmin")
    assert cred == {"username": "msfadmin", "password": "msfadmin"}


def test_context_privilege_update():
    ctx = AgentContext(target="metasploitable2")
    action = AgentAction(tool="exploit", params={})
    ctx.add_result(action, {"success": True, "output": "uid=0(root) gid=0(root)"})
    assert ctx.privilege == "root"


def test_context_user_privilege():
    ctx = AgentContext(target="metasploitable2")
    action = AgentAction(tool="exploit", params={})
    ctx.add_result(action, {"success": True, "output": "uid=1000(msfadmin)"})
    assert ctx.privilege == "user"


def test_context_summary():
    ctx = AgentContext(target="metasploitable2")
    ctx.credentials.append({"username": "msfadmin", "password": "msfadmin"})
    summary = ctx.summary()
    assert "metasploitable2" in summary
    assert "msfadmin:msfadmin" in summary


def test_agent_run_with_done():
    llm = _FakeLLM(['{"thought": "nothing to do", "tool": "done", "params": {}}'])
    agent = AutonomousAgent("metasploitable2", llm_client=llm, max_steps=5)
    ctx = agent.run()
    assert ctx.target == "metasploitable2"
    assert len(ctx.history) == 0  # done hemen cagrildi


def test_agent_run_executes_action():
    llm = _FakeLLM([
        '{"thought": "scan", "tool": "nmap", "params": {"ports": "22"}}',
        '{"thought": "done", "tool": "done", "params": {}}',
    ])
    agent = AutonomousAgent("metasploitable2", llm_client=llm, max_steps=5)
    with patch.object(agent, "_execute", return_value={"success": True, "output": "22/tcp open ssh"}):
        ctx = agent.run()
    assert len(ctx.history) == 1
    assert ctx.history[0]["action"]["tool"] == "nmap"


def test_agent_stuck_detection():
    # Ayni eylemi tekrar tekrar onerirse dongu durmali
    llm = _FakeLLM([
        '{"thought": "scan", "tool": "nmap", "params": {"ports": "22"}}',
        '{"thought": "scan again", "tool": "nmap", "params": {"ports": "22"}}',
    ])
    agent = AutonomousAgent("metasploitable2", llm_client=llm, max_steps=10)
    with patch.object(agent, "_execute", return_value={"success": False, "output": "fail"}):
        ctx = agent.run()
    # Tekrar tespiti ikinci adimda durdurur -> sadece 1 kayit
    assert len(ctx.history) == 1


def test_agent_out_of_scope_blocked():
    agent = AutonomousAgent("evil.com", llm_client=None)
    action = AgentAction(tool="nmap", params={})
    result = agent._execute(action)
    assert result["success"] is False
    assert "kapsam" in result["output"].lower() or "scope" in result["output"].lower()


def test_agent_dangerous_command_blocked():
    agent = AutonomousAgent("metasploitable2", llm_client=None)
    action = AgentAction(tool="post_exploit", params={"command": "rm -rf /"})
    result = agent._execute(action)
    assert result["success"] is False
    assert "tehlikeli" in result["output"].lower() or "dangerous" in result["output"].lower()
