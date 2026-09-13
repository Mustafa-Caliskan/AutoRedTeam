"""
Tests for core/browser_tool.py (Autonomous Browser & DOM Pentest Agent).
"""

import os
from pathlib import Path
import pytest

from core.browser_tool import BrowserPentestAgent, browser_agent, execute_browser_action
from core.assessment_tools import suggest_browser_action, ASSESSMENT_TOOLS
from core.assessment_assistant import AssessmentAssistant
from core.llm_client import BaseLLMClient, LLMResponse


def test_browser_agent_initialization():
    agent = BrowserPentestAgent(headless=True)
    assert agent.screenshots_dir.exists()
    assert isinstance(agent._has_playwright, bool)


def test_browser_screenshot(tmp_path):
    agent = BrowserPentestAgent(headless=True)
    agent.screenshots_dir = tmp_path
    res = agent.screenshot(name="test_proof")

    assert res["success"] is True
    assert os.path.exists(res["filepath"])
    assert "test_proof" in res["filename"]


def test_execute_browser_action_interface():
    # 1. Invalid action
    err_res = execute_browser_action(target="localhost:3000", action="non_existent_action")
    assert err_res["success"] is False
    assert "Unknown browser action" in err_res["error"]

    # 2. Screenshot action
    shot_res = execute_browser_action(target="localhost:3000", action="screenshot", screenshot_name="proof_x")
    assert shot_res["success"] is True
    assert "proof_x" in shot_res["filename"]


def test_suggest_browser_action_scope():
    # 1. Out of scope target
    blocked = suggest_browser_action("unauthorized-site.com", action="navigate")
    assert blocked["status"] == "REJECTED_OUT_OF_SCOPE"

    # 2. In scope awaiting approval
    pending = suggest_browser_action("localhost:3000", action="navigate", approved=False)
    assert pending["status"] == "AWAITING_APPROVAL"
    assert pending["tool"] == "browser_action"

    # 3. In scope approved execution
    approved = suggest_browser_action("localhost:3000", action="screenshot", approved=True)
    assert approved["status"] == "APPROVED"
    assert approved["tool"] == "browser_action"
    assert "filepath" in approved["output"]


def test_assessment_tools_registry_contains_browser():
    assert "browser_action" in ASSESSMENT_TOOLS
    tool_def = ASSESSMENT_TOOLS["browser_action"]
    assert tool_def["name"] == "browser_action"
    assert "DOM" in tool_def["description"]


class DummyLLM(BaseLLMClient):
    def __init__(self, response_text: str = '{"thought":"navigate","tool":"browser_action","target":"localhost:3000","action":"screenshot","rationale":"test"}'):
        self.response_text = response_text

    def generate(self, messages, **kwargs):
        return LLMResponse(content=self.response_text)


def test_assistant_browser_step_execution(tmp_path):
    assistant = AssessmentAssistant(
        llm_client=DummyLLM(),
        target="localhost:3000",
        max_steps=2,
        findings_file=tmp_path / "findings.jsonl",
        report_file=tmp_path / "report.md",
    )

    result = assistant.execute_step(
        tool="browser_action",
        target="localhost:3000",
        suggestion={"tool": "browser_action", "action": "screenshot", "thought": "capture proof", "rationale": "test"},
        approved=True
    )

    assert result["status"] == "APPROVED"
    assert result["tool"] == "browser_action"
    assert "filepath" in result["output"]
