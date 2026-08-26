"""
AutoRedTeam - Model Capability Test Driver.

Runs the Security Assessment Assistant against a live LLM endpoint with
automated human approval (all steps approved) to observe the model's
decision chain. Captures thoughts, tool usage, and outputs to a session log.

Usage:
    python scripts/run_model_test.py --target localhost:3000 --endpoint <URL> [--api-key KEY]
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Fix Windows UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

# Ensure project root is on path (script runs from scripts/)
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.assessment_assistant import AssessmentAssistant
from core.llm_client import create_llm_client


def load_env():
    for env_path in [Path(".env"), Path("config/.env")]:
        if env_path.exists():
            with open(env_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, val = line.partition("=")
                        os.environ.setdefault(key.strip(), val.strip())
            break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="localhost:3000")
    parser.add_argument("--endpoint", default="")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--model", default="huihui-ai/huihui-cyberstrike-offsec-35b-abliterated")
    parser.add_argument("--max-steps", type=int, default=20)
    parser.add_argument("--session-name", default="session")
    parser.add_argument("--mock", action="store_true",
                        help="Use a mock LLM (no endpoint required) to test the pipeline offline")
    args = parser.parse_args()

    load_env()

    if args.mock:
        # Mock mode: use a deterministic fake LLM to test the pipeline offline.
        # The fake LLM suggests nmap first, then searchsploit, then done.
        from core.llm_client import BaseLLMClient, LLMResponse

        class FakeAssessmentLLM(BaseLLMClient):
            def __init__(self):
                self.calls = 0

            def generate(self, messages, tools=None, temperature=0.7, max_tokens=1024):
                self.calls += 1
                if self.calls == 1:
                    return LLMResponse(content=json.dumps({
                        "thought": "Port discovery first to identify services",
                        "tool": "nmap",
                        "target": args.target,
                        "param": None,
                        "service_name": None,
                        "version": None,
                        "rationale": "Identify open ports and service versions"
                    }), model_name="mock-assessment")
                if self.calls == 2:
                    return LLMResponse(content=json.dumps({
                        "thought": "nmap found vsftpd 2.3.4, search known exploits",
                        "tool": "searchsploit",
                        "target": args.target,
                        "param": None,
                        "service_name": "vsftpd",
                        "version": "2.3.4",
                        "rationale": "Check known CVEs for detected service",
                        "finding": {
                            "category": "Known vulnerable service version",
                            "severity": "High",
                            "cwe_reference": "CWE-937",
                            "evidence_snippet": "vsftpd 2.3.4 backdoor (EDB-ID 17491)"
                        }
                    }), model_name="mock-assessment")
                if self.calls == 3:
                    return LLMResponse(content=json.dumps({
                        "thought": "Get the latest CVEs for vsftpd 2.3.4 via live lookup",
                        "tool": "cve_search",
                        "target": args.target,
                        "param": None,
                        "service_name": "vsftpd",
                        "version": "2.3.4",
                        "rationale": "Fetch up-to-date CVE info beyond training cutoff"
                    }), model_name="mock-assessment")
                if self.calls == 4:
                    return LLMResponse(content=json.dumps({
                        "thought": "Scan a different port to find more services",
                        "tool": "nmap",
                        "target": args.target,
                        "param": None,
                        "ports": "21,22,445",
                        "service_name": None,
                        "version": None,
                        "rationale": "Check additional services on other ports"
                    }), model_name="mock-assessment")
                return LLMResponse(content=json.dumps({
                    "thought": "Assessment complete",
                    "tool": "done",
                    "target": args.target,
                    "param": None,
                    "rationale": "Enough findings collected"
                }), model_name="mock-assessment")

        llm_client = FakeAssessmentLLM()
        print(f"🎯 Hedef: {args.target}")
        print(f"🤖 Model: MOCK (offline test)")
        print(f"✅ Bağlanılan model: mock-assessment")
    else:
        endpoint = args.endpoint or os.environ.get("COLAB_ATTACKER_URL", "")
        api_key = args.api_key or os.environ.get("COLAB_API_KEY", "EMPTY")

        if not endpoint:
            print("ERROR: No endpoint provided. Use --endpoint or set COLAB_ATTACKER_URL in .env")
            sys.exit(1)

        print(f"🎯 Hedef: {args.target}")
        print(f"🔗 Endpoint: {endpoint}")
        print(f"🤖 Model: {args.model}")

        # Create the LLM client (auto-detect model served by endpoint)
        llm_client = create_llm_client(
            provider="runpod",
            model_name=args.model,
            endpoint_url=endpoint,
            api_key=api_key,
            auto_detect_model=True
        )
        print(f"✅ Bağlanılan model: {llm_client.model_name}")

    # Session log setup
    session_dir = Path("data/session_logs")
    session_dir.mkdir(parents=True, exist_ok=True)
    session_file = session_dir / f"{args.session_name}.jsonl"

    # Monkeypatch input to auto-approve all steps (test mode)
    import builtins
    original_input = builtins.input
    approval_count = {"y": 0, "n": 0, "dur": 0}

    def auto_approve(prompt=""):
        # If the prompt is asking for a manual tool selection (LLM parse failed),
        # pick a sensible default tool instead of "y".
        if "araç seçin" in prompt or "Bir araç seçin" in prompt:
            print("   [TEST MANUEL ARAÇ] nmap")
            return "nmap"
        # Otherwise auto-approve the step to observe the model's decision chain
        approval_count["y"] += 1
        print(f"   [TEST OTO-ONAY] y")
        return "y"

    builtins.input = auto_approve

    # Patch the assistant to log thoughts and suggestions
    assistant = AssessmentAssistant(
        llm_client=llm_client,
        target=args.target,
        max_steps=args.max_steps
    )

    # Wrap _ask_llm_for_suggestion to capture thoughts
    original_ask = assistant._ask_llm_for_suggestion
    session_records = []

    def logging_ask(context):
        suggestion = original_ask(context)
        if suggestion:
            record = {
                "session": args.session_name,
                "target": args.target,
                "step": assistant.step_count,
                "thought": suggestion.get("thought", ""),
                "tool": suggestion.get("tool", ""),
                "target_suggested": suggestion.get("target", ""),
                "param": suggestion.get("param"),
                "service_name": suggestion.get("service_name"),
                "version": suggestion.get("version"),
                "rationale": suggestion.get("rationale", ""),
                "timestamp": datetime.now().isoformat()
            }
            session_records.append(record)
            with open(session_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return suggestion

    assistant._ask_llm_for_suggestion = logging_ask

    # Wrap _dispatch_tool to capture tool outputs
    original_dispatch = assistant._dispatch_tool

    def logging_dispatch(tool, target, param, approved, service_name=None, version=None, ports=None):
        result = original_dispatch(tool, target, param, approved, service_name=service_name, version=version, ports=ports)
        out_record = {
            "session": args.session_name,
            "target": args.target,
            "step": assistant.step_count,
            "event": "tool_result",
            "tool": tool,
            "status": result.get("status", ""),
            "command": result.get("command", ""),
            "output": result.get("output", "")[:1500],
            "timestamp": datetime.now().isoformat()
        }
        with open(session_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(out_record, ensure_ascii=False) + "\n")
        return result

    assistant._dispatch_tool = logging_dispatch

    print("\n" + "=" * 70)
    print("🚀 Değerlendirme oturumu başlıyor (tüm adımlar test için onaylanacak)...")
    print("=" * 70)

    try:
        findings = assistant.run()
    except KeyboardInterrupt:
        print("\n⏹️  Oturum kullanıcı tarafından kesildi.")
        findings = assistant.findings

    builtins.input = original_input

    print("\n" + "=" * 70)
    print(f"📊 Oturum tamamlandı.")
    print(f"   Onaylanan adım: {approval_count['y']}")
    print(f"   Kaydedilen bulgu: {len(findings)}")
    print(f"   Session log: {session_file}")
    print("=" * 70)

    # Generate report
    report_path = assistant.generate_report(findings)
    print(f"📄 Rapor: {report_path}")


if __name__ == "__main__":
    main()
