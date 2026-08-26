"""
AutoRedTeam - Security Assessment Assistant (Human-in-the-Loop Co-Pilot).

This module implements a DEFENSIVE, HUMAN-APPROVED vulnerability assessment
workflow against an AUTHORIZED, locally-hosted training target (OWASP Juice
Shop in Docker).

CRITICAL DESIGN PRINCIPLES:
  - The LLM is a co-pilot ONLY. It can NEVER execute a command directly.
  - The LLM's only output is a *recommendation*: "I suggest: <command> because <rationale>".
  - Every recommendation is shown to the human operator, who must approve it
    via input() ("y" = run, "n" = skip) before anything executes.
  - If the operator rejects a step, the LLM is told "the user rejected this
    step" and asked to propose an alternative.
  - Every target is validated against config/allowed_targets.txt at the code
    level (is_target_allowed). Out-of-scope targets are blocked before the
    operator is even asked, and logged as REJECTED_OUT_OF_SCOPE.
  - The loop is bounded to a maximum of 20 recommended steps to prevent
    infinite loops. The operator can say "dur" (stop) at any time.
"""

import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Fix Windows console UTF-8 encoding for emoji/unicode output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

from core.assessment_tools import (
    ASSESSMENT_TOOLS,
    is_target_allowed,
    suggest_nmap_scan,
    suggest_gobuster_scan,
    suggest_nikto_scan,
    suggest_whatweb_scan,
    suggest_ssl_check,
    suggest_sqlmap_check,
    suggest_searchsploit_lookup,
    suggest_cve_search,
)
from core.llm_client import BaseLLMClient

logger = logging.getLogger(__name__)

FINDINGS_FILE = Path(__file__).parent.parent / "data" / "assessment_findings.jsonl"
REPORT_FILE = Path(__file__).parent.parent / "reports" / "assessment_report.md"

MAX_STEPS = 20

ASSESSMENT_SYSTEM_PROMPT = """You are 'AssessmentCoPilot', a defensive security assessment assistant.

You are helping a human security analyst perform an AUTHORIZED vulnerability
assessment against locally-hosted, intentionally-vulnerable training targets
running in Docker:
  - OWASP Juice Shop (web-application layer) → target "localhost:3000"
  - Metasploitable2 (network/service layer)  → target "metasploitable2"

ACTIVE TARGET: The assessment is running against the target specified by the
operator. ALWAYS use that exact target in your "target" field. Do NOT switch
to the other target unless the operator asks.

STRICT RULES:
1. You are a CO-PILOT. You NEVER execute commands. You only RECOMMEND.
2. Your output must be a single JSON object with this exact shape:
   {
     "thought": "your reasoning about the current state and next best step",
     "tool": "one of: nmap, gobuster, nikto, whatweb, ssl_check, sqlmap, searchsploit, cve_search",
     "target": "the ACTIVE target (localhost:3000 or metasploitable2)",
     "param": "parameter name if tool is sqlmap, else null",
     "ports": "comma-separated ports if tool is nmap and you want to scan
               specific ports (e.g. '21,22,80'), else null",
     "service_name": "service name if tool is searchsploit or cve_search, else null",
     "version": "service version if tool is searchsploit or cve_search, else null",
     "rationale": "why this step is the logical next move",
     "finding": "optional. If the previous tool output revealed a concrete
                 vulnerability, include a finding object:
                 {category, severity (Low/Medium/High/Critical),
                  cwe_reference, evidence_snippet}. Otherwise null."
   }
3. Only recommend tools from the allowed list. Never invent other tools.
4. For sqlmap, ONLY recommend detection mode (--batch --level=1 --risk=1).
   Never recommend dump, exploit, or data extraction.
5. searchsploit and cve_search are LOOKUP-ONLY tools: they list known
   CVE/exploit records for a detected service/version. They NEVER run an
   exploit. If nmap detected a service/version, the logical next step is
   usually a searchsploit or cve_search lookup to find known vulnerabilities.
   Use cve_search for the LATEST CVEs (beyond your training cutoff).
6. If the user rejected a previous step, propose a DIFFERENT alternative.
7. When you have enough findings, set "tool" to "done" to end the assessment.
8. IMPORTANT: When a tool output reveals a real vulnerability (e.g. an old
   service version with known CVEs, an open dangerous port, a missing security
   header), include a "finding" object in your NEXT response so it gets
   recorded. Do not just say "findings recorded" — actually emit the finding.
9. IMPORTANT: NEVER repeat a command you have already run. If a tool already
   produced output, interpret it and move to the NEXT logical step (e.g. after
   nmap finds a service, use searchsploit or cve_search). Re-running the same
   scan is wasteful and must be avoided. If you want to scan a DIFFERENT port,
   use the "ports" field to target a new port.
10. Output ONLY the JSON. No markdown, no extra text."""


class AssessmentAssistant:
    """
    Human-in-the-loop assessment co-pilot. Orchestrates LLM suggestions,
    human approval, safe execution, finding logging, and report generation.
    """

    def __init__(
        self,
        llm_client: Optional[BaseLLMClient] = None,
        target: str = "localhost:3000",
        max_steps: int = MAX_STEPS,
        findings_file: Optional[Path] = None,
        report_file: Optional[Path] = None
    ):
        self.llm_client = llm_client
        self.target = target
        self.max_steps = max_steps
        self.findings: List[Dict[str, Any]] = []
        self.step_count = 0
        self.findings_file = findings_file or FINDINGS_FILE
        self.report_file = report_file or REPORT_FILE
        # State memory: tracks (tool, target, ports, service, version) combos
        # that have already been executed, to break repetition loops.
        self.visited_actions: set = set()
        # Decision chain: records each step's thought + tool for the summary.
        self.decision_chain: List[Dict[str, Any]] = []
        self.conversation: List[Dict[str, str]] = [
            {"role": "system", "content": ASSESSMENT_SYSTEM_PROMPT}
        ]

    # ── Finding Management ───────────────────────────────────────────────────

    def _load_existing_findings(self) -> List[Dict[str, Any]]:
        existing: List[Dict[str, Any]] = []
        if self.findings_file.exists():
            try:
                with open(self.findings_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            existing.append(json.loads(line))
            except Exception as e:
                logger.error(f"Could not read findings file: {e}")
        return existing

    def _next_finding_id(self) -> str:
        existing = self._load_existing_findings()
        max_num = 0
        for f in existing:
            m = re.search(r"FIND-(\d+)", f.get("finding_id", ""))
            if m:
                max_num = max(max_num, int(m.group(1)))
        return f"FIND-{max_num + 1:03d}"

    def record_finding(
        self,
        tool: str,
        category: str,
        severity: str,
        cwe_reference: str,
        evidence_snippet: str,
        human_approved: bool = True
    ) -> str:
        """Records a finding to data/assessment_findings.jsonl.

        Deduplication: if an identical finding (same target + category +
        cwe_reference + evidence) already exists, the existing finding ID is
        returned instead of writing a duplicate.
        """
        # Deduplication check against existing findings
        existing = self._load_existing_findings()
        evidence_norm = (evidence_snippet or "").strip().lower()
        for f in existing:
            if (
                f.get("target") == self.target
                and f.get("category") == category
                and f.get("cwe_reference") == cwe_reference
                and (f.get("evidence_snippet") or "").strip().lower() == evidence_norm
            ):
                logger.info(f"Deduplicated finding: returning existing {f.get('finding_id')}")
                return f.get("finding_id", "")

        finding_id = self._next_finding_id()
        finding = {
            "finding_id": finding_id,
            "tool": tool,
            "target": self.target,
            "category": category,
            "severity": severity,
            "cwe_reference": cwe_reference,
            "evidence_snippet": evidence_snippet[:500],
            "human_approved": human_approved,
            "timestamp": datetime.now().isoformat()
        }
        try:
            self.findings_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.findings_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(finding, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"Could not write finding: {e}")
        self.findings.append(finding)
        return finding_id

    def _record_model_finding(self, finding: Dict[str, Any], current_tool: str = "") -> Optional[str]:
        """
        Records a finding emitted by the LLM in its JSON suggestion.
        The finding dict should contain: category, severity, cwe_reference,
        evidence_snippet. The tool is taken from the finding or the current step.
        """
        category = str(finding.get("category", "")).strip()
        if not category:
            return None
        severity = str(finding.get("severity", "Medium")).strip()
        cwe = str(finding.get("cwe_reference", "")).strip()
        evidence = str(finding.get("evidence_snippet", "")).strip()
        tool = str(finding.get("tool", current_tool or "assessment")).strip()

        # Human approval for the finding (human-in-the-loop principle)
        print(f"\n📌 Model bir bulgu öneriyor:")
        print(f"   Kategori: {category}")
        print(f"   Şiddet: {severity}")
        print(f"   CWE: {cwe}")
        print(f"   Kanıt: {evidence[:200]}")
        approval = input("   Bu bulguyu kaydetmek istiyor musunuz? (y=evet / n=hayır): ").strip().lower()
        if approval != "y":
            print("   ⏭️  Bulgu kaydedilmedi (kullanıcı reddetti).")
            return None

        finding_id = self.record_finding(
            tool=tool,
            category=category,
            severity=severity,
            cwe_reference=cwe,
            evidence_snippet=evidence,
            human_approved=True
        )
        print(f"📌 Bulgu kaydedildi: {finding_id} — {category} ({severity})")
        return finding_id

    # ── LLM Suggestion Parsing ───────────────────────────────────────────────

    def _ask_llm_for_suggestion(self, context: str) -> Optional[Dict[str, Any]]:
        """
        Asks the LLM for the next recommended step and parses its JSON.
        If parsing fails, retries ONCE with a strict "JSON only" instruction.
        """
        if not self.llm_client:
            return None

        self.conversation.append({"role": "user", "content": context})
        try:
            response = self.llm_client.generate(
                messages=self.conversation,
                temperature=0.3,
                max_tokens=400
            )
            content = response.content or ""
            self.conversation.append({"role": "assistant", "content": content})
            suggestion = self._parse_suggestion(content)
            if suggestion is not None:
                return suggestion

            # Retry once with a strict JSON-only instruction
            print("⚠️  LLM yanıtı JSON olarak ayrıştırılamadı. Bir kez daha soruluyor...")
            self.conversation.append({
                "role": "user",
                "content": (
                    "Önceki yanıtınız JSON olarak ayrıştırılamadı. "
                    "YALNIZCA geçerli bir JSON nesnesi döndürün, başka hiçbir metin "
                    "veya markdown eklemeyin. Şu şekilde: "
                    '{"thought":"...","tool":"nmap","target":"localhost:3000","param":null,"rationale":"..."}'
                )
            })
            response2 = self.llm_client.generate(
                messages=self.conversation,
                temperature=0.2,
                max_tokens=400
            )
            content2 = response2.content or ""
            self.conversation.append({"role": "assistant", "content": content2})
            return self._parse_suggestion(content2)
        except Exception as e:
            logger.error(f"LLM suggestion error: {e}")
            return None

    def _parse_suggestion(self, content: str) -> Optional[Dict[str, Any]]:
        """
        Extracts the JSON recommendation from the LLM response.
        Handles: pure JSON, markdown code fences (```json ... ```), and
        mixed text + JSON. Returns None if no valid JSON object is found.
        """
        if not content:
            return None

        # 1. Try to extract a JSON object from markdown code fences first
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL | re.IGNORECASE)
        if fence_match:
            try:
                return json.loads(fence_match.group(1))
            except json.JSONDecodeError:
                pass

        # 2. Try to find the first balanced JSON object anywhere in the text
        #    (handles mixed prose + JSON)
        start = content.find("{")
        if start != -1:
            depth = 0
            in_string = False
            escape = False
            for i in range(start, len(content)):
                ch = content[i]
                if in_string:
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == '"':
                        in_string = False
                    continue
                if ch == '"':
                    in_string = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = content[start:i + 1]
                        try:
                            return json.loads(candidate)
                        except json.JSONDecodeError:
                            break
        return None

    # ── Tool Dispatch ────────────────────────────────────────────────────────

    def _dispatch_tool(self, tool: str, target: str, param: Optional[str], approved: bool,
                       service_name: Optional[str] = None, version: Optional[str] = None,
                       ports: Optional[str] = None) -> Dict[str, Any]:
        """Calls the appropriate safe wrapper for an approved/skipped step."""
        if tool == "nmap":
            return suggest_nmap_scan(target, approved=approved, ports=ports)
        if tool == "gobuster":
            return suggest_gobuster_scan(target, approved=approved)
        if tool == "nikto":
            return suggest_nikto_scan(target, approved=approved)
        if tool == "whatweb":
            return suggest_whatweb_scan(target, approved=approved)
        if tool == "ssl_check":
            return suggest_ssl_check(target, approved=approved)
        if tool == "sqlmap":
            return suggest_sqlmap_check(target, param or "id", approved=approved)
        if tool == "searchsploit":
            return suggest_searchsploit_lookup(service_name or target, version or "", approved=approved)
        if tool == "cve_search":
            return suggest_cve_search(service_name or target, version or "", approved=approved)
        return {
            "status": "UNKNOWN_TOOL",
            "tool": tool,
            "target": target,
            "message": f"Unknown tool '{tool}' requested by LLM. Blocked."
        }

    @staticmethod
    def _action_key(tool: str, target: str, ports: Optional[str],
                    service_name: Optional[str], version: Optional[str]) -> str:
        """Builds a canonical key for an action to detect repetition."""
        parts = [
            tool or "",
            target or "",
            str(ports or ""),
            str(service_name or ""),
            str(version or ""),
        ]
        return "|".join(parts)

    def _feed_repeat_warning(self, action_key: str) -> None:
        """Tells the LLM that it already ran this action and must change."""
        msg = (
            f"⚠️ LOOP BREAKER: You already ran the action '{action_key}' in a "
            f"previous step and received its output. Do NOT repeat it. "
            f"Propose a DIFFERENT action (different tool, port, service, or "
            f"version), or set \"tool\": \"done\" to end the assessment."
        )
        self.conversation.append({"role": "user", "content": msg})

    # ── Main Loop ────────────────────────────────────────────────────────────

    def run(self) -> List[Dict[str, Any]]:
        """
        Runs the human-in-the-loop assessment loop.
        Returns the list of findings recorded during this session.
        """
        print("\n" + "=" * 70)
        print("🛡️  AutoRedTeam — Security Assessment Assistant (Human-in-the-Loop)")
        print("=" * 70)
        print(f"🎯 Hedef: {self.target}")
        print("⚠️  Bu araç yalnızca YETKİLİ, eğitim amaçlı testler içindir.")
        print("    LLM hiçbir komutu doğrudan çalıştıramaz; her adım sizin onayınızı bekler.")
        print("    'dur' yazarak istediğiniz an durabilirsiniz.\n")

        while self.step_count < self.max_steps:
            self.step_count += 1
            print(f"\n── Adım {self.step_count}/{self.max_steps} ──")

            # 1. Ask the LLM for the next recommendation
            context = self._build_context()
            suggestion = self._ask_llm_for_suggestion(context)

            if suggestion is None:
                print("ℹ️  LLM öneri üretemedi. Manuel bir adım seçin veya 'dur' yazın.")
                suggestion = self._manual_suggestion()
                if suggestion is None:
                    break

            tool = suggestion.get("tool", "")
            target = suggestion.get("target", self.target)
            param = suggestion.get("param")
            ports = suggestion.get("ports")
            service_name = suggestion.get("service_name")
            version = suggestion.get("version")
            rationale = suggestion.get("rationale", "")

            # Record the decision step for the session summary
            self.decision_chain.append({
                "step": self.step_count,
                "thought": suggestion.get("thought", ""),
                "tool": tool,
                "target": target,
                "ports": ports,
                "service_name": service_name,
                "version": version,
                "rationale": rationale,
            })

            # 1b. Record a finding if the model emitted one (based on the
            #     previous tool output). This is the human-approved finding
            #     capture path.
            finding = suggestion.get("finding")
            if isinstance(finding, dict) and finding.get("category"):
                self._record_model_finding(finding, tool)

            # 2. LLM says done → end assessment
            if tool == "done":
                print("✅ LLM değerlendirmenin tamamlandığını bildirdi.")
                break

            # 3. Code-level scope validation (blocks out-of-scope before asking)
            if not is_target_allowed(target):
                print(f"🚫 KAPSAM DIŞI HEDEF REDDEDİLDİ: '{target}'")
                print("   Bu hedef config/allowed_targets.txt içinde değil. Komut çalıştırılmadı.")
                self._log_rejection(tool, target)
                continue

            # 3b. Loop breaker: detect if this exact action was already run.
            action_key = self._action_key(tool, target, ports, service_name, version)
            if action_key in self.visited_actions:
                print(f"🔁 TEKRAR TESPİTİ: Bu adım zaten çalıştırıldı ({action_key}).")
                print("   Modelden farklı bir adım isteniyor...")
                self._feed_repeat_warning(action_key)
                continue

            # 4. Show the recommendation and ask for human approval
            print(f"\n💡 LLM Önerisi:")
            print(f"   Araç: {tool}")
            print(f"   Hedef: {target}")
            if ports:
                print(f"   Portlar: {ports}")
            if param:
                print(f"   Parametre: {param}")
            if service_name:
                print(f"   Servis: {service_name}")
            if version:
                print(f"   Versiyon: {version}")
            print(f"   Gerekçe: {rationale}")

            if tool == "sqlmap":
                print("   ⚠️  NOT: Yalnızca TESPİT modu (--batch --level=1 --risk=1).")
                print("       Hiçbir veri çekme/dump işlemi yapılmaz.")

            if tool == "searchsploit":
                print("   ⚠️  NOT: Yalnızca BİLGİ amaçlıdır (LOOKUP-ONLY).")
                print("       Exploit ÇALIŞTIRMAZ; yalnızca bilinen zafiyetleri listeler.")

            approval = input("\n   Bu adımı çalıştırmak istiyor musunuz? (y=evet / n=hayır / dur=durdur): ").strip().lower()

            if approval == "dur":
                print("⏹️  Değerlendirme kullanıcı tarafından durduruldu.")
                break

            approved = (approval == "y")

            # 5. Execute (only if approved) and capture output
            result = self._dispatch_tool(
                tool, target, param, approved=approved,
                service_name=service_name, version=version, ports=ports
            )

            if result.get("status") == "REJECTED_OUT_OF_SCOPE":
                print(f"🚫 {result.get('message')}")
                continue

            if approved:
                print(f"\n🔧 Çalıştırılıyor: {result.get('command')}")
                output = result.get("output", "")
                print(f"📄 Çıktı:\n{output[:2000]}")
                # Record this action as visited (loop breaker state)
                self.visited_actions.add(action_key)
                # Auto-extract a finding from the tool output if a known
                # vulnerable version pattern is detected (proactive capture).
                self._auto_extract_finding(tool, output)
            else:
                print("\n⏭️  Adım kullanıcı tarafından reddedildi. LLM'den alternatif istenecek.")
                output = ""

            # 6. Feed the result back to the LLM for interpretation
            self._feed_result_to_llm(tool, target, approved, output)

        print("\n" + "=" * 70)
        print(f"📊 Değerlendirme tamamlandı. {len(self.findings)} bulgu kaydedildi.")
        print("=" * 70)
        return self.findings

    def _build_context(self) -> str:
        """Builds the context message for the LLM."""
        existing = self._load_existing_findings()
        summary = "Şu ana kadar kaydedilen bulgular:\n"
        if existing:
            for f in existing[-5:]:
                summary += f"- {f.get('finding_id')}: {f.get('tool')} / {f.get('category')} / {f.get('severity')}\n"
        else:
            summary += "(henüz bulgu yok)\n"
        summary += (
            f"\nHedef: {self.target}\n"
            f"Adım: {self.step_count}/{self.max_steps}\n"
            "Bir sonraki mantıklı değerlendirme adımını JSON olarak öner."
        )
        return summary

    def _feed_result_to_llm(self, tool: str, target: str, approved: bool, output: str) -> None:
        """Sends the tool result (or rejection) back to the LLM."""
        if approved:
            msg = (
                f"Tool '{tool}' ran against {target} with human approval.\n"
                f"Output:\n{output[:1500]}\n\n"
                "Interpret this output. If you found a vulnerability, note it. "
                "Then recommend the next step as JSON."
            )
        else:
            msg = (
                f"The human operator REJECTED the '{tool}' step against {target}.\n"
                "Propose a DIFFERENT alternative step as JSON."
            )
        self.conversation.append({"role": "user", "content": msg})

    # Known vulnerable version patterns for proactive finding extraction.
    # (service regex, category, cwe)
    _KNOWN_VULN_PATTERNS = [
        (r"vsftpd\s+2\.3\.4", "Known vulnerable service version", "CWE-937"),
        (r"Apache\s+httpd\s+2\.2\.8", "Old Software Version", "CWE-1104"),
        (r"Apache/2\.2\.8", "Old Software Version", "CWE-1104"),
        (r"PHP\s+5\.2\.4", "Old Software Version", "CWE-1104"),
        (r"PHP/5\.2\.4", "Old Software Version", "CWE-1104"),
        (r"Samba\s+3\.0\.20", "Known vulnerable service version", "CWE-937"),
        (r"OpenSSH\s+4\.7p1", "Old Software Version", "CWE-1104"),
        (r"MySQL\s+5\.0\.51", "Old Software Version", "CWE-1104"),
        (r"ProFTPD\s+1\.3\.1", "Known vulnerable service version", "CWE-937"),
        (r"UnrealIRCd", "Known vulnerable service version", "CWE-937"),
    ]

    def _auto_extract_finding(self, tool: str, output: str) -> None:
        """
        Proactively detects known vulnerable version patterns in a tool output
        and offers to record them as findings (human-approved). This catches
        vulnerabilities even if the model does not emit a 'finding' field.
        """
        if not output:
            return
        output_lower = output.lower()
        for pattern, category, cwe in self._KNOWN_VULN_PATTERNS:
            if re.search(pattern, output_lower):
                # Extract a short evidence snippet around the match
                m = re.search(pattern, output_lower)
                start = max(0, m.start() - 20)
                evidence = output[start:m.end() + 20].strip()
                print(f"\n🔎 Otomatik bulgu tespiti: '{pattern}' kalıbı bulundu.")
                approval = input(f"   '{category}' bulgusunu kaydetmek ister misiniz? (y/n): ").strip().lower()
                if approval == "y":
                    self.record_finding(
                        tool=tool,
                        category=category,
                        severity="High",
                        cwe_reference=cwe,
                        evidence_snippet=evidence,
                        human_approved=True
                    )
                    print(f"   📌 Bulgu kaydedildi: {category} (High)")
                else:
                    print("   ⏭️  Bulgu kaydedilmedi.")
                return  # only one auto-finding per tool output to avoid spam

    def _manual_suggestion(self) -> Optional[Dict[str, Any]]:
        """Allows the operator to pick a tool manually when the LLM fails."""
        print("   Mevcut araçlar: nmap, gobuster, nikto, whatweb, ssl_check, sqlmap, searchsploit, cve_search")
        choice = input("   Bir araç seçin (veya 'dur'): ").strip().lower()
        if choice == "dur":
            return None
        if choice in ASSESSMENT_TOOLS:
            param = None
            service_name = None
            version = None
            ports = None
            if choice == "sqlmap":
                param = input("   Parametre adı (ör. id): ").strip() or "id"
            if choice == "nmap":
                ports = input("   Portlar (ör. 21,22,80, boş = varsayılan): ").strip() or None
            if choice in ("searchsploit", "cve_search"):
                service_name = input("   Servis adı (ör. vsftpd): ").strip()
                version = input("   Versiyon (ör. 2.3.4): ").strip()
            return {
                "tool": choice,
                "target": self.target,
                "param": param,
                "ports": ports,
                "service_name": service_name,
                "version": version,
                "rationale": "Manuel olarak seçildi."
            }
        print("   Geçersiz araç. 'dur' yazın veya geçerli bir araç seçin.")
        return self._manual_suggestion()

    def _log_rejection(self, tool: str, target: str) -> None:
        """Logs an out-of-scope rejection to the audit log."""
        from core.assessment_tools import _log_audit
        _log_audit({
            "event": "REJECTED_OUT_OF_SCOPE",
            "tool": tool,
            "target": target,
            "timestamp": datetime.now().isoformat()
        })

    # ── Report Generation ────────────────────────────────────────────────────

    def generate_report(self, findings: Optional[List[Dict[str, Any]]] = None) -> Path:
        """
        Generates reports/assessment_report.md with an executive summary,
        OWASP WSTG-referenced methodology, a findings table, and per-finding
        impact/remediation guidance.
        """
        all_findings = findings if findings is not None else self._load_existing_findings()

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(
            all_findings,
            key=lambda f: severity_order.get(f.get("severity", "Low"), 99)
        )

        critical = sum(1 for f in all_findings if f.get("severity") == "Critical")
        high = sum(1 for f in all_findings if f.get("severity") == "High")
        medium = sum(1 for f in all_findings if f.get("severity") == "Medium")
        low = sum(1 for f in all_findings if f.get("severity") == "Low")

        # Describe the target environment based on the target alias
        target_desc = self._describe_target(self.target)

        md = f"""# 🛡️ AutoRedTeam: Güvenlik Değerlendirme Raporu (Security Assessment)

> **Hedef:** {self.target} ({target_desc})  
> **Tarih:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
> **Metodoloji:** OWASP Web Security Testing Guide (WSTG)  
> **Mod:** İnsan Onaylı (Human-in-the-Loop) — tüm adımlar operatör onayıyla çalıştırıldı

---

## 📊 1. Yönetici Özeti (Executive Summary)

Bu rapor, yerel Docker konteynerinde çalışan **{target_desc}** hedefi üzerinde,
**insan onaylı (human-in-the-loop)** güvenlik değerlendirmesi sonucunda elde edilen
bulguları özetler. LLM yalnızca öneri sunmuş; hiçbir komut operatör onayı olmadan
çalıştırılmamıştır.

| Metrik | Değer |
| :--- | :---: |
| **Toplam Bulgu** | `{len(all_findings)}` |
| **Kritik (Critical)** | `{critical}` |
| **Yüksek (High)** | `{high}` |
| **Orta (Medium)** | `{medium}` |
| **Düşük (Low)** | `{low}` |

---

## 🧪 2. Metodoloji (OWASP WSTG Referanslı)

Değerlendirme, OWASP Web Security Testing Guide (WSTG) bölümlerine göre yapılandırılmıştır:

- **WSTG-INFO-01/02:** Bilgi Toplama (nmap, whatweb) — teknoloji yığını ve servis keşfi
- **WSTG-CONF-01/02:** Konfigürasyon Yönetimi (nikto, ssl_check) — sunucu ve TLS ayarları
- **WSTG-ATHN / WSTG-ATHZ:** Kimlik Doğrulama / Yetkilendirme testleri
- **WSTG-INPV-05:** SQL Injection tespiti (sqlmap — yalnızca tespit modu)

---

## 🧭 3. Model Karar Zinciri (Decision Chain)

Modelin her adımda ürettiği akıl yürütme (thought) ve seçtiği araç:

| Adım | Araç | Hedef | Akıl Yürütme (Thought) |
| :---: | :--- | :--- | :--- |
"""
        if not self.decision_chain:
            md += "| *(karar zinciri kaydedilmedi)* | — | — | — |\n"
        else:
            for d in self.decision_chain:
                thought = (d.get("thought") or "")[:120]
                tool = d.get("tool", "")
                target = d.get("target", "")
                md += f"| {d.get('step')} | `{tool}` | {target} | {thought} |\n"

        md += "\n---\n\n## 📋 4. Bulgu Tablosu\n\n| Bulgu ID | Araç | Kategori | Şiddet | CWE |\n| :--- | :--- | :--- | :---: | :--- |\n"
        if not sorted_findings:
            md += "| *(bulgu yok)* | — | — | — | — |\n"
        else:
            for f in sorted_findings:
                md += (
                    f"| `{f.get('finding_id')}` | {f.get('tool')} | "
                    f"{f.get('category')} | {f.get('severity')} | "
                    f"{f.get('cwe_reference')} |\n"
                )

        md += "\n---\n\n## 🔍 5. Detaylı Bulgu Analizi ve Öneriler (Remediation)\n\n"

        if not sorted_findings:
            md += "*Değerlendirme sırasında kaydedilmiş bulgu bulunmamaktadır.*\n"
        else:
            for i, f in enumerate(sorted_findings, 1):
                md += f"""### 5.{i}. {f.get('finding_id')}: {f.get('category')} ({f.get('severity')})
* **Araç:** `{f.get('tool')}` | **Hedef:** `{f.get('target')}`
* **CWE Referansı:** `{f.get('cwe_reference')}`
* **İnsan Onayı:** {'✅ Evet' if f.get('human_approved') else '❌ Hayır'}
* **Kanıt (Evidence):**
```
{f.get('evidence_snippet', '')}
```

**Etki (Impact):**
> {self._impact_for_severity(f.get('severity'))}

**Önerilen Düzeltme (Remediation):**
> {self._remediation_for_category(f.get('category'))}

---
"""
        md += "\n*Rapor AutoRedTeam Security Assessment Assistant tarafından üretilmiştir.*\n"

        try:
            self.report_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.report_file, "w", encoding="utf-8") as f:
                f.write(md)
        except Exception as e:
            logger.error(f"Could not write report: {e}")
        return self.report_file

    @staticmethod
    def _describe_target(target: str) -> str:
        """Returns a human-readable description of the target environment."""
        t = (target or "").strip().lower()
        if t in ("localhost:3000", "localhost", "127.0.0.1", "127.0.0.1:3000"):
            return "OWASP Juice Shop — Docker"
        if t == "metasploitable2":
            return "Metasploitable2 — Docker"
        return "Docker eğitim ortamı"

    @staticmethod
    def _impact_for_severity(severity: str) -> str:
        mapping = {
            "Critical": "Kritik güvenlik açığı: sistem tamamen tehlikeye atılabilir, "
                        "veri bütünlüğü ve gizliliği ciddi şekilde ihlal edilebilir.",
            "High": "Yüksek risk: yetkisiz erişim veya hassas veri ifşası mümkündür.",
            "Medium": "Orta risk: sınırlı etki, ancak saldırı yüzeyini genişletebilir.",
            "Low": "Düşük risk: bilgi sızıntısı veya konfigürasyon iyileştirmesi gerektirir.",
        }
        return mapping.get(severity, "Bilinmeyen etki.")

    @staticmethod
    def _remediation_for_category(category: str) -> str:
        cat = (category or "").lower()
        if "sql" in cat:
            return ("Parametreli sorgular (prepared statements) kullanın, girdi doğrulama "
                    "(input validation) uygulayın ve ORM kullanın.")
        if "xss" in cat:
            return ("Çıktı kodlaması (output encoding) uygulayın, Content-Security-Policy "
                    "başlığı ekleyin ve kullanıcı girdisini sanitize edin.")
        if "auth" in cat or "kimlik" in cat:
            return ("Güçlü parola politikası, çok faktörlü doğrulama (MFA) ve oturum "
                    "yönetimi iyileştirmeleri uygulayın.")
        if "config" in cat or "konfig" in cat:
            return ("Sunucu ve TLS konfigürasyonunu sertleştirin, gereksiz servisleri "
                    "kapatın ve güvenli başlıkları etkinleştirin.")
        return "İlgili güvenlik kontrolünü uygulayın ve OWASP önerilerini takip edin."
