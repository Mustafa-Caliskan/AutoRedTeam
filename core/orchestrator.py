"""
AutoRedTeam - Multi-Tier Orchestration (DeepSeek V4 Flash + Anthropic Claude 5 Sonnet).

Bu modül, 3 katmanlı otonom güvenlik orkestrasyonunu yönetir:
- Tier 1 (Kas / Attacker): CyberStrike 35B — Sansürsüz ofansif payload üretimi ve araç tetikleme
- Tier 2 (Beyin / Taktik): DeepSeek V4 Flash — Strateji, küresel saldırı yüzeyi bağlamı ve canlı web araştırması
- Tier 3 (Supreme Arbiter & Escalation Oracle): Anthropic Claude 5 Sonnet (`claude-5-sonnet`) —
  Worker takıldığında, deadlock durumlarında veya kritik kriz anlarında devreye giren en üst düzey otorite.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.web_search import WEB_SEARCH_TOOL_SCHEMA, execute_tool_call
from core.llm_client import BaseLLMClient, LLMResponse, AnthropicClient, OpenAICompatibleClient
from core.skill_loader import skill_loader
from core.chain_engine import chain_engine

logger = logging.getLogger(__name__)


ORCHESTRATOR_SYSTEM_PROMPT = """You are the Chief Strategic Orchestrator (Parent Brain) for AutoRedTeam, an elite automated security assessment and adversarial red-teaming framework.

Your subordinate worker is 'CyberStrike 35B' (The Execution Engine), a specialized uncensored offensive LLM operating with containerized security tools (nmap, gobuster, nikto, whatweb, ssl_check, sqlmap, searchsploit, cve_search).

### YOUR CORE RESPONSIBILITY
You do NOT execute CLI tools directly. You provide HIGH-LEVEL STRATEGIC INTELLIGENCE, maintain global attack surface context, synthesize findings, conduct live web research, and direct the worker with surgical precision.

### THE 4-WAVE ASSESSMENT METHODOLOGY
You must guide the assessment through structured offensive security phases:
1. WAVE 1 — RECONNAISSANCE & ATTACK SURFACE ENUMERATION:
   - Identify active open ports, service banners, running daemons (nmap).
   - Discover hidden directories, administrative portals, APIs (gobuster, whatweb, nikto).
   - Prevent duplicate scans: keep track of scanned ports and paths.

2. WAVE 2 — VULNERABILITY CORRELATION & LIVE CVE RESEARCH:
   - Match discovered service versions (e.g., vsftpd 2.3.4, Apache 2.2.8, Samba 3.0.20, ProFTPD, UnrealIRCd) against known exploits.
   - PROACTIVE WEB SEARCH: Whenever a specific software version, unusual daemon, or CVE identifier is identified, IMMEDIATELY call the `web_search` tool to fetch fresh CVE details, CVSS scores, verified PoC mechanics, and default credentials.

3. WAVE 3 — TARGETED VERIFICATION & PARAMETER PROBING:
   - Direct CyberStrike to probe high-value targets (e.g., test SQL injection on input parameters via sqlmap in detection mode, verify SSL misconfigurations).
   - Require concrete evidence (status codes, banners, reflection, error triggers) before confirming a finding.

4. WAVE 4 — EXPLOIT CHAINING & STRATEGIC REPORTING:
   - Combine low/medium severity findings into high-impact attack chains (e.g., info disclosure + credential leak -> administrative takeover).
   - Ensure all verified vulnerabilities have severity ratings, CWE tags, and actionable remediation guidance.

### QUALITY & ANTI-HALLUCINATION GUARDRAILS (7-QUESTION GATE):
1. ZERO FLUFF: Never instruct the worker to report missing security headers alone (CSP/HSTS), banner grabs without CVE, or open redirect alone without an exploit chain.
2. CONCRETE PROOF ONLY: Demand status codes, exploit reflection, or verified CVE matches before accepting findings.
3. EXPLOIT CHAINING: Constantly look for opportunities to chain primitives (Capability A -> Capability B -> Critical Terminal Impact).

### WORKER KURTARMA (TAKILMA / TEKRAR TESPITI) - KRITIK GOREVIN:
Senin EN ONEMLI gorevin worker (CyberStrike) bir yerde takilip kalirsa onu KURTARMAKTIR.
- Worker ayni servise/araca 2+ kez donduyse (Worker Activity bolumunde gorursen), ona NET bir sekilde "DUR, bu servisi birak, SU farkli servise/exploit'e gec" diye emir ver.
- Worker sadece kesif (nmap/searchsploit) yapip EXPLOIT denemiyorsa, onu dogrudan exploit'e zorla: "tool:exploit, exploit:<ad>" JSON ciktisi uretmesini emret.
- Worker root (uid=0) aldiysa ama diger acik servisleri test etmediyse, "root aldin ama Samba/MySQL/SSH/ProFTPD/UnrealIRCd gibi diger servisleri de test et" diye yonlendir.
- Metasploitable2'de test edilecek servisler: vsftpd(21), SSH(22), Samba(445), ingreslock(1524), MySQL(3306), PostgreSQL(5432), UnrealIRCd(6667), Apache(80), distcc(3632).
- Worker'i asla ayni servise tekrar tekrar nmap taramasi yapmaya yonlendirme. Kesif zaten yapildiysa, exploit'e veya farkli servise gec.
"""


class OrchestratorAgent:
    """
    DeepSeek V4 Flash tabanlı Orkestrator Ajan.
    
    CyberStrike 35B Worker'a yuksek seviyeli gorev emri verir, baglami 
    yonetir ve web aramasini devreye alir.
    """

    def __init__(
        self,
        client: BaseLLMClient,
        max_search_calls: int = 10,
    ):
        """
        Args:
            client: DeepSeek V4 Flash LLM istemcisi (OpenAICompatibleClient veya DeepSeekClient)
            max_search_calls: Oturum basina maksimum web aramasi sayisi (maliyet kontrolu)
        """
        self.client = client
        self.max_search_calls = max_search_calls
        self._search_count = 0
        self._session_history: List[Dict[str, str]] = []

    def reset(self):
        """Oturum gecmisini ve sayaclari sifirlar."""
        self._session_history = []
        self._search_count = 0

    def plan_next_step(
        self,
        current_findings: List[Dict[str, Any]],
        recent_worker_output: Optional[str],
        step_number: int,
        target: str,
        extra_context: Optional[str] = None,
        worker_activity: Optional[str] = None,
        attack_surface_tree: Optional[str] = None,
    ) -> str:
        """
        Mevcut durumu analiz edip Worker'a (CyberStrike 35B) verilecek
        bir sonraki gorev emrini DeepSeek V4 Flash'tan alir.

        Args:
            current_findings: Simdiye kadar kaydedilen bulgular listesi
            recent_worker_output: CyberStrike'in son ciktisi veya hata mesaji
            step_number: Mevcut adim numarasi
            target: Hedef sistem (ornek: 'metasploitable2', 'localhost:3000')
            extra_context: Ek baglam metni (opsiyonel)
            worker_activity: Worker'in son islem gecmisi (tekrar/takilma tespiti icin)
            attack_surface_tree: L0/L1 saldırı yüzeyi ağacı (opsiyonel)
        
        Returns:
            Worker ajana verilecek gorev direktifi (duz metin).
        """
        # Ozet baglamı oluştur
        findings_summary = self._summarize_findings(current_findings)

        # Saldırı yüzeyi ağacını otomatik çek (verilmediyse)
        if not attack_surface_tree:
            try:
                from core.context_engine import context_engine
                attack_surface_tree = context_engine.render_attack_surface_tree(target)
            except Exception:
                attack_surface_tree = None
        
        context_parts = [
            f"=== Assessment Context ===",
            f"Target: {target}",
            f"Step: {step_number}",
            f"",
            f"=== Findings So Far ({len(current_findings)} total) ===",
            findings_summary,
            f"",
            f"=== Recent Worker Output ===",
            recent_worker_output or "(no output yet)",
        ]

        if attack_surface_tree:
            context_parts += ["", f"=== Attack Surface Tree (L0/L1 Live State) ===", attack_surface_tree]
        
        if worker_activity:
            context_parts += ["", f"=== Worker Activity (tekrar/takilma tespiti) ===", worker_activity]
        
        if extra_context:
            context_parts += ["", f"=== Extra Context ===", extra_context]

        # Progressive skill playbooks from 818 structured skills
        # Extract ports/services discovered so far from findings for smarter matching
        open_ports: list = []
        services: list = []
        for f in current_findings:
            if f.get("ports"):
                try:
                    open_ports.extend([int(p.strip()) for p in str(f["ports"]).split(",") if p.strip().isdigit()])
                except Exception:
                    pass
            if f.get("service_name"):
                services.append(str(f["service_name"]))
            # Also extract from evidence_snippet port patterns like "21/tcp open ftp vsftpd"
            evidence = str(f.get("evidence_snippet", ""))
            for m in __import__("re").finditer(r"(\d{2,5})/tcp\s+open\s+\S+\s+(\S+)", evidence):
                try:
                    open_ports.append(int(m.group(1)))
                    services.append(m.group(2))
                except Exception:
                    pass
        open_ports = list(set(open_ports))

        matched_skills = skill_loader.suggest_skills_for_target(
            target=target, open_ports=open_ports, services=services
        )
        if matched_skills:
            context_parts.extend([
                "",
                "=== Relevant Tactical Skills (818 Skills Library) ===",
                skill_loader.format_for_prompt(matched_skills[:4])
            ])

        # Exploit Chaining hints
        if current_findings:
            latest_finding = current_findings[-1]
            chains = chain_engine.suggest_next_hops(latest_finding)
            if chains:
                chain_tips = [f"- Candidate Target: {c.get('target')} -> Technique: {c.get('technique')} (Impact: {c.get('terminal_impact')})" for c in chains[:3]]
                context_parts.extend([
                    "",
                    "=== Exploit Chaining Opportunities (Chain Walk Engine) ===",
                    "\n".join(chain_tips)
                ])

        context_parts.append(
            "\n=== Task ===\n"
            "Based on the above, what should the worker agent (CyberStrike 35B) do next? "
            "Be specific about the tool, target, and parameters. "
            "If you need to research a specific CVE or exploit, use the web_search tool first."
        )

        user_message = "\n".join(context_parts)
        self._session_history.append({"role": "user", "content": user_message})

        # Tools: web_search kullanilabilir olmali, limit asildiysa kaldır
        tools = None
        if self._search_count < self.max_search_calls:
            tools = [WEB_SEARCH_TOOL_SCHEMA]

        messages = [
            {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
            *self._session_history
        ]

        response = self._call_with_tools(messages, tools)
        
        # Asistan yaniti gecmise ekle
        self._session_history.append({"role": "assistant", "content": response})
        
        return response

    def fallback_correction(self, failed_output: str, step_number: int, target: str) -> str:
        """
        CyberStrike 35B gecersiz JSON veya hata dondurdugunda devreye girer
        ve worker'a duzeltici bir yonlendirme verir.

        Args:
            failed_output: Worker'in hatali ciktisi
            step_number: Hata yasanan adim
            target: Hedef sistem
        
        Returns:
            Duzeltme direktifi (duz metin).
        """
        correction_prompt = (
            f"The worker agent (CyberStrike 35B) returned an invalid or incomplete output "
            f"at step {step_number} for target '{target}'.\n\n"
            f"=== Failed Output ===\n{failed_output[:500]}\n\n"
            "Please provide a corrective directive: a clearer, simpler instruction "
            "for what the worker should do next. Focus on a single tool call with "
            "concrete parameters."
        )

    def fallback_correction(self, failed_output: str, step_number: int, target: str) -> str:
        """
        CyberStrike 35B gecersiz JSON veya hata dondurdugunda devreye girer
        ve worker'a duzeltici bir yonlendirme verir.

        Args:
            failed_output: Worker'in hatali ciktisi
            step_number: Hata yasanan adim
            target: Hedef sistem
        
        Returns:
            Duzeltme direktifi (duz metin).
        """
        correction_prompt = (
            f"The worker agent (CyberStrike 35B) returned an invalid or incomplete output "
            f"at step {step_number} for target '{target}'.\n\n"
            f"=== Failed Output ===\n{failed_output[:500]}\n\n"
            "Please provide a corrective directive: a clearer, simpler instruction "
            "for what the worker should do next. Focus on a single tool call with "
            "concrete parameters."
        )

        messages = [
            {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
            {"role": "user", "content": correction_prompt}
        ]

        tools = [WEB_SEARCH_TOOL_SCHEMA] if self._search_count < self.max_search_calls else None
        result = self._call_with_tools(messages, tools)
        logger.info(f"[Orchestrator] Fallback correction at step {step_number}: {result[:120]}...")
        return result

    def analyze_and_rescue(
        self,
        worker_activity: str,
        recent_worker_output: str,
        current_findings: List[Dict[str, Any]],
        step_number: int,
        target: str,
        attack_surface_tree: Optional[str] = None,
    ) -> str:
        """
        Worker bir yerde takilip kaldiginda (tekrar tespiti / exploit'e gecmemesi)
        devreye girer. Worker'in son aktivitesini ve ciktisini ANALIZ eder:
          1. Hatanin ne oldugunu anlamaya calisir.
          2. Cozumu biliyorsa dogrudan soyler.
          3. Bilmiyorsa web_search ile internetten arastirir (model 2024 oncesi
             egitildigi icin guncel CVE/exploit bilgilerini bilemeyebilir).
          4. Worker'a net, tek bir kurtarma direktifi verir.

        Returns:
            Worker'a verilecek kurtarma direktifi (duz metin).
        """
        findings_summary = self._summarize_findings(current_findings)

        if not attack_surface_tree:
            try:
                from core.context_engine import context_engine
                attack_surface_tree = context_engine.render_attack_surface_tree(target)
            except Exception:
                attack_surface_tree = None

        tree_block = f"=== Attack Surface Tree (L0/L1 Live State) ===\n{attack_surface_tree}\n\n" if attack_surface_tree else ""

        rescue_prompt = (
            f"You are the Chief Strategic Orchestrator. Your worker (CyberStrike 35B) is STUCK "
            f"and needs your expert rescue at step {step_number} for target '{target}'.\n\n"
            f"=== Worker Activity (son islemler & tekrar tespiti) ===\n"
            f"{worker_activity}\n\n"
            f"{tree_block}"
            f"=== Recent Worker Output ===\n"
            f"{recent_worker_output[:800]}\n\n"
            f"=== Findings So Far ===\n"
            f"{findings_summary}\n\n"
            "### YOUR RESCUE TASK\n"
            "1. ANALYZE what the worker is doing wrong or where it is stuck. Be specific.\n"
            "2. If you KNOW the correct next action (e.g. which exploit to run, which service "
            "to pivot to, what command failed and why), state it clearly and precisely.\n"
            "3. If you are UNSURE about the correct technique, exploit mechanics, or a specific "
            "CVE/version, use the `web_search` tool to research it NOW (the worker model was "
            "trained only up to 2024 and may not know recent exploits or exact PoC steps).\n"
            "4. Give the worker ONE clear, actionable directive: exactly what tool/exploit to "
            "run next and why. If the worker is repeating a scan, tell it to STOP and pivot "
            "to a different service or to active exploitation.\n"
            "5. If the worker has NOT attempted exploitation yet, order it to run the matching "
            "exploit for a discovered vulnerable service (e.g. tool:exploit, exploit:ingreslock_backdoor).\n\n"
            "Output your rescue directive as clear prose the worker can follow."
        )

        messages = [
            {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
            {"role": "user", "content": rescue_prompt}
        ]

        tools = [WEB_SEARCH_TOOL_SCHEMA] if self._search_count < self.max_search_calls else None
        result = self._call_with_tools(messages, tools)
        logger.info(f"[Orchestrator] analyze_and_rescue at step {step_number}: {result[:150]}...")
        return result

    def direct_json_suggestion(
        self,
        current_findings: List[Dict[str, Any]],
        step_number: int,
        target: str,
        visited_actions: Optional[set] = None,
        attack_surface_tree: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        DeepSeek V4 Flash directly generates the structured JSON tool recommendation
        when the worker fails to produce valid JSON. Ensures zero downtime.
        """
        findings_summary = self._summarize_findings(current_findings)
        visited_str = ", ".join([str(a) for a in (visited_actions or set())])

        if not attack_surface_tree:
            try:
                from core.context_engine import context_engine
                attack_surface_tree = context_engine.render_attack_surface_tree(target)
            except Exception:
                attack_surface_tree = None
        tree_section = f"Current Attack Surface Tree:\n{attack_surface_tree}\n\n" if attack_surface_tree else ""

        prompt = (
            f"You are the senior assessment co-pilot. The worker failed to produce valid JSON.\n"
            f"Target: {target}\n"
            f"Step: {step_number}\n"
            f"{tree_section}"
            f"Findings so far:\n{findings_summary}\n"
            f"Already executed actions: {visited_str}\n\n"
            f"Output ONLY a single valid JSON object recommending the next best tool call.\n"
            f'{{"thought": "...", "tool": "one of: nmap, gobuster, nikto, whatweb, ssl_check, sqlmap, searchsploit, cve_search, exploit, privesc, done", '
            f'"target": "{target}", "param": null, "ports": null, "service_name": null, "version": null, '
            f'"exploit": null, "privesc": null, "username": null, "password": null, "rationale": "...", "finding": null}}\n'
            f"For metasploitable2, available exploits: vsftpd_backdoor, samba_usermap, ingreslock_backdoor, ssh_credential_spray. "
            f"Available privesc: suid_enumeration, sudoers_audit, sudo_privesc, gtfobins_privesc, verify_root.\n"
            f"Do NOT repeat an action in 'Already executed actions'. Output ONLY valid JSON, nothing else."
        )

        messages = [
            {"role": "system", "content": "You are a senior penetration tester. Output ONLY a valid JSON object."},
            {"role": "user", "content": prompt}
        ]

        try:
            res = self.client.generate(messages=messages, temperature=0.0, max_tokens=1024)
            content = res.content or ""
            parsed = self._extract_json_object(content)
            if parsed is not None:
                logger.info(f"[Orchestrator] Direct JSON suggestion succeeded: tool={parsed.get('tool')}")
                return parsed
        except Exception as e:
            logger.error(f"[Orchestrator] direct_json_suggestion failed: {e}")
        return None

    def research(self, query: str) -> str:
        """
        Web arama aracini dogrudan cagirir (orkestrator disinda da kullanilabilir).

        Args:
            query: Arama sorgusu

        Returns:
            Arama sonuclari ozeti.
        """
        from core.web_search import web_search
        self._search_count += 1
        logger.info(f"[Orchestrator] Web search #{self._search_count}: {query}")
        return web_search(query)

    def _call_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
    ) -> str:
        """
        DeepSeek'i araclarla birlikte cagirir.
        Model web_search araclayabilirse, sonucu mesaj gecmisine ekleyip
        tekrar cagirarak nihai duz metin yaniti dondurur.
        """
        MAX_TOOL_ROUNDS = 3
        current_messages = list(messages)

        for _ in range(MAX_TOOL_ROUNDS):
            response: LLMResponse = self.client.generate(
                messages=current_messages,
                tools=tools,
                temperature=0.3,
                max_tokens=1024,
            )

            # Tool call yoksa dogrudan metin dondur
            if not response.tool_calls:
                return response.content or "(orchestrator returned empty response)"

            # Tool calleri isle - OpenAI / DeepSeek formatina uygun tool_calls dizisi ekle
            current_messages.append({
                "role": "assistant",
                "content": response.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments) if isinstance(tc.arguments, dict) else str(tc.arguments),
                        }
                    }
                    for tc in response.tool_calls
                ]
            })

            for tc in response.tool_calls:
                logger.info(f"[Orchestrator] Tool call: {tc.name}({tc.arguments})")
                self._search_count += 1
                tool_result = execute_tool_call(tc.name, tc.arguments)
                logger.debug(f"[Orchestrator] Tool result: {tool_result[:200]}...")

                current_messages.append({
                    "role": "tool",
                    "content": tool_result,
                    "tool_call_id": tc.id,
                    "name": tc.name,
                })

        # Son bir kez tool cagirmadan yanit al
        final_response = self.client.generate(
            messages=current_messages,
            tools=None,
            temperature=0.3,
            max_tokens=1024,
        )
        return final_response.content or "(orchestrator returned empty final response)"

    @staticmethod
    def _extract_json_object(content: str) -> Optional[Dict[str, Any]]:
        """
        Metin icinden DENGELI suslu parantezli ilk JSON nesnesini cikarir.
        Ic ice parantezler ve string icindeki '}' karakterleri dogru islenir.
        (json.loads(content[start:end+1]) yaklasimindan daha guvenilir.)
        """
        if not content:
            return None
        start = content.find("{")
        if start == -1:
            return None
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
                        return None
        return None

    @staticmethod
    def _extract_json_object(content: str) -> Optional[Dict[str, Any]]:
        """
        Metin icinden DENGELI suslu parantezli ilk JSON nesnesini cikarir.
        Ic ice parantezler ve string icindeki '}' karakterleri dogru islenir.
        (json.loads(content[start:end+1]) yaklasimindan daha guvenilir.)
        """
        if not content:
            return None
        start = content.find("{")
        if start == -1:
            return None
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
                        return None
        return None

    def _summarize_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Bulgulari kisa ve okunakli bir metne donusturur."""
        if not findings:
            return "No findings recorded yet."
        
        lines = []
        for i, f in enumerate(findings[-10:], 1):  # Son 10 bulgu
            tool = str(f.get("tool") or "unknown")
            severity = str(f.get("severity") or "?").upper()
            category = str(f.get("category") or "")
            evidence = str(f.get("evidence_snippet") or "")[:80]
            note = f"{category} — {evidence}".strip(" —")
            lines.append(f"  [{i}] [{severity}] {tool}: {note}")

        
        if len(findings) > 10:
            lines.insert(0, f"  ... (showing last 10 of {len(findings)} findings)")
        
        return "\n".join(lines)



class HybridEscalationOrchestrator(OrchestratorAgent):
    """
    Tier-3 Hibrit Orkestrator (DeepSeek V4 Flash + Anthropic Claude 5 Sonnet).
    
    Mimari:
      - Tier 2 (Beyin / Taktik): DeepSeek V4 Flash — Rutin planlama, keşif ve sürekli analiz
        adımlarını hızlı ve maliyet-etkin bir şekilde yönetir.
      - Tier 3 (Supreme Arbiter & Escalation Oracle): Anthropic Claude 5 Sonnet (`claude-5-sonnet`) —
        Worker bir yerde takıldığında (tekrar tespiti, deadlock, exploit çalıştırmama), kriz anlarında
        veya direkt JSON kurtarmasında devreye girer.
      - Graceful Fallback: Claude API key yoksa veya çağrı başarısız olursa DeepSeek kesintisiz olarak devam eder.
    """

    def __init__(
        self,
        primary_client: BaseLLMClient,
        escalation_client: Optional[BaseLLMClient] = None,
        max_search_calls: int = 10,
    ):
        super().__init__(client=primary_client, max_search_calls=max_search_calls)
        self.primary_client = primary_client
        self.escalation_client = escalation_client

    def analyze_and_rescue(
        self,
        worker_activity: str,
        recent_worker_output: str,
        current_findings: List[Dict[str, Any]],
        step_number: int,
        target: str,
        attack_surface_tree: Optional[str] = None,
    ) -> str:
        """
        Worker takıldığında Tier-3 Escalation Oracle olarak Claude 5 Sonnet'e eskalasyon yapar.
        Claude 5 Sonnet hazır değilse veya hata alırsa DeepSeek V4 Flash ile devam eder.
        """
        if self.escalation_client is not None:
            try:
                model_tag = getattr(self.escalation_client, "model_name", "claude-5-sonnet")
                logger.info(
                    f"[HybridOrchestrator] Worker takilmasi tespit edildi (adim {step_number}). "
                    f"Tier-3 Escalation Oracle devreye giriyor: {model_tag}..."
                )
                original_client = self.client
                self.client = self.escalation_client
                try:
                    directive = super().analyze_and_rescue(
                        worker_activity=worker_activity,
                        recent_worker_output=recent_worker_output,
                        current_findings=current_findings,
                        step_number=step_number,
                        target=target,
                        attack_surface_tree=attack_surface_tree,
                    )
                    if directive and not directive.startswith("[API BAĞLANTI HATASI]"):
                        return f"[Tier-3 Oracle ({model_tag})]: {directive}"
                    logger.warning("[HybridOrchestrator] Escalation client baglanti hatasi verdi, DeepSeek'e donuluyor.")
                finally:
                    self.client = original_client
            except Exception as e:
                logger.warning(f"[HybridOrchestrator] Escalation client hatasi ({e}), DeepSeek kullanilacak.")

        return super().analyze_and_rescue(
            worker_activity=worker_activity,
            recent_worker_output=recent_worker_output,
            current_findings=current_findings,
            step_number=step_number,
            target=target,
            attack_surface_tree=attack_surface_tree,
        )

    def direct_json_suggestion(
        self,
        current_findings: List[Dict[str, Any]],
        step_number: int,
        target: str,
        visited_actions: Optional[set] = None,
        attack_surface_tree: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Worker JSON üretemediğinde önce DeepSeek dener. Başarısız olursa Claude 5 Sonnet'e devreder.
        """
        res = super().direct_json_suggestion(
            current_findings=current_findings,
            step_number=step_number,
            target=target,
            visited_actions=visited_actions,
            attack_surface_tree=attack_surface_tree,
        )
        if res is not None:
            return res

        if self.escalation_client is not None:
            try:
                logger.info("[HybridOrchestrator] Direct JSON DeepSeek'te basarisiz oldu, Claude 5 Sonnet deneniyor...")
                original_client = self.client
                self.client = self.escalation_client
                try:
                    return super().direct_json_suggestion(
                        current_findings=current_findings,
                        step_number=step_number,
                        target=target,
                        visited_actions=visited_actions,
                        attack_surface_tree=attack_surface_tree,
                    )
                finally:
                    self.client = original_client
            except Exception as e:
                logger.warning(f"[HybridOrchestrator] Direct JSON Claude eskalasyonu basarisiz: {e}")

        return None


def create_orchestrator(
    api_key: Optional[str] = None,
    model_name: Optional[str] = None,
    max_search_calls: int = 10,
    provider: Optional[str] = None,
    anthropic_api_key: Optional[str] = None,
    anthropic_model: Optional[str] = None,
) -> Optional[OrchestratorAgent]:
    """
    Factory: Orkestrator ajani olusturur.
    
    Desteklenen Saglayicilar (provider / ORCHESTRATOR_PROVIDER env):
      - 'hybrid' (varsayilan): DeepSeek V4 Flash (rutin) + Claude 5 Sonnet (Tier-3 eskalasyon)
      - 'deepseek': Yalnizca DeepSeek V4 Flash
      - 'claude' / 'anthropic': Yalnizca Claude 5 Sonnet
    
    Args:
        api_key: DeepSeek API anahtari (None ise DEEPSEEK_API_KEY env'den okunur)
        model_name: DeepSeek model adi (varsayilan: deepseek-chat)
        max_search_calls: Oturum basina maksimum web aramasi
        provider: 'hybrid', 'deepseek', veya 'claude' (None ise ORCHESTRATOR_PROVIDER env'den okunur)
        anthropic_api_key: Anthropic API anahtari (None ise ANTHROPIC_API_KEY env'den okunur)
        anthropic_model: Anthropic model adi (varsayilan: claude-5-sonnet veya ANTHROPIC_MODEL env)
    
    Returns:
        OrchestratorAgent, HybridEscalationOrchestrator veya None.
    """
    # If api_key explicitly passed as empty string and no anthropic key specified, treat as disabled
    if api_key == "" and not anthropic_api_key:
        return None

    prov = (provider or os.getenv("ORCHESTRATOR_PROVIDER", "hybrid")).strip().lower()

    d_key = api_key if api_key is not None else os.getenv("DEEPSEEK_API_KEY", "")
    d_model = model_name or os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    c_key = anthropic_api_key if anthropic_api_key is not None else os.getenv("ANTHROPIC_API_KEY", "")
    c_model = anthropic_model or os.getenv("ANTHROPIC_MODEL", "claude-5-sonnet")

    # If keys not found in environment and caller didn't pass explicit arguments, load .env
    if not d_key and not c_key and api_key is None and anthropic_api_key is None:
        env_file = Path(__file__).parent.parent / ".env"
        if env_file.exists():
            try:
                from dotenv import load_dotenv
                load_dotenv(env_file)
            except ImportError:
                with open(env_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            os.environ.setdefault(k.strip(), v.strip())
            d_key = os.getenv("DEEPSEEK_API_KEY", "")
            c_key = os.getenv("ANTHROPIC_API_KEY", "")

    # 1. Yalnızca Claude / Anthropic
    if prov in ["claude", "anthropic"]:
        if not c_key:
            logger.warning("[Orchestrator] ANTHROPIC_API_KEY bulunamadi. Orkestrator devre disi.")
            return None
        try:
            claude_client = AnthropicClient(api_key=c_key, model_name=c_model)
            orch = OrchestratorAgent(client=claude_client, max_search_calls=max_search_calls)
            logger.info(f"[Orchestrator] Claude 5 Sonnet Tekil Orkestrator hazir. Model: {c_model}")
            return orch
        except Exception as e:
            logger.error(f"[Orchestrator] Claude orkestrator olusturulamadi: {e}")
            return None

    # 2. Yalnızca DeepSeek
    if prov == "deepseek":
        if not d_key:
            logger.warning("[Orchestrator] DEEPSEEK_API_KEY bulunamadi. Orkestrator devre disi.")
            return None
        try:
            ds_client = OpenAICompatibleClient(
                base_url="https://api.deepseek.com/v1",
                api_key=d_key,
                model_name=d_model,
            )
            orch = OrchestratorAgent(client=ds_client, max_search_calls=max_search_calls)
            logger.info(f"[Orchestrator] DeepSeek V4 Flash Orkestrator hazir. Model: {d_model}")
            return orch
        except Exception as e:
            logger.error(f"[Orchestrator] DeepSeek orkestrator olusturulamadi: {e}")
            return None

    # 3. Hybrid (Varsayılan): DeepSeek V4 Flash + Claude 5 Sonnet Tier-3 Escalation
    primary_client = None
    if d_key:
        try:
            primary_client = OpenAICompatibleClient(
                base_url="https://api.deepseek.com/v1",
                api_key=d_key,
                model_name=d_model,
            )
        except Exception as e:
            logger.warning(f"[Orchestrator] Primary DeepSeek client baslatilamadi: {e}")

    escalation_client = None
    if c_key:
        try:
            escalation_client = AnthropicClient(api_key=c_key, model_name=c_model)
            logger.info(f"[Orchestrator] Tier-3 Escalation Oracle hazir: Claude 5 Sonnet ({c_model})")
        except Exception as e:
            logger.warning(f"[Orchestrator] Escalation Claude client baslatilamadi: {e}")

    if primary_client:
        orch = HybridEscalationOrchestrator(
            primary_client=primary_client,
            escalation_client=escalation_client,
            max_search_calls=max_search_calls,
        )
        mode_desc = f"Primary: {d_model}" + (f" + Tier-3 Oracle: {c_model}" if escalation_client else " (Claude key yok)")
        logger.info(f"[Orchestrator] Hibrit Orkestrator hazir ({mode_desc})")
        return orch

    if escalation_client:
        logger.info(f"[Orchestrator] DeepSeek key yok, tekil Claude 5 Sonnet ({c_model}) ile baslatiliyor.")
        return OrchestratorAgent(client=escalation_client, max_search_calls=max_search_calls)

    logger.warning(
        "[Orchestrator] Ne DEEPSEEK_API_KEY ne de ANTHROPIC_API_KEY bulundu. "
        "Orkestrator devre disi. Yalnizca CyberStrike 35B calisacak."
    )
    return None
