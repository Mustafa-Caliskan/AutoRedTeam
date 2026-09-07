"""
AutoRedTeam - DeepSeek V3 Orchestrator Agent.

Bu modul, DeepSeek V3'u ustun seviyeli Orkestrator (Parent) ajan olarak kullanir:
- Pentest/red-team stratejisini planlar ve baglami tutar
- Web search toolu ile taze CVE/exploit bilgisine erisir
- CyberStrike 35B (Worker) takilinca veya JSON uretmekte zorlaninca devralir
- Her 5 adimda bir durum ozeti cikartir

Mimari:
    DeepSeek V3 (Orkestrator/Beyin)
        -> Strateji + Baglam + Web Research
    CyberStrike 35B (Attacker/Kas)
        -> Sansursuz ofansif payload uretimi + araclari tetikler
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

from core.web_search import WEB_SEARCH_TOOL_SCHEMA, execute_tool_call
from core.llm_client import BaseLLMClient, LLMResponse

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

### RULES OF ENGAGEMENT:
1. BE SURGICALLY CONCISE & TECHNICAL: No conversational fluff, no generic pleasantries. Output purely actionable technical guidance.
2. RESEARCH PROACTIVELY: Use `web_search` whenever you need exact exploit paths, CVE numbers, or verification techniques.
3. PREVENT WORKER LOOPS: If CyberStrike repeated a tool or failed to extract a finding, explicitly order a new tool and target.
4. DIRECTIVE FORMAT:
   - [STATUS]: Current assessment phase (Recon / Vuln Research / Verification / Chaining).
   - [ANALYSIS]: 1-2 sentence technical assessment of recent results.
   - [DIRECTIVE FOR WORKER]: Explicit command for CyberStrike specifying:
     * Recommended Tool: (nmap / gobuster / nikto / whatweb / ssl_check / sqlmap / searchsploit / cve_search / done)
     * Target / Port / Parameter / Service: Exact arguments.
     * Rationale & Expected Finding: What exact vulnerability or indicator to record.
"""


class OrchestratorAgent:
    """
    DeepSeek V3 tabanli Orkestrator Ajan.
    
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
            client: DeepSeek V3 LLM istemcisi (OpenAICompatibleClient veya DeepSeekClient)
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
    ) -> str:
        """
        Mevcut durumu analiz edip Worker'a (CyberStrike 35B) verilecek
        bir sonraki gorev emrini DeepSeek V3'ten alir.

        Args:
            current_findings: Simdiye kadar kaydedilen bulgular listesi
            recent_worker_output: CyberStrike'in son ciktisi veya hata mesaji
            step_number: Mevcut adim numarasi
            target: Hedef sistem (ornek: 'metasploitable2', 'localhost:3000')
            extra_context: Ek baglam metni (opsiyonel)
        
        Returns:
            Worker ajana verilecek gorev direktifi (duz metin).
        """
        # Ozet baglamı oluştur
        findings_summary = self._summarize_findings(current_findings)
        
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
        
        if extra_context:
            context_parts += ["", f"=== Extra Context ===", extra_context]
        
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

        messages = [
            {"role": "system", "content": ORCHESTRATOR_SYSTEM_PROMPT},
            {"role": "user", "content": correction_prompt}
        ]

        tools = [WEB_SEARCH_TOOL_SCHEMA] if self._search_count < self.max_search_calls else None
        result = self._call_with_tools(messages, tools)
        logger.info(f"[Orchestrator] Fallback correction at step {step_number}: {result[:120]}...")
        return result

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

            # Tool calleri isle
            current_messages.append({
                "role": "assistant",
                "content": response.content or "",
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

    def _summarize_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Bulgulari kisa ve okunakli bir metne donusturur."""
        if not findings:
            return "No findings recorded yet."
        
        lines = []
        for i, f in enumerate(findings[-10:], 1):  # Son 10 bulgu
            tool = f.get("tool", "unknown")
            severity = f.get("severity", "?")
            note = f.get("finding", f.get("note", ""))[:120]
            lines.append(f"  [{i}] [{severity.upper()}] {tool}: {note}")
        
        if len(findings) > 10:
            lines.insert(0, f"  ... (showing last 10 of {len(findings)} findings)")
        
        return "\n".join(lines)


def create_orchestrator(
    api_key: Optional[str] = None,
    model_name: str = "deepseek-chat",
    max_search_calls: int = 10,
) -> Optional["OrchestratorAgent"]:
    """
    Factory: DeepSeek V3 Orkestrator ajani olusturur.
    
    DEEPSEEK_API_KEY env degiskeninden otomatik okur.
    API key yoksa None dondurur (orkestrator devre disi).
    
    Args:
        api_key: DeepSeek API anahtari (None ise env'den okunur)
        model_name: DeepSeek model adi (varsayilan: deepseek-chat = V3)
        max_search_calls: Oturum basina maksimum web aramasi
    
    Returns:
        OrchestratorAgent veya None.
    """
    from core.llm_client import OpenAICompatibleClient

    key = api_key or os.getenv("DEEPSEEK_API_KEY", "")
    if not key:
        logger.warning(
            "[Orchestrator] DEEPSEEK_API_KEY bulunamadi. "
            "Orkestrator devre disi. Yalnizca CyberStrike 35B calisacak."
        )
        return None

    try:
        client = OpenAICompatibleClient(
            base_url="https://api.deepseek.com/v1",
            api_key=key,
            model_name=model_name,
        )
        orch = OrchestratorAgent(client=client, max_search_calls=max_search_calls)
        logger.info(f"[Orchestrator] DeepSeek V3 Orkestrator hazir. Model: {model_name}")
        return orch
    except Exception as e:
        logger.error(f"[Orchestrator] Olusturulamadi: {e}")
        return None
