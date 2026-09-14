"""
AutoRedTeam - LLM Advisor Layer (Danisman Katmani).

v3.0 mimarisinde LLM artik "siradaki adim ne?" sorusuna cevap VERMEZ. Bu isi
deterministik ExploitPlanner yapar. LLM yalnizca su rollerde devreye girer:

  - PayloadCrafter  : Standart payload basarisiz olunca ozel payload uretir
                      (CyberStrike 35B - sansursuz model).
  - TriageAdvisor   : Kanit yorumu, oncelik karari, rapor anlatisi
                      (DeepSeek V4 Flash).
  - EscalationOracle: Tum deterministik yollar tukenince alternatif strateji
                      (Claude).

Bu modul, LLM erisilemezse (Colab kapali vb.) sessizce None doner; boylece
deterministik cekirdek LLM'siz calismaya devam eder.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.llm_client import BaseLLMClient, LLMResponse

logger = logging.getLogger(__name__)


# ── Prompt Sablonlari ───────────────────────────────────────────────────────

PAYLOAD_CRAFTER_PROMPT = """You are an offensive security payload specialist.
A standard exploit failed against an authorized training target.

Target: {target}
Service: {service} {version}
Port: {port}
Failed exploit: {exploit_module}
Failure output: {failure_output}

Do NOT explain your reasoning. Do NOT write a thinking process. Respond with
EXACTLY ONE line: the concrete alternative payload or command to try next.
Example: python3 -c 'import socket; ...'
Your one-line answer:"""


TRIAGE_ADVISOR_PROMPT = """You are a security assessment triage advisor.
Given the current evidence, decide the next highest-value target.

Current findings:
{findings_summary}

Untested services: {untested}
Obtained credentials: {credentials}

Do NOT explain your reasoning. Respond with ONLY a JSON object on one line:
{{"priority_target": "...", "reason": "...", "confidence": 0.0}}"""


ESCALATION_ORACLE_PROMPT = """You are a supreme escalation oracle.
All standard exploitation paths have been exhausted. The system is stuck.

Target: {target}
Attempted: {attempted_steps}
Findings: {findings}

Provide a creative, non-obvious attack strategy. Think laterally. Be concise."""


# ── Veri Modelleri ──────────────────────────────────────────────────────────

@dataclass
class AdvisorResult:
    """LLM danisman sonucu."""
    role: str
    content: str = ""
    parsed: Optional[Dict[str, Any]] = None
    available: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content[:2000],
            "parsed": self.parsed,
            "available": self.available,
            "error": self.error,
        }


# ── Ana Sinif ───────────────────────────────────────────────────────────────

class LLMAdvisor:
    """
    LLM danisman katmani. Uc rolu tek arayuzde sunar.
    LLM erisilemezse available=False doner; cagiran taraf deterministik
    davranisa devam eder.
    """

    def __init__(
        self,
        worker_client: Optional[BaseLLMClient] = None,
        orchestrator_client: Optional[BaseLLMClient] = None,
        escalation_client: Optional[BaseLLMClient] = None,
    ):
        self.worker_client = worker_client          # CyberStrike 35B
        self.orchestrator_client = orchestrator_client  # DeepSeek V4 Flash
        self.escalation_client = escalation_client  # Claude

    # ── Rol 1: Payload Crafter ──────────────────────────────────────────────

    def craft_payload(
        self,
        target: str,
        service: str,
        version: str,
        port: int,
        exploit_module: str,
        failure_output: str,
    ) -> AdvisorResult:
        """Standart payload basarisiz olunca ozel payload uretir."""
        if self.worker_client is None:
            return AdvisorResult(role="payload_crafter", available=False,
                                 error="worker_client yok")

        prompt = PAYLOAD_CRAFTER_PROMPT.format(
            target=target, service=service, version=version, port=port,
            exploit_module=exploit_module, failure_output=failure_output[:800],
        )
        resp = self._safe_generate(self.worker_client, prompt, max_tokens=512)
        if resp is None:
            return AdvisorResult(role="payload_crafter", available=False,
                                 error="LLM erisilemedi")
        return AdvisorResult(
            role="payload_crafter", content=resp.content or "",
            available=True,
        )

    # ── Rol 2: Triage Advisor ───────────────────────────────────────────────

    def triage(
        self,
        findings: List[Dict[str, Any]],
        untested: List[str],
        credentials: List[str],
    ) -> AdvisorResult:
        """Kanit yorumu ve oncelik karari."""
        if self.orchestrator_client is None:
            return AdvisorResult(role="triage", available=False,
                                 error="orchestrator_client yok")

        findings_summary = "\n".join(
            f"- {f.get('category')} ({f.get('severity')})" for f in findings[-10:]
        ) or "(henuz bulgu yok)"

        prompt = TRIAGE_ADVISOR_PROMPT.format(
            findings_summary=findings_summary,
            untested=", ".join(untested[:10]) or "(yok)",
            credentials=", ".join(credentials[:10]) or "(yok)",
        )
        resp = self._safe_generate(self.orchestrator_client, prompt, max_tokens=256)
        if resp is None:
            return AdvisorResult(role="triage", available=False,
                                 error="LLM erisilemedi")
        parsed = self._extract_json(resp.content or "")
        return AdvisorResult(
            role="triage", content=resp.content or "",
            parsed=parsed, available=True,
        )

    # ── Rol 3: Escalation Oracle ────────────────────────────────────────────

    def escalate(
        self,
        target: str,
        attempted_steps: List[str],
        findings: List[Dict[str, Any]],
    ) -> AdvisorResult:
        """Tum deterministik yollar tukenince alternatif strateji."""
        if self.escalation_client is None:
            return AdvisorResult(role="escalation", available=False,
                                 error="escalation_client yok")

        prompt = ESCALATION_ORACLE_PROMPT.format(
            target=target,
            attempted_steps=", ".join(attempted_steps[:15]) or "(yok)",
            findings=", ".join(f.get("category", "") for f in findings[-10:]) or "(yok)",
        )
        resp = self._safe_generate(self.escalation_client, prompt, max_tokens=512)
        if resp is None:
            return AdvisorResult(role="escalation", available=False,
                                 error="LLM erisilemedi")
        return AdvisorResult(
            role="escalation", content=resp.content or "", available=True,
        )

    # ── Yardimcilar ─────────────────────────────────────────────────────────

    def _safe_generate(
        self,
        client: BaseLLMClient,
        prompt: str,
        max_tokens: int = 512,
    ) -> Optional[LLMResponse]:
        """LLM cagrisini guvenli sekilde yapar; hata durumunda None doner."""
        try:
            resp = client.generate(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=max_tokens,
                enable_thinking=False,
            )
            if getattr(resp, "error", None):
                logger.warning(f"[LLMAdvisor] LLM hatasi: {resp.error}")
                return None
            # Thinking bloklarini temizle (CyberStrike 35B sik uretir)
            if resp.content:
                resp.content = self._strip_thinking(resp.content)
            return resp
        except Exception as e:
            logger.warning(f"[LLMAdvisor] LLM cagrisi basarisiz: {e}")
            return None

    def _strip_thinking(self, text: str) -> str:
        """
        Modelin 'Thinking Process:' / 'Here's a thinking process:' gibi
        dusunme bloklarini temizler; yalnizca nihai cevabi birakir.

        CyberStrike 35B sik sik 'Thinking Process:' + numarali liste uretir ve
        gercek cevabi EN SONA koyar. Bu yuzden once dusunme blogunu atariz,
        sonra kalan metnin son anlamli parcasini aliriz.
        """
        if not text:
            return text

        # 1. Dusunme blogunu bul ve at
        markers = ("Thinking Process:", "Here's a thinking process:",
                   "Here is a thinking process:", "Analysis:", "Deconstruct the")
        body = text
        for marker in markers:
            if marker in body:
                body = body.split(marker, 1)[1]
                break

        # 2. Numarali dusunme satirlarini temizle
        lines = body.split("\n")
        cleaned = []
        for line in lines:
            s = line.strip()
            if not s:
                continue
            # Numarali liste satirlari (1. / 1.  **...**) ve etiketli dusunme satirlari
            if re.match(r"^\d+\.", s):
                continue
            if s.startswith("**") or s.startswith("*"):
                continue
            if s.lower().startswith(("analyze", "identify", "draft", "check",
                                     "output", "ready", "done", "tone",
                                     "deconstruct", "formulate", "final",
                                     "role:", "context:", "constraint")):
                continue
            cleaned.append(s)

        if cleaned:
            # Son anlamli parca genelde gercek cevaptir
            return cleaned[-1][:500]
        # Hicbir anlamli cevap kalmadiysa (sadece dusunme blogu) bos don.
        # Ham dusunme metnini dondurmek yaniltici olur.
        return ""

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Metinden JSON nesnesi cikarir."""
        if not text:
            return None
        # Markdown fence temizle
        text = re.sub(r"```(?:json)?", "", text).strip()
        # Ilk { ... } blogunu bul
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except Exception:
            return None

    def is_available(self) -> bool:
        """Herhangi bir LLM danisman mevcut mu?"""
        return any([
            self.worker_client, self.orchestrator_client, self.escalation_client,
        ])


# Modul seviyesinde tekil ornek (client'lar sonradan atanabilir)
llm_advisor = LLMAdvisor()
