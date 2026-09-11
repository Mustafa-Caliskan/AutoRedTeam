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
import threading
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
    suggest_web_search,
)
from core.llm_client import BaseLLMClient
from core.validation_gate import validation_gate
from core.chain_engine import chain_engine
from core.skill_loader import skill_loader

logger = logging.getLogger(__name__)

FINDINGS_FILE = Path(__file__).parent.parent / "data" / "assessment_findings.jsonl"
REPORT_FILE = Path(__file__).parent.parent / "reports" / "assessment_report.md"

MAX_STEPS = 20

ASSESSMENT_SYSTEM_PROMPT = """You are 'AssessmentCoPilot' (powered by CyberStrike 35B), the tactical execution engine in an authorized security assessment framework.

You operate in tandem with a human security analyst (Human-in-the-Loop) and a Strategic Orchestrator (DeepSeek V4 Flash) against locally-hosted training targets in Docker:
  - OWASP Juice Shop (web-application layer) -> target "localhost:3000"
  - Metasploitable2 (network/service layer)  -> target "metasploitable2"

### ACTIVE TARGET
Always target the system designated by the operator/orchestrator ("localhost:3000" or "metasploitable2"). Never switch targets unprompted.

### ORCHESTRATOR SYNCHRONIZATION (KRITIK - DIREKTIFI UYGULA)
When the prompt contains a `=== Strategic Directive from Orchestrator (DeepSeek V4 Flash) ===` or `=== Orchestrator RESCUE Directive ===`:
- Treat this directive as an AUTHORITATIVE, BINDING instruction from your parent model.
- If the directive mentions an exploit name (e.g. "vsftpd_backdoor", "samba_usermap", "ingreslock_backdoor", "ssh_credential_spray"), you MUST output: {"tool":"exploit","exploit":"<o ad>","target":"metasploitable2",...}
- If the directive mentions a privesc technique (e.g. "sudo_privesc", "gtfobins_privesc", "verify_root"), you MUST output: {"tool":"privesc","privesc":"<o teknik>","target":"metasploitable2","username":"msfadmin","password":"msfadmin",...}
- If the directive says "STOP RECON" or "DO NOT run nmap/searchsploit again", you MUST NOT output nmap or searchsploit. Output an exploit or privesc action instead.
- DO NOT summarize, paraphrase, or re-plan. DIRECTLY translate the directive into the JSON action it commands.
- If the directive contains a JSON snippet (e.g. {"tool":"exploit","exploit":"vsftpd_backdoor"}), copy that JSON structure EXACTLY into your output.

### TAKILINCA SEFINDEN DESTEK ISTE (KRITIK)
Sen bir ekip uyesisin; sefin (DeepSeek V4 Flash Orchestrator) sana yardim eder. Takildiginda:
- Ayni servise/araca 2+ kez donduysen veya bir exploit basarisiz olduysa, AYNI SEYI TEKRAR DENEME.
- Farkli bir servise gec veya sefinden yardim iste. Sefin direktifi prompt'a eklenecektir.
- Bir zafiyet/exploit/CVE hakkinda emin degilsen veya 2024 sonrasi guncel bilgi gerekiyorsa, "tool":"web_search" ile arastir (modelin egitim verisi 2024'e kadar).
- Sefin sana bir kurtarma direktifi verdiyse, onu AYNEN uygula. Sefin analizine guven.
- Asla ayni nmap taramasini tekrar tekrar yapma. Kesif yapildiysa, exploit'e veya farkli servise gec.

### SKILL HINTS (818 Cybersecurity Skills Library)
When the orchestrator directive references a skill name like [BOLA/IDOR Detection] or [vsftpd Exploitation]:
- Interpret it as an operational playbook — apply the named technique directly using the most appropriate tool.
- Example: [SQL Injection Detection] → use sqlmap on the active target.

### OUTPUT SPECIFICATION (STRICT JSON ONLY)
Your response must be EXACTLY ONE valid JSON object. No markdown code blocks (no ```json), no preliminary thoughts, no trailing text.

JSON Schema:
{
  "thought": "Precise tactical reasoning: what was discovered, why this specific tool/target is chosen now",
  "tool": "one of: nmap, gobuster, nikto, whatweb, ssl_check, sqlmap, searchsploit, cve_search, web_search, debugger, exploit, privesc, done",
  "target": "the active target ('localhost:3000' or 'metasploitable2')",
  "param": "parameter name if tool is sqlmap (e.g. 'q', 'id'), else null",
  "ports": "comma-separated ports if tool is nmap and scanning specific ports (e.g. '21,22,80,3306'), else null",
  "service_name": "service daemon if tool is searchsploit/cve_search (e.g. 'vsftpd', 'apache', 'samba'), else null",
  "version": "service version if tool is searchsploit/cve_search (e.g. '2.3.4', '2.2.8', '3.0.20'), else null",
  "query": "exact DuckDuckGo search query if tool is web_search (e.g. 'vsftpd 2.3.4 CVE exploit PoC'), else null",
  "exploit": "if tool is 'exploit', one of: vsftpd_backdoor, samba_usermap, ingreslock_backdoor, ssh_credential_spray, juice_shop_admin; else null",
  "privesc": "if tool is 'privesc', one of: suid_enumeration, sudoers_audit, sudo_privesc, gtfobins_privesc, verify_root; else null",
  "username": "SSH username if privesc requires a foothold session (e.g. 'msfadmin'), else null",
  "password": "SSH password if privesc requires a foothold session (e.g. 'msfadmin'), else null",
  "command": "optional command for samba_usermap (default 'id'), else null",
  "rationale": "Clear technical explanation of what this action accomplishes",
  "finding": null or {
    "category": "e.g. Remote Code Execution, Backdoor, Outdated Service, SQL Injection, Security Misconfiguration, Privilege Escalation",
    "severity": "Low | Medium | High | Critical",
    "cwe_reference": "e.g. CWE-78, CWE-89, CWE-200, CWE-287, CWE-732",
    "evidence_snippet": "Exact proof line from previous output (e.g. 'vsftpd 2.3.4 backdoor CVE-2011-2523', 'uid=0(root)')"
  }
}

### CRITICAL OPERATIONAL RULES
1. NEVER REPEAT EXECUTED SCANS:
   - If nmap already found open ports (e.g. 21/vsftpd 2.3.4, 80/Apache), DO NOT run nmap again on those ports!
   - If nmap detected a service/version, the logical next step is a searchsploit or cve_search lookup to find known vulnerabilities.
2. EMIT REAL FINDINGS PROMPTLY:
   - As soon as a tool identifies an exploitable version (e.g., vsftpd 2.3.4 backdoor, Samba 3.0.20 usermap, vulnerable API), emit a concrete "finding" object in that turn so it is permanently logged.
   - CRITICAL: cve_search and searchsploit results are INTELLIGENCE ONLY, NOT findings. Do NOT emit a "finding" object for a cve_search/searchsploit lookup alone. Only emit a finding when you have CONCRETE PROOF (exploit output, uid=0, verified PoC execution, or a confirmed CVE match with exploit evidence).
   - IMPORTANT: If cve_search/searchsploit reveals an exploitable service (e.g. vsftpd 2.3.4, Samba 3.0.20, port 1524 ingreslock), your VERY NEXT action MUST be {"tool":"exploit","exploit":"<exploit_name>",...}. Do NOT search again. Do NOT emit a finding yet. Exploit first, THEN record the finding with uid=0 as evidence.

3. ACTIVE EXPLOITATION (REAL RED TEAM):
   - When a verified vulnerable service is found (e.g. vsftpd 2.3.4, Samba 3.0.20, port 1524 backdoor), DO NOT stop at reporting. Set "tool": "exploit" AND ALWAYS set the "exploit" field to the exact exploit name (e.g. "ingreslock_backdoor", "vsftpd_backdoor", "ssh_credential_spray", "samba_usermap", "juice_shop_admin").
   - CRITICAL: When "tool" is "exploit", the "exploit" field MUST be a non-null string. NEVER leave it null. Choose the exploit that matches the discovered service.
   - CRITICAL: The "target" field MUST always be the active target alias ("metasploitable2" or "localhost:3000"). NEVER put a port number or IP in "target".
   - After a foothold (e.g. SSH as msfadmin), set "tool": "privesc" AND ALWAYS set the "privesc" field (e.g. "suid_enumeration", "sudoers_audit", "sudo_privesc", "gtfobins_privesc", "verify_root"). Provide "username" and "password" for the foothold session (e.g. "msfadmin"/"msfadmin").
   - Recommended metasploitable2 chain: port 1524 -> "exploit":"ingreslock_backdoor" (root shell). If no 1524, use "exploit":"ssh_credential_spray" to get msfadmin, then "privesc":"sudo_privesc" or "privesc":"gtfobins_privesc" to reach root, then "privesc":"verify_root".

### ROOT SONRASI DEVAM (KRITIK - TUM ZAFIYETLERI BUL)
1. ROOT ALMAK DEGERLENDIRMENIN SONU DEGILDIR. Bir servis uzerinden root (uid=0) elde etsen bile, diger acik servisleri de test etmeye DEVAM ET. Sadece root alip "done" deme.
2. Metasploitable2'de test edilmesi gereken servisler ve HAZIR EXPLOIT durumu:
   - Port 21: vsftpd 2.3.4 -> "exploit":"vsftpd_backdoor" (HAZIR)
   - Port 22: SSH zayif kimlik -> "exploit":"ssh_credential_spray" (HAZIR)
   - Port 445: Samba 3.0.20 -> "exploit":"samba_usermap" (HAZIR)
   - Port 1524: Ingreslock backdoor -> "exploit":"ingreslock_backdoor" (HAZIR)
   - Port 3306: MySQL 5.0 -> HAZIR EXPLOIT YOK. searchsploit/cve_search ile dogrula, finding kaydet, BASKA SERVISE GEC.
   - Port 5432: PostgreSQL -> HAZIR EXPLOIT YOK. searchsploit/cve_search ile dogrula, finding kaydet, BASKA SERVISE GEC.
   - Port 6667: UnrealIRCd -> HAZIR EXPLOIT YOK. searchsploit ile dogrula, finding kaydet, BASKA SERVISE GEC.
   - Port 80: Apache/PHP -> nikto/gobuster ile web zafiyetlerini tara.
3. BIR EXPLOIT BASARISIZ OLURSA (ornegin vsftpd port 6200 acilmadi) veya bir servis icin HAZIR EXPLOIT YOKSA, O SERVISE TAKILIP KALMA. Ayni servisi 2'den fazla kez DENEME. Hemen diger servise gec.
4. Her basarili exploit/privesc icin bir "finding" kaydet (evidence ile). Boylece tum zafiyetler rapora girer.
5. "done" KARARI ICIN KATI KOSULLAR: "tool":"done" demeden ONCE su servislerin HEPSI test edilmis olmalidir:
   vsftpd(21), SSH(22), Samba(445), ingreslock(1524), MySQL(3306), PostgreSQL(5432), UnrealIRCd(6667), Apache/PHP(80), distcc(3632).
   Her biri icin en az bir kez searchsploit/cve_search veya exploit denemesi yapilmis olmalidir. Eksik servis varsa "done" DEME, o servisi test et.
6. ZERO FALSE POSITIVES (7-QUESTION VALIDATION GATE):
   - Never emit findings for missing headers alone (CSP/HSTS), banner grabbing alone without CVE, or open redirect alone without chain. Concrete proof required.
7. ZERO FLUFF: Output ONLY the JSON object. Start with '{' and end with '}'."""


ASSESSMENT_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "thought": {"type": "string"},
        "tool": {
            "type": "string",
            "enum": [
                "nmap", "gobuster", "nikto", "whatweb", "ssl_check",
                "sqlmap", "searchsploit", "cve_search", "web_search",
                "debugger", "exploit", "privesc", "done"
            ]
        },
        "target": {"type": "string"},
        "param": {"type": ["string", "null"]},
        "ports": {"type": ["string", "null"]},
        "service_name": {"type": ["string", "null"]},
        "version": {"type": ["string", "null"]},
        "query": {"type": ["string", "null"]},
        # Active exploitation fields
        "exploit": {
            "type": ["string", "null"],
            "enum": [
                None, "vsftpd_backdoor", "samba_usermap", "ingreslock_backdoor",
                "ssh_credential_spray", "juice_shop_admin"
            ]
        },
        # Privilege escalation fields
        "privesc": {
            "type": ["string", "null"],
            "enum": [
                None, "suid_enumeration", "sudoers_audit", "sudo_privesc",
                "gtfobins_privesc", "verify_root"
            ]
        },
        "username": {"type": ["string", "null"]},
        "password": {"type": ["string", "null"]},
        "command": {"type": ["string", "null"]},
        "rationale": {"type": "string"},
        "finding": {
            "type": ["object", "null"],
            "properties": {
                "category": {"type": "string"},
                "severity": {"type": "string", "enum": ["Low", "Medium", "High", "Critical", "Informational"]},
                "cwe_reference": {"type": "string"},
                "evidence_snippet": {"type": "string"}
            },
            "required": ["category", "severity", "evidence_snippet"]
        }
    },
    "required": ["thought", "tool", "target", "rationale"]
}


class AssessmentAssistant:
    """
    Human-in-the-loop assessment co-pilot. Orchestrates LLM suggestions,
    human approval, safe execution, finding logging, and report generation.

    Supports a dual-model architecture:
      - llm_client (Worker): CyberStrike 35B — sansürsüz ofansif analiz ajanı.
      - orchestrator_agent (Parent): DeepSeek V4 Flash — strateji, bağlam ve web araştırması.

    When orchestrator_agent is provided:
      - Every ORCHESTRATOR_INTERVAL steps, the orchestrator summarizes context
        and issues a directive to the worker.
      - If the worker returns invalid JSON, the orchestrator provides a corrective
        directive that is injected into the worker's next prompt.
    """

    ORCHESTRATOR_INTERVAL = 5  # Her kaç adımda bir orchestrator devreye girecek

    def __init__(
        self,
        llm_client: Optional[BaseLLMClient] = None,
        target: str = "localhost:3000",
        max_steps: int = MAX_STEPS,
        findings_file: Optional[Path] = None,
        report_file: Optional[Path] = None,
        orchestrator_agent: Optional[Any] = None,
        auto_approve_findings: bool = False,
    ):
        self.llm_client = llm_client
        self.target = target
        self.max_steps = max_steps
        self.findings: List[Dict[str, Any]] = []
        self.step_count = 0
        self.findings_file = findings_file or FINDINGS_FILE
        self.report_file = report_file or REPORT_FILE
        self.auto_approve_findings = auto_approve_findings
        # State memory: tracks (tool, target, ports, service, version) combos
        # that have already been executed, to break repetition loops.
        self.visited_actions: set = set()
        # Decision chain: records each step's thought + tool for the summary.
        self.decision_chain: List[Dict[str, Any]] = []
        self.conversation: List[Dict[str, str]] = [
            {"role": "system", "content": ASSESSMENT_SYSTEM_PROMPT}
        ]
        # DeepSeek V4 Flash Orchestrator (opsiyonel — None ise devre dışı)
        self.orchestrator_agent = orchestrator_agent
        self._last_orchestrator_directive: Optional[str] = None
        # Son LLM baglanti hatasi (varsa). UI bunu kullaniciya bildirir.
        self._last_llm_error: Optional[str] = None
        # Bulgu ID sayaci (in-memory; O(n^2) I/O onlenir). None ise ilk cagrida
        # mevcut dosyadan hesaplanir. Thread-safe erisim icin lock kullanilir.
        self._finding_counter: Optional[int] = None
        self._finding_lock = threading.Lock()
        # Basarisiz exploit takibi (Hata 1): hangi exploit'ler denendi ama uid=0
        # dogrulamasi basarisiz oldu. Kurtarma + fallback secimi icin kullanilir.
        self._failed_exploits: set = set()
        # Basarili exploit takibi: en az bir exploit uid=0 ile dogrulandi mi?
        self._exploit_succeeded: bool = False
        # nmap ciktisinda tespit edilen portlar (Hata 8): decision_chain.ports
        # alanina yazilmayan portlari da takip etmek icin kullanilir.
        self._discovered_ports: set = set()
        # Son ValidationGate sonucu (Hata 10: tek noktadan dogrulama)
        self._last_gate_result: Optional[Any] = None


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
        """
        Bir sonraki bulgu ID'sini uretir. In-memory sayac kullanir; boylece her
        cagrida tum dosyayi okumaz (O(n^2) I/O onlenir). Sayac ilk cagrida
        mevcut dosyadan bir kez hesaplanir. Thread-safe (lock).
        """
        with self._finding_lock:
            if self._finding_counter is None:
                existing = self._load_existing_findings()
                max_num = 0
                for f in existing:
                    m = re.search(r"FIND-(\d+)", f.get("finding_id", ""))
                    if m:
                        max_num = max(max_num, int(m.group(1)))
                self._finding_counter = max_num
            self._finding_counter += 1
            return f"FIND-{self._finding_counter:03d}"

    @staticmethod
    def _sanitize_evidence(evidence: str) -> str:
        """
        Evidence metnini temizler:
          - ANSI escape kodlarini kaldirir
          - Ham JSON parcalarini ({"status": "FOUND", "query": ...}) ozetler
          - nmap/nikto baslik satirlarini (Starting Nmap, Nmap scan report,
            Host is up, + Server:, - Nikto) kaldirir
          - Asiri bosluk/satir sonlarini sadelestirir
          - Uzunlugu 500 karakterle sinirlar
        """
        if not evidence:
            return ""
        text = str(evidence)
        # ANSI escape kodlari
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
        # Ham JSON benzeri parcalari temizle (cve_search ciktilari)
        if re.search(r'"(status|query|message|cves)"\s*:', text):
            # JSON'dan anlamli alanlari cikarmaya calis
            m = re.search(r'"message"\s*:\s*"([^"]+)"', text)
            if m:
                text = m.group(1)
            else:
                # JSON'u bosluklardan arindirip kisalt
                text = re.sub(r'[{}\[\]"]', " ", text)
        # nmap/nikto baslik/gurultu satirlarini kaldir
        noise_patterns = [
            r"Starting Nmap[^\n]*",
            r"Nmap scan report[^\n]*",
            r"Host is up[^\n]*",
            r"Nmap done[^\n]*",
            r"^\s*\+ Server:[^\n]*",
            r"^\s*- Nikto[^\n]*",
            r"^\s*\+ Target[^\n]*",
        ]
        for pat in noise_patterns:
            text = re.sub(pat, "", text, flags=re.IGNORECASE | re.MULTILINE)
        # Coklu bosluk/satir sonu sadelestir
        text = re.sub(r"\s+", " ", text).strip()
        return text[:500]

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
        # Evidence'i temizle (ham JSON, ANSI kodlari, asiri uzun metin)
        evidence_snippet = self._sanitize_evidence(evidence_snippet)

        # Quality gate check via ValidationGate (7-Question Gate) - Hata 10 tek nokta
        gate_res = validation_gate.evaluate({
            "category": category,
            "severity": severity,
            "cwe_reference": cwe_reference,
            "evidence_snippet": evidence_snippet
        })
        self._last_gate_result = gate_res
        if not gate_res.passed and gate_res.suggested_action == "reject":
            logger.warning(f"ValidationGate rejected finding '{category}': {gate_res.reason}")
            print(f"\n🚫 [Validation Gate]: Bulgu reddedildi.")
            print(f"   Sebep: {gate_res.reason}")
            return ""


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

        # ── ISTIHBARAT vs BULGU: cve_search/searchsploit sonuclari tek basina
        # bulgu DEGILDIR; bunlar yalnizca istihbarat/lookup sonucudur. Gercek
        # bir bulgu icin exploit/privesc/nmap kaniti veya dogrulanmis PoC gerekir.
        if tool in ("cve_search", "searchsploit"):
            # Kanit gercek bir exploit/dogrulama iceriyor mu?
            verified_markers = [
                "uid=0", "root shell", "exploit confirmed", "payload executed",
                "backdoor confirmed", "rce confirmed", "authentication bypass confirmed",
            ]
            ev_lower = evidence.lower()
            if not any(m in ev_lower for m in verified_markers):
                logger.info(
                    f"Intelligence-only finding from '{tool}' not recorded as finding: {category}"
                )
                print(f"\nℹ️  [İstihbarat] '{tool}' sonucu bulgu olarak kaydedilmedi "
                      f"(yalnızca CVE/lookup bilgisi; doğrulama gerekli).")
                # Hata 3 düzeltmesi: İstihbarat reddedildi ama modele "şimdi exploit et"
                # sinyali ver; aksi halde model ikileme düşüp pasifleşiyor.
                _vuln_signals = [
                    ("vsftpd 2.3.4", "vsftpd_backdoor"),
                    ("samba 3.0.20", "samba_usermap"),
                    ("samba usermap", "samba_usermap"),
                    ("ingreslock", "ingreslock_backdoor"),
                    ("port 1524", "ingreslock_backdoor"),
                    ("proftpd 1.3.1", None),
                    ("unrealircd", None),
                ]
                exploit_hint = None
                combined_evidence = (evidence + " " + category).lower()
                for signal, exploit_name in _vuln_signals:
                    if signal in combined_evidence:
                        exploit_hint = exploit_name
                        break
                if exploit_hint and exploit_hint not in self._failed_exploits:
                    self.conversation.append({
                        "role": "user",
                        "content": (
                            f"[SYSTEM] The '{tool}' result above is INTELLIGENCE ONLY — "
                            f"it has NOT been recorded as a finding. "
                            f"However, you identified a known-vulnerable service (evidence: '{evidence[:120]}'). "
                            f"Your IMMEDIATE next action MUST be: "
                            f"{{\"tool\": \"exploit\", \"exploit\": \"{exploit_hint}\", \"target\": \"{self.target}\"}}. "
                            f"Do NOT run searchsploit or cve_search again on the same service. "
                            f"Produce the exploit JSON NOW."
                        )
                    })
                    print(f"   → 🎯 [Sinyal] '{exploit_hint}' exploit'e yönlendirme eklendi.")
                elif exploit_hint and exploit_hint in self._failed_exploits:
                    self.conversation.append({
                        "role": "user",
                        "content": (
                            f"[SYSTEM] The '{tool}' result is INTELLIGENCE ONLY. "
                            f"Note: '{exploit_hint}' was already attempted and FAILED (uid=0 not confirmed). "
                            f"Try a DIFFERENT exploit. Available: ingreslock_backdoor (port 1524), "
                            f"ssh_credential_spray (port 22), vsftpd_backdoor (port 21), samba_usermap (port 445)."
                        )
                    })
                return None

        # Human approval for the finding (human-in-the-loop principle)
        if not self.auto_approve_findings:
            print(f"\n📌 Model bir bulgu öneriyor:")
            print(f"   Kategori: {category}")
            print(f"   Şiddet: {severity}")
            print(f"   CWE: {cwe}")
            print(f"   Kanıt: {evidence[:200]}")
            approval = input("   Bu bulguyu kaydetmek istiyor musunuz? (y=evet / n=hayır): ").strip().lower()
            if approval != "y":
                print("   ⏭️  Bulgu kaydedilmedi (kullanıcı reddetti).")
                return None
        else:
            print(f"\n📌 Model bir bulgu öneriyor: {category} ({severity})")
            print("   ✅ Bulgu otomatik onay modunda işleniyor.")

        # ValidationGate evaluate tek noktada (record_finding içinde) çalıştırılır.
        finding_id = self.record_finding(
            tool=tool,
            category=category,
            severity=severity,
            cwe_reference=cwe,
            evidence_snippet=evidence,
            human_approved=True
        )
        if not finding_id:
            # Gate veya dedup tarafından reddedildi
            return None

        print(f"📌 Bulgu kaydedildi: {finding_id} — {category} ({severity})")
        return finding_id


    # ── LLM Suggestion Parsing ───────────────────────────────────────────────

    def _get_compact_conversation(self, max_turns: int = 10) -> List[Dict[str, str]]:
        """
        Keeps system prompt at index 0 and slides the last N messages
        to prevent exceeding the 8192 token context window.
        """
        if len(self.conversation) <= max_turns + 1:
            return self.conversation
        return [self.conversation[0]] + self.conversation[-max_turns:]

    def _ask_llm_for_suggestion(self, context: str, skip_orchestrator: bool = False) -> Optional[Dict[str, Any]]:
        """
        Asks the LLM for the next recommended step and parses its JSON.

        Dual-model flow:
        1. If an orchestrator_agent is configured and this is an interval step,
           the orchestrator first issues a strategic directive which is appended
           to the worker's context.
        2. The worker (CyberStrike 35B) generates a JSON suggestion.
        3. If parsing fails once, the orchestrator (if available) provides a
           corrective directive and we retry. Otherwise we fall back to a
           strict JSON-only prompt.

        Args:
            context: Worker'a verilecek baglam metni.
            skip_orchestrator: True ise periyodik orchestrator direktifi ATLANIR.
                Web UI orchestrator'i kendisi cagirdigi icin cift cagriyi onler.
        """
        if not self.llm_client:
            return None

        # ── Orchestrator periodic directive ──────────────────────────────────
        enriched_context = context
        if (
            not skip_orchestrator
            and self.orchestrator_agent is not None
            and self.step_count > 0
            and self.step_count % self.ORCHESTRATOR_INTERVAL == 0
        ):
            try:
                print(f"\n🧠 [Orchestrator] Adım {self.step_count} — DeepSeek V4 Flash strateji özeti alınıyor...")
                directive = self.orchestrator_agent.plan_next_step(
                    current_findings=self.findings,
                    recent_worker_output=self._last_orchestrator_directive,
                    step_number=self.step_count,
                    target=self.target,
                    worker_activity=self._build_worker_activity(),
                )
                self._last_orchestrator_directive = directive
                if directive:
                    print(f"🧠 [Orchestrator Direktifi]: {directive[:200]}...")
                    enriched_context = (
                        context
                        + f"\n\n=== Strategic Directive from Orchestrator (DeepSeek V4 Flash) ===\n"
                        + directive
                        + "\n=== End Directive ===\n"
                        + "Follow the orchestrator's guidance above as your next step."
                    )
            except Exception as oe:
                logger.warning(f"[Orchestrator] Directive failed: {oe}")

        self.conversation.append({"role": "user", "content": enriched_context})
        compact_messages = self._get_compact_conversation(max_turns=10)
        try:
            response = self.llm_client.generate(
                messages=compact_messages,
                temperature=0.0,
                max_tokens=1024,
                enable_thinking=False,
                json_schema=ASSESSMENT_JSON_SCHEMA
            )
            # ── API/Baglanti hatasi tespiti: sessiz basarisizligi onle ───────
            if getattr(response, "error", None):
                self._last_llm_error = response.error
                logger.error(f"[Worker] LLM baglanti hatasi: {response.error}")
                print(f"🚨 [API HATASI] Model erisilemedi: {response.error[:200]}")
                return None
            content = response.content or ""
            self.conversation.append({"role": "assistant", "content": content})
            suggestion = self._parse_suggestion(content)
            if suggestion is not None:
                # Hata 14: tool alanı null veya boş string ise sessiz hata oluşur.
                # _dispatch_tool(None, ...) KeyError verebilir; noop ile logla.
                if not suggestion.get("tool"):
                    logger.warning("[Worker] Model returned valid JSON but tool=null/empty. Treating as parse failure.")
                    suggestion = None
                else:
                    return suggestion


            # ── First parse failure: ask orchestrator for correction ─────────
            if self.orchestrator_agent is not None:
                try:
                    print("⚠️  Worker JSON üretemedi. Orchestrator düzeltici direktif veriyor...")
                    corrective = self.orchestrator_agent.fallback_correction(
                        failed_output=content,
                        step_number=self.step_count,
                        target=self.target,
                    )
                    self._last_orchestrator_directive = corrective
                    print(f"🧠 [Orchestrator Düzeltme]: {corrective[:200]}...")
                    self.conversation.append({
                        "role": "user",
                        "content": (
                            f"=== Orchestrator Correction ===\n{corrective}\n"
                            "=== End Correction ===\n\n"
                            "Based on the orchestrator's correction above, produce a valid JSON "
                            "recommendation NOW. Output ONLY the JSON object, no other text."
                        ),
                    })
                except Exception as oe:
                    logger.warning(f"[Orchestrator] Fallback correction failed: {oe}")
                    self.conversation.append({
                        "role": "user",
                        "content": (
                            "Önceki yanıtınız JSON olarak ayrıştırılamadı. "
                            "YALNIZCA geçerli bir JSON nesnesi döndürün, başka hiçbir metin "
                            "veya markdown eklemeyin. Şu şekilde: "
                            '{"thought":"...","tool":"nmap","target":"localhost:3000","param":null,"rationale":"..."}'
                        ),
                    })
            else:
                # Retry once with a strict JSON-only instruction
                print("⚠️  LLM yanıtı JSON olarak ayrıştırılamadı. Bir kez daha soruluyor...")
                self.conversation.append({
                    "role": "user",
                    "content": (
                        "Önceki yanıtınız JSON olarak ayrıştırılamadı. "
                        "YALNIZCA geçerli bir JSON nesnesi döndürün, başka hiçbir metin "
                        "veya markdown eklemeyin. Şu şekilde: "
                        '{"thought":"...","tool":"nmap","target":"localhost:3000","param":null,"rationale":"..."}'
                    ),
                })

            compact_retry_messages = self._get_compact_conversation(max_turns=10)
            response2 = self.llm_client.generate(
                messages=compact_retry_messages,
                temperature=0.0,
                max_tokens=1024,
                enable_thinking=False,
                json_schema=ASSESSMENT_JSON_SCHEMA
            )
            content2 = response2.content or ""
            self.conversation.append({"role": "assistant", "content": content2})
            suggestion2 = self._parse_suggestion(content2)
            if suggestion2 is not None:
                return suggestion2

            # ── Second parse failure: let Orchestrator directly emit JSON ─────
            if self.orchestrator_agent is not None:
                print("🧠 [Orchestrator Devrede]: DeepSeek V4 Flash doğrudan JSON önerisi üretiyor...")
                suggestion_orch = self.orchestrator_agent.direct_json_suggestion(
                    current_findings=self.findings,
                    step_number=self.step_count,
                    target=self.target,
                    visited_actions=self.visited_actions
                )
                if suggestion_orch is not None:
                    return suggestion_orch

            return None
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
                       ports: Optional[str] = None, query: Optional[str] = None,
                       exploit: Optional[str] = None, privesc: Optional[str] = None,
                       username: Optional[str] = None, password: Optional[str] = None,
                       command: Optional[str] = None) -> Dict[str, Any]:
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
        if tool == "web_search":
            # Use CyberStrike's own query field first; fall back to heuristic construction
            effective_query = query or f"{service_name or target} {version or ''} exploit CVE".strip()
            return suggest_web_search(effective_query, approved=approved)
        if tool in ("debugger", "x64dbg"):
            from core.debugger_mcp import debugger_mcp
            res = debugger_mcp.get_all_registers()
            return {
                "status": "APPROVED" if approved else "AWAITING_APPROVAL",
                "tool": "debugger",
                "target": target,
                "command": "x64dbg MCP GetAllRegisters",
                "output": json.dumps(res, indent=2) if approved else "Awaiting operator approval for binary debugger analysis.",
                "rationale": "x64dbg MCP üzerinden CPU register ve bellek analizi."
            }
        if tool == "exploit":
            # Active exploitation against authorized training targets.
            # Hedef her zaman aktif hedefe zorlanir (model port gibi yanlis
            # hedef verebilir). Exploit adi bos ise hedefe gore otomatik secilir.
            from core.exploit_runner import dispatch_exploit
            active_target = self.target
            effective_exploit = exploit or self._auto_select_exploit(active_target, service_name, ports)
            return dispatch_exploit(effective_exploit, active_target, approved=approved, command=command)
        if tool == "privesc":
            # Local privilege escalation after a foothold (SSH session).
            from core.privesc_engine import dispatch_privesc
            active_target = self.target
            effective_privesc = privesc or "verify_root"
            # SSH portunu belirle: model 'ports' verdiyse ilk gecerli portu kullan,
            # yoksa varsayilan 22.
            ssh_port = 22
            if ports:
                for token in re.split(r"[,\s]+", str(ports)):
                    if token.strip().isdigit():
                        ssh_port = int(token.strip())
                        break
            return dispatch_privesc(
                effective_privesc, active_target,
                username=username or "msfadmin",
                password=password or "msfadmin",
                approved=approved,
                port=ssh_port,
                command=command,
            )
        return {
            "status": "UNKNOWN_TOOL",
            "tool": tool,
            "target": target,
            "message": f"Unknown tool '{tool}' requested by LLM. Blocked."
        }

    def _auto_select_exploit(self, target: str, service_name: Optional[str] = None,
                             ports: Optional[str] = None,
                             failed_exploits: Optional[set] = None) -> str:
        """
        Model exploit adi belirtmezse hedefe ve kesfedilen servise gore en uygun
        exploit'i otomatik secer. En guvenilir (root veren) exploit onceliklidir.

        Hata 4 duzeltmesi: failed_exploits parametresi eklendi. Daha once denenip
        basarisiz olan exploit'ler (uid=0 dogrulanamadi) listeden cikarilir;
        boylece vsftpd/samba basarisiz olduktan sonra ingreslock deterministik
        olarak secilir.

        Port eslesmesi TOKEN bazlidir (substring degil): "2121" icindeki "21"
        yanlis eslesme yapmaz.
        """
        t = (target or "").lower()
        svc = (service_name or "").lower()
        failed = failed_exploits or self._failed_exploits or set()

        # Portlari token'lara ayir (virgul/bosluk ile)
        port_tokens = set()
        for token in re.split(r"[,\s]+", str(ports or "")):
            token = token.strip()
            if token.isdigit():
                port_tokens.add(int(token))
        # _discovered_ports ile de birleştir (nmap çıktısından parse edilenler)
        port_tokens |= self._discovered_ports

        def has_port(p: int) -> bool:
            return p in port_tokens

        def pick(exploit_name: str) -> Optional[str]:
            """Exploit başarısız listesinde değilse seç, değilse None döndür."""
            return exploit_name if exploit_name not in failed else None

        # Metasploitable2 icin en guvenilir root vektorleri
        # Oncelik sirasi: ingreslock (direkt root) > ssh > vsftpd > samba
        # Basarisiz olanlar atlanir; hepsi basarisizsa son secenek zorlanir.
        if "metasploitable" in t:
            PRIORITY_ORDER = [
                ("ingreslock_backdoor", lambda: True),          # her zaman dene (1524 yok olsa bile)
                ("ssh_credential_spray", lambda: has_port(22) or "ssh" in svc),
                ("vsftpd_backdoor", lambda: has_port(21) or "ftp" in svc or "vsftpd" in svc),
                ("samba_usermap", lambda: has_port(445) or "samba" in svc or "smb" in svc),
            ]
            for exploit_name, condition in PRIORITY_ORDER:
                if condition() and exploit_name not in failed:
                    return exploit_name
            # Hepsi basarisiz: ingreslock son care (basarisiz olsa bile tekrar dene
            # cunku en kisa ve deterministik exploit'tir)
            return "ingreslock_backdoor"

        # Juice Shop
        if "juice" in t or has_port(3000) or "localhost" in t:
            return pick("juice_shop_admin") or "juice_shop_admin"

        return pick("ingreslock_backdoor") or "ingreslock_backdoor"


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

    # ── Ortak Adım ve Kurtarma Metodları (Hata 11 - UI/CLI Birliği) ──────────

    def should_trigger_rescue(self, step: int, cooldown: int = 3) -> bool:
        """
        Worker'in takilip takilmadigini ve kurtarmanin tetiklenip
        tetiklenmeyecegini kontrol eder (CLI ve UI ortak mantigi).
        """
        if not self.orchestrator_agent or len(self.decision_chain) < 3:
            return False
        activity = self._build_worker_activity()
        has_repeat = "TEKRAR TESPITI" in activity
        no_exploit = "HIC exploit denemedi" in activity
        no_successful_exploit = (
            "HICBIRI BASARILI OLMADI" in activity
            and len(self.decision_chain) >= 5
        )
        last_rescue = getattr(self, "_last_rescue_step", -99)
        can_rescue = (step - last_rescue) >= cooldown
        stuck = has_repeat or (no_exploit and len(self.decision_chain) >= 3) or no_successful_exploit
        return bool(stuck and can_rescue)

    def perform_rescue(self, step: int, target: str, context: str) -> Optional[Dict[str, Any]]:
        """
        Orchestrator ile kurtarma analizi yapar, direktifi conversation'a ekler
        ve modelden yeni JSON onerisi ister. Gerekirse dogrudan orchestrator onerisine basvurur.
        """
        if not self.orchestrator_agent:
            return None
        self._last_rescue_step = step
        activity = self._build_worker_activity()
        try:
            rescue = self.orchestrator_agent.analyze_and_rescue(
                worker_activity=activity,
                recent_worker_output=self._last_orchestrator_directive or "",
                current_findings=self.findings,
                step_number=step,
                target=target,
            )
            self._last_orchestrator_directive = rescue
            if not rescue:
                return None
            self.conversation.append({
                "role": "user",
                "content": (
                    f"=== Orchestrator RESCUE Directive ===\n{rescue}\n"
                    "=== End Rescue ===\n\n"
                    "The orchestrator analyzed your situation. Follow its rescue "
                    "directive EXACTLY. Produce a valid JSON recommendation NOW. "
                    "If the service you were trying has NO available exploit, "
                    "STOP retrying it and move to a DIFFERENT service."
                ),
            })
            suggestion2 = None
            try:
                suggestion2 = self._ask_llm_for_suggestion(context, skip_orchestrator=True)
            except Exception:
                suggestion2 = None
            if not suggestion2 or suggestion2.get("tool") in ("done", None):
                try:
                    forced = self.orchestrator_agent.direct_json_suggestion(
                        current_findings=self.findings,
                        step_number=step,
                        target=target,
                        visited_actions=self.visited_actions,
                    )
                    if forced and forced.get("tool") not in ("done", None):
                        suggestion2 = forced
                except Exception:
                    pass
            return suggestion2
        except Exception as e:
            logger.warning(f"[Orchestrator] Rescue failed: {e}")
            return None

    def check_periodic_scope(self, step: int) -> Optional[List[str]]:
        """Her 5 adimda bir henuz test edilmemis servisleri kontrol eder ve conversation'a ekler."""
        if step > 0 and step % 5 == 0:
            untested = self._untested_services()
            if untested:
                self.conversation.append({
                    "role": "user",
                    "content": (
                        f"[PERIODIC SCOPE CHECK at step {step}] "
                        f"The following critical services have NOT been tested yet: "
                        f"{', '.join(untested)}. "
                        f"Make sure to test ALL of them before saying 'done'. "
                        f"Continue with your current plan but keep these in mind."
                    ),
                })
                return untested
        return None

    def execute_step(
        self,
        tool: str,
        target: str,
        suggestion: Dict[str, Any],
        approved: bool = True,
    ) -> Dict[str, Any]:
        """
        Tek bir adimin arac cagrisini yapar, exploit ve bulgu sonuclarini
        isler, conversation'a doner ve visited_actions'i gunceller.
        CLI ve UI icin ORTAK calistirma metodudur (Hata 11).
        """
        param = suggestion.get("param")
        service_name = suggestion.get("service_name")
        version = suggestion.get("version")
        ports = suggestion.get("ports")
        query = suggestion.get("query")
        exploit = suggestion.get("exploit")
        privesc = suggestion.get("privesc")
        username = suggestion.get("username")
        password = suggestion.get("password")
        command = suggestion.get("command")

        _svc_for_key = service_name
        if tool == "exploit":
            _svc_for_key = exploit or service_name
        elif tool == "privesc":
            _svc_for_key = privesc or service_name
        action_key = self._action_key(tool, target, ports, _svc_for_key, version)

        result = self._dispatch_tool(
            tool=tool,
            target=target,
            param=param,
            approved=approved,
            service_name=service_name,
            version=version,
            ports=ports,
            query=query,
            exploit=exploit,
            privesc=privesc,
            username=username,
            password=password,
            command=command,
        )

        output = result.get("output", "")

        if approved:
            if tool in ("exploit", "privesc"):
                exploit_name_used = (
                    result.get("exploit") or result.get("technique") or exploit or privesc or tool
                )
                success = result.get("success", False)
                if success:
                    self._exploit_succeeded = True
                    self._record_exploit_finding(tool, result)
                else:
                    if exploit_name_used:
                        self._failed_exploits.add(exploit_name_used)
                if self.decision_chain:
                    self.decision_chain[-1]["exploit_succeeded"] = success
                self._feed_result_to_llm(
                    tool, target, approved, output,
                    exploit_success=success,
                    exploit_name=exploit_name_used
                )
            else:
                self._auto_extract_finding(tool, output)
                self._feed_result_to_llm(tool, target, approved, output)

            self.visited_actions.add(action_key)
        else:
            self._feed_result_to_llm(tool, target, approved, output)

        return result

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

            # ── Periyodik Kapsam Kontrolü (Hata 6) ───────────────────────────
            self.check_periodic_scope(self.step_count)

            # ── WORKER KURTARMA (CLI - Ortak metod kullanımı) ────────────────
            if (
                suggestion.get("tool") != "done"
                and self.should_trigger_rescue(self.step_count, cooldown=3)
            ):
                print("\n🧠 [Orchestrator] Worker takıldı tespit edildi. Analiz edilip kurtarılıyor...")
                res_sug = self.perform_rescue(self.step_count, self.target, context)
                if res_sug and res_sug.get("tool") not in ("done", None):
                    suggestion = res_sug
                    print(f"🧠 [Orchestrator Kurtarma]: {self._last_orchestrator_directive[:200] if self._last_orchestrator_directive else ''}")
                else:
                    print("⚠️  Kurtarma başarısız; bu adım atlanıyor.")
                    continue

            tool = suggestion.get("tool", "")
            target = suggestion.get("target", self.target)
            param = suggestion.get("param")
            ports = suggestion.get("ports")
            service_name = suggestion.get("service_name")
            version = suggestion.get("version")
            exploit = suggestion.get("exploit")
            privesc = suggestion.get("privesc")
            username = suggestion.get("username")
            command = suggestion.get("command")
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
                "exploit": exploit,
                "privesc": privesc,
                "rationale": rationale,
            })

            # 1b. Record a finding if the model emitted one
            finding = suggestion.get("finding")
            if isinstance(finding, dict) and finding.get("category"):
                self._record_model_finding(finding, tool)

            # 2. LLM says done → end assessment (deterministik kontrol ile)
            if tool == "done":
                untested = self._untested_services()
                if untested and self.step_count < self.max_steps:
                    print(f"🧠 [Sistem] Model 'done' dedi ancak şu servisler test edilmedi: {', '.join(untested)}")
                    print("   Devam ediliyor...")
                    self.conversation.append({
                        "role": "user",
                        "content": (
                            "STOP: You said 'done' but the following critical services "
                            f"have NOT been tested yet: {', '.join(untested)}. "
                            "You MUST continue. Test each remaining service with "
                            "searchsploit/cve_search (and exploit if a ready exploit exists). "
                            "Only say 'done' after ALL services have been tested. "
                            "Produce the next JSON recommendation NOW."
                        ),
                    })
                    suggestion2 = None
                    try:
                        suggestion2 = self._ask_llm_for_suggestion(context, skip_orchestrator=True)
                    except Exception:
                        suggestion2 = None
                    if not suggestion2 or suggestion2.get("tool") in ("done", None):
                        if self.orchestrator_agent is not None:
                            try:
                                forced = self.orchestrator_agent.direct_json_suggestion(
                                    current_findings=self.findings,
                                    step_number=self.step_count,
                                    target=self.target,
                                    visited_actions=self.visited_actions,
                                )
                                if forced and forced.get("tool") not in ("done", None):
                                    suggestion2 = forced
                            except Exception:
                                pass
                    if suggestion2 and suggestion2.get("tool") not in ("done", None):
                        suggestion = suggestion2
                        tool = suggestion.get("tool", "")
                    else:
                        print("✅ LLM değerlendirmenin tamamlandığını bildirdi.")
                        break
                else:
                    print("✅ LLM değerlendirmenin tamamlandığını bildirdi.")
                    break

            # 3. Code-level scope validation
            if not is_target_allowed(target):
                print(f"🚫 KAPSAM DIŞI HEDEF REDDEDİLDİ: '{target}'")
                print("   Bu hedef config/allowed_targets.txt içinde değil. Komut çalıştırılmadı.")
                self._log_rejection(tool, target)
                continue

            # 3b. Loop breaker
            _svc_for_key = service_name
            if tool == "exploit":
                _svc_for_key = exploit or service_name
            elif tool == "privesc":
                _svc_for_key = privesc or service_name
            action_key = self._action_key(tool, target, ports, _svc_for_key, version)
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
            if exploit:
                print(f"   Exploit: {exploit}")
            if privesc:
                print(f"   Privesc Tekniği: {privesc}")
            if username:
                print(f"   Kullanıcı: {username}")
            if command:
                print(f"   Komut: {command}")
            print(f"   Gerekçe: {rationale}")

            approval = input("\n   Bu adımı çalıştırmak istiyor musunuz? (y=evet / n=hayır / dur=durdur): ").strip().lower()

            if approval == "dur":
                print("⏹️  Değerlendirme kullanıcı tarafından durduruldu.")
                break

            approved = (approval == "y")

            # 5. Execute via unified execute_step method
            result = self.execute_step(tool, target, suggestion, approved=approved)
            output = result.get("output", "")

            if approved:
                if tool in ("exploit", "privesc"):
                    exploit_name_used = result.get("exploit") or result.get("technique") or exploit or privesc
                    print(f"\n🔧 Çalıştırılıyor: {tool} ({exploit_name_used})")
                    print(f"📄 Çıktı:\n{output[:2000]}")
                    if result.get("success"):
                        print(f"✅ BAŞARILI: {tool} hedefte yetki/erişim sağladı!")
                    else:
                        print("ℹ️  Exploit/Privesc başarısız oldu veya hedef bu zafiyete açık değil.")
                else:
                    print(f"\n🔧 Çalıştırılıyor: {result.get('command')}")
                    print(f"📄 Çıktı:\n{output[:2000]}")
            else:
                print("\n⏭️  Adım kullanıcı tarafından reddedildi. LLM'den alternatif istenecek.")



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

    def _build_worker_activity(self) -> str:
        """
        Worker'in son islem gecmisini ozetler ve tekrar/takilma tespit eder.
        Orchestrator'a gonderilir ki worker takildiginda onu farkli bir yone
        yonlendirebilsin.

        Hata 1 duzeltmesi: exploit_attempted yerine no_successful_exploit kontrolu
        yapilir. Basarisiz exploit'ler ayri raporlanir; boylece kurtarma
        'exploit denendi ama uid=0 alinamadi' durumunu da tespit eder.
        """
        if not self.decision_chain:
            return "(worker henuz islem yapmadi)"

        # Son 8 adimi listele
        recent = self.decision_chain[-8:]
        lines = []
        for d in recent:
            tool = d.get("tool", "?")
            target = d.get("target", "")
            svc = d.get("service_name") or d.get("exploit") or d.get("privesc") or ""
            succeeded = d.get("exploit_succeeded", None)
            status = ""
            if tool in ("exploit", "privesc") and succeeded is not None:
                status = " [BAŞARILI]" if succeeded else " [BAŞARISIZ]"
            lines.append(f"  Adim {d.get('step')}: {tool} {svc} ({target}){status}")

        # Tekrar tespiti: SON 5 adimda ayni tool+servis 2+ kez tekrarlandi mi?
        from collections import Counter
        recent_window = self.decision_chain[-5:]
        action_counts = Counter()
        for d in recent_window:
            tool = d.get("tool", "")
            svc = d.get("service_name") or d.get("exploit") or d.get("privesc") or ""
            action_counts[(tool, svc)] += 1

        repeats = {k: v for k, v in action_counts.items() if v >= 2}
        if repeats:
            lines.append("  TEKRAR TESPITI (worker ayni islemi tekrarliyor):")
            for (tool, svc), count in repeats.items():
                lines.append(f"    - {tool}/{svc}: {count} kez")

        # Hata 1 duzeltmesi: Exploit durumu — basarisiz ve basarili ayrı raporla
        exploit_attempted = any(d.get("tool") == "exploit" for d in self.decision_chain)
        privesc_attempted = any(d.get("tool") == "privesc" for d in self.decision_chain)

        if not exploit_attempted:
            lines.append("  NOT: Worker HIC exploit denemedi (sadece kesif yapti).")
        else:
            if not self._exploit_succeeded:
                failed_list = sorted(self._failed_exploits) if self._failed_exploits else ["(bilinmiyor)"]
                untried = [e for e in ["ingreslock_backdoor", "ssh_credential_spray",
                                       "vsftpd_backdoor", "samba_usermap"]
                           if e not in self._failed_exploits]
                lines.append(
                    f"  KRITIK: Worker exploit DENEDI ama HICBIRI BASARILI OLMADI. "
                    f"Basarisiz: {failed_list}. "
                    f"Denenmemis: {untried or ['yok']}. "
                    f"HEMEN farkli bir exploit veya servis dene."
                )
            else:
                lines.append(f"  BASARILI exploit mevcut. Kalan servisler test edilmeli.")

        if not privesc_attempted:
            lines.append("  NOT: Worker HIC privesc denemedi.")

        # Desteklenen exploit'ler listesi
        lines.append(
            "  DESTEKLENEN EXPLOITLER (yalnizca bunlar calisir): "
            "vsftpd_backdoor, samba_usermap, ingreslock_backdoor, "
            "ssh_credential_spray, juice_shop_admin. "
            "MySQL/ProFTPD/UnrealIRCd/distcc/PostgreSQL icin HAZIR EXPLOIT YOKTUR; "
            "bu servislerde israr etmeyin, searchsploit/cve_search ile dogrulayip "
            "finding olarak kaydedin ve DIGER servise gecin."
        )

        return "\n".join(lines)


    # Metasploitable2'de test edilmesi gereken kritik servisler.
    # (port, servis adi, servis-adi anahtar kelimeleri)
    # NOT: Eslesme YALNIZCA gercek eylem alanlarinda yapilir (tool/service_name/
    # exploit/ports); serbest 'thought' metni TARANMAZ (yanlis pozitif onlenir).
    _CRITICAL_SERVICES = [
        (21, "vsftpd", ["vsftpd", "ftp"]),
        (22, "ssh", ["ssh", "msfadmin"]),
        (445, "samba", ["samba", "smb"]),
        (1524, "ingreslock", ["ingreslock"]),
        (3306, "mysql", ["mysql"]),
        (5432, "postgresql", ["postgres", "postgresql"]),
        (6667, "unrealircd", ["unrealircd", "irc"]),
        (80, "apache", ["apache", "http", "nikto", "gobuster", "whatweb"]),
        (3632, "distcc", ["distcc"]),
        (23, "telnet", ["telnet"]),
        (2049, "nfs", ["nfs"]),
        (5900, "vnc", ["vnc"]),
        (1099, "java-rmi", ["rmi", "java"]),
    ]

    def _untested_services(self) -> List[str]:
        """
        Karar zincirine bakarak HENUZ test edilmemis kritik servisleri dondurur.
        Model 'done' demek istediginde, eksik servisler varsa devam etmeye
        zorlamak icin kullanilir (deterministik kontrol).

        ONEMLI: Yalnizca GERCEK eylem alanlarina bakilir (tool, service_name,
        exploit, privesc, ports). Serbest 'thought' metni TARANMAZ; aksi halde
        modelin dusuncesinde gecen "port 80" gibi ifadeler servisi yanlislikla
        'test edilmis' sayar ve erken bitise yol acar.
        """
        # Gercek eylem alanlarini topla (thought HARIC)
        action_text_parts = []
        tested_ports = set()
        for d in self.decision_chain:
            tool = str(d.get("tool", "")).lower()
            svc = str(d.get("service_name", "")).lower()
            exploit = str(d.get("exploit", "")).lower()
            privesc = str(d.get("privesc", "")).lower()
            ports = str(d.get("ports", ""))
            action_text_parts.append(f"{tool} {svc} {exploit} {privesc}")
            # Portlari token bazli ayir (substring degil)
            for token in re.split(r"[,\s]+", ports):
                if token.strip().isdigit():
                    tested_ports.add(int(token.strip()))

        action_text = " ".join(action_text_parts)

        untested = []
        for port, name, keywords in self._CRITICAL_SERVICES:
            # 1. Port tam eslesme ile test edildi mi?
            if port in tested_ports:
                continue
            # 2. Servis adi gercek eylem alanlarinda geciyor mu?
            if any(kw in action_text for kw in keywords):
                continue
            untested.append(f"{name} (port {port})")
        return untested

    def _feed_result_to_llm(self, tool: str, target: str, approved: bool, output: str,
                            exploit_success: Optional[bool] = None,
                            exploit_name: Optional[str] = None) -> None:
        """Sends the tool result (or rejection) back to the LLM.

        Hata 2 duzeltmesi: exploit/privesc sonuclari artik success=True/False
        olarak acikca yaziliyor; boylece model 'injection sent' ifadesini gorunce
        basarili zannetmiyor.

        Hata 8 duzeltmesi: nmap ciktisindaki portlar _discovered_ports setine parse edilir.
        """
        if not approved:
            msg = (
                f"The human operator REJECTED the '{tool}' step against {target}.\n"
                "Propose a DIFFERENT alternative step as JSON."
            )
            self.conversation.append({"role": "user", "content": msg})
            return

        # Hata 8: nmap çıktısından port parse et
        if tool == "nmap" and output:
            for port_match in re.finditer(r"(\d+)/tcp\s+open", output):
                try:
                    self._discovered_ports.add(int(port_match.group(1)))
                except ValueError:
                    pass

        if tool in ("exploit", "privesc") and exploit_success is not None:
            # Hata 2: Başarı durumunu açıkça yaz; model çıktıdan tahmin etmesin.
            if exploit_success:
                msg = (
                    f"Exploit '{exploit_name or tool}' result: SUCCESS=True. "
                    f"Root/admin access CONFIRMED (uid=0 or authentication bypass verified).\n"
                    f"Output:\n{output[:1500]}\n\n"
                    f"Record a Critical finding for this. Then continue to test OTHER services "
                    f"(do NOT stop just because one exploit succeeded — check all remaining services)."
                )
            else:
                # Başarısız exploit: hangi exploit'in başarısız olduğunu ve ne denemeleri gerektiğini söyle
                untried = [
                    e for e in ["ingreslock_backdoor", "ssh_credential_spray",
                                "vsftpd_backdoor", "samba_usermap"]
                    if e not in self._failed_exploits
                ]
                untried_str = ", ".join(untried) if untried else "none remaining"
                msg = (
                    f"Exploit '{exploit_name or tool}' result: SUCCESS=False. "
                    f"The exploit was attempted but uid=0 was NOT confirmed. "
                    f"Do NOT claim success. Do NOT retry this same exploit.\n"
                    f"Output:\n{output[:1200]}\n\n"
                    f"Failed exploits so far: {sorted(self._failed_exploits) or 'none yet'}.\n"
                    f"Untried exploits available: {untried_str}.\n"
                    f"IMMEDIATELY try the next untried exploit or move to a different service."
                )
        else:
            msg = (
                f"Tool '{tool}' ran against {target} with human approval.\n"
                f"Output:\n{output[:1500]}\n\n"
                "Interpret this output. If you found a vulnerability, note it. "
                "Then recommend the next step as JSON."
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
        (r"distcc", "Known vulnerable service version", "CWE-937"),
        (r"PostgreSQL\s+8\.3", "Old Software Version", "CWE-1104"),
        (r"VNC", "Known vulnerable service version", "CWE-937"),
    ]

    def _auto_extract_finding(self, tool: str, output: str) -> None:
        """
        Proactively detects known vulnerable version patterns in a tool output
        and offers to record them as findings (human-approved). This catches
        vulnerabilities even if the model does not emit a 'finding' field.

        Bir cikti birden fazla zafiyetli servis icerebilir (ornegin nmap cikti);
        bu yuzden TUM eslesmeler islenir (erken return yok). Dedup zaten
        record_finding icinde yapilir.
        """
        if not output:
            return
        for pattern, category, cwe in self._KNOWN_VULN_PATTERNS:
            m = re.search(pattern, output, re.IGNORECASE)
            if m:
                # Evidence olarak SADECE eslesen satiri al (tum cikti degil).
                line_start = output.rfind("\n", 0, m.start()) + 1
                line_end = output.find("\n", m.end())
                if line_end == -1:
                    line_end = len(output)
                evidence = output[line_start:line_end].strip() or output[m.start():m.end() + 20].strip()
                print(f"\n🔎 Otomatik bulgu tespiti: '{pattern}' kalıbı bulundu.")
                if self.auto_approve_findings:
                    approval = "y"
                    print("   ✅ Otomatik bulgu kaydedildi.")
                else:
                    approval = input(f"   '{category}' bulgusunu kaydetmek ister misiniz? (y/n): ").strip().lower()
                if approval == "y":
                    # Hata 7 duzeltmesi: Banner/versiyon tespiti tek basina High/Medium
                    # DEGILDIR; bu istihbarat/keşif bulgusudur (Informational).
                    # Exploit dogrulanirsa _record_exploit_finding ile Critical olarak
                    # ayrica kaydedilir. Raporda Critical/High ile karismasin diye
                    # Informational olarak isaretlenir.
                    self.record_finding(
                        tool=tool,
                        category=category,
                        severity="Informational",
                        cwe_reference=cwe,
                        evidence_snippet=evidence,
                        human_approved=True
                    )
                    print(f"   📌 Bulgu kaydedildi: {category} (Informational — keşif/banner tespiti)")

                else:
                    print("   ⏭️  Bulgu kaydedilmedi.")
                # NOT: erken return YOK - tum eslesmeler islenir (dedup korur)

    def _record_exploit_finding(self, tool: str, result: Dict[str, Any]) -> None:
        """
        Basarili bir exploit/privesc sonucunu bulgu olarak kaydeder.
        Exploit icin 'exploit' alani, privesc icin 'technique' alani kullanilir.
        Kanit (evidence) ve kategori, sonuc nesnesinden alinir.
        """
        evidence = result.get("evidence", "") or result.get("output", "")[:300]
        if not evidence:
            return

        if tool == "exploit":
            exploit_name = result.get("exploit", "")
            category_map = {
                "vsftpd_backdoor": "Backdoor Exploitation (CVE-2011-2523)",
                "samba_usermap": "Remote Code Execution (CVE-2007-2447)",
                "ingreslock_backdoor": "Backdoor Exploitation",
                "ssh_credential_spray": "Weak Default Credentials",
                "juice_shop_admin": "Broken Access Control",
            }
            cwe_map = {
                "vsftpd_backdoor": "CWE-912",
                "samba_usermap": "CWE-78",
                "ingreslock_backdoor": "CWE-912",
                "ssh_credential_spray": "CWE-521",
                "juice_shop_admin": "CWE-284",
            }
            category = category_map.get(exploit_name, "Active Exploitation")
            cwe = cwe_map.get(exploit_name, "CWE-912")
            severity = "Critical"
        else:  # privesc
            technique = result.get("technique", "")
            category = "Privilege Escalation"
            cwe = "CWE-732"
            severity = "Critical"

        print(f"\n📌 Başarılı {tool} bulgusu kaydediliyor: {category}")
        if self.auto_approve_findings:
            approval = "y"
            print("   ✅ Otomatik bulgu kaydedildi.")
        else:
            approval = input(f"   '{category}' bulgusunu kaydetmek ister misiniz? (y/n): ").strip().lower()
        if approval == "y":
            self.record_finding(
                tool=tool,
                category=category,
                severity=severity,
                cwe_reference=cwe,
                evidence_snippet=evidence,
                human_approved=True
            )
            print(f"   📌 Bulgu kaydedildi: {category} ({severity})")
        else:
            print("   ⏭️  Bulgu kaydedilmedi.")

    def _manual_suggestion(self) -> Optional[Dict[str, Any]]:
        """Allows the operator to pick a tool manually when the LLM fails."""
        print("   Mevcut araçlar: nmap, gobuster, nikto, whatweb, ssl_check, sqlmap, searchsploit, cve_search")
        print("   Aktif sömürü: exploit (vsftpd_backdoor, samba_usermap, ingreslock_backdoor, ssh_credential_spray, juice_shop_admin)")
        print("   Yetki yükseltme: privesc (suid_enumeration, sudoers_audit, sudo_privesc, gtfobins_privesc, verify_root)")
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
        if choice == "exploit":
            exploit = input("   Exploit seçin (vsftpd_backdoor, samba_usermap, ingreslock_backdoor, ssh_credential_spray, juice_shop_admin): ").strip()
            return {
                "tool": "exploit",
                "target": self.target,
                "exploit": exploit,
                "rationale": "Manuel olarak seçilen aktif sömürü."
            }
        if choice == "privesc":
            privesc = input("   Teknik seçin (suid_enumeration, sudoers_audit, sudo_privesc, gtfobins_privesc, verify_root): ").strip()
            username = input("   SSH kullanıcı adı (ör. msfadmin): ").strip() or "msfadmin"
            password = input("   SSH parola (ör. msfadmin): ").strip() or "msfadmin"
            return {
                "tool": "privesc",
                "target": self.target,
                "privesc": privesc,
                "username": username,
                "password": password,
                "rationale": "Manuel olarak seçilen yetki yükseltme."
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

        # Root elde edildi mi? (privesc/exploit bulgularinda uid=0 kaniti)
        root_obtained = any(
            "uid=0" in str(f.get("evidence_snippet", ""))
            or "root" in str(f.get("evidence_snippet", "")).lower()
            for f in all_findings
        )
        foothold_obtained = any(
            f.get("tool") in ("exploit", "privesc")
            for f in all_findings
        )

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
| **Foothold Elde Edildi** | `{'✅ Evet' if foothold_obtained else '❌ Hayır'}` |
| **Root Elde Edildi (UID=0)** | `{'✅ EVET — SİSTEM TAMAMEN ELE GEÇİRİLDİ' if root_obtained else '❌ Hayır'}` |

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

        # Section 6: Exploit Chaining Analysis (Chain Walk Algorithm)
        chains = chain_engine.build_chain_narrative(sorted_findings)
        md += "\n---\n\n## 🔗 6. Exploit Zincirleme Analizi (Exploit Chaining & Attack Narratives)\n\n"
        if not chains:
            md += "*Mevcut bulgular arasında doğrudan çok aşamalı bir istismar zinciri tespit edilmedi.*\n\n"
        else:
            md += (
                "Tekil güvenlik bulgularının bir araya getirilerek nasıl kritik bir istismar "
                "zincirine dönüştürülebileceğinin analizi (pentest-agents Chain Walk standardı):\n\n"
            )
            md += chain_engine.format_chain_summary(chains)

        md += "\n*Rapor AutoRedTeam Security Assessment Assistant tarafından üretilmiştir.*\n"

        try:
            self.report_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.report_file, "w", encoding="utf-8") as f:
                f.write(md)
        except Exception as e:
            logger.error(f"Could not write report: {e}")

        # ── Profesyonel PDF raporu da uret (raporlar/ klasoru) ──────────────
        try:
            from reports.pdf_report_generator import PDFReportGenerator
            pdf_gen = PDFReportGenerator(output_dir="raporlar")
            pdf_path = pdf_gen.generate(
                findings=all_findings,
                target=self.target,
                decision_chain=self.decision_chain,
                chains=chains,
            )
            if pdf_path:
                logger.info(f"PDF rapor olusturuldu: {pdf_path}")
        except Exception as e:
            logger.warning(f"PDF rapor uretilemedi: {e}")

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
