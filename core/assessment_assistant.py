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
    suggest_browser_action,
)
from core.llm_client import BaseLLMClient
from core.validation_gate import validation_gate
from core.chain_engine import chain_engine
from core.skill_loader import skill_loader
from core.context_engine import context_engine
from core.target_memory import target_memory

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
  "exploit": "if tool is 'exploit', one of: vsftpd_backdoor, samba_usermap, ingreslock_backdoor, ssh_credential_spray, distcc_exec, unrealircd_backdoor, juice_shop_admin; else null",
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
   - When a verified vulnerable service is found (e.g. vsftpd 2.3.4, Samba 3.0.20, port 1524 backdoor), DO NOT stop at reporting. Set "tool": "exploit" AND ALWAYS set the "exploit" field to the exact exploit name (e.g. "ingreslock_backdoor", "vsftpd_backdoor", "ssh_credential_spray", "samba_usermap", "distcc_exec", "unrealircd_backdoor", "juice_shop_admin").
   - CRITICAL: When "tool" is "exploit", the "exploit" field MUST be a non-null string. NEVER leave it null. Choose the exploit that matches the discovered service.
   - CRITICAL: The "target" field MUST always be the active target alias ("metasploitable2" or "localhost:3000"). NEVER put a port number or IP in "target".
   - After a foothold (e.g. SSH as msfadmin), set "tool": "privesc" AND ALWAYS set the "privesc" field (e.g. "suid_enumeration", "sudoers_audit", "sudo_privesc", "gtfobins_privesc", "verify_root"). Provide "username" and "password" for the foothold session (e.g. "msfadmin"/"msfadmin").
   - Recommended metasploitable2 chain: port 1524 -> "exploit":"ingreslock_backdoor" (root shell). If no 1524, use "exploit":"ssh_credential_spray" to get msfadmin, then "privesc":"sudo_privesc" or "privesc":"gtfobins_privesc" to reach root, then "privesc":"verify_root".

### ROOT SONRASI DEVAM (KRITIK - TUM ZAFIYETLERI BUL)
1. ROOT ALMAK DEGERLENDIRMENIN SONU DEGILDIR. Bir servis uzerinden root (uid=0) elde etsen bile, diger acik servisleri de test etmeye DEVAM ET. Sadece root alip "done" deme.
2. DINAMIK KESIF YAP (EZBER YAPMA): Sana verilen tarama sonuclarindaki (attack surface tree) servisleri ve versiyonlari KENDIN analiz et. Bir servisin zafiyetini bilmiyorsan:
   - "tool":"searchsploit" ile o servis+versiyon icin exploit ara, VEYA
   - "tool":"cve_search" ile guncel CVE istihbarati al, VEYA
   - "tool":"web_search" ile internette PoC/exploit arastir.
   Model egitim verisi 2024'e kadar olabilir; yeni zafiyetler icin MUTLAKA web_search/cve_search kullan.
3. HAZIR EXPLOITLER (yalnizca bunlar kod olarak mevcut): vsftpd_backdoor, samba_usermap, ingreslock_backdoor, ssh_credential_spray, distcc_exec, unrealircd_backdoor, proftpd_modcopy, java_rmi_deserialize, ruby_drb_rce, vnc_null_auth, tomcat_manager_deploy, juice_shop_admin.
   Bir servis icin hazir exploit YOKSA, searchsploit/cve_search/web_search ile arastir ve bulguyu finding olarak kaydet; ardindan DIGER servise gec.
4. BIR EXPLOIT BASARISIZ OLURSA, O SERVISE TAKILIP KALMA. Ayni exploit'i 2'den fazla kez DENEME. Hemen diger servise gec.
5. Her basarili exploit/privesc icin bir "finding" kaydet (evidence ile). Boylece tum zafiyetler rapora girer.
6. "done" KARARI: Attack surface tree'deki TUM acik servisler test edilmis olmalidir. Eksik servis varsa "done" DEME.
7. ZERO FALSE POSITIVES (7-QUESTION VALIDATION GATE):
   - Never emit findings for missing headers alone (CSP/HSTS), banner grabbing alone without CVE, or open redirect alone without chain. Concrete proof required.
8. ZERO FLUFF: Output ONLY the JSON object. Start with '{' and end with '}'."""


ASSESSMENT_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "thought": {"type": "string"},
        "tool": {
            "type": "string",
            "enum": [
                "nmap", "gobuster", "nikto", "whatweb", "ssl_check",
                "sqlmap", "searchsploit", "cve_search", "web_search",
                "debugger", "exploit", "privesc", "browser_action", "done"
            ]
        },
        "target": {"type": "string"},
        "param": {"type": ["string", "null"]},
        "ports": {"type": ["string", "null"]},
        "service_name": {"type": ["string", "null"]},
        "version": {"type": ["string", "null"]},
        "query": {"type": ["string", "null"]},
        # Browser / DOM interaction fields
        "action": {"type": ["string", "null"]},
        "selector": {"type": ["string", "null"]},
        "value": {"type": ["string", "null"]},
        # Active exploitation fields
        "exploit": {
            "type": ["string", "null"],
            "enum": [
                None, "vsftpd_backdoor", "samba_usermap", "ingreslock_backdoor",
                "ssh_credential_spray", "distcc_exec", "unrealircd_backdoor",
                "proftpd_modcopy", "java_rmi_deserialize", "ruby_drb_rce",
                "vnc_null_auth", "tomcat_manager_deploy", "juice_shop_admin"
            ]
        },
        # Privilege escalation fields
        "privesc": {
            "type": ["string", "null"],
            "enum": [
                None, "suid_enumeration", "sudoers_audit", "sudo_privesc",
                "gtfobins_privesc", "verify_root", "linpeas"
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

    # Her kaç adımda bir orchestrator devreye girecek.
    # v2.4: 5 -> 10. Kullanıcı geri bildirimi: model mümkün olduğunca ÖZGÜR
    # karar versin, DeepSeek rutin adımlarda müdahale etmesin. Orchestrator
    # artık yalnızca periyodik strateji özeti ve gerçek kriz (JSON üretilemez,
    # model takılır) durumlarında devreye girer.
    ORCHESTRATOR_INTERVAL = 10

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
        # Otonom tarama sonucu (ReconEngine). run_recon() cagrildiginda dolar.
        self.recon_result: Optional[Any] = None

        # Kalıcı hedef hafızası (TargetMemory)
        self.target_memory = target_memory
        self.memory_data = None
        try:
            self.memory_data = self.target_memory.recall_target(self.target)
            if self.memory_data:
                for fe in self.memory_data.failed_exploits:
                    self._failed_exploits.add(fe)
                for p in self.memory_data.open_ports.keys():
                    try:
                        p_num = int(re.sub(r"\D", "", p))
                        self._discovered_ports.add(p_num)
                    except ValueError:
                        pass
                brief = self.target_memory.render_memory_brief(self.target)
                if brief:
                    self.conversation.append({
                        "role": "user",
                        "content": f"{brief}\n\nDo NOT run initial port scans again. Move directly to untested services or exploitation."
                    })
        except Exception as tm_err:
            logger.warning(f"[TargetMemory] Init recall error: {tm_err}")


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

        # ── ISTIHBARAT vs BULGU: cve_search/searchsploit/web_search sonuclari
        # tek basina bulgu DEGILDIR; bunlar yalnizca istihbarat/lookup sonucudur.
        # Gercek bir bulgu icin exploit/privesc/nmap kaniti veya dogrulanmis PoC
        # gerekir. Model 'tool' alanini yanlis doldursa bile, kanit metni bir
        # lookup sonucu gibi gorunuyorsa (exploit baslik listesi, CVE listesi)
        # bulguyu reddet.
        _lookup_tools = ("cve_search", "searchsploit", "web_search")
        _lookup_evidence_markers = [
            "exploit title", "exploit db", "shellcodes:", "no results",
            "| path", "edb id", "cve-", "nvd", "searchsploit",
        ]
        ev_lower = evidence.lower()
        _looks_like_lookup = any(m in ev_lower for m in _lookup_evidence_markers)
        if tool in _lookup_tools or _looks_like_lookup:
            # Kanit gercek bir exploit/dogrulama iceriyor mu?
            verified_markers = [
                "uid=0", "root shell", "exploit confirmed", "payload executed",
                "backdoor confirmed", "rce confirmed", "authentication bypass confirmed",
            ]
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
                    ("distcc", "distcc_exec"),
                    ("unrealircd", "unrealircd_backdoor"),
                    ("proftpd 1.3.1", None),
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
                            f"distcc_exec (port 3632), unrealircd_backdoor (port 6667), "
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

    def _get_compact_conversation(self, max_turns: int = 6, max_tokens_budget: int = 3800) -> List[Dict[str, str]]:
        """
        Token-aware and turn-aware conversation compaction to strictly prevent
        exceeding the 8192 token context window of open-source models (CyberStrike 35B).

        Guarantees:
        1. Preserves system prompt at index 0 (clamped if oversized).
        2. Preserves active final prompt (index -1, clamped if oversized).
        3. Prunes redundant intermediate full-context snapshots (superseded by current state).
        4. Truncates intermediate tool outputs to keep high signal without token bloat.
        5. Dynamically fits messages backwards to stay strictly within max_tokens_budget.
        """
        if not self.conversation:
            return []
        if len(self.conversation) == 1:
            return [dict(self.conversation[0])]

        system_msg = dict(self.conversation[0])
        last_msg = dict(self.conversation[-1])

        # Conservative estimation: ~3.0 chars per token for mixed Turkish/English/JSON/code
        def est_tokens(text: str) -> int:
            return max(1, int(len(text) / 3.0))

        # Clamp system prompt if too long. Sistem promptu cok uzunsa (uzun
        # kural listesi) kisalt; aksi halde 8192 token butcesinin buyuk kismini
        # yer ve modelin JSON uretmesine yer kalmaz.
        sys_content = system_msg.get("content", "")
        if len(sys_content) > 3200:
            system_msg["content"] = sys_content[:3000] + "\n...[system prompt truncated]"

        # Clamp last message if too long (e.g. large scan output)
        last_content = last_msg.get("content", "")
        if len(last_content) > 3600:
            last_msg["content"] = (
                last_content[:2000]
                + "\n\n...[intermediate scan output truncated for context limits]...\n\n"
                + last_content[-1400:]
            )

        # Filter and clean intermediate messages
        intermediate = self.conversation[1:-1]
        cleaned: List[Dict[str, str]] = []
        for msg in intermediate:
            c = msg.get("content", "")
            r = msg.get("role", "user")
            # If this is an older full context snapshot (attack surface tree + recent history),
            # replace it with a brief tombstone because the active prompt contains the current state.
            if "=== Target Attack Surface:" in c:
                cleaned.append({
                    "role": r,
                    "content": "[Previous tactical attack surface snapshot omitted — superseded by current step state]"
                })
            elif len(c) > 450:
                cleaned.append({
                    "role": r,
                    "content": c[:400] + "\n...[truncated for token context limits]"
                })
            else:
                cleaned.append(dict(msg))

        # Budget calculation: reserve tokens for system prompt and last message
        sys_tokens = est_tokens(system_msg.get("content", ""))
        last_tokens = est_tokens(last_msg.get("content", ""))
        remaining_budget = max(0, max_tokens_budget - sys_tokens - last_tokens)

        # Select recent intermediate messages backwards up to max_turns and within budget
        selected: List[Dict[str, str]] = []
        used = 0
        for msg in reversed(cleaned):
            if len(selected) >= max_turns:
                break
            t = est_tokens(msg.get("content", ""))
            if used + t <= remaining_budget:
                selected.append(msg)
                used += t
            else:
                break

        selected.reverse()
        return [system_msg] + selected + [last_msg]

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
                    attack_surface_tree=context_engine.render_attack_surface_tree(self.target),
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
        # Model 8192 token limitli. Sistem promptu + gecmis + son mesaj + uretim
        # toplaminin 8192'yi ASMAMASI gerekir. Onceki 3800 budget'i gercek
        # tokenizer'a gore olculmedigi icin input 9977 token'a kadar cikiyor,
        # max_tokens 64'e dusuyor ve model gecerli JSON uretemeyip ayni eylemi
        # tekrarliyordu. Guvenli hedef: input <= 4800 token, output >= 512 token.
        compact_messages = self._get_compact_conversation(max_turns=6, max_tokens_budget=4800)
        est_input_tokens = sum(len(m.get("content", "")) for m in compact_messages) // 3.0
        calc_max_tokens = max(256, min(512, int(7800 - est_input_tokens)))

        try:
            response = self.llm_client.generate(
                messages=compact_messages,
                temperature=0.0,
                max_tokens=calc_max_tokens,
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

            compact_retry_messages = self._get_compact_conversation(max_turns=4, max_tokens_budget=3500)
            est_retry_tokens = sum(len(m.get("content", "")) for m in compact_retry_messages) // 3.0
            calc_retry_tokens = max(128, min(256, int(7200 - est_retry_tokens)))
            response2 = self.llm_client.generate(
                messages=compact_retry_messages,
                temperature=0.0,
                max_tokens=calc_retry_tokens,
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
                res = json.loads(fence_match.group(1))
                if isinstance(res, dict) and getattr(self, "target", None):
                    res["target"] = self.target
                return res
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
                            res = json.loads(candidate)
                            if isinstance(res, dict) and getattr(self, "target", None):
                                res["target"] = self.target
                            return res
                        except json.JSONDecodeError:
                            break
        return None

    # ── Tool Dispatch ────────────────────────────────────────────────────────

    def _dispatch_tool(self, tool: str, target: str, param: Optional[str], approved: bool,
                       service_name: Optional[str] = None, version: Optional[str] = None,
                       ports: Optional[str] = None, query: Optional[str] = None,
                       exploit: Optional[str] = None, privesc: Optional[str] = None,
                       username: Optional[str] = None, password: Optional[str] = None,
                       command: Optional[str] = None,
                       action: Optional[str] = None, selector: Optional[str] = None,
                       value: Optional[str] = None) -> Dict[str, Any]:
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
        if tool in ("browser", "browser_action"):
            return suggest_browser_action(
                target=target,
                action=action or command or "navigate",
                selector=selector or service_name,
                value=value or version,
                approved=approved
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
        exploit'i otomatik secer.

        DINAMIK KESIF (v2.4): Sabit port->exploit ezber listesi KALDIRILDI.
        Bunun yerine EXPLOIT_REGISTRY'deki her exploit'in hedef servis
        anahtar kelimeleri (registry 'services' alani) ile eslesme yapilir.
        Boylece yeni bir exploit eklendiginde bu fonksiyon otomatik kapsar;
        kod degistirmeye gerek kalmaz.

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

        arg_port_tokens = set()
        for token in re.split(r"[,\s]+", str(ports or "")):
            token = token.strip()
            if token.isdigit():
                arg_port_tokens.add(int(token))

        def pick(exploit_name: str) -> Optional[str]:
            """Exploit başarısız listesinde değilse seç, değilse None döndür."""
            return exploit_name if exploit_name not in failed else None

        # ── DINAMIK KESIF: EXPLOIT_REGISTRY uzerinden eslesme ────────────────
        from core.exploit_runner import EXPLOIT_REGISTRY

        candidates = [
            (name, entry)
            for name, entry in EXPLOIT_REGISTRY.items()
            if target in entry.get("targets", [])
        ]

        # 1. Verilen port/servis ile dogrudan eslesme
        for name, entry in candidates:
            entry_ports = set(entry.get("ports", []))
            svc_keys = entry.get("services", [])
            if arg_port_tokens & entry_ports:
                if pick(name):
                    return name
            if svc and any(k in svc for k in svc_keys):
                if pick(name):
                    return name

        # 2. Hedefte kesfedilmis portlarla eslesme
        for name, entry in candidates:
            entry_ports = set(entry.get("ports", []))
            if entry_ports & set(self._discovered_ports):
                if pick(name):
                    return name

        # 3. Hedefe uygun ilk denenmemis exploit (fallback)
        for name, entry in candidates:
            if pick(name):
                return name

        # 4. Hepsi basarisiz: hedefe uygun ilk exploit (son care)
        for name, entry in candidates:
            return name

        return "ingreslock_backdoor"


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
            surface_tree = context_engine.render_attack_surface_tree(target)
            rescue = self.orchestrator_agent.analyze_and_rescue(
                worker_activity=activity,
                recent_worker_output=self._last_orchestrator_directive or "",
                current_findings=self.findings,
                step_number=step,
                target=target,
                attack_surface_tree=surface_tree,
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
                        attack_surface_tree=surface_tree,
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

        action = suggestion.get("action")
        selector = suggestion.get("selector")
        value = suggestion.get("value")

        target = self.target or target
        suggestion["target"] = target

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
            action=action,
            selector=selector,
            value=value,
        )

        output = result.get("output", "")

        if approved:
            # ContextEngine Ingestion (L0/L1/L2 hierarchical context compression)
            try:
                context_engine.ingest(
                    target=target,
                    tool=tool,
                    step=self.step_count,
                    raw_output=output,
                    suggestion=suggestion,
                    command=result.get("command", "")
                )
            except Exception as ce_err:
                logger.warning(f"[ContextEngine] Ingestion error: {ce_err}")

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

        # Distill session experience into persistent Target Memory
        try:
            self.target_memory.distill_session(
                target=self.target,
                findings=self.findings,
                decision_chain=self.decision_chain
            )
        except Exception as dm_err:
            logger.warning(f"[TargetMemory] Distillation error: {dm_err}")

        return self.findings

    def run_recon(self, progress_cb=None) -> Optional[Any]:
        """
        Otonom tarama katmanini (ReconEngine) calistirir. LLM'e hic ihtiyac
        duymaz; nmap -sV -sC, nuclei, enum4linux, gobuster, nikto, whatweb
        zincirini calistirir ve sonucu self.recon_result'a kaydeder.

        Bu, degerlendirmenin ILK adimidir: model "ne tarayacagim" diye
        takilmadan once tum zafiyet yuzeyi deterministik olarak cikarilir.

        Args:
            progress_cb: Opsiyonel callback(stage, message) - UI ilerlemesi icin
        """
        try:
            from core.recon_engine import recon_engine
        except Exception as e:
            logger.warning(f"[ReconEngine] Import failed: {e}")
            return None

        if not is_target_allowed(self.target):
            logger.warning(f"[ReconEngine] Target '{self.target}' not allowed.")
            return None

        try:
            result = recon_engine.run_full_recon(self.target, progress_cb=progress_cb)
            self.recon_result = result

            # Kesfedilen portlari kaydet (exploit secimi icin)
            for svc in result.services:
                self._discovered_ports.add(svc.port)

            # Tarama bulgularini conversation'a ekle (model gorsun)
            if result.services or result.findings:
                self.conversation.append({
                    "role": "user",
                    "content": (
                        "[OTONOM TARAMA TAMAMLANDI]\n"
                        + result.summary()
                        + "\n\nBu tarama sonuclarina gore istismar edilecek "
                          "servisleri ve zafiyetleri degerlendir."
                    ),
                })
            return result
        except Exception as e:
            logger.error(f"[ReconEngine] run_recon failed: {e}")
            return None

    def _build_context(self) -> str:
        """Builds the compact, high-density context message for the LLM."""
        existing = self._load_existing_findings()
        summary = "Şu ana kadar kaydedilen bulgular:\n"
        if existing:
            for f in existing[-5:]:
                summary += f"- {f.get('finding_id')}: {f.get('tool')} / {f.get('category')} / {f.get('severity')}\n"
        else:
            summary += "(henüz bulgu yok)\n"

        try:
            compact_context = context_engine.render_compact_context(
                target=self.target,
                current_step=self.step_count,
                max_steps=self.max_steps,
                recent_history_count=4
            )

            # ── TAKILMAYI ONLE: Basarisiz exploitler ve denenmemis servisler ──
            # Model, context'te "bu zaten denendi ve basarisiz oldu" bilgisini
            # net gormezse ayni eylemi tekrar tekrar onerir (24 adim boyunca
            # vsftpd_backdoor onermesi gibi). Bu bolum her adimda modele
            # deterministik bir "yapilacaklar / yapilmayacaklar" listesi verir.
            guard_lines = []
            if self._failed_exploits:
                guard_lines.append(
                    "⛔ BASARISIZ EXPLOITLER (BUNLARI TEKRAR DENEME): "
                    + ", ".join(sorted(self._failed_exploits))
                )
            if self._exploit_succeeded:
                guard_lines.append("✅ En az bir exploit basarili oldu (root/foothold elde edildi).")
            untested = self._untested_services()
            if untested:
                guard_lines.append(
                    "🎯 HENUZ TEST EDILMEMIS SERVISLER (siradaki hedefler): "
                    + ", ".join(untested[:8])
                )
            guard_section = ("\n".join(guard_lines) + "\n\n") if guard_lines else ""

            return (
                f"{compact_context}\n\n"
                f"{guard_section}"
                f"{summary}\n"
                "Bir sonraki mantıklı değerlendirme adımını JSON olarak öner."
            )
        except Exception as ce_err:
            logger.warning(f"[ContextEngine] Compact context render fallback: {ce_err}")
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
                                       "vsftpd_backdoor", "samba_usermap",
                                       "distcc_exec", "unrealircd_backdoor"]
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
            "ssh_credential_spray, distcc_exec, unrealircd_backdoor, "
            "proftpd_modcopy, java_rmi_deserialize, ruby_drb_rce, "
            "vnc_null_auth, tomcat_manager_deploy, juice_shop_admin. "
            "MySQL/PostgreSQL icin HAZIR EXPLOIT YOKTUR; "
            "bu servislerde israr etmeyin, searchsploit/cve_search ile dogrulayip "
            "finding olarak kaydedin ve DIGER servise gecin."
        )

        return "\n".join(lines)


    # Metasploitable2'de test edilmesi gereken kritik servisler.
    # (port, servis adi, servis-adi anahtar kelimeleri)
    # NOT: Eslesme YALNIZCA gercek eylem alanlarinda yapilir (tool/service_name/
    # exploit/ports); serbest 'thought' metni TARANMAZ (yanlis pozitif onlenir).
    _CRITICAL_SERVICES = [
        # (port, canonical_name, [keyword aliases])
        # Metasploitable2 tam zafiyet haritası (nmap -sV ile doğrulanmış portlar).
        (21, "vsftpd", ["vsftpd", "ftp"]),
        (22, "ssh", ["ssh", "msfadmin"]),
        (23, "telnet", ["telnet"]),
        (25, "smtp", ["smtp", "postfix", "smtpd"]),
        (80, "apache", ["apache", "http", "nikto", "gobuster", "whatweb"]),
        (111, "rpcbind", ["rpcbind", "rpc", "portmapper"]),
        (139, "samba", ["samba", "smb", "netbios"]),
        (445, "samba", ["samba", "smb", "netbios"]),
        (512, "rexec", ["rexec", "exec", "rsh"]),
        (513, "rlogin", ["rlogin", "login"]),
        (514, "rsh", ["rsh", "shell", "tcpwrapped"]),
        (1099, "java-rmi", ["rmi", "java", "rmiregistry"]),
        (1524, "ingreslock", ["ingreslock"]),
        (2121, "proftpd", ["proftpd"]),
        (3306, "mysql", ["mysql"]),
        (3632, "distcc", ["distcc"]),
        (5432, "postgresql", ["postgres", "postgresql"]),
        (5900, "vnc", ["vnc"]),
        (6667, "unrealircd", ["unrealircd", "irc"]),
        (6697, "unrealircd", ["unrealircd", "irc"]),
        (8180, "tomcat", ["tomcat", "catalina"]),
        (8787, "ruby-drb", ["drb", "ruby"]),
        (2049, "nfs", ["nfs"]),
    ]

    # Web uygulaması dizinleri (port 80 üzerinde). Bunlar da "test edilmiş"
    # sayılmalı; aksi halde model 'done' dediğinde sistem sürekli web
    # uygulamalarını test etmeye zorlar.
    _WEB_APP_PATHS = [
        "/dvwa/", "/mutillidae/", "/phpMyAdmin/", "/tikiwiki/",
        "/twiki/", "/dav/", "/test/", "/doc/",
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
        # Exploit'i olan servisler icin yalnizca GERCEK exploit/privesc denemesi
        # "test edildi" sayilir. searchsploit/cve_search lookup'lari tek basina
        # yeterli DEGILDIR; aksi halde model lookup yapip servisi 'test edilmis'
        # sayar ve gercek istismar hic denenmez.
        exploit_attempted_text_parts = []
        for d in self.decision_chain:
            tool = str(d.get("tool", "")).lower()
            svc = str(d.get("service_name", "")).lower()
            exploit = str(d.get("exploit", "")).lower()
            privesc = str(d.get("privesc", "")).lower()
            ports = str(d.get("ports", ""))
            action_text_parts.append(f"{tool} {svc} {exploit} {privesc}")
            if tool in ("exploit", "privesc"):
                exploit_attempted_text_parts.append(f"{svc} {exploit} {privesc}")
            # Portlari token bazli ayir (substring degil)
            for token in re.split(r"[,\s]+", ports):
                if token.strip().isdigit():
                    tested_ports.add(int(token.strip()))

        action_text = " ".join(action_text_parts)
        exploit_attempted_text = " ".join(exploit_attempted_text_parts)

        # Exploit'i olan servisler: bu servisler icin gercek exploit denemesi sart.
        _EXPLOIT_REQUIRED = {
            "vsftpd": ["vsftpd", "ftp"],
            "ssh": ["ssh", "msfadmin"],
            "samba": ["samba", "smb"],
            "ingreslock": ["ingreslock"],
            "distcc": ["distcc"],
            "unrealircd": ["unrealircd", "irc"],
            "proftpd": ["proftpd"],
            "java-rmi": ["rmi", "java"],
            "ruby-drb": ["drb", "ruby"],
            "vnc": ["vnc"],
            "tomcat": ["tomcat"],
        }

        untested = []
        for port, name, keywords in self._CRITICAL_SERVICES:
            # 1. Port tam eslesme ile test edildi mi?
            if port in tested_ports:
                continue
            # 2. Exploit'i olan bir servis mi? Oyleyse GERCEK exploit denemesi ara.
            if name in _EXPLOIT_REQUIRED:
                if any(kw in exploit_attempted_text for kw in keywords):
                    continue
                untested.append(f"{name} (port {port})")
                continue
            # 3. Exploit'i olmayan servisler icin herhangi bir eylem yeterli.
            if any(kw in action_text for kw in keywords):
                continue
            untested.append(f"{name} (port {port})")
        return untested

    def get_fallback_action_for_untested(self) -> Optional[Dict[str, Any]]:
        """
        When the model (or orchestrator) prematurely says 'done' while critical
        services remain untested, this method deterministically generates the next
        logical reconnaissance/vulnerability check so the assessment reaches
        full coverage rather than stalling.
        """
        untested = self._untested_services()

        SERVICE_TOOL_REC = {
            "vsftpd": {"tool": "exploit", "exploit": "vsftpd_backdoor", "ports": "21", "service_name": "vsftpd", "rationale": "Test vsftpd 2.3.4 smiley face backdoor (CVE-2011-2523) on port 21."},
            "ssh": {"tool": "exploit", "exploit": "ssh_credential_spray", "ports": "22", "service_name": "ssh", "rationale": "Spray default credentials on SSH port 22."},
            "samba": {"tool": "exploit", "exploit": "samba_usermap", "ports": "445", "service_name": "samba", "rationale": "Test Samba 3.0.20 usermap script RCE (CVE-2007-2447)."},
            "ingreslock": {"tool": "exploit", "exploit": "ingreslock_backdoor", "ports": "1524", "service_name": "ingreslock", "rationale": "Connect to Ingreslock backdoor on port 1524."},
            "mysql": {"tool": "searchsploit", "service_name": "mysql", "version": "5.0", "rationale": "Enumerate MySQL 5.0 vulnerabilities (CVE-2012-2122 / UDF privesc)."},
            "postgresql": {"tool": "searchsploit", "service_name": "postgresql", "version": "8.3", "rationale": "Enumerate PostgreSQL 8.3 known vulnerabilities."},
            "distcc": {"tool": "exploit", "exploit": "distcc_exec", "ports": "3632", "service_name": "distcc", "rationale": "Test distcc daemon code execution (CVE-2004-2687) on port 3632."},
            "telnet": {"tool": "nmap", "ports": "23", "rationale": "Banner grab and check unauthenticated access on Telnet port 23."},
            "nfs": {"tool": "nmap", "ports": "2049", "rationale": "Check exported NFS shares and permissions."},
            "vnc": {"tool": "exploit", "exploit": "vnc_null_auth", "ports": "5900", "service_name": "vnc", "rationale": "Test VNC null/weak authentication bypass on port 5900."},
            "java-rmi": {"tool": "exploit", "exploit": "java_rmi_deserialize", "ports": "1099", "service_name": "java-rmi", "rationale": "Test Java RMI registry deserialization RCE on port 1099."},
            "proftpd": {"tool": "exploit", "exploit": "proftpd_modcopy", "ports": "2121", "service_name": "proftpd", "rationale": "Test ProFTPD 1.3.1 mod_copy unauthenticated file copy (CVE-2015-3306)."},
            "unrealircd": {"tool": "exploit", "exploit": "unrealircd_backdoor", "ports": "6667", "service_name": "unrealircd", "rationale": "Test UnrealIRCd 3.2.8.1 backdoor trigger (CVE-2010-2075) on port 6667."},
            "smtp": {"tool": "searchsploit", "service_name": "postfix", "version": None, "rationale": "Enumerate Postfix SMTP vulnerabilities and check for open relay."},
            "rpcbind": {"tool": "nmap", "ports": "111", "rationale": "Enumerate RPC services via rpcinfo/portmapper on port 111."},
            "rexec": {"tool": "searchsploit", "service_name": "rsh", "version": None, "rationale": "Check rexec/rsh unauthenticated remote execution on port 512."},
            "rlogin": {"tool": "searchsploit", "service_name": "rlogin", "version": None, "rationale": "Check rlogin trust-based authentication bypass on port 513."},
            "rsh": {"tool": "searchsploit", "service_name": "rsh", "version": None, "rationale": "Check rsh trust-based authentication bypass on port 514."},
            "tomcat": {"tool": "exploit", "exploit": "tomcat_manager_deploy", "ports": "8180", "service_name": "tomcat", "rationale": "Test Apache Tomcat manager default credentials and WAR deployment on port 8180."},
            "ruby-drb": {"tool": "exploit", "exploit": "ruby_drb_rce", "ports": "8787", "service_name": "ruby-drb", "rationale": "Test Ruby DRb remote code execution on port 8787."},
            "apache": {"tool": "nikto", "ports": "80", "service_name": "apache", "rationale": "Run nikto web vulnerability scan against Apache 2.2.8 on port 80."},
        }

        if untested:
            for u in untested:
                svc_clean = u.split("(")[0].strip().lower()
                rec = SERVICE_TOOL_REC.get(svc_clean)
                if rec:
                    _svc_for_key = rec.get("exploit") or rec.get("service_name")
                    action_key = self._action_key(rec["tool"], self.target, rec.get("ports"), _svc_for_key, rec.get("version"))
                    if action_key not in self.visited_actions:
                        return {
                            "thought": f"Comprehensive testing: {svc_clean} has not been assessed yet. Executing security verification.",
                            "tool": rec["tool"],
                            "target": self.target,
                            "param": None,
                            "ports": rec.get("ports"),
                            "service_name": rec.get("service_name"),
                            "version": rec.get("version"),
                            "exploit": rec.get("exploit"),
                            "rationale": rec["rationale"],
                            "finding": None
                        }

            first_untested = untested[0].split("(")[0].strip().lower()
            return {
                "thought": f"Comprehensive testing: {first_untested} has not been assessed yet. Checking service vulnerability database.",
                "tool": "searchsploit",
                "target": self.target,
                "param": None,
                "ports": None,
                "service_name": first_untested,
                "version": None,
                "rationale": f"Identify vulnerabilities for {first_untested}.",
                "finding": None
            }

        # ── Kapsamdaki tüm servisler test edildiyse: Denenmemiş exploit veya privesc tekniklerini tamamla ──
        if "metasploitable" in self.target.lower():
            metasploitable_exploits = [
                ("vsftpd_backdoor", "vsftpd 2.3.4 Backdoor (CVE-2011-2523)", "21"),
                ("samba_usermap", "Samba 3.0.20 Usermap RCE (CVE-2007-2447)", "445"),
                ("ingreslock_backdoor", "Ingreslock port 1524 backdoor", "1524"),
                ("ssh_credential_spray", "SSH default credential spray", "22"),
                ("distcc_exec", "distcc daemon code execution (CVE-2004-2687)", "3632"),
                ("unrealircd_backdoor", "UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075)", "6667"),
                ("proftpd_modcopy", "ProFTPD 1.3.1 mod_copy unauthenticated file copy (CVE-2015-3306)", "2121"),
                ("java_rmi_deserialize", "Java RMI registry deserialization RCE", "1099"),
                ("tomcat_manager_deploy", "Apache Tomcat manager default credentials WAR deploy", "8180"),
                ("ruby_drb_rce", "Ruby DRb remote code execution", "8787"),
                ("vnc_null_auth", "VNC null authentication bypass", "5900"),
            ]
            for exp_name, exp_desc, port_str in metasploitable_exploits:
                exp_key = self._action_key("exploit", self.target, port_str, exp_name, None)
                exp_key_noport = self._action_key("exploit", self.target, None, exp_name, None)
                if (exp_key not in self.visited_actions and 
                    exp_key_noport not in self.visited_actions and 
                    exp_name not in self._failed_exploits):
                    return {
                        "thought": f"Exhaustive testing: Attempting exploit '{exp_name}' against target.",
                        "tool": "exploit",
                        "target": self.target,
                        "ports": port_str,
                        "exploit": exp_name,
                        "rationale": f"Attempt exploitation of {exp_desc}.",
                        "finding": None
                    }

            # Foothold veya root varsa post-exploitation ve yetki yükseltme denetimleri
            if self._exploit_succeeded or self._credentials:
                privesc_checks = [
                    ("verify_root", "Verify Root Access (Proof of Privilege)"),
                    ("sudoers_audit", "Audit sudoers permissions (sudo -l)"),
                    ("suid_enumeration", "Scan filesystem for misconfigured SUID binaries"),
                ]
                for p_tech, p_desc in privesc_checks:
                    p_key = self._action_key("privesc", self.target, None, p_tech, None)
                    if p_key not in self.visited_actions:
                        return {
                            "thought": f"Post-exploitation verification: Executing {p_desc}.",
                            "tool": "privesc",
                            "target": self.target,
                            "privesc": p_tech,
                            "username": "msfadmin",
                            "password": "msfadmin",
                            "rationale": f"Perform {p_desc}.",
                            "finding": None
                        }

        return None

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
                    e for e in [
                        "ingreslock_backdoor", "ssh_credential_spray",
                        "vsftpd_backdoor", "samba_usermap", "distcc_exec",
                        "unrealircd_backdoor", "proftpd_modcopy",
                        "java_rmi_deserialize", "ruby_drb_rce",
                        "vnc_null_auth", "tomcat_manager_deploy",
                    ]
                    if e not in self._failed_exploits
                ]
                untried_str = ", ".join(untried) if untried else "none remaining"
                # Henuz test edilmemis servisleri de acikca bildir; model boylece
                # ayni servise takilmak yerine yeni hedefe yonelir.
                untested_svcs = self._untested_services()
                untested_str = ", ".join(untested_svcs[:6]) if untested_svcs else "none remaining"
                msg = (
                    f"Exploit '{exploit_name or tool}' result: SUCCESS=False. "
                    f"The exploit was attempted but uid=0 was NOT confirmed. "
                    f"Do NOT claim success. Do NOT retry this same exploit.\n"
                    f"Output:\n{output[:1200]}\n\n"
                    f"Failed exploits so far: {sorted(self._failed_exploits) or 'none yet'}.\n"
                    f"Untried exploits available: {untried_str}.\n"
                    f"Untested services remaining: {untested_str}.\n"
                    f"IMMEDIATELY try the next untried exploit or move to a different service. "
                    f"NEVER propose an exploit that is in the 'Failed exploits' list."
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

        # ── ISTIHBARAT vs BULGU (KRITIK) ─────────────────────────────────────
        # searchsploit/cve_search/web_search ciktilari yalnizca ARAMA SONUCUDUR;
        # hedefte o servisin/zafiyetin GERCEKTEN var oldugunun kaniti DEGILDIR.
        # Ornegin searchsploit 'vnc' aramasi RealVNC basliklari dondurur ama
        # hedefte VNC acik olmayabilir. Bu yuzden bu araclarin ciktilarindan
        # otomatik bulgu CIKARILMAZ. Gercek bulgu icin nmap/whatweb/nikto gibi
        # kesif araclarinin ciktisi veya dogrulanmis exploit kaniti gerekir.
        if tool in ("searchsploit", "cve_search", "web_search"):
            logger.info(f"[Intelligence] '{tool}' ciktisindan otomatik bulgu cikarilmadi (lookup-only).")
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
                "distcc_exec": "Remote Code Execution (CVE-2004-2687)",
                "unrealircd_backdoor": "Backdoor Exploitation (CVE-2010-2075)",
                "proftpd_modcopy": "Unauthenticated File Copy (CVE-2015-3306)",
                "java_rmi_deserialize": "Insecure Java RMI Registry (Deserialization Surface)",
                "ruby_drb_rce": "Remote Code Execution (Ruby DRb)",
                "vnc_null_auth": "VNC Weak/Null Authentication",
                "tomcat_manager_deploy": "Apache Tomcat Manager Default Credentials",
                "juice_shop_admin": "Broken Access Control",
            }
            cwe_map = {
                "vsftpd_backdoor": "CWE-912",
                "samba_usermap": "CWE-78",
                "ingreslock_backdoor": "CWE-912",
                "ssh_credential_spray": "CWE-521",
                "distcc_exec": "CWE-78",
                "unrealircd_backdoor": "CWE-912",
                "proftpd_modcopy": "CWE-22",
                "java_rmi_deserialize": "CWE-502",
                "ruby_drb_rce": "CWE-78",
                "vnc_null_auth": "CWE-287",
                "tomcat_manager_deploy": "CWE-521",
                "juice_shop_admin": "CWE-284",
            }
            # Bazi exploitler yalnizca zafiyet YUZEYINI dogrular (RCE kaniti
            # degil). Bunlar Critical yerine High/Medium olarak kaydedilir ki
            # rapor gercek RCE ile karismasin.
            _surface_only = {
                "java_rmi_deserialize": "High",
                "vnc_null_auth": "High",
                "proftpd_modcopy": "High",
                "tomcat_manager_deploy": "High",
            }
            category = category_map.get(exploit_name, "Active Exploitation")
            cwe = cwe_map.get(exploit_name, "CWE-912")
            severity = _surface_only.get(exploit_name, "Critical")
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
