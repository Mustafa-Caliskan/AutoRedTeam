"""
AutoRedTeam - Autonomous AI Agent (OODA Loop).

v3.1: AI modelinin tool'lari KENDI secip calistirdigi otonom somuru dongusu.

Mimari (OODA):
  OBSERVE -> mevcut durumu (bulgular, creds, privilege) AI'ye ver
  ORIENT  -> AI durumu yorumlar
  DECIDE  -> AI bir sonraki tool'u secer (JSON)
  ACT     -> tool calistirilir, sonuc baglama geri beslenir

Deterministik cekirdek (v3.0) "temiz baslangic" saglar; AI "derin somuru" yapar.

Guvenlik:
  - Kapsam kontrolu (her adimda is_target_allowed)
  - Tehlikeli komut filtresi
  - Max adim + tekrar tespiti (sonsuz dongu onleme)
  - Audit log
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.scope import is_target_allowed, log_audit

logger = logging.getLogger(__name__)

AUDIT_LOG_FILE = Path(__file__).resolve().parent.parent / "data" / "autonomous_audit.jsonl"


# ── Guvenlik: Tehlikeli Komut Filtresi ──────────────────────────────────────

DANGEROUS_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"mkfs",
    r"dd\s+if=/dev/zero",
    r":\(\)\s*\{",          # fork bomb
    r"shutdown",
    r"reboot",
    r"iptables\s+-F",
    r"halt",
    r"poweroff",
    r">\s*/dev/sda",
]


def is_dangerous_command(command: str) -> bool:
    """Komut tehlikeli mi? (yikici islemleri engelle)"""
    if not command:
        return False
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True
    return False


# ── Veri Modelleri ──────────────────────────────────────────────────────────

@dataclass
class AgentAction:
    """AI'nin sectigi tek bir eylem."""
    thought: str = ""
    tool: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "thought": self.thought,
            "tool": self.tool,
            "params": self.params,
            "rationale": self.rationale,
        }


@dataclass
class AgentContext:
    """
    Ajan baglami: AI'nin karar vermek icin gordugu tum durum.
    """
    target: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    sessions: List[Dict[str, Any]] = field(default_factory=list)
    privilege: str = "none"  # none | user | root
    history: List[Dict[str, Any]] = field(default_factory=list)
    discovered_services: List[Dict[str, Any]] = field(default_factory=list)

    def add_result(self, action: AgentAction, result: Dict[str, Any]) -> None:
        """Bir eylem sonucunu baglama ekle ve durumu guncelle."""
        self.history.append({
            "step": len(self.history) + 1,
            "action": action.to_dict(),
            "result": {
                "success": result.get("success", False),
                "output": str(result.get("output", ""))[:500],
            },
        })

        output = str(result.get("output", ""))

        # Privilege guncelle
        if "uid=0(root)" in output:
            self.privilege = "root"
        elif re.search(r"uid=\d+\((?!root)", output) and self.privilege == "none":
            self.privilege = "user"

        # Credential cikar
        cred = self._extract_credential(output)
        if cred and cred not in self.credentials:
            self.credentials.append(cred)

        # Session (foothold) kaydet
        if result.get("success") and action.tool in ("exploit", "credential_spray"):
            session = {
                "tool": action.tool,
                "params": action.params,
                "privilege": self.privilege,
            }
            if session not in self.sessions:
                self.sessions.append(session)

    def _extract_credential(self, output: str) -> Optional[Dict[str, Any]]:
        """Cikti metninden kimlik bilgisi cikarir."""
        # 'user:pass' formati
        m = re.search(r"([\w.-]+):([\w!@#$%^&*.-]+)\s*(?:is valid|->)", output)
        if m:
            return {"username": m.group(1), "password": m.group(2)}
        # 'Valid credentials: user:pass'
        m = re.search(r"[Vv]alid credentials:\s*([\w.-]+):([\w!@#$%^&*.-]+)", output)
        if m:
            return {"username": m.group(1), "password": m.group(2)}
        return None

    def summary(self) -> str:
        """AI'ye gonderilecek kompakt durum ozeti."""
        lines = [f"Target: {self.target}", f"Privilege: {self.privilege}"]

        if self.credentials:
            creds = ", ".join(f"{c['username']}:{c['password']}" for c in self.credentials[:5])
            lines.append(f"Credentials: {creds}")
        else:
            lines.append("Credentials: (none)")

        if self.findings:
            lines.append(f"Findings ({len(self.findings)}):")
            for f in self.findings[-8:]:
                lines.append(f"  - {f.get('category')} ({f.get('severity')})")
        else:
            lines.append("Findings: (none)")

        if self.history:
            lines.append("Recent actions:")
            for h in self.history[-6:]:
                a = h["action"]
                r = h["result"]
                status = "SUCCESS" if r["success"] else "FAILED"
                lines.append(f"  {h['step']}. {a['tool']} -> {status}")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "privilege": self.privilege,
            "findings": self.findings,
            "credentials": self.credentials,
            "sessions": self.sessions,
            "history": self.history,
        }


# ── AI Prompt ───────────────────────────────────────────────────────────────

AGENT_SYSTEM_PROMPT = """You are an autonomous penetration testing agent operating on an
AUTHORIZED training target (Metasploitable2 in a local Docker lab).

You have these tools available:
- nmap(ports): scan ports/services
- exploit(exploit_name): run a known exploit. Names: vsftpd_backdoor, samba_usermap,
  ingreslock_backdoor, ssh_credential_spray, distcc_exec, unrealircd_backdoor,
  proftpd_modcopy, java_rmi_deserialize, ruby_drb_rce, vnc_null_auth, tomcat_manager_deploy
- privesc(technique): privilege escalation. Techniques: suid_enumeration, sudoers_audit,
  sudo_privesc, gtfobins_privesc, verify_root, linpeas
- credential_spray(service, port): try default credentials
- web_exploit(app): exploit a web application. Apps: dvwa, mutillidae, phpmyadmin,
  tikiwiki, webdav. This auto-logs-in and tests SQLi/XSS/command-injection/upload.
- post_exploit(command): run a shell command on an obtained foothold
- done: finish the assessment

RULES:
1. If you have credentials, USE them (ssh, sudo, mysql, etc.).
2. If you have a foothold, try privilege escalation (sudo -l, SUID, kernel).
3. If you are root, dump credentials (/etc/shadow, config files).
4. Web applications (DVWA, Mutillidae, phpMyAdmin, TikiWiki, WebDAV) are HIGH VALUE:
   use web_exploit(app) to test them. They contain SQLi, XSS, command injection.
5. Do NOT repeat an action that already failed.
6. Be concise and decisive.

Respond with ONLY a JSON object, no explanation, no markdown:
{"thought": "...", "tool": "...", "params": {...}, "rationale": "..."}"""


# ── Ana Sinif ───────────────────────────────────────────────────────────────

class AutonomousAgent:
    """
    AI'nin tool'lari kendi secip calistirdigi otonom somuru dongusu.
    """

    def __init__(
        self,
        target: str,
        llm_client: Any,
        max_steps: int = 20,
        auto_approve: bool = True,
        progress_cb: Optional[Callable] = None,
    ):
        self.target = target
        self.llm = llm_client
        self.max_steps = max_steps
        self.auto_approve = auto_approve
        self.progress_cb = progress_cb
        self.context = AgentContext(target=target)
        self._action_keys: set = set()  # tekrar tespiti

    def _progress(self, stage: str, msg: str) -> None:
        try:
            print(f"   [ai/{stage}] {msg}")
        except UnicodeEncodeError:
            # Windows konsolu bazi karakterleri encode edemez; guvenli yaz.
            print(f"   [ai/{stage}] {msg.encode('ascii', 'replace').decode('ascii')}")
        if self.progress_cb:
            try:
                self.progress_cb(stage, msg)
            except Exception:
                pass

    def _audit(self, entry: Dict[str, Any]) -> None:
        try:
            AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning(f"[Agent] Audit log hatasi: {e}")

    # ── OODA Dongusu ────────────────────────────────────────────────────────

    def run(self, seed_findings: Optional[List[Dict]] = None,
            seed_credentials: Optional[List[Dict]] = None) -> AgentContext:
        """
        Otonom dongu. Deterministik cekirdekten gelen bulgular/creds ile
        baslatilabilir (seed).
        """
        if seed_findings:
            self.context.findings.extend(seed_findings)
        if seed_credentials:
            self.context.credentials.extend(seed_credentials)

        self._progress("start", f"Otonom AI ajanı başladı (max {self.max_steps} adım)")

        for step in range(1, self.max_steps + 1):
            # OBSERVE + ORIENT: baglami olustur
            prompt = self._build_prompt()

            # DECIDE: AI karar verir
            action = self._ask_ai(prompt)
            if action is None:
                self._progress("decide", "AI karar üretemedi; döngü durduruluyor.")
                break

            if action.tool == "done":
                self._progress("done", f"AI bitirdi: {action.thought[:120]}")
                break

            # Tekrar tespiti
            key = self._action_key(action)
            if key in self._action_keys:
                self._progress("stuck", f"Tekrar tespit edildi: {action.tool}; durduruluyor.")
                break
            self._action_keys.add(key)

            self._progress("decide", f"Adım {step}: {action.tool} — {action.thought[:100]}")

            # ACT: tool'u calistir
            result = self._execute(action)

            # Sonucu baglama ekle
            self.context.add_result(action, result)
            status = "OK" if result.get("success") else "FAIL"
            self._progress("act", f"[{status}] {action.tool}: {str(result.get('output', ''))[:120]}")

            # Audit
            self._audit({
                "event": "AGENT_ACTION",
                "step": step,
                "target": self.target,
                "action": action.to_dict(),
                "success": result.get("success", False),
                "timestamp": datetime.now().isoformat(),
            })

        return self.context

    # ── AI Karar ────────────────────────────────────────────────────────────

    def _build_prompt(self) -> str:
        return (
            f"{AGENT_SYSTEM_PROMPT}\n\n"
            f"=== CURRENT STATE ===\n{self.context.summary()}\n"
            f"=== END STATE ===\n\n"
            "IMPORTANT: Do NOT write a thinking process. Do NOT explain. "
            "Output ONLY the JSON object on a single line, starting with { and ending with }.\n"
            "Your JSON:"
        )

    def _ask_ai(self, prompt: str) -> Optional[AgentAction]:
        """AI'den bir sonraki eylemi ister ve JSON'u ayristirir."""
        if self.llm is None:
            return None
        try:
            resp = self.llm.generate(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=900,
                enable_thinking=False,
            )
            if getattr(resp, "error", None):
                logger.warning(f"[Agent] LLM hatasi: {resp.error}")
                return None
            content = resp.content or ""
            action = self._parse_action(content)
            if action is None:
                # Ikinci deneme: daha kisa, JSON-only talimat
                logger.info("[Agent] Ilk parse basarisiz; JSON-only tekrar deneniyor.")
                retry = (
                    "STOP. Output ONLY this JSON object, nothing else, no thinking, no explanation:\n"
                    '{"thought": "short", "tool": "nmap", "params": {"ports": "22"}, "rationale": "short"}'
                )
                resp2 = self.llm.generate(
                    messages=[{"role": "user", "content": retry}],
                    temperature=0.0,
                    max_tokens=200,
                    enable_thinking=False,
                )
                action = self._parse_action(resp2.content or "")
            return action
        except Exception as e:
            logger.warning(f"[Agent] AI cagrisi basarisiz: {e}")
            return None

    def _parse_action(self, content: str) -> Optional[AgentAction]:
        """AI ciktisindan JSON eylemi cikarir (thinking bloklarini atlar)."""
        if not content:
            return None

        # 1. </think> sonrasi nihai cevabi tercih et (CyberStrike 35B formati)
        if "</think>" in content:
            content = content.split("</think>")[-1]

        # 2. Thinking bloklarini temizle
        for marker in ("Thinking Process:", "Here's a thinking process:", "Analysis:"):
            if marker in content:
                content = content.split(marker, 1)[1]

        # 3. Dengeli suslu parantez taramasi ile TUM JSON nesnelerini bul
        candidates = self._extract_json_objects(content)

        # 4. En SON gecerli JSON'u tercih et (model once ornek, sonra gercek yazar)
        for cand in reversed(candidates):
            try:
                data = json.loads(cand)
            except Exception:
                continue
            tool = str(data.get("tool", "")).strip()
            if not tool:
                continue
            return AgentAction(
                thought=str(data.get("thought", "")),
                tool=tool,
                params=data.get("params", {}) or {},
                rationale=str(data.get("rationale", "")),
            )
        return None

    @staticmethod
    def _extract_json_objects(text: str) -> List[str]:
        """
        Metinden dengeli suslu parantezli JSON nesnelerini cikarir.
        Ic ice nesneleri ({"params": {...}}) dogru sekilde yakalar.
        """
        objects = []
        depth = 0
        start = -1
        in_string = False
        escape = False
        for i, ch in enumerate(text):
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start >= 0:
                        objects.append(text[start:i + 1])
                        start = -1
        return objects

    def _action_key(self, action: AgentAction) -> str:
        """Tekrar tespiti icin eylem anahtari."""
        return f"{action.tool}:{json.dumps(action.params, sort_keys=True)}"

    # ── Tool Executor ───────────────────────────────────────────────────────

    def _execute(self, action: AgentAction) -> Dict[str, Any]:
        """AI'nin sectigi tool'u guvenli sekilde calistirir."""
        # 1. Kapsam kontrolu (ZORUNLU)
        if not is_target_allowed(self.target):
            return {"success": False, "output": "[!] Hedef kapsam dışı; engellendi."}

        # 2. Tehlikeli komut filtresi
        cmd = str(action.params.get("command", ""))
        if is_dangerous_command(cmd):
            self._audit({
                "event": "DANGEROUS_COMMAND_BLOCKED",
                "target": self.target,
                "command": cmd,
                "timestamp": datetime.now().isoformat(),
            })
            return {"success": False, "output": "[!] Tehlikeli komut engellendi."}

        # 3. Tool dispatch
        tool = action.tool
        params = action.params
        try:
            if tool == "nmap":
                from core.assessment_tools import suggest_nmap_scan
                return suggest_nmap_scan(self.target, approved=True, ports=params.get("ports"))
            elif tool == "exploit":
                from core.exploit_runner import dispatch_exploit
                return dispatch_exploit(params.get("exploit_name", ""), self.target, approved=True)
            elif tool == "privesc":
                return self._run_privesc(params)
            elif tool == "credential_spray":
                return self._run_credential_spray(params)
            elif tool == "web_exploit":
                return self._run_web_exploit(params)
            elif tool == "post_exploit":
                return self._run_post_exploit(params)
            else:
                return {"success": False, "output": f"[!] Bilinmeyen tool: {tool}"}
        except Exception as e:
            logger.warning(f"[Agent] Tool hatasi ({tool}): {e}")
            return {"success": False, "output": f"[!] Tool hatası: {e}"}

    def _run_privesc(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from core.privesc_engine import dispatch_privesc
        cred = self.context.credentials[0] if self.context.credentials else {}
        return dispatch_privesc(
            technique=params.get("technique", "suid_enumeration"),
            target=self.target,
            username=cred.get("username", "msfadmin"),
            password=cred.get("password", "msfadmin"),
            approved=True,
            command=params.get("command", ""),
        )

    def _run_credential_spray(self, params: Dict[str, Any]) -> Dict[str, Any]:
        service = params.get("service", "ssh")
        port = int(params.get("port", 22))
        # SSH icin exploit_runner'daki dogrulanmis runner'i kullan
        if service == "ssh":
            from core.exploit_runner import dispatch_exploit
            return dispatch_exploit("ssh_credential_spray", self.target, approved=True)
        from core.credential_engine import CredentialEngine
        engine = CredentialEngine(self.target)
        creds = engine.try_default_creds(service, self.target, port)
        if creds:
            c = creds[0]
            return {"success": True,
                    "output": f"Valid credentials: {c.username}:{c.password}",
                    "exploit": "credential_spray"}
        return {"success": False, "output": "[credential_spray] kimlik bulunamadı."}

    def _run_web_exploit(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from core.web_exploit_engine import WebExploitEngine
        engine = WebExploitEngine(self.target, f"http://{self.target}")

        # Yeni format: app adi (dvwa, mutillidae, ...)
        app = params.get("app")
        if app:
            results = engine.run_for_target(app)
            if results:
                # Ilk dogrulanmis bulguyu dondur
                f = results[0]
                return {"success": True,
                        "output": f"[{app}] {f.vuln_type}: {f.evidence[:200]}",
                        "exploit": f"web_{f.vuln_type}"}
            return {"success": False, "output": f"[web] {app}: zafiyet bulunamadı."}

        # Eski format: url + vuln_type
        url = params.get("url", f"http://{self.target}")
        vuln_type = params.get("vuln_type", "sqli")
        method = getattr(engine, f"exploit_{vuln_type}", None)
        if method is None:
            return {"success": False, "output": f"[!] Bilinmeyen web vuln: {vuln_type}"}
        finding = method(url)
        if finding and finding.verified:
            return {"success": True, "output": finding.evidence,
                    "exploit": f"web_{vuln_type}"}
        return {"success": False, "output": f"[web] {vuln_type} bulunamadı."}

    def _run_post_exploit(self, params: Dict[str, Any]) -> Dict[str, Any]:
        from core.post_exploit import PostExploit, Session
        cred = self.context.credentials[0] if self.context.credentials else {}
        session = Session(
            host=self.target,
            user=cred.get("username", "msfadmin"),
            privilege=self.context.privilege,
            method="ssh",
            port=22,
            password=cred.get("password", "msfadmin"),
        )
        pe = PostExploit(session)
        command = params.get("command", "id")
        output = pe._run(command)
        success = bool(output) and "error" not in output.lower()
        return {"success": success, "output": output, "exploit": "post_exploit"}

    def to_dict(self) -> Dict[str, Any]:
        return self.context.to_dict()
