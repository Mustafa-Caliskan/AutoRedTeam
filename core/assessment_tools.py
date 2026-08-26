"""
AutoRedTeam - Security Assessment Assistant: Tool Wrappers.

Defensive security tooling for AUTHORIZED vulnerability assessment on
locally-hosted, intentionally-vulnerable training targets (OWASP Juice Shop).

DESIGN PRINCIPLE (HUMAN-IN-THE-LOOP):
  - These functions NEVER execute anything on their own.
  - Each returns a *recommendation* (command + rationale) for the human
    operator to review and approve via input().
  - No command is ever run without explicit human approval.
  - Every target is validated against config/allowed_targets.txt via
    is_target_allowed(); anything out of scope is rejected at the code
    level and logged as REJECTED_OUT_OF_SCOPE.
"""

import json
import logging
import os
import shlex
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ALLOWED_TARGETS_FILE = Path(__file__).parent.parent / "config" / "allowed_targets.txt"
AUDIT_LOG_FILE = Path(__file__).parent.parent / "data" / "assessment_audit_log.jsonl"

# Docker tools container name (see docker/docker-compose.yml)
TOOLS_CONTAINER = os.environ.get("ASSESSMENT_TOOLS_CONTAINER", "autoredteam-assessment-tools")

# Target alias → Docker service name mapping.
# When tools run inside the assessment-net Docker network, these aliases
# resolve to the corresponding container service names. Each entry maps a
# user-facing target alias to the actual Docker service name.
# NOTE: 127.0.0.1 is intentionally NOT mapped here — it is ambiguous across
# multiple target environments. Use the explicit service aliases instead.
TARGET_SERVICE_MAP = {
    "localhost:3000": os.environ.get("JUICE_SHOP_SERVICE", "juice-shop"),
    "localhost": os.environ.get("JUICE_SHOP_SERVICE", "juice-shop"),
    "metasploitable2": os.environ.get("METASPLOITABLE2_SERVICE", "metasploitable2"),
}


# ── Scope Validation ─────────────────────────────────────────────────────────

def load_allowed_targets() -> List[str]:
    """Loads the allow-listed targets from config/allowed_targets.txt."""
    targets: List[str] = []
    if ALLOWED_TARGETS_FILE.exists():
        try:
            with open(ALLOWED_TARGETS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except Exception as e:
            logger.error(f"Could not read allowed targets file: {e}")
    return targets


def is_target_allowed(target: str) -> bool:
    """
    Code-level scope validation. Returns True only if the target is
    explicitly allow-listed in config/allowed_targets.txt.
    """
    allowed = load_allowed_targets()
    normalized = target.strip().lower()
    if normalized in allowed:
        return True
    # Allow a bare hostname/port match (e.g. "localhost:3000" vs "localhost")
    for entry in allowed:
        if normalized == entry:
            return True
    return False


def _log_audit(entry: Dict[str, Any]) -> None:
    """Appends an audit record to data/assessment_audit_log.jsonl."""
    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"Could not write audit log: {e}")


def _reject_out_of_scope(target: str, tool: str) -> Dict[str, Any]:
    """Records a rejected out-of-scope attempt and returns a safe result."""
    _log_audit({
        "event": "REJECTED_OUT_OF_SCOPE",
        "tool": tool,
        "target": target,
        "timestamp": datetime.now().isoformat()
    })
    return {
        "status": "REJECTED_OUT_OF_SCOPE",
        "tool": tool,
        "target": target,
        "message": (
            f"Target '{target}' is not in the allow-list "
            f"({ALLOWED_TARGETS_FILE}). Command was blocked before execution."
        )
    }


def _build_recommendation(
    tool: str,
    target: str,
    command: str,
    rationale: str,
    approved: bool,
    output: str = "",
    note: str = ""
) -> Dict[str, Any]:
    """Builds a structured recommendation result."""
    return {
        "status": "APPROVED" if approved else "SKIPPED",
        "tool": tool,
        "target": target,
        "command": command,
        "rationale": rationale,
        "approved": approved,
        "output": output,
        "note": note,
        "timestamp": datetime.now().isoformat()
    }


def _docker_container_available() -> bool:
    """Checks whether the assessment-tools Docker container is running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", TOOLS_CONTAINER],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except Exception as e:
        logger.warning(f"Docker container check failed: {e}")
        return False


def _resolve_host(target: str) -> str:
    """
    Resolves a target to a bare hostname for execution inside the tools
    container. When tools run inside Docker, target aliases (e.g.
    'localhost:3000', 'metasploitable2') map to their Docker service names
    on the shared network. Host execution keeps the original hostname.
    """
    if _docker_container_available():
        # Exact alias match (e.g. "localhost:3000", "metasploitable2")
        normalized = target.strip().lower()
        if normalized in TARGET_SERVICE_MAP:
            return TARGET_SERVICE_MAP[normalized]
        # Match alias without port (e.g. "localhost" → juice-shop)
        host_only = normalized.split("://")[-1].split(":")[0]
        if host_only in TARGET_SERVICE_MAP:
            return TARGET_SERVICE_MAP[host_only]
    # Strip any scheme and port for a bare hostname
    host = target.split("://")[-1].split(":")[0]
    return host


def _resolve_port(target: str) -> str:
    """
    Extracts the port from a target. Defaults to 3000 for localhost/juice-shop
    and 80 for bare service names (e.g. metasploitable2's web server).
    """
    if ":" in target.split("://")[-1]:
        return target.split("://")[-1].split(":")[1]
    # Bare service name without port
    if target.strip().lower() in ("localhost", "127.0.0.1"):
        return "3000"
    return "80"


def _resolve_url(target: str) -> str:
    """
    Resolves a target to a full URL for web tools (gobuster, nikto, whatweb,
    sqlmap). Inside Docker, target aliases map to their service names.
    """
    host = _resolve_host(target)
    port = _resolve_port(target)
    return f"http://{host}:{port}"


def _run_command(command: str) -> str:
    """
    Executes a command and captures its output.
    Only called AFTER human approval and scope validation.
    If the assessment-tools Docker container is available, the command is
    executed inside it via 'docker exec' so the tools are guaranteed present.
    """
    try:
        if _docker_container_available():
            # Run inside the tools container (tools guaranteed installed)
            args = ["docker", "exec", TOOLS_CONTAINER] + shlex.split(command)
        else:
            # Fallback: run directly on the host (tools may not be installed)
            args = shlex.split(command)

        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=180,
            shell=False
        )
        combined = (result.stdout or "") + (result.stderr or "")
        return combined.strip() or "(no output)"
    except FileNotFoundError as e:
        return f"[TOOL NOT INSTALLED / DOCKER NOT AVAILABLE]: {e}"
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]: Command exceeded 180s and was terminated."
    except Exception as e:
        return f"[ERROR]: {e}"


# ── Safe Tool Wrappers (each returns a recommendation) ───────────────────────

def suggest_nmap_scan(target: str, approved: bool = False, ports: Optional[str] = None) -> Dict[str, Any]:
    """
    Recommends a non-destructive port/service discovery scan.
    Uses only standard flags (-sV -sC). Aggressive flags (-A) and aggressive
    timing are intentionally NOT offered.
    If `ports` is provided (e.g. "21,22,80"), only those ports are scanned.
    """
    if not is_target_allowed(target):
        return _reject_out_of_scope(target, "nmap")

    exec_host = _resolve_host(target)
    if ports:
        exec_port = ports
    else:
        exec_port = _resolve_port(target)
    command = f"nmap -sV -sC {exec_host} -p {exec_port}"
    rationale = (
        "Port ve servis keşfi: hedefte açık portları ve çalışan servis "
        "versiyonlarını tespit eder. Yalnızca standart, non-destructive "
        "flag'ler kullanılır (-sV -sC); agresif tarama önerilmez."
    )
    if ports:
        rationale += f" Belirtilen portlar taranır: {ports}."
    output = _run_command(command) if approved else ""
    return _build_recommendation(
        tool="nmap", target=target, command=command,
        rationale=rationale, approved=approved, output=output
    )


def suggest_gobuster_scan(target_url: str, approved: bool = False) -> Dict[str, Any]:
    """
    Recommends a directory/endpoint discovery scan against a web target.
    Uses a small, common wordlist. Non-destructive GET-based discovery.
    """
    if not is_target_allowed(target_url):
        return _reject_out_of_scope(target_url, "gobuster")

    exec_url = _resolve_url(target_url)
    command = f"gobuster dir -u {exec_url} -w /usr/share/wordlists/dirb/common.txt -t 20"
    rationale = (
        "Dizin/endpoint keşfi: web uygulamasındaki gizli dizinleri ve "
        "uç noktaları ortaya çıkarır. Yalnızca GET tabanlı, non-destructive "
        "keşif yapar."
    )
    output = _run_command(command) if approved else ""
    return _build_recommendation(
        tool="gobuster", target=target_url, command=command,
        rationale=rationale, approved=approved, output=output
    )


def suggest_nikto_scan(target_url: str, approved: bool = False) -> Dict[str, Any]:
    """
    Recommends a web server configuration vulnerability scan.
    Nikto is a passive web scanner; no aggressive payloads are sent.
    """
    if not is_target_allowed(target_url):
        return _reject_out_of_scope(target_url, "nikto")

    exec_url = _resolve_url(target_url)
    command = f"nikto -h {exec_url} -nointeractive -maxtime 60"
    rationale = (
        "Web sunucu konfigürasyon zafiyeti taraması: bilinen güvenlik "
        "açıklarını, hatalı yapılandırmaları ve tehlikeli dosyaları tespit "
        "eder. Pasif bir tarayıcıdır, agresif payload göndermez."
    )
    output = _run_command(command) if approved else ""
    return _build_recommendation(
        tool="nikto", target=target_url, command=command,
        rationale=rationale, approved=approved, output=output
    )


def suggest_whatweb_scan(target_url: str, approved: bool = False) -> Dict[str, Any]:
    """
    Recommends a technology stack fingerprinting scan.
    Identifies frameworks, servers, and libraries in use.
    """
    if not is_target_allowed(target_url):
        return _reject_out_of_scope(target_url, "whatweb")

    exec_url = _resolve_url(target_url)
    command = f"whatweb {exec_url}"
    rationale = (
        "Teknoloji yığını tespiti: web uygulamasının kullandığı framework, "
        "sunucu ve kütüphane sürümlerini belirler. Tamamen pasif bir "
        "fingerprinting aracıdır."
    )
    output = _run_command(command) if approved else ""
    return _build_recommendation(
        tool="whatweb", target=target_url, command=command,
        rationale=rationale, approved=approved, output=output
    )


def suggest_ssl_check(target: str, approved: bool = False) -> Dict[str, Any]:
    """
    Recommends a TLS/SSL configuration check using testssl.sh or sslyze.
    Verifies certificate validity, protocol support, and cipher strength.
    """
    if not is_target_allowed(target):
        return _reject_out_of_scope(target, "ssl_check")

    exec_host = _resolve_host(target)
    exec_port = _resolve_port(target)
    command = f"testssl.sh {exec_host}:{exec_port}"
    rationale = (
        "TLS/SSL konfigürasyon kontrolü: sertifika geçerliliği, protokol "
        "desteği ve şifre (cipher) gücünü doğrular. Salt okunur bir "
        "denetimdir, hedefe zarar vermez."
    )
    output = _run_command(command) if approved else ""
    return _build_recommendation(
        tool="ssl_check", target=target, command=command,
        rationale=rationale, approved=approved, output=output
    )


def suggest_sqlmap_check(target_url: str, param: str, approved: bool = False) -> Dict[str, Any]:
    """
    Recommends a SQL injection DETECTION-ONLY check.
    IMPORTANT: This runs in detection mode ONLY (--batch --level=1 --risk=1).
    NO data extraction, NO dump, NO exploitation flags are ever used.
    The purpose is solely to determine whether a parameter is injectable.
    """
    if not is_target_allowed(target_url):
        return _reject_out_of_scope(target_url, "sqlmap")

    exec_url = _resolve_url(target_url)
    command = (
        f"sqlmap -u \"{exec_url}\" -p {param} "
        f"--batch --level=1 --risk=1"
    )
    rationale = (
        "SQL Injection TESPİT MODU (yalnızca tespit): '{param}' parametresinin "
        "enjekte edilebilir olup olmadığını kontrol eder. "
        "YALNIZCA --batch --level=1 --risk=1 kullanılır. "
        "Veri çekme (dump), exploit veya veritabanı değiştirme işlemi "
        "KESİNLİKLE yapılmaz."
    )
    output = _run_command(command) if approved else ""
    return _build_recommendation(
        tool="sqlmap", target=target_url, command=command,
        rationale=rationale, approved=approved, output=output,
        note="DETECTION-ONLY: hiçbir veri çekme/dump işlemi yapılmaz."
    )


def suggest_searchsploit_lookup(service_name: str, version: str = "", approved: bool = False) -> Dict[str, Any]:
    """
    Recommends a searchsploit (Exploit-DB offline) lookup for a detected
    service/version. This LISTS known CVE/exploit records — it does NOT
    run or execute any exploit. It only reports "these known vulnerabilities
    exist for this version".
    """
    # searchsploit is a local lookup tool; no target scope validation needed,
    # but we still require human approval before running.
    query = f"{service_name} {version}".strip()
    command = f"searchsploit {query}"
    rationale = (
        f"Bilinen zafiyet araması: '{query}' için Exploit-DB'de kayıtlı "
        "CVE/exploit kayıtlarını listeler. YALNIZCA bilgi amaçlıdır — "
        "hiçbir exploit ÇALIŞTIRMAZ, yalnızca 'bu versiyon için bilinen "
        "şu zafiyetler var' bilgisini getirir."
    )
    output = _run_command(command) if approved else ""
    return _build_recommendation(
        tool="searchsploit", target=service_name, command=command,
        rationale=rationale, approved=approved, output=output,
        note="LOOKUP-ONLY: exploit çalıştırmaz, yalnızca bilinen zafiyetleri listeler."
    )


def suggest_cve_search(service_name: str, version: str = "", approved: bool = False) -> Dict[str, Any]:
    """
    Recommends a LIVE CVE lookup via the NVD API for a detected service/version.
    This is a LOOKUP-ONLY tool: it fetches the latest known CVE metadata
    (descriptions, CVSS scores) from the NVD. It NEVER runs or suggests any
    exploit. It gives the model up-to-date CVE info beyond its training cutoff.
    """
    from core.cve_lookup import lookup_cve

    query = f"{service_name} {version}".strip()
    rationale = (
        f"Canlı CVE istihbaratı: '{query}' için NVD veritabanından en güncel "
        "bilinen zafiyet kayıtlarını getirir. YALNIZCA bilgi amaçlıdır — "
        "hiçbir exploit ÇALIŞTIRMAZ; modelin 2024 sonrası güncel CVE'leri "
        "öğrenmesini sağlar."
    )

    if approved:
        result = lookup_cve(service_name, version)
        output = json.dumps(result, ensure_ascii=False, indent=2)
    else:
        output = ""

    return _build_recommendation(
        tool="cve_search", target=service_name, command=f"cve_search {query}",
        rationale=rationale, approved=approved, output=output,
        note="LOOKUP-ONLY: NVD'den canlı CVE bilgisi getirir, exploit çalıştırmaz."
    )


# ── Tool Registry ────────────────────────────────────────────────────────────

ASSESSMENT_TOOLS: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "name": "nmap",
        "description": "Port/servis keşfi (non-destructive, -sV -sC)",
        "function": suggest_nmap_scan,
        "params": ["target"]
    },
    "gobuster": {
        "name": "gobuster",
        "description": "Dizin/endpoint keşfi",
        "function": suggest_gobuster_scan,
        "params": ["target_url"]
    },
    "nikto": {
        "name": "nikto",
        "description": "Web sunucu konfigürasyon zafiyeti taraması",
        "function": suggest_nikto_scan,
        "params": ["target_url"]
    },
    "whatweb": {
        "name": "whatweb",
        "description": "Teknoloji yığını tespiti",
        "function": suggest_whatweb_scan,
        "params": ["target_url"]
    },
    "ssl_check": {
        "name": "ssl_check",
        "description": "TLS/SSL konfigürasyon kontrolü",
        "function": suggest_ssl_check,
        "params": ["target"]
    },
    "sqlmap": {
        "name": "sqlmap",
        "description": "SQL Injection tespiti (DETECTION-ONLY, dump/exploit yasak)",
        "function": suggest_sqlmap_check,
        "params": ["target_url", "param"]
    },
    "searchsploit": {
        "name": "searchsploit",
        "description": "Bilinen CVE/exploit kayıtlarını listele (LOOKUP-ONLY, exploit çalıştırmaz)",
        "function": suggest_searchsploit_lookup,
        "params": ["service_name", "version"]
    },
    "cve_search": {
        "name": "cve_search",
        "description": "NVD'den canlı CVE istihbaratı (LOOKUP-ONLY, güncel CVE'ler)",
        "function": suggest_cve_search,
        "params": ["service_name", "version"]
    },
}
