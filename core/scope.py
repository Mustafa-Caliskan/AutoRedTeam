"""
AutoRedTeam - Ortak Kapsam (Scope) ve Docker Yardimci Modulu.

Bu modul, daha once assessment_tools.py, exploit_runner.py ve privesc_engine.py
icinde KOPYALANMIS olan ortak fonksiyonlari tek yerde toplar (DRY):
  - load_allowed_targets / is_target_allowed  (kapsam dogrulama)
  - _log_audit                                (denetim logu)
  - resolve_host                              (hedef alias -> Docker servis adi)
  - docker_container_available                (tools konteyneri kontrolu)
  - run_command                               (docker exec / host komut calistirma)

Tum guvenlik degerlendirme modulleri bu ortak modulu kullanmalidir.
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

# ── Sabitler ────────────────────────────────────────────────────────────────

ALLOWED_TARGETS_FILE = Path(__file__).parent.parent / "config" / "allowed_targets.txt"
AUDIT_LOG_FILE = Path(__file__).parent.parent / "data" / "assessment_audit_log.jsonl"
CONFIG_DIR = Path(__file__).parent.parent / "config"

# Docker tools container name (see docker/docker-compose.yml)
TOOLS_CONTAINER = os.environ.get("ASSESSMENT_TOOLS_CONTAINER", "autoredteam-assessment-tools")

# Hedef alias -> Docker servis adi eslemesi (assessment-net aginda).
# Tools konteyneri hedefe bu servis adiyla erisir.
TARGET_SERVICE_MAP = {
    "localhost:3000": os.environ.get("JUICE_SHOP_SERVICE", "juice-shop"),
    "localhost": os.environ.get("JUICE_SHOP_SERVICE", "juice-shop"),
    "metasploitable2": os.environ.get("METASPLOITABLE2_SERVICE", "metasploitable2"),
}


# ── Kapsam Dogrulama ────────────────────────────────────────────────────────

def load_allowed_targets() -> List[str]:
    """config/allowed_targets.txt icindeki izinli hedefleri yukler."""
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
    Hedefin config/allowed_targets.txt icinde olup olmadigini kod seviyesinde
    dogrular. Yalnizca acikca izin verilen hedefler True doner.

    Ek olarak config/scope.yaml varsa dinamik scope (domain wildcard, IP range)
    da kontrol edilir. Bu, bug bounty programlari icin kullanilir.
    """
    normalized = (target or "").strip().lower()
    allowed = load_allowed_targets()
    if normalized in allowed:
        return True
    # Dinamik scope (varsa)
    scope = load_scope_config()
    if scope:
        return is_target_in_scope(target, scope)
    return False


# ── Dinamik Scope (config/scope.yaml) ───────────────────────────────────────

SCOPE_CONFIG_FILE = CONFIG_DIR / "scope.yaml"


def load_scope_config() -> Optional[Dict[str, Any]]:
    """
    config/scope.yaml dosyasini yukler (varsa). PyYAML yoksa veya dosya yoksa
    None doner (geriye uyumluluk korunur).
    """
    if not SCOPE_CONFIG_FILE.exists():
        return None
    try:
        import yaml  # opsiyonel bagimlilik
        with open(SCOPE_CONFIG_FILE, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        logger.debug("[Scope] PyYAML yok; scope.yaml atlaniyor.")
        return None
    except Exception as e:
        logger.warning(f"[Scope] scope.yaml yuklenemedi: {e}")
        return None


def is_target_in_scope(target: str, scope: Dict[str, Any]) -> bool:
    """
    Domain/IP/wildcard scope kontrolu.

    scope ornegi:
      scope:
        domains: ["*.example.com", "api.example.com"]
        ips: ["10.0.0.0/24"]
        excluded: ["admin.example.com"]
    """
    import fnmatch
    import ipaddress

    normalized = (target or "").strip().lower()
    # Sema/port soy
    host = normalized.split("://")[-1].split(":")[0]

    scope_block = scope.get("scope", scope)

    # Excluded kontrolu (once)
    for ex in scope_block.get("excluded", []) or []:
        if fnmatch.fnmatch(host, str(ex).lower()):
            return False

    # Domain kontrolu
    for domain in scope_block.get("domains", []) or []:
        if fnmatch.fnmatch(host, str(domain).lower()):
            return True

    # IP range kontrolu
    try:
        ip = ipaddress.ip_address(host)
        for net in scope_block.get("ips", []) or []:
            if ip in ipaddress.ip_network(str(net), strict=False):
                return True
    except ValueError:
        pass

    return False


# ── Denetim Logu ────────────────────────────────────────────────────────────

def log_audit(entry: Dict[str, Any]) -> None:
    """Denetim kaydini data/assessment_audit_log.jsonl dosyasina ekler."""
    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"Could not write audit log: {e}")


# ── Hedef Cozumleme ─────────────────────────────────────────────────────────

def resolve_host(target: str) -> str:
    """
    Hedef alias'ini Docker servis adina cevirir (tools konteyneri icin).
    Ornek: 'metasploitable2' -> 'metasploitable2', 'localhost:3000' -> 'juice-shop'.
    """
    normalized = (target or "").strip().lower()
    if normalized in TARGET_SERVICE_MAP:
        return TARGET_SERVICE_MAP[normalized]
    # Sema ve portu soyup bare hostname dondur
    host = target.split("://")[-1].split(":")[0]
    return host


def resolve_port(target: str) -> str:
    """
    Hedefteki portu cikarir. localhost/juice-shop icin 3000, digerleri icin 80.
    """
    if ":" in target.split("://")[-1]:
        return target.split("://")[-1].split(":")[1]
    if (target or "").strip().lower() in ("localhost", "127.0.0.1"):
        return "3000"
    return "80"


def resolve_url(target: str) -> str:
    """Hedefi web araclari icin tam URL'ye cevirir."""
    return f"http://{resolve_host(target)}:{resolve_port(target)}"


# ── Docker / Komut Calistirma ───────────────────────────────────────────────

def docker_container_available() -> bool:
    """autoredteam-assessment-tools konteynerinin calisip calismadigini kontrol eder."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", TOOLS_CONTAINER],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except Exception as e:
        logger.warning(f"Docker container check failed: {e}")
        return False


def run_command(command: str, timeout: int = 60) -> str:
    """
    Komutu calistirir ve ciktisini yakalar.
    Tools konteyneri varsa komut icinde (docker exec) calistirilir; yoksa
    host uzerinde dogrudan denenir. Yalnizca onay sonrasi cagrilmalidir.
    """
    try:
        if docker_container_available():
            args = ["docker", "exec", TOOLS_CONTAINER] + shlex.split(command)
        else:
            args = shlex.split(command)

        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        combined = (result.stdout or "") + (result.stderr or "")
        return combined.strip() or "(no output)"
    except FileNotFoundError as e:
        return f"[TOOL NOT INSTALLED / DOCKER NOT AVAILABLE]: {e}"
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]: Command exceeded timeout and was terminated."
    except Exception as e:
        return f"[ERROR]: {e}"
