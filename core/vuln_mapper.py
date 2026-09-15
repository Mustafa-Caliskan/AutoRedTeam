"""
AutoRedTeam - Vulnerability Mapper (Servis -> CVE -> Exploit Eslemesi).

Recon katmanindan gelen servis/versiyon bilgisini alir; searchsploit ve yerel
bilgi tabani ile eslestirir; her zafiyet icin istismar edilebilirlik skoru
hesaplar ve kullanilacak exploit modulunu belirler.

Bu modul LLM'siz calisir (deterministik). Cikti, ExploitPlanner'a girdi olur.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.scope import run_command

logger = logging.getLogger(__name__)

# Yerel CVE -> exploit haritasi (knowledge_base/ altinda)
KB_DIR = Path(__file__).resolve().parent.parent / "knowledge_base"
CVE_EXPLOIT_MAP_FILE = KB_DIR / "cve_exploit_map.json"


# ── Veri Modelleri ──────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    """Tek bir zafiyet kaydi."""
    service: str
    version: str
    port: int
    cves: List[str] = field(default_factory=list)
    exploit_module: Optional[str] = None
    exploitability: float = 0.0  # 0.0 - 1.0
    status: str = "pending"  # pending | attempted | exploited | not_vulnerable
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "version": self.version,
            "port": self.port,
            "cves": self.cves,
            "exploit_module": self.exploit_module,
            "exploitability": self.exploitability,
            "status": self.status,
            "evidence": self.evidence,
        }


# ── Yerel Bilgi Tabani ──────────────────────────────────────────────────────

# Metasploitable2 icin bilinen servis -> exploit eslemesi.
# Bu, "ezber" DEGIL; hizli baslangic noktasi. Bilinmeyen servisler icin
# searchsploit dinamik olarak kullanilir.
KNOWN_SERVICE_EXPLOITS: Dict[str, Dict[str, Any]] = {
    "vsftpd": {
        "versions": ["2.3.4"],
        "cves": ["CVE-2011-2523"],
        "exploit_module": "vsftpd_backdoor",
        "base_score": 0.95,
    },
    "samba": {
        "versions": ["3.0.20"],
        "cves": ["CVE-2007-2447"],
        "exploit_module": "samba_usermap",
        "base_score": 0.90,
    },
    "smbd": {
        "versions": ["3.0.20"],
        "cves": ["CVE-2007-2447"],
        "exploit_module": "samba_usermap",
        "base_score": 0.90,
    },
    "distccd": {
        "versions": ["1"],
        "cves": ["CVE-2004-2687"],
        "exploit_module": "distcc_exec",
        "base_score": 0.85,
    },
    "distcc": {
        "versions": ["1"],
        "cves": ["CVE-2004-2687"],
        "exploit_module": "distcc_exec",
        "base_score": 0.85,
    },
    "unrealircd": {
        "versions": ["3.2.8.1"],
        "cves": ["CVE-2010-2075"],
        "exploit_module": "unrealircd_backdoor",
        "base_score": 0.90,
    },
    "irc": {
        "versions": ["3.2.8.1"],
        "cves": ["CVE-2010-2075"],
        "exploit_module": "unrealircd_backdoor",
        "base_score": 0.85,
    },
    "proftpd": {
        "versions": ["1.3.1"],
        "cves": ["CVE-2015-3306"],
        "exploit_module": "proftpd_modcopy",
        "base_score": 0.60,
    },
    "mysql": {
        "versions": ["5.0.51a"],
        "cves": ["CVE-2012-2122"],
        "exploit_module": None,  # credential_engine ile denenir
        "base_score": 0.80,
    },
    "postgresql": {
        "versions": ["8.3"],
        "cves": [],
        "exploit_module": None,
        "base_score": 0.50,
    },
    "tomcat": {
        "versions": [],
        "cves": [],
        "exploit_module": "tomcat_manager_deploy",
        "base_score": 0.70,
    },
    "drb": {
        "versions": [],
        "cves": [],
        "exploit_module": "ruby_drb_rce",
        "base_score": 0.65,
    },
    "java-rmi": {
        "versions": [],
        "cves": [],
        "exploit_module": "java_rmi_deserialize",
        "base_score": 0.55,
    },
    "rmiregistry": {
        "versions": [],
        "cves": [],
        "exploit_module": "java_rmi_deserialize",
        "base_score": 0.55,
    },
    "vnc": {
        "versions": [],
        "cves": [],
        "exploit_module": "vnc_null_auth",
        "base_score": 0.60,
    },
    "ssh": {
        "versions": [],
        "cves": [],
        "exploit_module": "ssh_credential_spray",
        "base_score": 0.80,
    },
    "telnet": {
        "versions": [],
        "cves": [],
        "exploit_module": "telnet_default_creds",
        "base_score": 0.80,
    },
    "ftp": {
        "versions": [],
        "cves": [],
        "exploit_module": "credential_spray",
        "base_score": 0.55,
    },
    "ingreslock": {
        "versions": [],
        "cves": [],
        "exploit_module": "ingreslock_backdoor",
        "base_score": 0.95,
    },
    "netbios-ssn": {
        "versions": [],
        "cves": [],
        "exploit_module": "samba_usermap",
        "base_score": 0.85,
    },
    "microsoft-ds": {
        "versions": [],
        "cves": [],
        "exploit_module": "samba_usermap",
        "base_score": 0.85,
    },
}


# ── Ana Sinif ───────────────────────────────────────────────────────────────

class VulnerabilityMapper:
    """
    Servis/versiyon -> CVE -> exploit eslemesi yapar ve skorlar.
    """

    def __init__(self, kb_file: Optional[Path] = None):
        self.kb_file = kb_file or CVE_EXPLOIT_MAP_FILE
        self._local_kb = self._load_local_kb()

    def _load_local_kb(self) -> Dict[str, Any]:
        """Yerel CVE->exploit haritasini yukler (varsa)."""
        if self.kb_file.exists():
            try:
                with open(self.kb_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"[VulnMapper] KB yuklenemedi: {e}")
        return {}

    def map_service(
        self,
        service: str,
        version: str = "",
        port: int = 0,
    ) -> List[Vulnerability]:
        """
        Bir servisi CVE'lerle esler ve Vulnerability listesi dondurur.

        ONEMLI: nmap servis adini genel verir (ornek: 'ftp'), ama gercek urun
        versiyon alanindadir (ornek: 'vsftpd 2.3.4'). Bu yuzden esleme hem
        servis adi hem de versiyon metni uzerinden yapilir.
        """
        service_lower = service.lower().strip()
        version_lower = (version or "").lower()
        vulns: List[Vulnerability] = []

        # 1. Yerel bilgi tabanindan bak (servis adi VEYA versiyon metni ile)
        known_key = self._match_known_service(service_lower, version_lower)
        if known_key:
            known = KNOWN_SERVICE_EXPLOITS[known_key]
            vulns.append(Vulnerability(
                service=service,
                version=version,
                port=port,
                cves=list(known.get("cves", [])),
                exploit_module=known.get("exploit_module"),
                exploitability=known.get("base_score", 0.5),
            ))

        # 2. searchsploit ile dinamik arama (yalnizca bilinen esleme YOKSA)
        #    Aksi halde her servis icin onlarca gurultulu kayit uretilir.
        #    Web servisleri (http/apache/ssl) haric tutulur; onlar web exploit
        #    motoru ile ayrica ele alinir ve searchsploit'te yuzlerce gurultulu
        #    kayit uretirler.
        _WEB_SERVICES = {"http", "https", "http-proxy", "ssl", "http-alt", "apache"}
        if not known_key and service_lower not in _WEB_SERVICES:
            dynamic = self._searchsploit(service, version)
            seen_cves = set()
            for d in dynamic[:10]:  # gurultuyu sinirla: en fazla 10 kayit
                cve = d.get("cve")
                if cve and cve in seen_cves:
                    continue
                if cve:
                    seen_cves.add(cve)
                vulns.append(Vulnerability(
                    service=service,
                    version=version,
                    port=port,
                    cves=[cve] if cve else [],
                    exploit_module=None,
                    exploitability=0.4,
                    evidence=d.get("title", ""),
                ))

        # 3. Skorlari hesapla
        for v in vulns:
            v.exploitability = self.score_exploitability(v)

        return vulns

    def _match_known_service(self, service_lower: str, version_lower: str) -> Optional[str]:
        """
        Servis adi veya versiyon metninden bilinen servis anahtarini bulur.

        ONEMLI: Versiyon metni ONCE kontrol edilir. Cunku nmap servis adini
        genel verir ('ftp'), ama gercek urun versiyondadir ('vsftpd 2.3.4').
        Ornek: service='ftp', version='vsftpd 2.3.4' -> 'vsftpd'

        nmap bazen servis adina '?' ekler (ornek: 'ingreslock?'). Bu yuzden
        temizlik + substring eslesmesi de yapilir.
        """
        # Servis adini temizle: '?' ve bosluklari kaldir
        svc_clean = service_lower.replace("?", "").strip()

        # 1. Versiyon metninde bilinen urun adi ara (en uzun eslesme once)
        for key in sorted(KNOWN_SERVICE_EXPLOITS, key=len, reverse=True):
            if key in version_lower:
                return key
        # 2. Dogrudan servis adi eslesmesi (temizlenmis)
        if svc_clean in KNOWN_SERVICE_EXPLOITS:
            return svc_clean
        # 3. Servis adi bilinen bir anahtari iceriyor mu? (en uzun once)
        for key in sorted(KNOWN_SERVICE_EXPLOITS, key=len, reverse=True):
            if key in svc_clean:
                return key
        return None

    def _searchsploit(self, service: str, version: str) -> List[Dict[str, Any]]:
        """searchsploit ile dinamik arama yapar (JSON cikti)."""
        query = f"{service} {version}".strip()
        if not query:
            return []
        try:
            output = run_command(f"searchsploit --json {query}", timeout=60)
            data = json.loads(output)
            results = []
            for item in data.get("RESULTS_EXPLOIT", []):
                title = item.get("Title", "")
                cve_match = re.search(r"CVE-\d{4}-\d+", title)
                results.append({
                    "title": title,
                    "cve": cve_match.group(0) if cve_match else None,
                    "path": item.get("Path", ""),
                })
            return results
        except Exception as e:
            logger.debug(f"[VulnMapper] searchsploit hatasi: {e}")
            return []

    def score_exploitability(self, vuln: Vulnerability) -> float:
        """
        Istismar edilebilirlik skoru hesaplar (0.0 - 1.0).

        Faktorler:
          - Exploit modulu var mi? (+0.4)
          - CVE var mi? (+0.3)
          - Bilinen servis mi? (+0.2)
          - Versiyon eslesiyor mu? (+0.1)
        """
        score = 0.0
        if vuln.exploit_module:
            score += 0.4
        if vuln.cves:
            score += 0.3
        if vuln.service.lower() in KNOWN_SERVICE_EXPLOITS:
            score += 0.2
        known = KNOWN_SERVICE_EXPLOITS.get(vuln.service.lower(), {})
        if vuln.version and any(v in vuln.version for v in known.get("versions", [])):
            score += 0.1
        return min(1.0, score)

    def map_all(self, services: List[Any]) -> List[Vulnerability]:
        """
        Recon sonucundaki tum servisleri esler.

        Args:
            services: ServiceInfo listesi (recon_engine'den) veya dict listesi.
        """
        all_vulns: List[Vulnerability] = []
        for svc in services:
            if hasattr(svc, "service"):
                name, ver, port = svc.service, svc.version, svc.port
            else:
                name = svc.get("service", "")
                ver = svc.get("version", "")
                port = svc.get("port", 0)
            all_vulns.extend(self.map_service(name, ver, port))
        return all_vulns


# Modul seviyesinde tekil ornek
vuln_mapper = VulnerabilityMapper()
