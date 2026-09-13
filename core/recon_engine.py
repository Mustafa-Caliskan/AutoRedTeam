"""
AutoRedTeam - Autonomous Recon Engine (LLM-Free Scanning Layer).

Bu modul, degerlendirmenin ILK ve EN ONEMLI katmanidir: hedef uzerinde
LLM'e hic ihtiyac duymadan, deterministik bir tarama zinciri calistirir ve
TUM zafiyet yuzeyini ortaya cikarir.

Neden LLM'siz?
  - Kucuk modeller (CyberStrike 35B) "siradaki tarama adimi ne?" kararinda
    takilip ayni eylemi tekrarliyor.
  - Tarama isi deterministiktir: nmap -> nuclei -> enum4linux -> gobuster
    zinciri her zaman ayni sirayla calisir. LLM'e gerek yoktur.
  - LLM yalnizca BULUNAN zafiyetleri yorumlamak ve istismar onceligini
    belirlemek icin kullanilir (bkz. assessment_assistant).

Tarama Zinciri:
  1. nmap -sV -sC -p-        : Tam port + servis/versiyon + default scriptler
  2. nuclei                  : 5000+ CVE/misconfig/exposure sablonu
  3. enum4linux              : SMB/NetBIOS/RPC numaralandirma (Samba hedefleri)
  4. gobuster/ffuf           : Web dizin/dosya kesfi
  5. nikto                   : Web sunucu zafiyet taramasi
  6. whatweb                 : Web teknoloji parmak izi

Cikti: Yapilandirilmis `ReconResult` nesnesi (acik portlar, servisler,
bulunan zafiyetler, web dizinleri, SMB paylasimlari).
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.scope import (
    is_target_allowed,
    resolve_host,
    resolve_port,
    resolve_url,
    run_command,
)

logger = logging.getLogger(__name__)


# ── Veri Modelleri ──────────────────────────────────────────────────────────

@dataclass
class ServiceInfo:
    """Tek bir acik port/servis."""
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    extra: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "extra": self.extra,
        }


@dataclass
class ReconFinding:
    """Tarama sirasinda bulunan ham zafiyet/isaret."""
    source: str          # nmap | nuclei | enum4linux | gobuster | nikto | whatweb
    severity: str        # Critical | High | Medium | Low | Info
    title: str
    evidence: str
    port: Optional[int] = None
    cve: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence,
            "port": self.port,
            "cve": self.cve,
        }


@dataclass
class ReconResult:
    """Otonom tarama katmaninin tam ciktisi."""
    target: str
    services: List[ServiceInfo] = field(default_factory=list)
    findings: List[ReconFinding] = field(default_factory=list)
    web_paths: List[str] = field(default_factory=list)
    smb_shares: List[str] = field(default_factory=list)
    raw_outputs: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "services": [s.to_dict() for s in self.services],
            "findings": [f.to_dict() for f in self.findings],
            "web_paths": self.web_paths,
            "smb_shares": self.smb_shares,
        }

    def summary(self) -> str:
        """LLM'e gonderilecek kompakt ozet."""
        lines = [f"=== Otonom Tarama Sonucu: {self.target} ==="]
        lines.append(f"Acik Portlar ({len(self.services)}):")
        for s in self.services:
            ver = f" {s.version}" if s.version else ""
            lines.append(f"  - {s.port}/{s.protocol} {s.service}{ver}")
        if self.web_paths:
            lines.append(f"Web Dizinleri ({len(self.web_paths)}): {', '.join(self.web_paths[:15])}")
        if self.smb_shares:
            lines.append(f"SMB Paylasimlari: {', '.join(self.smb_shares[:10])}")
        if self.findings:
            lines.append(f"Bulunan Zafiyet Isaretleri ({len(self.findings)}):")
            for f in self.findings[:20]:
                cve = f" [{f.cve}]" if f.cve else ""
                lines.append(f"  - [{f.severity}] {f.title}{cve} (kaynak: {f.source})")
        return "\n".join(lines)


# ── Tarama Motoru ───────────────────────────────────────────────────────────

class ReconEngine:
    """
    LLM'siz otonom tarama motoru. Hedef uzerinde deterministik bir tarama
    zinciri calistirir ve yapilandirilmis sonuc dondurur.
    """

    def __init__(self, timeout_nmap: int = 300, timeout_nuclei: int = 300,
                 timeout_web: int = 180):
        self.timeout_nmap = timeout_nmap
        self.timeout_nuclei = timeout_nuclei
        self.timeout_web = timeout_web

    # ── 1. Port & Servis Taramasi ───────────────────────────────────────────

    def scan_ports(self, target: str) -> List[ServiceInfo]:
        """nmap -sV -sC ile tam port + servis/versiyon taramasi."""
        host = resolve_host(target)
        # -sC: default NSE scriptleri (banner, vuln ipuclari)
        # -sV: servis/versiyon tespiti
        # --min-rate: hizli tarama
        cmd = (
            f"nmap -sV -sC -Pn --min-rate 1500 -T4 "
            f"-p 1-10000 {host}"
        )
        out = run_command(cmd, timeout=self.timeout_nmap)
        return self._parse_nmap_services(out)

    def _parse_nmap_services(self, output: str) -> List[ServiceInfo]:
        services: List[ServiceInfo] = []
        for line in output.splitlines():
            m = re.match(
                r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", line.strip()
            )
            if m:
                port = int(m.group(1))
                proto = m.group(2)
                svc = m.group(3)
                rest = m.group(4).strip()
                # "vsftpd 2.3.4" -> service=vsftpd, version=2.3.4
                parts = rest.split(None, 1)
                version = parts[0] if parts else ""
                extra = parts[1] if len(parts) > 1 else ""
                services.append(ServiceInfo(
                    port=port, protocol=proto, service=svc,
                    version=version, extra=extra,
                ))
        return services

    # ── 2. Nuclei Zafiyet Taramasi ──────────────────────────────────────────

    def scan_nuclei(self, target: str, ports: Optional[List[int]] = None) -> List[ReconFinding]:
        """nuclei ile 5000+ CVE/misconfig/exposure sablonu taramasi."""
        host = resolve_host(target)
        findings: List[ReconFinding] = []

        # Web portlari icin nuclei HTTP taramasi
        web_ports = ports or [80, 443, 8080, 8180, 3000]
        for port in web_ports:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}"
            cmd = (
                f"nuclei -u {url} -severity critical,high,medium "
                f"-silent -no-color -timeout 5 -retries 1 "
                f"-t http/cves/ -t http/misconfiguration/ -t http/exposures/ "
                f"-t http/default-logins/ -t http/vulnerabilities/"
            )
            out = run_command(cmd, timeout=self.timeout_nuclei)
            findings.extend(self._parse_nuclei(out, port))

        # Servis bazli network sablonlari (ornegin SMB, FTP)
        net_cmd = (
            f"nuclei -u {host} -severity critical,high,medium "
            f"-silent -no-color -timeout 5 -retries 1 "
            f"-t network/ 2>/dev/null"
        )
        net_out = run_command(net_cmd, timeout=self.timeout_nuclei)
        findings.extend(self._parse_nuclei(net_out, None))

        return findings

    def _parse_nuclei(self, output: str, port: Optional[int]) -> List[ReconFinding]:
        findings: List[ReconFinding] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # nuclei cikti formati: [template-id] [protocol] [severity] url [extra]
            m = re.search(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)", line)
            if m:
                template_id = m.group(1)
                severity = m.group(3).capitalize()
                url = m.group(4)
                cve_match = re.search(r"(CVE-\d{4}-\d+)", template_id, re.IGNORECASE)
                findings.append(ReconFinding(
                    source="nuclei",
                    severity=severity,
                    title=template_id,
                    evidence=line[:300],
                    port=port,
                    cve=cve_match.group(1).upper() if cve_match else None,
                ))
        return findings

    # ── 3. SMB / NetBIOS Numaralandirma ─────────────────────────────────────

    def scan_smb(self, target: str) -> tuple:
        """enum4linux ile SMB/NetBIOS/RPC numaralandirma."""
        host = resolve_host(target)
        findings: List[ReconFinding] = []
        shares: List[str] = []

        cmd = f"enum4linux -a {host}"
        out = run_command(cmd, timeout=self.timeout_web)

        # Paylasimlari ayikla. Iki format olabilir:
        #   1) "//host/share\tMapping: OK Listing: OK Writing: N/A"
        #   2) "  sharename       Disk      Comment"
        for line in out.splitlines():
            m = re.search(r"//[^/\s]+/([^\s\t]+)\s+Mapping:\s*(\S+)", line)
            if m:
                share = m.group(1)
                if share not in shares:
                    shares.append(share)
                continue
            m2 = re.match(r"^\s+(\S+)\s+(Disk|IPC|Printer)\s", line)
            if m2:
                share = m2.group(1)
                if share not in shares:
                    shares.append(share)

        # Zayif yapilandirma isaretleri
        if re.search(r"Mapping:\s*OK", out) and re.search(r"Writing:\s*OK", out):
            findings.append(ReconFinding(
                source="enum4linux", severity="High",
                title="SMB share writable (anonymous)",
                evidence="enum4linux: anonim yazilabilir SMB paylasimi tespit edildi",
            ))
        if re.search(r"password:\s*$", out, re.MULTILINE) or "null session" in out.lower():
            findings.append(ReconFinding(
                source="enum4linux", severity="High",
                title="SMB null session / anonymous access",
                evidence="enum4linux: anonymous/null session erisimi mumkun",
            ))
        if "Samba" in out and re.search(r"[0-9]\.[0-9]\.[0-9]", out):
            findings.append(ReconFinding(
                source="enum4linux", severity="Medium",
                title="Samba version disclosed",
                evidence=out[:300],
            ))

        return findings, shares

    # ── 4. Web Dizin Kesfi ──────────────────────────────────────────────────

    def scan_web_dirs(self, target: str, port: int = 80) -> List[str]:
        """gobuster ile web dizin/dosya kesfi."""
        host = resolve_host(target)
        url = f"http://{host}:{port}"
        cmd = (
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt "
            f"-t 30 -q --timeout 5s -k"
        )
        out = run_command(cmd, timeout=self.timeout_web)
        paths: List[str] = []
        for line in out.splitlines():
            # gobuster cikti formati: "phpMyAdmin           (Status: 301) [Size: 328]"
            m = re.match(r"^(\S+)\s+\(Status:\s*(\d+)\)", line.strip())
            if m:
                status = int(m.group(2))
                if status in (200, 301, 302, 401, 403):
                    paths.append(m.group(1))
        return paths

    # ── 5. Nikto Web Zafiyet Taramasi ───────────────────────────────────────

    def scan_nikto(self, target: str, port: int = 80) -> List[ReconFinding]:
        host = resolve_host(target)
        cmd = f"nikto -h {host} -p {port} -maxtime 120s -nointeractive"
        out = run_command(cmd, timeout=self.timeout_web)
        findings: List[ReconFinding] = []
        for line in out.splitlines():
            if line.startswith("+ ") and "OSVDB" not in line:
                # Onemli satirlari filtrele
                if any(k in line.lower() for k in [
                    "vulnerab", "outdated", "default", "exposed", "disclos",
                    "injection", "traversal", "xss", "sql", "backup", "config",
                ]):
                    findings.append(ReconFinding(
                        source="nikto", severity="Medium",
                        title=line[2:120], evidence=line[:300], port=port,
                    ))
        return findings

    # ── 6. WhatWeb Teknoloji Parmak Izi ─────────────────────────────────────

    def scan_whatweb(self, target: str, port: int = 80) -> List[ReconFinding]:
        host = resolve_host(target)
        cmd = f"whatweb -q http://{host}:{port}"
        out = run_command(cmd, timeout=60)
        findings: List[ReconFinding] = []
        if out and out != "(no output)":
            findings.append(ReconFinding(
                source="whatweb", severity="Info",
                title="Web teknoloji parmak izi",
                evidence=out[:400], port=port,
            ))
        return findings

    # ── Ana Zincir ──────────────────────────────────────────────────────────

    def run_full_recon(self, target: str, progress_cb=None) -> ReconResult:
        """
        Tam otonom tarama zincirini calistirir. LLM'e hic ihtiyac duymaz.

        Args:
            target: Hedef alias (ornegin 'metasploitable2')
            progress_cb: Opsiyonel callback(stage_name, message) - UI ilerlemesi icin
        """
        if not is_target_allowed(target):
            logger.warning(f"[ReconEngine] Target '{target}' not in allow-list. Aborting.")
            return ReconResult(target=target)

        result = ReconResult(target=target)

        def _progress(stage: str, msg: str):
            logger.info(f"[ReconEngine] {stage}: {msg}")
            if progress_cb:
                try:
                    progress_cb(stage, msg)
                except Exception:
                    pass

        # 1. Port & servis taramasi
        _progress("nmap", "Tam port ve servis taramasi baslatiliyor...")
        result.services = self.scan_ports(target)
        result.raw_outputs["nmap"] = json.dumps([s.to_dict() for s in result.services])
        _progress("nmap", f"{len(result.services)} acik port bulundu.")

        open_ports = [s.port for s in result.services]

        # 2. Web portlarini belirle
        web_ports = [p for p in open_ports if p in (80, 443, 8080, 8180, 3000, 8000, 8888)]

        # 3. Nuclei zafiyet taramasi
        if web_ports or open_ports:
            _progress("nuclei", "CVE/misconfig sablonlari taraniyor...")
            result.findings.extend(self.scan_nuclei(target, web_ports or None))
            _progress("nuclei", f"{len(result.findings)} zafiyet isareti bulundu.")

        # 4. SMB numaralandirma (139/445 aciksa)
        if 139 in open_ports or 445 in open_ports:
            _progress("enum4linux", "SMB/NetBIOS numaralandirma...")
            smb_findings, shares = self.scan_smb(target)
            result.findings.extend(smb_findings)
            result.smb_shares = shares
            _progress("enum4linux", f"{len(shares)} paylasim bulundu.")

        # 5. Web dizin kesfi + nikto + whatweb
        for wp in web_ports[:2]:  # Ilk 2 web portu
            _progress("gobuster", f"Web dizin kesfi (port {wp})...")
            result.web_paths.extend(self.scan_web_dirs(target, wp))

            _progress("nikto", f"Web zafiyet taramasi (port {wp})...")
            result.findings.extend(self.scan_nikto(target, wp))

            _progress("whatweb", f"Teknoloji parmak izi (port {wp})...")
            result.findings.extend(self.scan_whatweb(target, wp))

        _progress("complete", f"Tarama tamamlandi: {len(result.services)} port, "
                              f"{len(result.findings)} zafiyet isareti, "
                              f"{len(result.web_paths)} web dizini.")
        return result


# Modul seviyesinde tekil ornek
recon_engine = ReconEngine()
