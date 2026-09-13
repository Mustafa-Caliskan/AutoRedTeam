"""
Tests for the Autonomous Recon Engine (LLM-free scanning layer).

Bu testler, recon motorunun cikti ayristirma (parsing) mantigini dogrular.
Gercek ag taramasi yapmaz; ornek ciktilar uzerinden parser'lari test eder.
"""
import pytest

from core.recon_engine import (
    ReconEngine,
    ReconFinding,
    ReconResult,
    ServiceInfo,
)


class TestNmapParsing:
    def test_parse_services(self):
        engine = ReconEngine()
        sample = (
            "Starting Nmap 7.99\n"
            "PORT     STATE SERVICE     VERSION\n"
            "21/tcp   open  ftp         vsftpd 2.3.4\n"
            "22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1\n"
            "80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)\n"
            "3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5\n"
        )
        services = engine._parse_nmap_services(sample)
        assert len(services) == 4
        assert services[0].port == 21
        assert services[0].service == "ftp"
        assert services[0].version == "vsftpd"
        assert services[2].port == 80
        assert "Apache" in services[2].version

    def test_parse_empty(self):
        engine = ReconEngine()
        assert engine._parse_nmap_services("") == []
        assert engine._parse_nmap_services("no open ports") == []


class TestNucleiParsing:
    def test_parse_nuclei_findings(self):
        engine = ReconEngine()
        sample = (
            "[CVE-2021-41773] [http] [critical] http://target:80/cgi-bin/.%2e/\n"
            "[apache-server-status] [http] [medium] http://target:80/server-status\n"
            "not a finding line\n"
        )
        findings = engine._parse_nuclei(sample, 80)
        assert len(findings) == 2
        assert findings[0].cve == "CVE-2021-41773"
        assert findings[0].severity == "Critical"
        assert findings[1].severity == "Medium"


class TestGobusterParsing:
    def test_parse_web_dirs(self):
        engine = ReconEngine()
        # gobuster cikti formati
        sample = (
            "phpMyAdmin           (Status: 301) [Size: 328]\n"
            ".htaccess            (Status: 403) [Size: 297]\n"
            "index.php            (Status: 200) [Size: 891]\n"
            "notfound             (Status: 404) [Size: 0]\n"
        )
        # scan_web_dirs ag cagrisi yapar; parser mantigini izole test edelim
        import re
        paths = []
        for line in sample.splitlines():
            m = re.match(r"^(\S+)\s+\(Status:\s*(\d+)\)", line.strip())
            if m:
                status = int(m.group(2))
                if status in (200, 301, 302, 401, 403):
                    paths.append(m.group(1))
        assert "phpMyAdmin" in paths
        assert "index.php" in paths
        assert "notfound" not in paths


class TestReconResult:
    def test_summary_renders(self):
        result = ReconResult(target="metasploitable2")
        result.services = [
            ServiceInfo(port=21, service="ftp", version="vsftpd 2.3.4"),
            ServiceInfo(port=80, service="http", version="Apache 2.2.8"),
        ]
        result.findings = [
            ReconFinding(source="nikto", severity="Medium",
                         title="Outdated Apache", evidence="Apache/2.2.8"),
        ]
        result.web_paths = ["/phpMyAdmin", "/dav"]
        result.smb_shares = ["tmp", "opt"]

        summary = result.summary()
        assert "metasploitable2" in summary
        assert "21/tcp" in summary
        assert "phpMyAdmin" in summary
        assert "tmp" in summary
        assert "Outdated Apache" in summary

    def test_to_dict(self):
        result = ReconResult(target="t")
        result.services = [ServiceInfo(port=22, service="ssh")]
        d = result.to_dict()
        assert d["target"] == "t"
        assert d["services"][0]["port"] == 22


class TestReconEngineSafety:
    def test_out_of_scope_target_returns_empty(self):
        engine = ReconEngine()
        # Izinsiz hedef: hicbir tarama yapilmadan bos sonuc donmeli
        result = engine.run_full_recon("evil.example.com")
        assert result.services == []
        assert result.findings == []
