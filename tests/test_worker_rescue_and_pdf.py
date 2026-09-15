# tests/test_worker_rescue_and_pdf.py
"""
Unit tests for AutoRedTeam's worker rescue mechanism and PDF report generator:
1. AssessmentAssistant._build_worker_activity (repetition/stuck detection)
2. AssessmentAssistant._auto_select_exploit (service -> exploit mapping)
3. PDFReportGenerator (professional PDF report generation)
"""

import pytest
from pathlib import Path

from core.assessment_assistant import AssessmentAssistant


class TestWorkerActivity:
    def test_empty_chain(self):
        a = AssessmentAssistant(target="metasploitable2")
        activity = a._build_worker_activity()
        assert "henuz islem yapmadi" in activity

    def test_detects_repetition(self):
        a = AssessmentAssistant(target="metasploitable2")
        a.decision_chain = [
            {"step": 1, "tool": "nmap", "service_name": "vsftpd", "target": "metasploitable2"},
            {"step": 2, "tool": "nmap", "service_name": "vsftpd", "target": "metasploitable2"},
            {"step": 3, "tool": "nmap", "service_name": "vsftpd", "target": "metasploitable2"},
        ]
        activity = a._build_worker_activity()
        assert "TEKRAR TESPITI" in activity
        assert "nmap/vsftpd" in activity

    def test_detects_no_exploit(self):
        a = AssessmentAssistant(target="metasploitable2")
        a.decision_chain = [
            {"step": 1, "tool": "nmap", "target": "metasploitable2"},
            {"step": 2, "tool": "searchsploit", "target": "metasploitable2"},
        ]
        activity = a._build_worker_activity()
        assert "HIC exploit denemedi" in activity

    def test_no_repeat_when_diverse(self):
        a = AssessmentAssistant(target="metasploitable2")
        a.decision_chain = [
            {"step": 1, "tool": "nmap", "service_name": "vsftpd", "target": "metasploitable2"},
            {"step": 2, "tool": "searchsploit", "service_name": "samba", "target": "metasploitable2"},
            {"step": 3, "tool": "exploit", "exploit": "ingreslock_backdoor", "target": "metasploitable2"},
        ]
        activity = a._build_worker_activity()
        assert "TEKRAR TESPITI" not in activity
        assert "HIC exploit denemedi" not in activity

    def test_repeat_only_in_recent_window(self):
        """Eski bir tekrar, worker duzeldikten sonra kalici tetiklememeli."""
        a = AssessmentAssistant(target="metasploitable2")
        a.decision_chain = [
            {"step": 1, "tool": "nmap", "service_name": "vsftpd", "target": "metasploitable2"},
            {"step": 2, "tool": "nmap", "service_name": "vsftpd", "target": "metasploitable2"},
            # Sonra farkli adimlar (son 5 penceresinde tekrar yok)
            {"step": 3, "tool": "searchsploit", "service_name": "samba", "target": "metasploitable2"},
            {"step": 4, "tool": "exploit", "exploit": "samba_usermap", "target": "metasploitable2"},
            {"step": 5, "tool": "privesc", "privesc": "sudo_privesc", "target": "metasploitable2"},
            {"step": 6, "tool": "privesc", "privesc": "verify_root", "target": "metasploitable2"},
        ]
        activity = a._build_worker_activity()
        assert "TEKRAR TESPITI" not in activity


class TestUntestedServices:
    def test_all_untested_when_empty(self):
        a = AssessmentAssistant(target="metasploitable2")
        untested = a._untested_services()
        # Bos zincirde tum kritik servisler test edilmemis olmali
        assert len(untested) >= 5
        assert any("vsftpd" in u for u in untested)

    def test_some_tested(self):
        a = AssessmentAssistant(target="metasploitable2")
        a.decision_chain = [
            {"step": 1, "tool": "exploit", "exploit": "vsftpd_backdoor", "thought": "vsftpd 2.3.4 bulundu"},
            {"step": 2, "tool": "exploit", "exploit": "ssh_credential_spray", "thought": "SSH msfadmin"},
            {"step": 3, "tool": "exploit", "exploit": "samba_usermap", "thought": "Samba 445"},
        ]
        untested = a._untested_services()
        # Exploit denenen servisler listede olmamali
        assert not any("vsftpd" in u for u in untested)
        assert not any("ssh" in u.lower() for u in untested)
        assert not any("samba" in u.lower() for u in untested)
        # Test edilmeyenler olmali
        assert any("mysql" in u.lower() for u in untested)

    def test_lookup_only_not_counted_as_tested(self):
        """searchsploit/cve_search lookup'i exploit gerektiren servisi 'test edildi' SAYMAMALI."""
        a = AssessmentAssistant(target="metasploitable2")
        a.decision_chain = [
            # Sadece lookup yapildi, gercek exploit denemesi YOK
            {"step": 1, "tool": "searchsploit", "service_name": "vsftpd", "thought": "vsftpd 2.3.4"},
            {"step": 2, "tool": "searchsploit", "service_name": "distcc", "thought": "distcc 3632"},
        ]
        untested = a._untested_services()
        # Exploit'i olan servisler hala test edilmemis sayilmali
        assert any("vsftpd" in u for u in untested)
        assert any("distcc" in u for u in untested)

    def test_all_tested(self):
        a = AssessmentAssistant(target="metasploitable2")
        a.decision_chain = [
            {"step": 1, "tool": "exploit", "exploit": "vsftpd_backdoor", "thought": "vsftpd ftp 21"},
            {"step": 2, "tool": "exploit", "exploit": "ssh_credential_spray", "thought": "ssh 22 msfadmin"},
            {"step": 3, "tool": "exploit", "exploit": "samba_usermap", "thought": "samba smb 445"},
            {"step": 4, "tool": "exploit", "exploit": "ingreslock_backdoor", "thought": "ingreslock 1524"},
            {"step": 5, "tool": "searchsploit", "service_name": "mysql", "thought": "mysql 3306"},
            {"step": 6, "tool": "searchsploit", "service_name": "postgresql", "thought": "postgres 5432"},
            {"step": 7, "tool": "exploit", "exploit": "unrealircd_backdoor", "thought": "unrealircd 6667"},
            {"step": 8, "tool": "nikto", "service_name": "apache", "thought": "apache http 80 web"},
            {"step": 9, "tool": "exploit", "exploit": "distcc_exec", "thought": "distcc 3632"},
            {"step": 10, "tool": "searchsploit", "service_name": "telnet", "thought": "telnet 23"},
            {"step": 11, "tool": "searchsploit", "service_name": "nfs", "thought": "nfs 2049"},
            {"step": 12, "tool": "exploit", "exploit": "vnc_null_auth", "thought": "vnc 5900"},
            {"step": 13, "tool": "exploit", "exploit": "java_rmi_deserialize", "thought": "rmi 1099"},
            {"step": 14, "tool": "searchsploit", "service_name": "postfix", "thought": "smtp 25"},
            {"step": 15, "tool": "nmap", "service_name": "rpcbind", "thought": "rpcbind 111"},
            {"step": 16, "tool": "searchsploit", "service_name": "rsh", "thought": "rexec 512 rsh 514"},
            {"step": 17, "tool": "searchsploit", "service_name": "rlogin", "thought": "rlogin 513"},
            {"step": 18, "tool": "exploit", "exploit": "proftpd_modcopy", "thought": "proftpd 2121"},
            {"step": 19, "tool": "exploit", "exploit": "tomcat_manager_deploy", "thought": "tomcat 8180"},
            {"step": 20, "tool": "exploit", "exploit": "ruby_drb_rce", "thought": "ruby drb 8787"},
            # Web uygulamalari (path bazli)
            {"step": 21, "tool": "nikto", "service_name": "dvwa", "thought": "dvwa"},
            {"step": 22, "tool": "nikto", "service_name": "mutillidae", "thought": "mutillidae"},
            {"step": 23, "tool": "searchsploit", "service_name": "phpmyadmin", "thought": "phpmyadmin"},
            {"step": 24, "tool": "searchsploit", "service_name": "tikiwiki", "thought": "tikiwiki"},
            {"step": 25, "tool": "searchsploit", "service_name": "webdav", "thought": "webdav"},
        ]
        untested = a._untested_services()
        assert len(untested) == 0

    def test_thought_text_not_counted(self):
        """Serbest 'thought' metnindeki servis adlari test edilmis SAYILMAMALI."""
        a = AssessmentAssistant(target="metasploitable2")
        a.decision_chain = [
            # thought'ta mysql gecmesine ragmen gercek eylem yok
            {"step": 1, "tool": "nmap", "thought": "mysql 3306 ve postgres 5432 olabilir"},
        ]
        untested = a._untested_services()
        # mysql ve postgres hala test edilmemis sayilmali
        assert any("mysql" in u for u in untested)
        assert any("postgres" in u for u in untested)

    def test_port_token_match(self):
        """Port eslesmesi token bazli olmali (2121 icindeki 21 sayilmamali)."""
        a = AssessmentAssistant(target="metasploitable2")
        a.decision_chain = [
            {"step": 1, "tool": "nmap", "ports": "2121"},
        ]
        untested = a._untested_services()
        # 2121 taranmis ama 21 (vsftpd) taranmis SAYILMAMALI
        assert any("vsftpd" in u for u in untested)


class TestAutoSelectExploit:
    def test_metasploitable_ingreslock(self):
        a = AssessmentAssistant(target="metasploitable2")
        assert a._auto_select_exploit("metasploitable2", ports="1524") == "ingreslock_backdoor"

    def test_metasploitable_ssh(self):
        # Yeni mantık: ingreslock her zaman önce denenir. SSH ikinci öncelik.
        # ingreslock başarısız olduysa ssh seçilir.
        a = AssessmentAssistant(target="metasploitable2")
        a._failed_exploits = {"ingreslock_backdoor"}
        assert a._auto_select_exploit("metasploitable2", ports="22") == "ssh_credential_spray"

    def test_metasploitable_ftp(self):
        # ingreslock ve ssh başarısız olduysa vsftpd seçilir.
        a = AssessmentAssistant(target="metasploitable2")
        a._failed_exploits = {"ingreslock_backdoor", "ssh_credential_spray"}
        assert a._auto_select_exploit("metasploitable2", service_name="vsftpd") == "vsftpd_backdoor"

    def test_metasploitable_samba(self):
        # ingreslock, ssh ve vsftpd başarısız olduysa samba seçilir.
        a = AssessmentAssistant(target="metasploitable2")
        a._failed_exploits = {"ingreslock_backdoor", "ssh_credential_spray", "vsftpd_backdoor"}
        assert a._auto_select_exploit("metasploitable2", ports="445") == "samba_usermap"

    def test_metasploitable_default(self):
        # Port/servis verilmemisse hedefe uygun ilk denenmemis exploit secilir.
        a = AssessmentAssistant(target="metasploitable2")
        result = a._auto_select_exploit("metasploitable2")
        assert result in {
            "vsftpd_backdoor", "ingreslock_backdoor", "samba_usermap",
            "ssh_credential_spray", "distcc_exec", "unrealircd_backdoor",
            "proftpd_modcopy", "java_rmi_deserialize", "ruby_drb_rce",
            "vnc_null_auth", "tomcat_manager_deploy",
        }

    def test_juice_shop(self):
        a = AssessmentAssistant(target="localhost:3000")
        assert a._auto_select_exploit("localhost:3000") == "juice_shop_admin"

    def test_ingreslock_fallback_when_all_failed(self):
        # Tüm exploit'ler başarısız olsa bile son çare olarak bir exploit seçilir.
        a = AssessmentAssistant(target="metasploitable2")
        a._failed_exploits = {
            "ingreslock_backdoor", "ssh_credential_spray", "vsftpd_backdoor",
            "samba_usermap", "distcc_exec", "unrealircd_backdoor",
            "proftpd_modcopy", "java_rmi_deserialize", "ruby_drb_rce",
            "vnc_null_auth", "tomcat_manager_deploy", "telnet_default_creds",
        }
        result = a._auto_select_exploit("metasploitable2")
        # Hepsi basarisiz olsa bile hedefe uygun bir exploit donmeli (bos degil).
        assert result in {
            "vsftpd_backdoor", "ingreslock_backdoor", "samba_usermap",
            "ssh_credential_spray", "distcc_exec", "unrealircd_backdoor",
            "proftpd_modcopy", "java_rmi_deserialize", "ruby_drb_rce",
            "vnc_null_auth", "tomcat_manager_deploy", "telnet_default_creds",
        }

    def test_new_exploits_selected_by_port(self):
        # Yeni eklenen exploit'ler port/servis eslesmesiyle secilebilmeli.
        a = AssessmentAssistant(target="metasploitable2")
        assert a._auto_select_exploit("metasploitable2", ports="2121") == "proftpd_modcopy"
        assert a._auto_select_exploit("metasploitable2", ports="1099") == "java_rmi_deserialize"
        assert a._auto_select_exploit("metasploitable2", ports="8787") == "ruby_drb_rce"
        assert a._auto_select_exploit("metasploitable2", ports="5900") == "vnc_null_auth"
        assert a._auto_select_exploit("metasploitable2", ports="8180") == "tomcat_manager_deploy"




class TestPDFReportGenerator:
    def test_pdf_generation(self, tmp_path):
        from reports.pdf_report_generator import PDFReportGenerator, REPORTLAB_AVAILABLE
        if not REPORTLAB_AVAILABLE:
            pytest.skip("reportlab kurulu degil")

        findings = [
            {
                "finding_id": "FIND-001", "tool": "nmap", "target": "metasploitable2",
                "category": "Known vulnerable service version", "severity": "High",
                "cwe_reference": "CWE-937", "evidence_snippet": "open ftp vsftpd 2.3.4",
            },
            {
                "finding_id": "FIND-002", "tool": "exploit", "target": "metasploitable2",
                "category": "Backdoor Exploitation", "severity": "Critical",
                "cwe_reference": "CWE-912", "evidence_snippet": "uid=0(root) gid=0(root)",
            },
        ]
        chain = [{"step": 1, "tool": "nmap", "target": "metasploitable2", "thought": "Kesif"}]
        chains = [{
            "title": "Recon -> Root", "severity": "Critical",
            "steps": [{"step": 1, "phase": "Discovery", "detail": "vsftpd bulundu"}],
        }]

        gen = PDFReportGenerator(output_dir=str(tmp_path))
        path = gen.generate(
            findings, target="metasploitable2",
            decision_chain=chain, chains=chains,
            output_filename="test.pdf",
        )
        assert path is not None
        assert path.exists()
        assert path.stat().st_size > 1000

    def test_pdf_empty_findings(self, tmp_path):
        from reports.pdf_report_generator import PDFReportGenerator, REPORTLAB_AVAILABLE
        if not REPORTLAB_AVAILABLE:
            pytest.skip("reportlab kurulu degil")

        gen = PDFReportGenerator(output_dir=str(tmp_path))
        path = gen.generate([], target="metasploitable2", output_filename="empty.pdf")
        assert path is not None
        assert path.exists()


class TestReportIntegration:
    def test_generate_report_creates_pdf(self, tmp_path, monkeypatch):
        """generate_report hem Markdown hem PDF uretmeli."""
        from reports.pdf_report_generator import REPORTLAB_AVAILABLE
        if not REPORTLAB_AVAILABLE:
            pytest.skip("reportlab kurulu degil")

        # PDF cikisini tmp_path'e yonlendir
        monkeypatch.chdir(tmp_path)
        (tmp_path / "raporlar").mkdir(exist_ok=True)

        findings_file = tmp_path / "f.jsonl"
        report_file = tmp_path / "r.md"
        a = AssessmentAssistant(
            target="metasploitable2", findings_file=findings_file,
            report_file=report_file, auto_approve_findings=True,
        )
        a.record_finding(
            tool="exploit", category="Backdoor Exploitation", severity="Critical",
            cwe_reference="CWE-912", evidence_snippet="uid=0(root)",
        )
        a.generate_report()
        assert report_file.exists()
        pdfs = list((tmp_path / "raporlar").glob("*.pdf"))
        assert len(pdfs) >= 1


class TestEvidenceSanitizer:
    def test_strips_ansi(self):
        raw = "\x1b[01;31m\x1b[KUnrealIRCd\x1b[m\x1b[K 3.2.8"
        out = AssessmentAssistant._sanitize_evidence(raw)
        assert "\x1b" not in out
        assert "UnrealIRCd" in out

    def test_extracts_json_message(self):
        raw = '{"status": "FOUND", "query": "unrealircd 3.2.8", "message": "2 CVEs found"}'
        out = AssessmentAssistant._sanitize_evidence(raw)
        assert out == "2 CVEs found"

    def test_strips_nmap_headers(self):
        raw = "Starting Nmap 7.94 ( https://nmap.org )\nNmap scan report for metasploitable2\nHost is up\n21/tcp open ftp vsftpd 2.3.4"
        out = AssessmentAssistant._sanitize_evidence(raw)
        assert "Starting Nmap" not in out
        assert "Nmap scan report" not in out
        assert "vsftpd 2.3.4" in out

    def test_preserves_uid_proof(self):
        raw = "uid=0(root) gid=0(root)"
        out = AssessmentAssistant._sanitize_evidence(raw)
        assert "uid=0(root)" in out

    def test_limits_length(self):
        raw = "x" * 1000
        out = AssessmentAssistant._sanitize_evidence(raw)
        assert len(out) <= 500


class TestIntelligenceVsFinding:
    def test_cve_search_lookup_not_recorded(self, tmp_path):
        """cve_search lookup sonucu (dogrulama yok) bulgu olarak kaydedilmemeli."""
        findings_file = tmp_path / "f.jsonl"
        a = AssessmentAssistant(
            target="metasploitable2", findings_file=findings_file,
            auto_approve_findings=True,
        )
        finding = {
            "category": "Known vulnerable service version",
            "severity": "High",
            "cwe_reference": "CWE-937",
            "evidence_snippet": "3 CVEs found for mysql 5.0",
        }
        fid = a._record_model_finding(finding, current_tool="cve_search")
        assert fid is None
        assert len(a.findings) == 0

    def test_cve_search_with_proof_recorded(self, tmp_path):
        """cve_search sonucu gercek exploit kaniti iceriyorsa kaydedilmeli."""
        findings_file = tmp_path / "f.jsonl"
        a = AssessmentAssistant(
            target="metasploitable2", findings_file=findings_file,
            auto_approve_findings=True,
        )
        finding = {
            "category": "Backdoor Exploitation",
            "severity": "Critical",
            "cwe_reference": "CWE-912",
            "evidence_snippet": "vsftpd backdoor confirmed, uid=0(root) shell obtained",
        }
        fid = a._record_model_finding(finding, current_tool="cve_search")
        assert fid is not None
        assert fid.startswith("FIND-")

    def test_nmap_finding_still_recorded(self, tmp_path):
        """nmap bulgulari (gercek kesif) kaydedilmeli."""
        findings_file = tmp_path / "f.jsonl"
        a = AssessmentAssistant(
            target="metasploitable2", findings_file=findings_file,
            auto_approve_findings=True,
        )
        finding = {
            "category": "Known vulnerable service version",
            "severity": "Medium",
            "cwe_reference": "CWE-937",
            "evidence_snippet": "21/tcp open ftp vsftpd 2.3.4",
        }
        fid = a._record_model_finding(finding, current_tool="nmap")
        assert fid is not None
        assert fid.startswith("FIND-")

    def test_auto_extract_skips_searchsploit_output(self, tmp_path):
        """searchsploit ciktisindaki exploit basliklari bulgu olarak cikarilmamali."""
        findings_file = tmp_path / "f.jsonl"
        a = AssessmentAssistant(
            target="metasploitable2", findings_file=findings_file,
            auto_approve_findings=True,
        )
        # searchsploit 'vnc' aramasi RealVNC basliklari dondurur; hedefte VNC
        # acik olmasa bile eski kod bunu 'Known vulnerable service version'
        # olarak kaydediyordu. Artik kaydedilmemeli.
        searchsploit_output = (
            "---------------------------------------------- ---------------------------------\n"
            " Exploit Title                                |  Path\n"
            "---------------------------------------------- ---------------------------------\n"
            "RealVNC - Authentication Bypass (Metasploit)  | windows/remote/17719.rb\n"
            "RealVNC 4.1.0/4.1.1 - Authentication Bypass   | windows/remote/36932.py\n"
            "---------------------------------------------- ---------------------------------\n"
            "Shellcodes: No Results\n"
        )
        a._auto_extract_finding("searchsploit", searchsploit_output)
        assert len(a.findings) == 0

    def test_auto_extract_still_works_for_nmap(self, tmp_path):
        """nmap ciktisindaki gercek zafiyetli versiyon bulgu olarak cikarilmali."""
        findings_file = tmp_path / "f.jsonl"
        a = AssessmentAssistant(
            target="metasploitable2", findings_file=findings_file,
            auto_approve_findings=True,
        )
        nmap_output = "21/tcp open ftp vsftpd 2.3.4\n22/tcp open ssh OpenSSH 4.7p1"
        a._auto_extract_finding("nmap", nmap_output)
        assert len(a.findings) >= 1
        assert any("vsftpd" in f.get("evidence_snippet", "").lower() for f in a.findings)
