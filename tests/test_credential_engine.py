"""CredentialEngine unit testleri (mock ile)."""
from unittest.mock import patch

from core.credential_engine import CredentialEngine, Credential


def test_default_creds_ssh_success():
    engine = CredentialEngine("metasploitable2")
    with patch("core.credential_engine.run_command", return_value="uid=1000(msfadmin)"):
        creds = engine.try_default_creds("ssh", "metasploitable2", 22)
    assert len(creds) >= 1
    assert creds[0].username == "msfadmin"
    assert creds[0].source == "default"


def test_default_creds_ssh_failure():
    engine = CredentialEngine("metasploitable2")
    with patch("core.credential_engine.run_command", return_value="Permission denied"):
        creds = engine.try_default_creds("ssh", "metasploitable2", 22)
    assert creds == []


def test_reuse_credentials():
    engine = CredentialEngine("metasploitable2")
    existing = [Credential("msfadmin", "msfadmin", "ssh", "metasploitable2", 22)]
    with patch("core.credential_engine.run_command", return_value="1"):
        reused = engine.reuse_credentials(existing, ["mysql"])
    assert len(reused) >= 1
    assert reused[0].source == "reuse"
    assert reused[0].service == "mysql"


def test_reuse_skips_same_service():
    engine = CredentialEngine("metasploitable2")
    existing = [Credential("msfadmin", "msfadmin", "ssh", "metasploitable2", 22)]
    with patch("core.credential_engine.run_command", return_value="uid=0(root)"):
        reused = engine.reuse_credentials(existing, ["ssh"])
    assert reused == []


def test_out_of_scope_blocked():
    engine = CredentialEngine("evil.com")
    creds = engine.try_default_creds("ssh", "evil.com", 22)
    assert creds == []


def test_parse_hydra_output():
    engine = CredentialEngine("metasploitable2")
    output = "[22][ssh] host: metasploitable2   login: msfadmin   password: msfadmin"
    creds = engine._parse_hydra_output(output, "ssh", "metasploitable2", 22)
    assert len(creds) == 1
    assert creds[0].username == "msfadmin"
    assert creds[0].source == "brute"


def test_default_port_lookup():
    engine = CredentialEngine("metasploitable2")
    assert engine._default_port("mysql") == 3306
    assert engine._default_port("unknown") == 0
