"""Verifier unit testleri."""
from core.verifier import Verifier, Evidence


def test_verify_root_uid():
    v = Verifier()
    ev = v.verify_exploit({"output": "uid=0(root) gid=0(root)", "success": True})
    assert ev.verified
    assert ev.verification_method == "uid_check"
    assert ev.confidence == 1.0
    assert ev.details["privilege"] == "root"


def test_verify_user_uid():
    v = Verifier()
    ev = v.verify_exploit({"output": "uid=1000(msfadmin)", "success": True})
    assert ev.verified
    assert ev.confidence == 0.8
    assert ev.details["privilege"] == "msfadmin"


def test_verify_shell_prompt():
    v = Verifier()
    ev = v.verify_exploit({"output": "root@metasploitable:/# ls", "success": True})
    assert ev.verified
    assert ev.verification_method == "shell_prompt"


def test_verify_failure():
    v = Verifier()
    ev = v.verify_exploit({"output": "connection refused", "success": False})
    assert not ev.verified
    assert ev.confidence == 0.0


def test_verify_flag_only():
    v = Verifier()
    ev = v.verify_exploit({"output": "something happened", "success": True})
    assert ev.verified
    assert ev.verification_method == "flag"
    assert ev.confidence == 0.5


def test_false_positive_detection():
    v = Verifier()
    ev = Evidence(verified=True, confidence=0.2)
    assert v.is_false_positive(ev)


def test_verify_finding_version_low_confidence():
    v = Verifier()
    ev = v.verify_finding({
        "category": "Old Software Version",
        "evidence_snippet": "Apache 2.2.8",
        "tool": "nmap",
    })
    assert ev.confidence <= 0.3


def test_verify_finding_exploit_root():
    v = Verifier()
    ev = v.verify_finding({
        "category": "Backdoor Exploitation",
        "evidence_snippet": "uid=0(root)",
        "tool": "exploit",
    })
    assert ev.confidence == 1.0
