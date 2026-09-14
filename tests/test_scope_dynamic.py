"""Dinamik scope (config/scope.yaml) testleri."""
from core.scope import is_target_in_scope


def _scope():
    return {
        "scope": {
            "domains": ["*.example.com", "api.example.com"],
            "ips": ["10.0.0.0/24"],
            "excluded": ["admin.example.com"],
        }
    }


def test_domain_wildcard_match():
    assert is_target_in_scope("sub.example.com", _scope())


def test_domain_exact_match():
    assert is_target_in_scope("api.example.com", _scope())


def test_domain_no_match():
    assert not is_target_in_scope("evil.com", _scope())


def test_excluded_takes_precedence():
    assert not is_target_in_scope("admin.example.com", _scope())


def test_ip_range_match():
    assert is_target_in_scope("10.0.0.5", _scope())


def test_ip_range_no_match():
    assert not is_target_in_scope("10.0.1.5", _scope())


def test_target_with_port():
    assert is_target_in_scope("sub.example.com:8080", _scope())


def test_target_with_scheme():
    assert is_target_in_scope("https://sub.example.com", _scope())


def test_flat_scope_without_block():
    flat = {"domains": ["*.test.com"], "ips": [], "excluded": []}
    assert is_target_in_scope("a.test.com", flat)
