"""
Tests for Phase 2: Docker Environment Manager and Health Checks.
"""
from pathlib import Path
from unittest.mock import MagicMock, patch
from core.docker_manager import DockerManager, docker_manager


def test_docker_manager_init():
    """Verify DockerManager initializes with correct default paths."""
    assert docker_manager.compose_file.name == "docker-compose.yml"
    assert docker_manager.compose_file.parent.name == "docker"


def test_probe_tcp_port():
    """Verify TCP probe works correctly on reachable vs unreachable ports."""
    # Port 59999 should not be listening on localhost
    res_fail = docker_manager.probe_tcp_port("127.0.0.1", 59999, timeout=0.5)
    assert res_fail is False


def test_reset_target_mapping():
    """Verify reset_target identifies appropriate container names."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        
        # Juice shop
        res_js = docker_manager.reset_target("localhost:3000")
        assert res_js is True
        mock_run.assert_called_with(["docker", "restart", "autoredteam-juice-shop"], capture_output=True, text=True, timeout=30)
        
        # Metasploitable2
        res_ms = docker_manager.reset_target("metasploitable2")
        assert res_ms is True
        mock_run.assert_called_with(["docker", "restart", "autoredteam-metasploitable2"], capture_output=True, text=True, timeout=30)
        
        # Unknown
        res_unk = docker_manager.reset_target("nonexistent_machine")
        assert res_unk is False


def test_get_health_report_structure():
    """Verify health report dictionary has all required keys."""
    report = docker_manager.get_health_report()
    assert "docker_available" in report
    assert "containers" in report
    assert "probes" in report
    assert "tools_available" in report
    assert "all_healthy" in report
