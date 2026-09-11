# core/docker_manager.py
"""
AutoRedTeam - Docker Environment Manager & Health-Check Automation.

Manages the lifecycle of containerized assessment targets and tools:
  - autoredteam-juice-shop (OWASP Juice Shop on port 3000)
  - autoredteam-metasploitable2 (Metasploitable2 on ports 2222, 8081)
  - autoredteam-assessment-tools (Containerized nmap, nikto, sqlmap, gobuster)

Provides:
  - check_docker_available(): Checks if Docker CLI / daemon is alive
  - check_containers_status(): Queries running status of all 3 assessment containers
  - ensure_environment_ready(): Starts containers via docker compose if stopped
  - reset_target(target): Restarts a specific target to clear dirty exploit state
  - run_health_checks(): Port-level TCP probe for targets and 'which' check for tools
"""

import logging
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("autoredteam.docker_manager")

COMPOSE_FILE = Path(__file__).parent.parent / "docker" / "docker-compose.yml"

CONTAINER_NAMES = {
    "juice_shop": "autoredteam-juice-shop",
    "metasploitable2": "autoredteam-metasploitable2",
    "assessment_tools": "autoredteam-assessment-tools"
}

TARGET_PORT_PROBES = {
    "localhost:3000": ("127.0.0.1", 3000),
    "juice_shop": ("127.0.0.1", 3000),
    "metasploitable2": ("127.0.0.1", 8081),
    "metasploitable2:22": ("127.0.0.1", 2222),
    "metasploitable2:80": ("127.0.0.1", 8081),
}


class DockerManager:
    """
    Automated Docker management and environment recovery for AutoRedTeam.
    """

    def __init__(self, compose_file: Optional[Path] = None):
        self.compose_file = Path(compose_file) if compose_file else COMPOSE_FILE

    def is_docker_available(self) -> bool:
        """Verifies if docker CLI is available and docker daemon is reachable."""
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return res.returncode == 0
        except Exception:
            return False

    def get_container_status(self, container_name: str) -> str:
        """
        Returns status of a specific container ('running', 'exited', 'not_found', etc.)
        """
        try:
            res = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Status}}", container_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            if res.returncode == 0:
                return res.stdout.strip()
            return "not_found"
        except Exception as e:
            logger.debug(f"Could not inspect container {container_name}: {e}")
            return "unknown"

    def check_all_containers(self) -> Dict[str, str]:
        """
        Returns running status for all required AutoRedTeam containers.
        """
        status_map = {}
        for key, name in CONTAINER_NAMES.items():
            status_map[key] = self.get_container_status(name)
        return status_map

    def ensure_containers_running(self) -> bool:
        """
        Verifies all containers are running; if any are stopped, runs docker compose up -d.
        """
        if not self.is_docker_available():
            logger.warning("Docker is not available on host system.")
            return False

        statuses = self.check_all_containers()
        all_running = all(s == "running" for s in statuses.values())
        if all_running:
            return True

        logger.info("One or more assessment containers not running. Launching via docker compose...")
        try:
            cmd = ["docker", "compose", "-f", str(self.compose_file), "up", "-d"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to launch docker compose: {e}")
            return False

    def probe_tcp_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Lightweight TCP connect probe."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def verify_tool_installed(self, tool_name: str) -> bool:
        """Verifies if a specific tool exists inside autoredteam-assessment-tools."""
        container = CONTAINER_NAMES["assessment_tools"]
        try:
            res = subprocess.run(
                ["docker", "exec", container, "which", tool_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            return res.returncode == 0
        except Exception:
            return False

    def reset_target(self, target_identifier: str) -> bool:
        """
        Restarts a target container to wipe dirty state from previous exploit executions.
        """
        container_to_restart = None
        target_lower = target_identifier.lower()

        if "3000" in target_lower or "juice" in target_lower:
            container_to_restart = CONTAINER_NAMES["juice_shop"]
        elif "metasploitable" in target_lower:
            container_to_restart = CONTAINER_NAMES["metasploitable2"]

        if not container_to_restart:
            logger.warning(f"Unknown target identifier for reset: {target_identifier}")
            return False

        logger.info(f"Resetting target container: {container_to_restart}...")
        try:
            res = subprocess.run(
                ["docker", "restart", container_to_restart],
                capture_output=True,
                text=True,
                timeout=30
            )
            return res.returncode == 0
        except Exception as e:
            logger.error(f"Failed to reset container {container_to_restart}: {e}")
            return False

    def get_health_report(self) -> Dict[str, Any]:
        """
        Produces a comprehensive health check dictionary for the entire testbed.
        """
        docker_ok = self.is_docker_available()
        containers = self.check_all_containers() if docker_ok else {}

        # Port probes
        probes = {}
        for target_name, (host, port) in TARGET_PORT_PROBES.items():
            probes[target_name] = self.probe_tcp_port(host, port)

        # Tools inside assessment-tools
        tools = {}
        if containers.get("assessment_tools") == "running":
            for tool in ["nmap", "gobuster", "nikto", "whatweb", "sqlmap", "searchsploit"]:
                tools[tool] = self.verify_tool_installed(tool)

        return {
            "docker_available": docker_ok,
            "containers": containers,
            "probes": probes,
            "tools_available": tools,
            "all_healthy": docker_ok and all(s == "running" for s in containers.values())
        }


# Singleton instance
docker_manager = DockerManager()
