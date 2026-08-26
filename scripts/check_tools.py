"""
AutoRedTeam - Tool Health Check Script.

Verifies that all security assessment tools are reachable and reports their
availability in a table. Tools are checked inside the assessment-tools Docker
container if it is running; otherwise they are checked on the host.

Usage:
    python scripts/check_tools.py
    python main.py --mode check-tools
"""

import json
import shlex
import subprocess
import sys
from typing import Any, Dict, List, Tuple

# Fix Windows console UTF-8
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

TOOLS_CONTAINER = "autoredteam-assessment-tools"

# Each tool: (name, version command)
TOOLS: List[Tuple[str, str]] = [
    ("nmap", "nmap --version"),
    ("gobuster", "gobuster --version"),
    ("nikto", "nikto -Version"),
    ("whatweb", "whatweb --version"),
    ("sqlmap", "sqlmap --version"),
    ("testssl.sh", "testssl.sh --version"),
    ("searchsploit", "which searchsploit"),
]


def _docker_container_available() -> bool:
    """Checks whether the assessment-tools Docker container is running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", TOOLS_CONTAINER],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except Exception:
        return False


def _run_version_check(command: str) -> Tuple[bool, str]:
    """Runs a version check command and returns (available, output)."""
    try:
        args = shlex.split(command)
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False
        )
        combined = (result.stdout or "").strip() + (result.stderr or "").strip()
        first_line = combined.splitlines()[0] if combined else "(no output)"
        return result.returncode == 0, first_line[:120]
    except FileNotFoundError:
        return False, "NOT FOUND"
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, f"ERROR: {e}"


def check_tools() -> List[Dict[str, Any]]:
    """
    Checks all tools and returns a list of result dicts:
    [{"tool": ..., "available": bool, "version": ..., "source": "docker"|"host"}]
    """
    in_docker = _docker_container_available()
    source = "docker" if in_docker else "host"
    results: List[Dict[str, Any]] = []

    for name, version_cmd in TOOLS:
        if in_docker:
            full_cmd = f"docker exec {TOOLS_CONTAINER} {version_cmd}"
        else:
            full_cmd = version_cmd
        available, version = _run_version_check(full_cmd)
        results.append({
            "tool": name,
            "available": available,
            "version": version,
            "source": source
        })

    return results


def print_report(results: List[Dict[str, Any]]) -> None:
    """Prints the tool availability table."""
    print("\n" + "=" * 70)
    print("🛡️  AutoRedTeam — Araç Erişilebilirlik Kontrolü")
    print("=" * 70)

    source = results[0]["source"] if results else "unknown"
    print(f"Çalışma ortamı: {'🐳 Docker konteyneri' if source == 'docker' else '💻 Host (doğrudan)'}\n")

    print(f"{'Araç':<14} {'Durum':<10} {'Sürüm / Çıktı'}")
    print("-" * 70)

    available_count = 0
    for r in results:
        status = "✅ OK" if r["available"] else "❌ YOK"
        if r["available"]:
            available_count += 1
        print(f"{r['tool']:<14} {status:<10} {r['version']}")

    print("-" * 70)
    print(f"Toplam: {available_count}/{len(results)} araç erişilebilir.\n")

    if available_count < len(results):
        print("⚠️  Bazı araçlar eksik. Docker ortamını kurmak için:")
        print("    docker compose -f docker/docker-compose.yml up -d --build")
        print("    Ardından bu scripti tekrar çalıştırın.\n")


def main() -> int:
    results = check_tools()
    print_report(results)
    # Exit non-zero if any tool is missing
    return 0 if all(r["available"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
