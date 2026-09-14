"""
AutoRedTeam - CVSS Scorer (CVSS v3.1 Skorlayici).

Bulgu kategorisine gore CVSS v3.1 skoru ve vektoru uretir.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

# Kategori -> (base_score, vector)
CVSS_MAP: Dict[str, Tuple[float, str]] = {
    "Weak Default Credentials": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Backdoor Exploitation": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Privilege Escalation": (8.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "SQL Injection": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Command Injection": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "File Upload": (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "Local File Inclusion": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Cross-Site Scripting": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "Known vulnerable service version": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Old Software Version": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

DEFAULT_CVSS = (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")


def score_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Bir bulguya CVSS skoru ekler."""
    category = finding.get("category", "")
    score, vector = CVSS_MAP.get(category, DEFAULT_CVSS)
    finding["cvss_score"] = score
    finding["cvss_vector"] = vector
    return finding


def severity_from_cvss(score: float) -> str:
    """CVSS skorundan severity."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"
