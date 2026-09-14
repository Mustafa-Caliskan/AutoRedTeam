"""
AutoRedTeam - Finding Correlator (Bulgu Korelasyonu).

Ayni kategori/hedef bulgulari birlestirir, privesc bulgularini tek zincirde
toplar ve saldiri anlatilari (attack chain) olusturur.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


@dataclass
class AttackChain:
    """Saldiri zinciri."""
    name: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    severity: str = "High"
    impact: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "steps": self.steps,
            "severity": self.severity, "impact": self.impact,
        }


class FindingCorrelator:
    """Bulgulari birlestirir ve zincirler olusturur."""

    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Ayni kategori + hedef + tool bulgulari birlestirir.
        Ozellikle privesc bulgulari tek bulgu olur.
        """
        grouped: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            key = f"{f.get('category')}|{f.get('target')}|{f.get('tool')}"
            if key in grouped:
                existing = grouped[key]
                existing["evidence_snippet"] = (
                    existing.get("evidence_snippet", "") + "\n---\n"
                    + f.get("evidence_snippet", "")
                )
                existing["merged_count"] = existing.get("merged_count", 1) + 1
            else:
                grouped[key] = dict(f)
        return list(grouped.values())

    def build_chains(self, findings: List[Dict[str, Any]]) -> List[AttackChain]:
        """Bulgulardan saldiri zincirleri olusturur."""
        chains: List[AttackChain] = []

        privesc = [f for f in findings if "Privilege" in f.get("category", "")]
        if privesc:
            chains.append(AttackChain(
                name="Privilege Escalation Chain",
                steps=[
                    {"finding": f.get("finding_id"),
                     "detail": f.get("evidence_snippet", "")[:200]}
                    for f in privesc
                ],
                severity="Critical",
                impact="Full system compromise (root access).",
            ))

        creds = [f for f in findings if "Credential" in f.get("category", "")]
        backdoor = [f for f in findings if "Backdoor" in f.get("category", "")]
        if creds or backdoor:
            chains.append(AttackChain(
                name="Initial Access Chain",
                steps=[
                    {"finding": f.get("finding_id"), "detail": f.get("category")}
                    for f in (creds + backdoor)
                ],
                severity="Critical",
                impact="Unauthorized remote access obtained.",
            ))

        return chains

    def correlate(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Tam korelasyon: dedupe + chains."""
        deduped = self.deduplicate(findings)
        chains = self.build_chains(deduped)
        return {
            "findings": deduped,
            "chains": [c.to_dict() for c in chains],
            "original_count": len(findings),
            "deduped_count": len(deduped),
        }
