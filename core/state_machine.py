"""
AutoRedTeam - Assessment State Machine (Pentest Faz Makinesi).

Pentest fazlari arasindaki gecisleri yonetir. Her fazin tamamlanma kosullarini
kontrol eder ve bir sonraki faza gecisi tetikler. Boylece sistem "foothold
alindi -> privesc'e gec" gibi mantikli kararlar verebilir.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Phase(str, Enum):
    RECON = "recon"
    VULN_MAPPING = "vuln_mapping"
    EXPLOITATION = "exploitation"
    FOOTHOLD = "foothold"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    REPORTING = "reporting"
    COMPLETE = "complete"


# Faz gecis kurallari: hangi fazdan hangi faza gecilebilir
TRANSITIONS: Dict[Phase, List[Phase]] = {
    Phase.RECON: [Phase.VULN_MAPPING],
    Phase.VULN_MAPPING: [Phase.EXPLOITATION],
    Phase.EXPLOITATION: [Phase.FOOTHOLD, Phase.PRIVESC, Phase.REPORTING],
    Phase.FOOTHOLD: [Phase.PRIVESC, Phase.LATERAL, Phase.REPORTING],
    Phase.PRIVESC: [Phase.LATERAL, Phase.REPORTING],
    Phase.LATERAL: [Phase.REPORTING],
    Phase.REPORTING: [Phase.COMPLETE],
    Phase.COMPLETE: [],
}


class AssessmentStateMachine:
    """
    Pentest fazlarini yonetir.
    """

    def __init__(self):
        self.phase = Phase.RECON
        self.history: List[Phase] = [Phase.RECON]
        self.foothold_obtained = False
        self.root_obtained = False

    def current_phase(self) -> Phase:
        return self.phase

    def can_transition(self, to_phase: Phase) -> bool:
        """Gecis kuralina uygun mu?"""
        return to_phase in TRANSITIONS.get(self.phase, [])

    def transition(self, to_phase: Phase) -> bool:
        """Faz gecisi yapar. Basariliysa True doner."""
        if not self.can_transition(to_phase):
            logger.warning(
                f"[StateMachine] Gecersiz gecis: {self.phase.value} -> {to_phase.value}"
            )
            return False
        self.phase = to_phase
        self.history.append(to_phase)
        logger.info(f"[StateMachine] Faz gecisi: {to_phase.value}")
        return True

    def on_foothold(self) -> None:
        """Foothold alindiginda cagrilir."""
        self.foothold_obtained = True
        if self.phase == Phase.EXPLOITATION:
            self.transition(Phase.FOOTHOLD)

    def on_root(self) -> None:
        """Root alindiginda cagrilir."""
        self.root_obtained = True
        if self.phase in (Phase.EXPLOITATION, Phase.FOOTHOLD):
            self.transition(Phase.PRIVESC)

    def next_phase(self) -> Optional[Phase]:
        """Mevcut duruma gore mantikli sonraki fazi onerir."""
        if self.phase == Phase.RECON:
            return Phase.VULN_MAPPING
        if self.phase == Phase.VULN_MAPPING:
            return Phase.EXPLOITATION
        if self.phase == Phase.EXPLOITATION:
            return Phase.FOOTHOLD if self.foothold_obtained else None
        if self.phase == Phase.FOOTHOLD:
            return Phase.PRIVESC if not self.root_obtained else Phase.LATERAL
        if self.phase == Phase.PRIVESC:
            return Phase.LATERAL
        if self.phase == Phase.LATERAL:
            return Phase.REPORTING
        if self.phase == Phase.REPORTING:
            return Phase.COMPLETE
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current_phase": self.phase.value,
            "history": [p.value for p in self.history],
            "foothold_obtained": self.foothold_obtained,
            "root_obtained": self.root_obtained,
        }
