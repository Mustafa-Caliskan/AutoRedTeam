"""
AutoRedTeam - Verifier (Kanit Dogrulayici).

Exploit/privesc sonuclarini alir; gercekten basarili olup olmadigini somut
kanitla dogrular (uid=0, dosya icerigi, DB dump, banner). Yanlis pozitifleri
filtreler ve her bulguya guven skoru atar.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class Evidence:
    """Yapilandirilmis kanit."""
    command: str = ""
    output: str = ""
    verified: bool = False
    verification_method: str = ""  # uid_check | file_content | db_dump | banner | none
    confidence: float = 0.0  # 0.0 - 1.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "output": self.output[:2000],
            "verified": self.verified,
            "verification_method": self.verification_method,
            "confidence": self.confidence,
            "details": self.details,
        }


# Dogrulama desenleri
UID_ROOT_PATTERN = re.compile(r"uid=0\(root\)")
UID_ANY_PATTERN = re.compile(r"uid=\d+\((\w+)\)")
SHELL_PROMPT_PATTERN = re.compile(r"root@[\w.-]+[:#]")
DB_DUMP_PATTERN = re.compile(r"(Database|information_schema|mysql)", re.IGNORECASE)


class Verifier:
    """
    Exploit sonuclarini kanitla dogrular.
    """

    def verify_exploit(
        self,
        result: Dict[str, Any],
        expected: Optional[str] = None,
    ) -> Evidence:
        """
        Exploit sonucunu dogrular.

        Args:
            result: exploit_runner ciktisi (success, output, evidence icerir)
            expected: beklenen kanit tipi (uid_check, file_content vb.)
        """
        output = str(result.get("output", ""))
        command = str(result.get("command", ""))
        evidence = Evidence(command=command, output=output)

        # 1. uid=0(root) kontrolu (en guclu kanit)
        if UID_ROOT_PATTERN.search(output):
            evidence.verified = True
            evidence.verification_method = "uid_check"
            evidence.confidence = 1.0
            evidence.details["privilege"] = "root"
            return evidence

        # 2. Herhangi bir uid (kullanici seviyesi erisim)
        uid_match = UID_ANY_PATTERN.search(output)
        if uid_match:
            evidence.verified = True
            evidence.verification_method = "uid_check"
            evidence.confidence = 0.8
            evidence.details["privilege"] = uid_match.group(1)
            return evidence

        # 3. Shell promptu
        if SHELL_PROMPT_PATTERN.search(output):
            evidence.verified = True
            evidence.verification_method = "shell_prompt"
            evidence.confidence = 0.7
            return evidence

        # 4. DB dump
        if DB_DUMP_PATTERN.search(output):
            evidence.verified = True
            evidence.verification_method = "db_dump"
            evidence.confidence = 0.75
            return evidence

        # 5. Sonuc success bayragina guven (dusuk guven)
        if result.get("success"):
            evidence.verified = True
            evidence.verification_method = "flag"
            evidence.confidence = 0.5
            return evidence

        evidence.verified = False
        evidence.verification_method = "none"
        evidence.confidence = 0.0
        return evidence

    def verify_finding(self, finding: Dict[str, Any]) -> Evidence:
        """Bir bulgunun gercekten zafiyet oldugunu dogrular."""
        evidence_text = str(finding.get("evidence_snippet", ""))
        category = str(finding.get("category", ""))
        ev = Evidence(output=evidence_text)

        # Versiyon tespiti -> dusuk guven (gercek istismar degil)
        if "version" in category.lower() or "software" in category.lower():
            ev.verified = True
            ev.verification_method = "banner"
            ev.confidence = 0.3
            return ev

        # Exploit/privesc -> yuksek guven
        if finding.get("tool") in ("exploit", "privesc"):
            if UID_ROOT_PATTERN.search(evidence_text):
                ev.verified = True
                ev.verification_method = "uid_check"
                ev.confidence = 1.0
                return ev

        ev.verified = bool(evidence_text)
        ev.verification_method = "text"
        ev.confidence = 0.4
        return ev

    def is_false_positive(self, evidence: Evidence) -> bool:
        """Yanlis pozitif tespiti."""
        return not evidence.verified or evidence.confidence < 0.3


# Modul seviyesinde tekil ornek
verifier = Verifier()
