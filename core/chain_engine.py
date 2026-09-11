# core/chain_engine.py
"""
Exploit Chaining Engine for AutoRedTeam.
Derived from pentest-agents (rules/chain-table.md) and advanced penetration testing methodologies.

Implements the Chain Walk Algorithm:
Transforms isolated low/medium primitives into high/critical impact attack chains
(e.g., Info Disclosure + Leak -> Credential Replay -> Admin Takeover).
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger("autoredteam.chain_engine")

DEFAULT_CHAIN_PATH = Path(__file__).parent.parent / "knowledge_base" / "rules" / "chain_table.json"


class ChainEngine:
    """
    Analyzes verified findings and suggests multi-hop exploit escalation chains.
    """

    def __init__(self, chain_path: Optional[Path] = None):
        self.chain_path = Path(chain_path) if chain_path else DEFAULT_CHAIN_PATH
        self.chains_by_primitive: Dict[str, List[Dict[str, Any]]] = {}
        self._load_chains()

    def _load_chains(self):
        """Loads chain_table.json into memory."""
        if not self.chain_path.exists():
            logger.warning(f"Chain table not found at {self.chain_path}. Using internal fallback chains.")
            self._apply_fallbacks()
            return

        try:
            with open(self.chain_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            chains = data.get("chains", [])
            for entry in chains:
                prim = entry.get("primitive", "").lower()
                if prim:
                    self.chains_by_primitive[prim] = entry.get("candidates", [])
            logger.info(f"Loaded {len(self.chains_by_primitive)} exploit chaining primitives into ChainEngine.")
        except Exception as e:
            logger.error(f"Failed to load chain table: {e}")
            self._apply_fallbacks()

    def _apply_fallbacks(self):
        self.chains_by_primitive = {
            "ssrf": [
                {"target": "Cloud Metadata API (169.254.169.254)", "technique": "AWS IAM Role Credential Extraction", "terminal_impact": "Cloud Account Takeover", "severity": "Critical"},
                {"target": "Internal Services (127.0.0.1)", "technique": "Unauthenticated Admin API Access", "terminal_impact": "Internal Network Compromise", "severity": "High"}
            ],
            "sql injection": [
                {"target": "Database System Tables", "technique": "Extract Password Hashes", "terminal_impact": "Administrative Takeover", "severity": "Critical"},
                {"target": "Underlying Host OS", "technique": "xp_cmdshell or INTO OUTFILE", "terminal_impact": "Remote Code Execution (RCE)", "severity": "Critical"}
            ],
            "information disclosure": [
                {"target": "Exposed Credentials / .env", "technique": "Replay credentials on admin portal", "terminal_impact": "Privilege Escalation", "severity": "High"},
                {"target": "Service Version Banners", "technique": "CVE correlation and exploit lookup", "terminal_impact": "Remote Code Execution", "severity": "Critical"}
            ]
        }

    def suggest_next_hops(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Takes a single finding and looks up next-link candidates in the Chain Table.
        """
        category = str(finding.get("category", "")).lower()
        evidence = str(finding.get("evidence_snippet", "")).lower()
        combined = f"{category} {evidence}"

        matched_candidates: List[Dict[str, Any]] = []

        for prim, candidates in self.chains_by_primitive.items():
            if prim in combined:
                matched_candidates.extend(candidates)

        # Heuristic fallbacks if exact primitive keyword not matched
        if not matched_candidates:
            if "sqli" in combined or "database" in combined or "injection" in combined:
                matched_candidates.extend(self.chains_by_primitive.get("sql injection", []))
            elif "ssrf" in combined or "metadata" in combined:
                matched_candidates.extend(self.chains_by_primitive.get("ssrf", []))
            elif "disclosure" in combined or "outdated" in combined or "banner" in combined or "cve" in combined:
                matched_candidates.extend(self.chains_by_primitive.get("information disclosure", []))
            elif any(k in combined for k in ["privesc", "root", "suid", "privilege", "backdoor", "rce", "daemon"]):
                matched_candidates.extend(self.chains_by_primitive.get("privilege escalation", []))

        return matched_candidates

    def build_chain_narrative(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Connects verified findings into a cohesive multi-step attack chain narrative.
        Returns a list of structured attack chain stories.
        Works with single findings as well as multi-step chains.
        """
        if not findings:
            return []

        chains: List[Dict[str, Any]] = []

        # Find initial foothold (e.g. recon/info disclosure/port banner)
        footholds = [f for f in findings if
                     "service" in f.get("category", "").lower()
                     or "port" in f.get("category", "").lower()
                     or "recon" in f.get("tool", "").lower()
                     or "nmap" in f.get("tool", "").lower()
                     or "disclosure" in f.get("category", "").lower()]
        exploits = [f for f in findings if
                    "cve" in (f.get("evidence_snippet") or "").lower()
                    or "backdoor" in (f.get("evidence_snippet") or "").lower()
                    or "execution" in f.get("category", "").lower()
                    or "injection" in f.get("category", "").lower()
                    or f.get("severity", "") in ("High", "Critical")]

        if footholds and exploits:
            # Multi-hop chain: foothold → exploit
            step1 = footholds[0]
            step2 = exploits[0]
            chain_story = {
                "title": f"Chained Exploit: {step1.get('category', 'Recon')} -> {step2.get('category', 'Exploit')}",
                "severity": "Critical",
                "steps": [
                    {
                        "step": 1,
                        "phase": "Initial Discovery & Surface Enumeration",
                        "finding_id": step1.get("finding_id"),
                        "tool": step1.get("tool"),
                        "detail": step1.get("evidence_snippet")
                    },
                    {
                        "step": 2,
                        "phase": "Vulnerability Correlation & Weaponization",
                        "finding_id": step2.get("finding_id"),
                        "tool": step2.get("tool"),
                        "detail": step2.get("evidence_snippet")
                    },
                    {
                        "step": 3,
                        "phase": "Terminal Impact",
                        "impact": "Unrestricted Remote Code Execution or Unauthorized Database Access on Target.",
                        "remediation": "Update the affected daemon and restrict network ingress exposure via firewall/security groups."
                    }
                ]
            }
            chains.append(chain_story)
        elif exploits:
            # Single exploit finding: generate a standalone chain
            step1 = exploits[0]
            hops = self.suggest_next_hops(step1)
            next_hop = hops[0] if hops else {"technique": "Privilege Escalation", "terminal_impact": "Full System Compromise"}
            chain_story = {
                "title": f"Standalone Exploit: {step1.get('category', 'Vulnerability')} -> {next_hop.get('technique', 'Escalation')}",
                "severity": step1.get("severity", "High"),
                "steps": [
                    {
                        "step": 1,
                        "phase": "Vulnerability Confirmed",
                        "finding_id": step1.get("finding_id"),
                        "tool": step1.get("tool", "assessment"),
                        "detail": step1.get("evidence_snippet")
                    },
                    {
                        "step": 2,
                        "phase": "Recommended Next Hop",
                        "impact": next_hop.get("terminal_impact", "Critical Impact"),
                        "remediation": "Apply vendor patches and enforce network segmentation to prevent lateral movement."
                    }
                ]
            }
            chains.append(chain_story)
        elif footholds:
            # Only recon findings: generate a reconnaissance chain
            step1 = footholds[0]
            chain_story = {
                "title": f"Reconnaissance Chain: {step1.get('category', 'Discovery')} -> CVE Research -> Exploit",
                "severity": "Medium",
                "steps": [
                    {
                        "step": 1,
                        "phase": "Attack Surface Discovery",
                        "finding_id": step1.get("finding_id"),
                        "tool": step1.get("tool", "nmap"),
                        "detail": step1.get("evidence_snippet")
                    },
                    {
                        "step": 2,
                        "phase": "Recommended Action",
                        "impact": "Run searchsploit/cve_search on discovered service versions to find exploitable CVEs.",
                        "remediation": "Ensure all discovered services are patched to latest versions and unnecessary ports are firewalled."
                    }
                ]
            }
            chains.append(chain_story)

        return chains

    def format_chain_summary(self, chains: List[Dict[str, Any]]) -> str:
        """Formats chain narratives into markdown for reports and prompt context."""
        if not chains:
            return "(No active exploit chains formed yet)"

        lines = []
        for c in chains:
            lines.append(f"### 🔗 {c.get('title', 'Attack Chain')} [Severity: {c.get('severity')}]")
            for s in c.get("steps", []):
                if "phase" in s and "tool" in s:
                    lines.append(f"- **Step {s.get('step')} ({s.get('phase')}):** Via `{s.get('tool')}` — {s.get('detail')}")
                elif "impact" in s:
                    lines.append(f"- **Step {s.get('step')} (Terminal Impact):** 💥 {s.get('impact')}")
            lines.append("")
        return "\n".join(lines)


# Singleton instance
chain_engine = ChainEngine()
