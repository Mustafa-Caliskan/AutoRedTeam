# core/skill_loader.py
"""
Skill Loader for AutoRedTeam.
Indexes and progressively loads structured cybersecurity skills from
knowledge_base/index.json (818 structured skills following agentskills.io standard).

Enables DeepSeek V4 Flash (Orchestrator) and CyberStrike 35B (Worker) to query
specialized playbooks dynamically without inflating the LLM context window.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger("autoredteam.skill_loader")

DEFAULT_INDEX_PATH = Path(__file__).parent.parent / "knowledge_base" / "index.json"


class SkillLoader:
    """
    Fast in-memory indexer and progressive disclosure loader for 800+ cybersecurity skills.
    """

    def __init__(self, index_path: Optional[Path] = None):
        self.index_path = Path(index_path) if index_path else DEFAULT_INDEX_PATH
        self.skills: List[Dict[str, Any]] = []
        self.skills_by_name: Dict[str, Dict[str, Any]] = {}
        self._load_index()

    def _load_index(self):
        """Loads and indexes all skills from the index.json file."""
        if not self.index_path.exists():
            logger.warning(f"Skills index not found at {self.index_path}. Using empty index.")
            return

        try:
            with open(self.index_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            raw_skills = data.get("skills", []) if isinstance(data, dict) else data
            self.skills = raw_skills
            self.skills_by_name = {s.get("name", ""): s for s in self.skills if s.get("name")}
            logger.info(f"Loaded {len(self.skills)} cybersecurity skills into index.")
        except Exception as e:
            logger.error(f"Failed to parse skills index at {self.index_path}: {e}")

    @property
    def total_skills(self) -> int:
        return len(self.skills)

    def search(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Performs lightweight keyword search across skill names and descriptions.
        Returns top matching skills with concise summaries (~30-50 tokens each).
        """
        if not query:
            return self.skills[:limit]

        q_terms = [t.lower().strip() for t in query.split() if t.strip()]
        scored: List[tuple[int, Dict[str, Any]]] = []

        for skill in self.skills:
            score = 0
            name = skill.get("name", "").lower()
            desc = skill.get("description", "").lower()

            for term in q_terms:
                if term in name:
                    score += 5  # Higher priority for name matches
                if term in desc:
                    score += 2

            if score > 0:
                scored.append((score, skill))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored[:limit]]

    def suggest_skills_for_target(
        self,
        target: str,
        open_ports: Optional[List[int]] = None,
        services: Optional[List[str]] = None,
        limit: int = 6
    ) -> List[Dict[str, Any]]:
        """
        Recommends targeted playbooks based on discovered open ports and services.
        """
        queries: List[str] = []
        open_ports = open_ports or []
        services = services or []

        # Port-based heuristics
        if 21 in open_ports or any("ftp" in s.lower() for s in services):
            queries.extend(["ftp", "vsftpd"])
        if 22 in open_ports or any("ssh" in s.lower() for s in services):
            queries.extend(["ssh brute", "ssh key"])
        if (
            80 in open_ports
            or 443 in open_ports
            or 3000 in open_ports
            or 8080 in open_ports
            or any("http" in s.lower() for s in services)
        ):
            queries.extend(["bola idor", "sql injection", "api gateway", "cross site scripting"])
        if 139 in open_ports or 445 in open_ports or any("samba" in s.lower() or "smb" in s.lower() for s in services):
            queries.extend(["smb", "samba", "active directory"])
        if 389 in open_ports or 88 in open_ports or any("ldap" in s.lower() or "kerberos" in s.lower() for s in services):
            queries.extend(["kerberoasting", "active directory acl", "shadow credentials"])
        if 3306 in open_ports or 5432 in open_ports or any("sql" in s.lower() for s in services):
            queries.extend(["database credential access", "sql injection"])

        # Target heuristic for AI / LLM targets
        if "ai" in target.lower() or "llm" in target.lower() or "agent" in target.lower():
            queries.extend(["prompt injection", "ai agent", "tool poisoning"])

        if not queries:
            queries = ["reconnaissance", "vulnerability scanning"]

        # Aggregate unique results
        seen_names = set()
        results: List[Dict[str, Any]] = []

        for q in queries:
            matches = self.search(q, limit=3)
            for m in matches:
                name = m.get("name")
                if name and name not in seen_names:
                    seen_names.add(name)
                    results.append(m)
                    if len(results) >= limit:
                        return results

        return results

    def format_for_prompt(self, skills: List[Dict[str, Any]]) -> str:
        """
        Formats a list of skills into a concise string suitable for model prompts.
        Keeps token count minimal (~40 tokens per skill).
        """
        if not skills:
            return "(No specialized skills currently matched)"

        lines = []
        for i, s in enumerate(skills, 1):
            name = s.get("name", "unknown")
            desc = s.get("description", "").strip()
            # Trim description to 160 chars for progressive efficiency
            short_desc = desc[:160] + "..." if len(desc) > 160 else desc
            lines.append(f"{i}. [{name}]: {short_desc}")
        return "\n".join(lines)


# Singleton instance for simple imports across core modules
skill_loader = SkillLoader()
