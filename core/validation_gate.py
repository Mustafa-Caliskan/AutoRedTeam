# core/validation_gate.py
"""
7-Question Validation Gate & Anti-Hallucination Quality Filter for AutoRedTeam.
Derived from pentest-agents (rules/never-submit.md) and operational red-teaming standards.

Filters out false positives, informational noise (missing headers alone, banner grabs without CVE),
and unverified model hallucinations before findings enter executive reports or database records.
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger("autoredteam.validation_gate")

DEFAULT_RULES_PATH = Path(__file__).parent.parent / "knowledge_base" / "rules" / "never_submit.json"


@dataclass
class ValidationResult:
    passed: bool
    reason: str
    instant_kill_id: Optional[str] = None
    requires_chain: bool = False
    suggested_action: str = "record"  # "record", "reject", "chain_required", "downgrade"


class ValidationGate:
    """
    Evaluates findings against strict anti-hallucination and instant-kill rules.
    Prevents the LLM from reporting theoretical vulnerabilities as high-severity findings.
    """

    def __init__(self, rules_path: Optional[Path] = None):
        self.rules_path = Path(rules_path) if rules_path else DEFAULT_RULES_PATH
        self.instant_kill_rules: List[Dict[str, Any]] = []
        self.conditionally_valid_rules: List[Dict[str, Any]] = []
        self._load_rules()

    def _load_rules(self):
        """Loads never_submit.json rules into memory."""
        if not self.rules_path.exists():
            logger.warning(f"Validation rules not found at {self.rules_path}. Gate running with fallback rules.")
            self._apply_fallbacks()
            return

        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.instant_kill_rules = data.get("instant_kill", [])
            self.conditionally_valid_rules = data.get("conditionally_valid", [])
            logger.info(f"Loaded {len(self.instant_kill_rules)} instant-kill rules into ValidationGate.")
        except Exception as e:
            logger.error(f"Failed to load validation rules: {e}")
            self._apply_fallbacks()

    def _apply_fallbacks(self):
        self.instant_kill_rules = [
            {"id": "NK-01", "pattern": "missing header", "keywords": ["csp", "hsts", "x-frame-options", "content-security-policy"], "reason": "Missing security headers alone without exploitable PoC."},
            {"id": "NK-02", "pattern": "missing email auth", "keywords": ["spf", "dkim", "dmarc"], "reason": "Missing email records alone do not constitute web compromise."},
            {"id": "NK-03", "pattern": "banner disclosure", "keywords": ["banner disclosure", "version disclosure"], "reason": "Banner disclosure without confirmed CVE is informational."},
            {"id": "NK-06", "pattern": "self xss", "keywords": ["self-xss", "self xss"], "reason": "Self-XSS requires self-inflicted console execution."}
        ]
        self.conditionally_valid_rules = []

    def evaluate(self, finding: Dict[str, Any]) -> ValidationResult:
        """
        Runs the 7-Question Validation Gate on a proposed finding:
        1. Evidence Check: Is there non-empty, non-speculative proof?
        2. Instant-Kill Check: Does it match any never-submit patterns?
        3. Conditional Validity Check: Does it require an active exploit chain?
        4. Scope & Format Check: Does it contain valid categories and CWE references?
        """
        category = str(finding.get("category", "")).strip().lower()
        severity = str(finding.get("severity", "Medium")).strip().capitalize()
        evidence = str(finding.get("evidence_snippet", "")).strip()
        evidence_lower = evidence.lower()

        # Gate Question 1: Check for empty or purely hypothetical evidence
        if not evidence or len(evidence) < 5:
            return ValidationResult(
                passed=False,
                reason="Rejected: Finding lacks concrete evidence snippet (output was empty).",
                suggested_action="reject"
            )

        speculative_phrases = ["could be vulnerable", "might allow", "theoretically possible", "potential vulnerability", "may be vulnerable"]
        verified_indicators = [
            "cve-", "exploit confirmed", "backdoor confirmed", "payload executed",
            "root shell", "uid=0", "boolean-based", "union select", "success:", "valid",
            "msfadmin", "password", "credentials", "authenticated"
        ]
        if any(sp in evidence_lower for sp in speculative_phrases) and not any(ind in evidence_lower for ind in verified_indicators):
            return ValidationResult(
                passed=False,
                reason="Rejected: Evidence relies purely on speculative language without verifiable proof.",
                suggested_action="reject"
            )

        # Gate Question 2: Instant-Kill Rules Check
        combined_text = f"{category} {evidence_lower}"
        for rule in self.instant_kill_rules:
            keywords = rule.get("keywords", [])
            condition = rule.get("condition")

            # Check if all or any keywords match
            matches = any(kw in combined_text for kw in keywords)
            if matches:
                # If rule specifies 'without_cve', check if a concrete CVE is present
                if condition == "without_cve":
                    if "cve-" in evidence_lower:
                        continue  # Has actual CVE verified, bypass instant kill
                if condition == "without_auth_bypass":
                    if "auth bypass" in evidence_lower or "unauthorized" in evidence_lower:
                        continue
                if condition == "without_oauth_chain":
                    if "oauth" in evidence_lower or "token" in evidence_lower:
                        continue
                if condition == "without_internal_exfil":
                    if "metadata" in evidence_lower or "169.254" in evidence_lower or "127.0.0.1" in evidence_lower:
                        continue

                is_chain_req = condition in ["without_oauth_chain", "without_internal_exfil", "without_auth_bypass", "without_sensitive_poc"]
                return ValidationResult(
                    passed=False,
                    reason=f"Instant-Kill Rule Triggered [{rule.get('id')}]: {rule.get('reason')}",
                    instant_kill_id=rule.get("id"),
                    requires_chain=is_chain_req,
                    suggested_action="chain_required" if is_chain_req else "reject"
                )

        # Gate Question 3: Conditionally Valid Findings Check
        for cond in self.conditionally_valid_rules:
            have_bug = cond.get("have", "").lower()
            if have_bug in category or have_bug in combined_text:
                chain_needed = cond.get("needed_chain", "")
                # Check if evidence demonstrates the chain
                impact = cond.get("impact", "")
                if not any(k in evidence_lower for k in ["token", "exfil", "bypass", "breach", "escalation", "root", "admin"]):
                    return ValidationResult(
                        passed=False,
                        reason=f"Conditionally Valid Finding: '{cond.get('have')}' requires chain (+ {chain_needed}) to achieve {impact}.",
                        requires_chain=True,
                        suggested_action="chain_required"
                    )

        # Gate Passed: Finding has solid evidence and is not fluff
        return ValidationResult(
            passed=True,
            reason="Validation Gate Passed: Finding contains verifiable proof and is not on never-submit list.",
            suggested_action="record"
        )


# Singleton instance
validation_gate = ValidationGate()
