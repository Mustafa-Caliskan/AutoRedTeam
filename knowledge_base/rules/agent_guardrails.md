# 🛡️ AutoRedTeam Agent Operational Guardrails & Anti-Hallucination Standards

Derived from operational field lessons (pentest-agents & industry standards).
These rules govern both **DeepSeek V4 Flash (Orchestrator)** and **CyberStrike 35B (Worker)**.

## 🚫 Top Operational Rules (Zero Hallucination)

1. **Concrete Evidence on Disk:**
   - Terminal strings alone are not findings until matched against actual execution output (HTTP status code, banner string, database response).
   - If an endpoint or file was not confirmed, it cannot be reported as vulnerable.

2. **The Sibling Rule:**
   - If one API parameter, method, or endpoint is tested (e.g. GET /api/v1/user/1), also test siblings (POST /api/v1/user/1, GET /api/v1/users/1, DELETE /api/v1/user/1). Over 30% of critical IDORs occur on unlinked sibling methods.

3. **Demonstrate Real Impact, Not Speculation:**
   - Avoid speculative phrasing like *'this could theoretically allow...'* without proof.
   - Present the concrete finding: *'Target returned version vsftpd 2.3.4 which contains verified backdoor CVE-2011-2523, confirmed via port 21 banner.'*

4. **Never Submit Fluff Alone:**
   - Informational findings like missing CSP headers, open redirect alone, or banner grabbing alone MUST NOT be logged as standalone High/Critical vulnerabilities.
   - Either chain them into a working exploit sequence or discard them to prevent noise.

5. **Tool Loop Prevention:**
   - If an Nmap or Nikto scan has already completed for a port range, DO NOT re-run identical scans. Proceed immediately to service-specific vulnerability lookup and parameter probing.
