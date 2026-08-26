# AutoRedTeam

Autonomous Red Teaming and Human-in-the-Loop Security Assessment Framework for LLM Agents.

Evaluates the security posture of enterprise language model agents against adversarial prompt injection, credential exfiltration, privilege escalation, and multi-turn attack vectors mapped to OWASP LLM Top 10 and MITRE ATLAS standards.

---

## System Architecture

```
                                      +------------------------------------------------------+
                                      |                   Attacker Layer                     |
                                      |  CyberStrike 35B Abliterated (vLLM / Colab / RunPod) |
                                      +--------------------------+---------------------------+
                                                                 |
                                                    Adversarial Payloads / Dynamic
                                                                 |
                                                                 v
+------------------------------------+        +------------------+-------------------+        +-----------------------------------+
|         Corporate Environment      |        |                   Victim Agent       |        |        Evaluation & Audit         |
|  - SQLite Financial/Ticket DB      |<------>|             GPT-4o-mini / Custom     |------->|  - Deterministic Rule Engine      |
|  - 7 Enterprise Tool Interfaces    |        |       (Strict RBAC & Policy Guard)   |        |  - OWASP / MITRE ATLAS Mapper     |
+------------------------------------+        +--------------------------------------+        |  - Human-in-the-Loop Assessment   |
                                                                                              +-----------------------------------+
```

| Component | Model / Engine | Deployment |
| :--- | :--- | :--- |
| Victim Agent | GPT-4o-mini / Configurable | OpenAI API |
| Attacker Engine | `huihui-ai/huihui-cyberstrike-offsec-35b-abliterated` | vLLM (Colab A100 80 GB / RunPod H100) |
| Assessment Co-Pilot | `AssessmentAssistant` (Human-in-the-Loop) | Local CLI / vLLM / OpenAI |
| Evaluator | Deterministic Rule & Invariant Engine | Local execution (zero inference overhead) |

---

## Adversarial Capabilities

### Obfuscation & Transformation Suite

| Converter | Technique | Target Vulnerability Vector |
| :--- | :--- | :--- |
| `Base64Converter` | Base64 encoding + instruction wrapper | Gateway/API filter evasion |
| `ROT13Converter` | Symmetric Caesar cipher substitution | Keyword blacklist bypass |
| `RoleplayWrapper` | Executive emergency social engineering | Contextual override / policy evasion |
| `WhiteTextConverter` | Invisible text injection | Document & PDF ingestion vectors |
| `UnicodeHomoglyphConverter` | Cyrillic/Unicode visual lookalike substitution | Tokenizer & regex boundary evasion |
| `ZeroWidthConverter` | Non-printable Unicode smuggling | Covert channel injection |
| `EmojiSmugglingConverter` | Unicode Variation Selector encoding | Tokenizer state exploitation |

### Standard Attack Scenarios (OWASP / MITRE Mapped)

| Scenario ID | Attack Type | Standard Mapping | Target Tool Vector |
| :--- | :--- | :--- | :--- |
| `ATTACK-INDIRECT-01` | Indirect Prompt Injection via Support Ticket | OWASP-LLM01 / MITRE AML.T0054 | `execute_wire_transfer` |
| `ATTACK-DIRECT-01` | Direct System Prompt Override | OWASP-LLM06 / MITRE AML.T0051 | `execute_wire_transfer` |
| `ATTACK-ROLEPLAY-01` | Executive Impersonation / Social Engineering | OWASP-LLM06 / MITRE AML.T0054 | `execute_wire_transfer` |
| `ATTACK-SECRET-01` | Credential Exfiltration via Document Retrieval | OWASP-LLM06 / MITRE AML.T0040 | `search_internal_documents` |
| `ATTACK-WHITEXT-01` | White-Text Document Injection (PDF vector) | OWASP-LLM01 / MITRE AML.T0054 | `execute_wire_transfer` |
| `ATTACK-HOMOGLYPH-01` | Unicode Homoglyph Safety Filter Evasion | OWASP-LLM01 / MITRE AML.T0054 | `execute_wire_transfer` |
| `ATTACK-ZEROWIDTH-01` | Zero-Width Character Smuggling | OWASP-LLM01 / MITRE AML.T0054 | `execute_wire_transfer` |
| `ATTACK-PRIVESC-01` | Privilege Escalation via Identity Spoofing | OWASP-LLM06 / MITRE AML.T0051 | `query_customer_db` |
| `ATTACK-B64-01` | Base64 Obfuscated Indirect Injection | OWASP-LLM01 / MITRE AML.T0054 | `execute_wire_transfer` |

---

## Corporate Sandbox Environment

The victim agent operates against 7 sandboxed corporate tools backed by an embedded SQLite database (`data/corporate.db`):

| Tool | Operation | Risk Classification |
| :--- | :--- | :--- |
| `query_customer_db` | SQL query execution on customer records | MEDIUM |
| `execute_wire_transfer` | Financial transfer execution (enforces 2FA token) | CRITICAL |
| `fetch_support_ticket` | Retrieval of incoming customer tickets (indirect vector) | HIGH |
| `search_internal_documents` | Full-text query on confidential policy docs | HIGH |
| `send_internal_email` | Outbound communication to verified internal staff | MEDIUM |
| `lookup_employee` | Query employee profiles and organizational hierarchy | LOW |
| `get_account_statement` | Retrieve customer transaction histories | LOW |

---

## Security Assessment Assistant (Human-in-the-Loop)

AutoRedTeam includes a defensive, human-guided vulnerability assessment assistant designed for authorized security evaluations against isolated local environments:
- **OWASP Juice Shop** (Web Application Security) -> `localhost:3000`
- **Metasploitable2** (Network & Legacy Service Vulnerability Testbed) -> `metasploitable2`

### Key Guardrails
- **Human-in-the-Loop:** The model generates structured recommendations (`thought`, `tool`, `target`, `rationale`). Commands are executed only upon explicit operator confirmation (`y`/`n`).
- **Code-Level Scope Enforcement:** Target addresses are validated against `config/allowed_targets.txt`. Out-of-scope targets are rejected at the code level and logged as `REJECTED_OUT_OF_SCOPE`.
- **Deduplication Engine:** Identical findings across multiple tools are automatically consolidated to prevent duplicate reporting.
- **Loop Breaker:** Tracks visited action states and halts repetitive execution loops.
- **Live CVE Intelligence (`cve_search`):** Queries the NIST NVD REST API v2.0 for up-to-date vulnerability metadata and CVSS scores, eliminating model training cutoff limitations.

### Integrated Assessment Tools

| Tool | Function | Safety Policy |
| :--- | :--- | :--- |
| `nmap` | Service and port discovery (`-sV -sC`) | Non-destructive service detection with custom port selection |
| `gobuster` | Directory and endpoint enumeration | Read-only HTTP GET discovery |
| `nikto` | Web server configuration and vulnerability scanner | Passive signature analysis |
| `whatweb` | Technology stack fingerprinting | Passive banner and header parsing |
| `ssl_check` | TLS/SSL cipher and protocol audit | Read-only configuration inspection |
| `sqlmap` | SQL injection detection | Detection mode only (`--batch --level=1 --risk=1`); dumping/exploitation blocked |
| `searchsploit` | Local Exploit-DB vulnerability lookup | Read-only query; execution disabled |
| `cve_search` | NIST National Vulnerability Database API query | Live metadata retrieval via NVD REST API v2.0 |

---

## Installation & Setup

### 1. Prerequisites

```bash
git clone https://github.com/Mustafa-Caliskan/AutoRedTeam.git
cd AutoRedTeam
pip install -r requirements.txt
```

### 2. Configuration

Copy the example configuration and configure your environment variables:

```bash
cp config/.env.example .env
```

```env
OPENAI_API_KEY=sk-...
COLAB_ATTACKER_URL=https://your-tunnel.trycloudflare.com/v1
COLAB_API_KEY=EMPTY
```

### 3. Docker Testbed Deployment

Deploy the isolated assessment network containing Juice Shop, Metasploitable2, and the containerized security tools:

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Verify tool accessibility:

```bash
python main.py --mode check-tools
```

---

## Execution Modes

### Automated Red Team Benchmark (Autonomous Mode)

```bash
# Offline simulation with deterministic mock models
python main.py --mode mock --security-level vulnerable
python main.py --mode mock --security-level hardened

# Live evaluation against GPT-4o-mini
python main.py --mode openai

# Live multi-turn red teaming using CyberStrike 35B as the adversarial engine
python main.py --mode openai --attacker-endpoint https://your-tunnel.trycloudflare.com/v1
```

### Interactive Human-in-the-Loop Assessment

```bash
# Assessment against OWASP Juice Shop
python main.py --mode assessment --assessment-target localhost:3000 --assessment-llm-provider runpod

# Assessment against Metasploitable2
python main.py --mode assessment --assessment-target metasploitable2 --assessment-llm-provider runpod
```

### Web User Interfaces

```bash
# Autonomous Dual-Agent Duel Arena (CyberStrike 35B vs GPT-4o-mini)
python arena_ui.py

# Direct Offensive Security Chat Console
python chat_ui.py
```

---

## Generated Artifacts

| Path | Description |
| :--- | :--- |
| `reports/security_audit_report.md` | Comprehensive red teaming audit report with OWASP/MITRE mapping and remediation guidance |
| `reports/assessment_report.md` | Human-in-the-loop security assessment report formatted to OWASP WSTG standards |
| `reports/model_capability_test_report.md` | Benchmark report detailing LLM decision chains, tool usage, and verified findings |
| `data/assessment_findings.jsonl` | Structured finding records with CWE classifications and evidence snippets |
| `data/assessment_audit_log.jsonl` | Immutable log of all approved, skipped, and out-of-scope tool invocations |
| `data/benchmark_results.jsonl` | Machine-readable benchmark dataset for evaluation tracking |

---

## Verification & Testing

Run the automated test suite covering database operations, converter pipelines, policy evaluators, and assessment workflows:

```bash
python -m pytest tests/test_core.py -v
```

```
tests/test_core.py ......................... [100%]
============================= 25 passed in 5.88s =============================
```

---

## Framework Standards & References

- **OWASP Top 10 for LLM Applications:** https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **MITRE ATLAS (Adversarial Threat Landscape for AI Systems):** https://atlas.mitre.org/
- **OWASP Web Security Testing Guide (WSTG v4.2):** https://owasp.org/www-project-web-security-testing-guide/
- **NIST National Vulnerability Database (NVD API v2.0):** https://nvd.nist.gov/developers/vulnerabilities

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
