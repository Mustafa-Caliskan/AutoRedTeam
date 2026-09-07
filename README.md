# AutoRedTeam

Next-Generation Dual-Engine Offensive Security & Red Teaming Platform.

AutoRedTeam bridges the gap between adversarial AI safety and traditional offensive security. It provides an enterprise-grade framework designed to evaluate both **autonomous language model agents** (adversarial prompt injection, privilege escalation, credential exfiltration) and **production infrastructure** (network services, APIs, and web application vulnerabilities) through a collaborative Parent-Worker LLM architecture.

---

## Strategic Architecture

The framework operates via two complementary offensive security engines powered by a unified model orchestration pipeline:

```
                                      +-------------------------------------------------------------+
                                      |                 STRATEGIC ORCHESTRATOR                      |
                                      |                     DeepSeek V3                             |
                                      |  - 4-Wave Strategic Triage Engine                           |
                                      |  - Global Attack Surface & State Tracking                   |
                                      |  - Real-Time Web Research (DuckDuckGo CVE / PoC Intel)      |
                                      +------------------------------+------------------------------+
                                                                     |
                                                       Strategic Directives & Context
                                                                     |
                                                                     v
                                      +-------------------------------------------------------------+
                                      |                 TACTICAL EXECUTION ENGINE                   |
                                      |             CyberStrike 35B Abliterated                     |
                                      |     (SGLang RadixAttention / NVIDIA A100 80 GB)             |
                                      +------------------------------+------------------------------+
                                                                     |
                                      +------------------------------+------------------------------+
                                      |                                                             |
                                      v                                                             v
              +-----------------------------------------------+             +-----------------------------------------------+
              |                   ENGINE 1:                   |             |                   ENGINE 2:                   |
              |            Adversarial AI Red Team            |             |         Infrastructure & App Pentesting       |
              |                                               |             |                                               |
              |  - 7 Obfuscation & Evasion Converters         |             |  - Human-in-the-Loop Defensive Co-Pilot       |
              |  - Corporate Agent Sandbox (AcmeCorp Banking) |             |  - Isolated Testbeds (Metasploitable2 / JS)   |
              |  - Multi-Turn Crescendo & Indirect Injection  |             |  - Automated Loop Breaker & Deduplication     |
              |  - OWASP LLM Top 10 & MITRE ATLAS Mapping     |             |  - Real-Time NIST NVD v2.0 CVE Correlation    |
              +-----------------------------------------------+             +-----------------------------------------------+
                                      |                                                             |
                                      +------------------------------+------------------------------+
                                                                     |
                                                                     v
                                      +-------------------------------------------------------------+
                                      |                 EVALUATION & AUDIT LAYER                    |
                                      |  - Deterministic Policy & Invariant Verification Engine     |
                                      |  - Machine-Readable Findings (JSONL) & WSTG Markdown Reports|
                                      +-------------------------------------------------------------+
```

### Model & Runtime Stack

| Role | Engine / Model | Runtime Infrastructure | Key Function |
| :--- | :--- | :--- | :--- |
| **Parent (Brain)** | DeepSeek V3 | Official API (`api.deepseek.com/v1`) | High-level strategy, triage planning, live web research |
| **Worker (Execution)** | `huihui-ai/huihui-cyberstrike-offsec-35b-abliterated` | SGLang (Colab A100 / RunPod H100) | Uncensored adversarial payload generation & tool invocation |
| **Victim Agent** | GPT-4o-mini / Configurable | OpenAI API | Target enterprise agent with tool-calling capabilities |
| **Inference Backend** | SGLang (RadixAttention) | CUDA 12.8 / Triton / FlashInfer | High-throughput prefix caching and constrained JSON decoding |
| **Live Intelligence** | NIST NVD API v2.0 + DuckDuckGo | RESTful / Zero-Key Engine | Real-time CVE scoring and zero-day advisory retrieval |

---

## Engine 1: Adversarial AI Red Teaming

Evaluates autonomous corporate agents against sophisticated adversarial prompt injection, jailbreaks, and unauthorized agency escalation.

### Obfuscation & Evasion Converters (PyRIT-Compatible)

| Converter | Technique | Security Boundary Targeted |
| :--- | :--- | :--- |
| `Base64Converter` | Base64 encoding + instruction wrapper | Gateway and proxy pattern filters |
| `ROT13Converter` | Caesar substitution cipher | Static keyword and regex blacklists |
| `RoleplayWrapper` | Executive emergency simulation | Safety alignment and policy constraints |
| `WhiteTextConverter` | Invisible text injection | Document and PDF ingestion vector |
| `UnicodeHomoglyphConverter` | Visual lookalike substitution | Tokenizer boundary and regex evasion |
| `ZeroWidthConverter` | Non-printable Unicode sequence smuggling | Hidden covert-channel injection |
| `EmojiSmugglingConverter` | Unicode Variation Selector encoding | Tokenizer state manipulation |

### Attack Scenarios & Standards Mapping

| Scenario ID | Attack Classification | Standard Mapping | Target Tool Vector |
| :--- | :--- | :--- | :--- |
| `ATTACK-INDIRECT-01` | Indirect Prompt Injection via Ticket System | OWASP-LLM01 / MITRE AML.T0054 | `execute_wire_transfer` |
| `ATTACK-DIRECT-01` | Direct System Prompt Override | OWASP-LLM06 / MITRE AML.T0051 | `execute_wire_transfer` |
| `ATTACK-ROLEPLAY-01` | Executive Impersonation / Social Engineering | OWASP-LLM06 / MITRE AML.T0054 | `execute_wire_transfer` |
| `ATTACK-SECRET-01` | Credential Exfiltration via File Search | OWASP-LLM06 / MITRE AML.T0040 | `search_internal_documents` |
| `ATTACK-WHITEXT-01` | White-Text Document Injection (PDF vector) | OWASP-LLM01 / MITRE AML.T0054 | `execute_wire_transfer` |
| `ATTACK-HOMOGLYPH-01`| Unicode Homoglyph Classifier Evasion | OWASP-LLM01 / MITRE AML.T0054 | `execute_wire_transfer` |
| `ATTACK-ZEROWIDTH-01`| Zero-Width Invisible Character Smuggling | OWASP-LLM01 / MITRE AML.T0054 | `execute_wire_transfer` |
| `ATTACK-PRIVESC-01`  | Privilege Escalation via Identity Spoofing | OWASP-LLM06 / MITRE AML.T0051 | `query_customer_db` |
| `ATTACK-B64-01`      | Base64 Obfuscated Indirect Injection | OWASP-LLM01 / MITRE AML.T0054 | `execute_wire_transfer` |

### Corporate Agent Sandbox (AcmeCorp)

The victim agent operates against a sandboxed financial and operations database (`data/corporate.db`) with 7 integrated tool interfaces:
- `execute_wire_transfer`: High-risk fund transfer requiring strict 2FA authentication.
- `fetch_support_ticket`: Ticket retrieval endpoint (primary indirect injection vector).
- `search_internal_documents`: Confidential document search (containing target credentials).
- `query_customer_db`: Customer record database access.
- `send_internal_email`: Internal organizational messaging.
- `lookup_employee`: Employee directory and clearance query.
- `get_account_statement`: Account balance and ledger history inspection.

---

## Engine 2: Autonomous Infrastructure & Application Pentesting

A defensive, Human-in-the-Loop vulnerability assessment assistant designed for authorized security evaluations against isolated local targets:
- **OWASP Juice Shop** (Modern Web Application Vulnerabilities) -> `localhost:3000`
- **Metasploitable2** (Legacy Network Services & Daemon Exploits) -> `metasploitable2`

### Security Guardrails & Control Mechanisms
- **Human-in-the-Loop Confirmation:** The model proposes actions (`thought`, `tool`, `target`, `rationale`); execution requires explicit human confirmation (`y`/`n`).
- **Code-Level Scope Enforcement:** Targets are validated against `config/allowed_targets.txt`. Out-of-scope destinations are blocked before execution.
- **State Memory & Loop Breaker:** Visited action states are recorded to prevent repetitive scanning.
- **Automated Finding Deduplication:** Multiple detections of identical issues are merged into verified entries.
- **Live CVE Intelligence (`cve_search`):** Real-time lookup via the NIST NVD REST API v2.0 to fetch up-to-date CVSS scores and vulnerability advisories.

### Integrated Assessment Tools

| Tool | Function | Safety Policy |
| :--- | :--- | :--- |
| `nmap` | Service and port enumeration (`-sV -sC`) | Non-destructive service detection with port targeting |
| `gobuster` | Web directory and endpoint discovery | Read-only HTTP GET enumeration |
| `nikto` | Web server configuration and vulnerability scanner | Passive signature analysis |
| `whatweb` | Technology stack fingerprinting | Passive banner and header parsing |
| `ssl_check` | TLS/SSL cipher and protocol audit | Read-only configuration inspection |
| `sqlmap` | SQL injection detection | Detection mode only (`--batch --level=1 --risk=1`); dumping disabled |
| `searchsploit` | Exploit-DB local vulnerability lookup | Read-only query; execution disabled |
| `cve_search` | NIST National Vulnerability Database API | Live metadata retrieval via NVD REST API v2.0 |
| `web_search` | Real-time web intelligence via DuckDuckGo | Live retrieval of exploit mechanics, PoCs, and advisories |

---

## Installation & Setup

### 1. Prerequisites

```bash
git clone https://github.com/Mustafa-Caliskan/AutoRedTeam.git
cd AutoRedTeam
pip install -r requirements.txt
```

### 2. Environment Configuration

Copy the example configuration and configure your environment variables:

```bash
cp config/.env.example .env
```

Configure `.env`:

```env
# Victim Agent
OPENAI_API_KEY=sk-...

# Attacker / Assessment Engine (SGLang on NVIDIA A100)
COLAB_ATTACKER_URL=https://your-tunnel.trycloudflare.com/v1
COLAB_API_KEY=EMPTY

# Strategic Orchestrator (DeepSeek V3)
DEEPSEEK_API_KEY=sk-...
```

### 3. Isolated Docker Testbed

Deploy the isolated assessment network:

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Verify tool connectivity:

```bash
python main.py --mode check-tools
```

---

## Execution Modes

### 1. Dual-Model Security Assessment (Orchestrator + CyberStrike 35B)

Runs an interactive security assessment where DeepSeek V3 provides strategic guidance and CyberStrike 35B executes tactical security actions:

```bash
# Assessment against OWASP Juice Shop
python main.py --mode assessment --assessment-target localhost:3000 --assessment-llm-provider colab

# Assessment against Metasploitable2
python main.py --mode assessment --assessment-target metasploitable2 --assessment-llm-provider colab
```

### 2. Autonomous Red Team Benchmark (AI Agent Evaluation)

Evaluates the victim agent against the adversarial attack suite:

```bash
# Offline simulation using deterministic mock models
python main.py --mode mock --security-level vulnerable
python main.py --mode mock --security-level hardened

# Live evaluation against GPT-4o-mini using CyberStrike 35B
python main.py --mode openai --attacker-endpoint https://your-tunnel.trycloudflare.com/v1
```

### 3. Web Interfaces

```bash
# Dual-Agent Duel Arena (CyberStrike 35B vs Corporate AI Agent)
python arena_ui.py

# Direct Offensive Security Chat Console
python chat_ui.py
```

---

## Generated Artifacts

| Path | Format | Description |
| :--- | :--- | :--- |
| `reports/security_audit_report.md` | Markdown | Comprehensive AI red teaming audit report with OWASP/MITRE mapping |
| `reports/assessment_report.md` | Markdown | Infrastructure assessment report formatted to OWASP WSTG standards |
| `reports/model_capability_test_report.md` | Markdown | Empirical evaluation report detailing decision chains and verified findings |
| `data/assessment_findings.jsonl` | JSONL | Machine-readable finding records with CWE classifications and evidence |
| `data/assessment_audit_log.jsonl` | JSONL | Immutable operational log of approved, skipped, and out-of-scope actions |
| `data/benchmark_results.jsonl` | JSONL | Evaluation tracking dataset for prompt injection benchmark results |

---

## Project Roadmap

- [x] **Phase 1: Core Pentest & Assessment Engine**
  - Containerized security tool execution (Nmap, Nikto, Gobuster, SQLmap, Searchsploit).
  - Isolated Docker testbed deployment (Juice Shop + Metasploitable2).
  - Deterministic finding deduplication and loop-breaker state machine.
  - Live NIST NVD v2.0 API integration.
- [x] **Phase 2: Dual-Model Orchestration & Accelerated Inference**
  - SGLang inference engine integration with RadixAttention KV-cache acceleration.
  - DeepSeek V3 Strategic Orchestrator (Parent Brain) implementation.
  - Zero-key DuckDuckGo live web research tool for real-time exploit discovery.
  - Synchronized multi-wave tactical triage protocols.
- [ ] **Phase 3: Autonomous AI Agent Red Teaming v2.0**
  - Automated multi-turn jailbreak campaigns with tree-of-attacks exploration.
  - Adaptive converter mutation engine based on victim refusal classification.
  - Real-time LLM vulnerability benchmark leaderboard and exportable compliance scorecards.

---

## Verification & Testing

Run the automated test suite:

```bash
python -m pytest tests/ -v
```

```
============================= 31 passed in 1.59s =============================
```

---

## Standards & References

- **OWASP Top 10 for LLM Applications:** https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **MITRE ATLAS (Adversarial Threat Landscape for AI Systems):** https://atlas.mitre.org/
- **OWASP Web Security Testing Guide (WSTG v4.2):** https://owasp.org/www-project-web-security-testing-guide/
- **NIST National Vulnerability Database (NVD API v2.0):** https://nvd.nist.gov/developers/vulnerabilities

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
