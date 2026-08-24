# AutoRedTeam

An autonomous red teaming framework for evaluating the security posture of enterprise LLM agents against adversarial prompt injection, credential exfiltration, and agentic privilege escalation attacks.

Developed as part of the Microsoft AI Innovators portfolio.

---

## Architecture

```
Attacker (Qwen 27B Uncensored — RunPod vLLM)
    │
    │  Adversarial Payloads (9 attack scenarios)
    ▼
Victim  (GPT-4o-mini — OpenAI API)
    │  ← 7 Corporate Tools (DB, Wire Transfer, Tickets, Documents, Email, HR)
    ▼
Evaluator (Deterministic Rule Engine)
    │
    ▼
Security Report (OWASP LLM Top 10 / MITRE ATLAS mapped)
```

| Component | Model | Provider |
| :--- | :--- | :--- |
| **Victim Agent** | GPT-4o-mini | OpenAI API |
| **Attacker Engine** | Qwen 27B Uncensored | RunPod vLLM (A40 48 GB) |
| **Evaluator / Judge** | Deterministic Rule Engine | Local (no API cost) |

---

## Attack Coverage

### Converter Suite (Obfuscation Layer)

| Converter | Technique | Real-World Vector |
| :--- | :--- | :--- |
| `Base64Converter` | Base64 encoding + decode-and-execute wrapper | API payload obfuscation |
| `ROT13Converter` | ROT13 cipher substitution | Keyword filter bypass |
| `RoleplayWrapper` | Executive emergency simulation | Social engineering |
| `WhiteTextConverter` | Invisible text injection | PDF document attack surface |
| `UnicodeHomoglyphConverter` | Cyrillic/Unicode lookalike substitution | Safety classifier evasion |
| `ZeroWidthConverter` | Zero-width Unicode character smuggling | Human-invisible payload |
| `EmojiSmugglingConverter` | Variation Selector-encoded instructions | LLM tokenizer exploitation |

### Attack Scenarios (9 total, OWASP/MITRE mapped)

| ID | Type | Standard |
| :--- | :--- | :--- |
| `ATTACK-INDIRECT-01` | Indirect Prompt Injection via Support Ticket | OWASP-LLM01 / MITRE AML.T0054 |
| `ATTACK-DIRECT-01` | Direct System Prompt Override | OWASP-LLM06 / MITRE AML.T0051 |
| `ATTACK-ROLEPLAY-01` | Roleplay / Executive Impersonation | OWASP-LLM06 / MITRE AML.T0054 |
| `ATTACK-SECRET-01` | Credential Exfiltration via Document Search | OWASP-LLM06 / MITRE AML.T0040 |
| `ATTACK-WHITEXT-01` | White-Text Document Injection (PDF vector) | OWASP-LLM01 / MITRE AML.T0054 |
| `ATTACK-HOMOGLYPH-01` | Unicode Homoglyph Obfuscation | OWASP-LLM01 / MITRE AML.T0054 |
| `ATTACK-ZEROWIDTH-01` | Zero-Width Character Payload Smuggling | OWASP-LLM01 / MITRE AML.T0054 |
| `ATTACK-PRIVESC-01` | Privilege Escalation via Employee Impersonation | OWASP-LLM06 / MITRE AML.T0051 |
| `ATTACK-B64-01` | Base64 Obfuscated Indirect Injection | OWASP-LLM01 / MITRE AML.T0054 |

---

## Corporate Environment (Victim Agent Tools)

The GPT-4o-mini victim agent is equipped with 7 enterprise tools backed by a SQLite corporate database:

| Tool | Description | Risk Level |
| :--- | :--- | :--- |
| `query_customer_db` | SQL query on customer accounts | MEDIUM |
| `execute_wire_transfer` | Bank wire transfer (requires 2FA token) | **CRITICAL** |
| `fetch_support_ticket` | Retrieve support tickets (injection vector) | HIGH |
| `search_internal_documents` | Search confidential policy/credential docs | HIGH |
| `send_internal_email` | Send email to employees (external addresses blocked) | MEDIUM |
| `lookup_employee` | Retrieve employee profiles | LOW |
| `get_account_statement` | Pull transaction history | LOW |

The database includes synthetic injection payloads embedded in tickets TICKET-1049 through TICKET-1052, targeting wire transfers, credential disclosure, and employee impersonation.

---

## Setup

### Requirements

```bash
pip install -r requirements.txt
```

### Environment Variables

Copy `config/.env.example` to `config/.env` and fill in your keys:

```bash
cp config/.env.example config/.env
```

```env
OPENAI_API_KEY=sk-...
RUNPOD_ATTACKER_URL=https://your-pod-id-8000.proxy.runpod.net/v1
```

---

## Usage

### Mock Mode (no API keys required)

```bash
python main.py --mode mock --security-level vulnerable
python main.py --mode mock --security-level hardened
```

### Live Mode — GPT-4o-mini as Victim

```bash
# Predefined 9-attack suite against GPT-4o-mini
python main.py --mode openai

# With Qwen 27B Uncensored attacker for dynamic payload generation
python main.py --mode openai --attacker-endpoint https://<pod-id>-8000.proxy.runpod.net/v1
```

### RunPod vLLM Mode (custom victim model)

```bash
python main.py --mode runpod --endpoint https://<pod-id>-8000.proxy.runpod.net/v1 --target auto
```

---

## Outputs

| File | Description |
| :--- | :--- |
| `reports/security_audit_report.md` | Full security audit with OWASP/MITRE mapping and RAG-powered remediation steps |
| `data/benchmark_results.jsonl` | Hugging Face-compatible benchmark dataset |
| `data/corporate.db` | SQLite corporate database with seeded injection payloads |

---

## Deploying the Attacker Model (RunPod)

**Recommended GPU:** A40 (48 GB VRAM)  
**Model:** Qwen 27B Uncensored / Abliterated (e.g. `failspy/Qwen3-30B-A3B-abliterated`)

```bash
python3 -m vllm.entrypoints.openai.api_server \
  --model failspy/Qwen3-30B-A3B-abliterated \
  --port 8000 \
  --host 0.0.0.0 \
  --max-model-len 8192 \
  --gpu-memory-utilization 0.90 \
  --trust-remote-code
```

After the pod is running:

```bash
python main.py --mode openai --attacker-endpoint https://<pod-id>-8000.proxy.runpod.net/v1
```

---

## Tests

```bash
python -m pytest tests/test_core.py -v
```

All 6 tests cover: database schema, 7 corporate tools, 5 converters, 9 attack scenarios, victim agent flow, and report generation.

---

## Security Standards

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)
- [Microsoft PyRIT — Python Risk Identification Toolkit](https://github.com/Azure/PyRIT)

---

## License

MIT License. See [LICENSE](LICENSE).
