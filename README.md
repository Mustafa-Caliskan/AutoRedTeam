# AutoRedTeam

An autonomous red teaming framework for evaluating the security posture of enterprise LLM agents against adversarial prompt injection, credential exfiltration, and agentic privilege escalation attacks.

Developed as part of the Microsoft AI Innovators portfolio.

---

## Architecture

```
Attacker (CyberStrike 35B Abliterated — RunPod vLLM)
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
| **Attacker Engine** | huihui-ai/huihui-cyberstrike-offsec-35b-abliterated | RunPod vLLM (H100 80 GB) |
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

# With CyberStrike 35B attacker for dynamic payload generation
python main.py --mode openai --attacker-endpoint https://<pod-id>-8000.proxy.runpod.net/v1
```

### RunPod vLLM Mode (custom victim model)

```bash
python main.py --mode runpod --endpoint https://<pod-id>-8000.proxy.runpod.net/v1 --target auto
```

### Security Assessment Assistant (Human-in-the-Loop)

> ⚠️ **EĞİTİM / TEST AMAÇLI ORTAM**  
> Bu mod, güvenlik topluluğunun resmi olarak sağladığı, **kasıtlı olarak
> zafiyetli** açık kaynak eğitim uygulamaları üzerinde çalışır:
> - **OWASP Juice Shop** (web-uygulama seviyesi) → [owasp.org/www-project-juice-shop](https://owasp.org/www-project-juice-shop)
> - **Metasploitable2** (network/servis seviyesi) → Rapid7 tarafından yayınlanır
>
> Yalnızca kendi Docker konteynerlerinizde, localhost üzerinde yetkili testler
> içindir. Üçüncü taraf, izinsiz hiçbir sisteme bağlanılmaz.

Bu mod, **insan onaylı (human-in-the-loop)** bir güvenlik değerlendirme
asistanıdır. LLM yalnızca **öneri** sunar; hiçbir komutu doğrudan çalıştıramaz.
Her adım terminalde gösterilir ve kullanıcının `input()` onayı (`y`/`n`) ile
çalıştırılır.

**Kapsam Kısıtı:** Yalnızca `config/allowed_targets.txt` içinde tanımlı
hedefler kabul edilir:
- `localhost:3000` → OWASP Juice Shop
- `metasploitable2` → Metasploitable2 (servis adı)

Kapsam dışı hedefler kod seviyesinde `is_target_allowed()` ile reddedilir ve
`data/assessment_audit_log.jsonl` içine `REJECTED_OUT_OF_SCOPE` olarak yazılır.

#### Kurulum (Docker)

Tek komutla **OWASP Juice Shop**, **Metasploitable2** ve **tarama araçları
konteyneri** (nmap, gobuster, nikto, whatweb, sqlmap, testssl.sh, searchsploit)
ayağa kalkar. Başka hiçbir manuel `apt install` gerekmez:

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

- **Juice Shop:** `http://localhost:3000`
- **Metasploitable2:** yalnızca localhost'a bağlı (`127.0.0.1:2222` SSH, `127.0.0.1:8081` HTTP), dış dünyaya KAPALI
- **Araç konteyneri:** `autoredteam-assessment-tools` (aynı `assessment-net`
  ağında; tools konteyneri Juice Shop'a `juice-shop:3000`, Metasploitable2'ye
  `metasploitable2` servis adıyla erişir)

#### Araç Erişilebilirlik Kontrolü

Tüm araçların gerçekten erişilebilir olduğunu doğrulamak için:

```bash
python main.py --mode check-tools
# veya doğrudan:
python scripts/check_tools.py
```

Bu, her aracın sürümünü kontrol edip tablo halinde raporlar. Araçlar Docker
konteyneri içinde çalışıyorsa `🐳 Docker konteyneri`, değilse `💻 Host` olarak
işaretlenir.

#### Değerlendirme Asistanını Çalıştırma

```bash
# Mock LLM ile (API anahtarı gerekmez)
python main.py --mode assessment --assessment-target localhost:3000

# OpenAI LLM ile (OPENAI_API_KEY .env'de olmalı)
python main.py --mode assessment --assessment-llm-provider openai

# RunPod vLLM ile (endpoint ve key verilir)
python main.py --mode assessment --assessment-llm-provider runpod \
    --endpoint https://<pod-id>-8000.proxy.runpod.net/v1 --api-key EMPTY
```

`--assessment-llm-provider` seçenekleri: `mock` (varsayılan), `runpod`, `openai`.
`--endpoint` ve `--api-key` argümanları LLM bağlantısı için kullanılır.

**Akış:** LLM bir sonraki adımı önerir → kullanıcı onaylar/reddeder →
onaylanırsa güvenli wrapper ile çalıştırılır → çıktı LLM'e geri verilir →
LLM bulguyu yorumlar ve bir sonraki öneriyi sunar. `dur` yazarak istediğiniz
an durabilirsiniz. En fazla 20 önerilen adım (sonsuz döngü koruması).

**Entegre araçlar (her biri ayrı onay adımı):**

| Araç | Amaç | Güvenlik Notu |
| :--- | :--- | :--- |
| `nmap` | Port/servis keşfi | Yalnızca `-sV -sC` (non-destructive) |
| `gobuster` | Dizin/endpoint keşfi | GET tabanlı keşif |
| `nikto` | Web sunucu zafiyet taraması | Pasif tarayıcı |
| `whatweb` | Teknoloji yığını tespiti | Pasif fingerprinting |
| `ssl_check` | TLS/SSL konfigürasyon kontrolü | Salt okunur denetim |
| `sqlmap` | SQL Injection **tespiti** | **Yalnızca `--batch --level=1 --risk=1`; dump/exploit YASAK** |
| `searchsploit` | Bilinen CVE/exploit kayıtlarını listele | **LOOKUP-ONLY; exploit ÇALIŞTIRMAZ** |

> 💡 **İpucu:** `nmap` bir servis/versiyon tespit ettiğinde (örn. Apache 2.2.8,
> MySQL 5.0.51a), sıradaki mantıklı adım genelde `searchsploit` ile o versiyon
> için bilinen zafiyetleri aramaktır.

**Hedef seçimi:**

```bash
# OWASP Juice Shop (web-uygulama seviyesi)
python main.py --mode assessment --assessment-target localhost:3000

# Metasploitable2 (network/servis seviyesi)
python main.py --mode assessment --assessment-target metasploitable2
```

**Çıktılar:**

| Dosya | Açıklama |
| :--- | :--- |
| `data/assessment_findings.jsonl` | Kaydedilen bulgular (FIND-xxx) |
| `reports/assessment_report.md` | OWASP WSTG referanslı değerlendirme raporu |
| `data/assessment_audit_log.jsonl` | Onay / red / kapsam dışı denetim kayıtları |

---

## Outputs

| File | Description |
| :--- | :--- |
| `reports/security_audit_report.md` | Full security audit with OWASP/MITRE mapping and RAG-powered remediation steps |
| `reports/assessment_report.md` | Human-in-the-loop security assessment report (OWASP WSTG) |
| `data/benchmark_results.jsonl` | Hugging Face-compatible benchmark dataset |
| `data/assessment_findings.jsonl` | Recorded assessment findings (FIND-xxx) |
| `data/corporate.db` | SQLite corporate database with seeded injection payloads |

---

## Deploying the Attacker Model (RunPod)

**Recommended GPU:** H100 (80 GB VRAM)  
**Model:** CyberStrike 35B Abliterated (e.g. `huihui-ai/huihui-cyberstrike-offsec-35b-abliterated`)

```bash
python3 -m vllm.entrypoints.openai.api_server \
  --model huihui-ai/huihui-cyberstrike-offsec-35b-abliterated \
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
