# 🛡️ AutoRedTeam — Security Assessment Assistant: Sistem Dokümantasyonu

> **Amaç:** Bu doküman, AutoRedTeam projesine eklenen **Security Assessment
> Assistant** modülünün ne yaptığını, nasıl çalıştığını ve her bileşenin
> görevini detaylı şekilde açıklar.
>
> **Temel Felsefe:** Bu araç **otonom değildir** ve asla otonom çalışmayacak
> şekilde tasarlanmıştır. LLM yalnızca **öneri** sunar; kararı her zaman insan
> verir. Bu, bir insan güvenlik uzmanının "co-pilot"u gibi çalışır.

---

## 📑 İçindekiler

1. [Genel Bakış](#1-genel-bakış)
2. [Mimari ve Bileşenler](#2-mimari-ve-bileşenler)
3. [İnsan Onaylı Akış (Human-in-the-Loop)](#3-insan-onaylı-akış)
4. [Kapsam Kısıtı ve Hedef Validasyonu](#4-kapsam-kısıtı-ve-hedef-validasyonu)
5. [Hedef Ortamlar](#5-hedef-ortamlar)
6. [Entegre Araçlar](#6-entegre-araçlar)
7. [Docker Altyapısı](#7-docker-altyapısı)
8. [Çıktılar ve Raporlama](#8-çıktılar-ve-raporlama)
9. [Kurulum ve Kullanım](#9-kurulum-ve-kullanım)
10. [Güvenlik Tasarım İlkeleri](#10-güvenlik-tasarım-ilkeleri)
11. [Testler](#11-testler)

---

## 1. Genel Bakış

**Security Assessment Assistant**, kurumsal bir LLM ajanının güvenliğini
denetlemek yerine, **insan güvenlik uzmanına yardımcı olan** bir modüldür.
Yerel Docker ortamında çalışan, **kasıtlı olarak zafiyetli** eğitim
uygulamalarını (OWASP Juice Shop, Metasploitable2) tarar.

**Neden var?**
- Geleneksel güvenlik taramaları tek başına yetersizdir; uzman bir analistin
  yönlendirmesi gerekir.
- LLM'ler güçlü analiz yapabilir ama **asla** doğrudan komut çalıştırmamalıdır.
- Bu modül, LLM'in analiz gücünü insan onayıyla birleştirir: LLM "şunu
  önerebilirim" der, insan "çalıştır" veya "atla" der.

**Kullanılan modeller:**
| Katman | Model | Rol |
| :--- | :--- | :--- |
| **Co-Pilot (LLM)** | Mock / OpenAI / RunPod | Analiz ve öneri üretir |
| **İnsan Operatör** | — | Karar verir, onaylar/reddeder |
| **Araç Konteyneri** | Kali Linux | Tarama araçlarını çalıştırır |

---

## 2. Mimari ve Bileşenler

```
┌─────────────────────────────────────────────────────────────────────┐
│                    HOST (Python)                                    │
│                                                                     │
│  main.py ──► run_assessment_assistant()                            │
│                  │                                                  │
│                  ▼                                                  │
│  core/assessment_assistant.py  (Co-Pilot Motoru)                   │
│    • LLM'den öneri ister (JSON)                                     │
│    • İnsan onayı alır (input y/n/dur)                               │
│    • Bulguları kaydeder, rapor üretir                               │
│                  │                                                  │
│                  ▼                                                  │
│  core/assessment_tools.py  (Güvenli Wrapper'lar)                    │
│    • is_target_allowed() → kapsam kontrolü                          │
│    • suggest_nmap_scan(), suggest_sqlmap_check(), ...               │
│    • _run_command() → docker exec ile çalıştırır                    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ docker exec
┌──────────────────────────────▼──────────────────────────────────────┐
│              DOCKER (assessment-net ağı)                            │
│                                                                     │
│  autoredteam-assessment-tools  (Kali: nmap, gobuster, nikto,        │
│                                 whatweb, sqlmap, testssl.sh,        │
│                                 searchsploit)                       │
│        │                                                             │
│        ├──► juice-shop:3000      (OWASP Juice Shop)                 │
│        └──► metasploitable2      (Metasploitable2)                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Bileşen Dosyaları

| Dosya | Görev |
| :--- | :--- |
| `main.py` | CLI giriş noktası; `--mode assessment` ve `--mode check-tools` |
| `core/assessment_assistant.py` | Co-Pilot motoru; LLM önerisi + insan onayı döngüsü |
| `core/assessment_tools.py` | Güvenli araç wrapper'ları + kapsam validasyonu |
| `core/config.py` | YAML konfigürasyon yükleyici |
| `config/allowed_targets.txt` | İzin verilen hedefler (kapsam listesi) |
| `docker/docker-compose.yml` | Juice Shop + Metasploitable2 + araç konteyneri |
| `docker/Dockerfile.assessment-tools` | Araç konteyneri imajı (Kali tabanlı) |
| `scripts/check_tools.py` | Araç erişilebilirlik kontrolü |
| `data/assessment_findings.jsonl` | Kaydedilen bulgular |
| `data/assessment_audit_log.jsonl` | Onay/red/kapsam dışı denetim kayıtları |
| `reports/assessment_report.md` | OWASP WSTG referanslı değerlendirme raporu |

---

## 3. İnsan Onaylı Akış

Modülün kalbi `AssessmentAssistant.run()` metodundaki döngüdür. Adım adım:

```
┌──────────────────────────────────────────────────────────────────────┐
│ 1. LLM'den öneri iste (JSON)                                        │
│    { "tool": "nmap", "target": "metasploitable2", ... }             │
│                                                                      │
│ 2. Öneriyi terminalde göster                                        │
│    "💡 LLM Önerisi: nmap / metasploitable2 / port keşfi"            │
│                                                                      │
│ 3. Kapsam kontrolü (is_target_allowed)                              │
│    • Kapsam dışıysa → BLOKLA, REJECTED_OUT_OF_SCOPE logla           │
│    • Kapsam içindeyse → devam et                                    │
│                                                                      │
│ 4. İnsan onayı iste (input)                                         │
│    "y" = evet çalıştır / "n" = hayır atla / "dur" = durdur          │
│                                                                      │
│ 5. Onaylandıysa → docker exec ile güvenli çalıştır                  │
│    Çıktıyı yakala ve göster                                          │
│                                                                      │
│ 6. Çıktıyı LLM'e geri ver → LLM yorumlar, bulgu kaydeder            │
│                                                                      │
│ 7. Adım 1'e dön (maks. 20 adım)                                     │
└──────────────────────────────────────────────────────────────────────┘
```

### Kritik Noktalar

- **LLM asla komut çalıştıramaz.** LLM'in tek çıktısı bir JSON önerisidir.
- **Kapsam dışı hedef, kullanıcıya sorulmadan bloklanır.** Bu, kod seviyesinde
  `is_target_allowed()` ile yapılır.
- **"n" (hayır) derse** LLM'e "kullanıcı bu adımı reddetti" bilgisi verilir ve
  alternatif bir öneri üretmesi istenir.
- **"dur" yazarsa** döngü anında durur.
- **Maksimum 20 adım** — sonsuz döngü koruması.

### LLM Öneri Formatı

LLM'in ürettiği JSON şu yapıda olmalıdır:

```json
{
  "thought": "nmap port 80'de Apache 2.2.8 tespit etti",
  "tool": "searchsploit",
  "target": "metasploitable2",
  "param": null,
  "service_name": "apache",
  "version": "2.2.8",
  "rationale": "Apache 2.2.8 için bilinen zafiyetleri aramak mantıklı"
}
```

LLM yanıtı saf JSON değilse (açıklama + JSON karışık, veya ` ```json ` code
fence içinde), `_parse_suggestion()` bunları temizleyip parse eder. Parse
başarısız olursa LLM'e "yalnızca JSON döndür" uyarısıyla **1 kez** daha sorulur,
sonra manuel moda düşülür.

---

## 4. Kapsam Kısıtı ve Hedef Validasyonu

**Kapsam kısıtı kod seviyesinde sabittir ve değiştirilemez.** Yalnızca
`config/allowed_targets.txt` içinde tanımlı hedefler kabul edilir.

### `is_target_allowed(target)`

Bu fonksiyon, hedefin allow-list'te olup olmadığını kontrol eder:

```python
def is_target_allowed(target: str) -> bool:
    allowed = load_allowed_targets()
    normalized = target.strip().lower()
    if normalized in allowed:
        return True
    for entry in allowed:
        if normalized == entry:
            return True
    return False
```

### Kapsam Dışı Davranış

Eğer LLM kapsam dışı bir hedef önerirse (örn. `evil.com`):

1. Komut **kullanıcıya sorulmadan** bloklanır.
2. `data/assessment_audit_log.jsonl` içine `REJECTED_OUT_OF_SCOPE` olarak yazılır.
3. Döngü bir sonraki öneriye geçer.

### Allow-List İçeriği

```
# OWASP Juice Shop (web-uygulama seviyesi) — Docker, localhost:3000
localhost:3000
# Metasploitable2 (network/servis seviyesi) — Docker, servis adı
metasploitable2
# Genel localhost erişimi
127.0.0.1
```

---

## 5. Hedef Ortamlar

Sistem iki farklı zafiyetli eğitim ortamını destekler:

| Hedef | Ortam | Seviye | Erişim |
| :--- | :--- | :--- | :--- |
| `localhost:3000` | OWASP Juice Shop | Web-uygulama | Host: `localhost:3000` |
| `metasploitable2` | Metasploitable2 | Network/servis | Host: `127.0.0.1:2222` (SSH), `127.0.0.1:8081` (HTTP) |

### Hedef Çözümleme (`_resolve_host`)

Araçlar Docker konteyneri içinde çalıştığında, hedef alias'ları Docker servis
adlarına çözülür. Bu, `TARGET_SERVICE_MAP` ile yapılır:

```python
TARGET_SERVICE_MAP = {
    "localhost:3000": "juice-shop",
    "localhost": "juice-shop",
    "127.0.0.1": "juice-shop",
    "127.0.0.1:3000": "juice-shop",
    "metasploitable2": "metasploitable2",
}
```

Örneğin, `nmap -sV -sC localhost:3000` komutu Docker içinde
`nmap -sV -sC juice-shop -p 3000` olarak çalışır. Böylece araç konteyneri,
hedef konteynere **servis adıyla** (aynı Docker ağında) erişir.

---

## 6. Entegre Araçlar

Her araç ayrı bir `suggest_*()` fonksiyonuyla sarılır ve **her biri ayrı bir
onay adımı** gerektirir. Hiçbiri kendi başına çalışmaz.

| Araç | Fonksiyon | Amaç | Güvenlik Notu |
| :--- | :--- | :--- | :--- |
| `nmap` | `suggest_nmap_scan` | Port/servis keşfi | Yalnızca `-sV -sC` (non-destructive) |
| `gobuster` | `suggest_gobuster_scan` | Dizin/endpoint keşfi | GET tabanlı keşif |
| `nikto` | `suggest_nikto_scan` | Web sunucu zafiyet taraması | Pasif tarayıcı |
| `whatweb` | `suggest_whatweb_scan` | Teknoloji yığını tespiti | Pasif fingerprinting |
| `ssl_check` | `suggest_ssl_check` | TLS/SSL konfigürasyon kontrolü | Salt okunur denetim |
| `sqlmap` | `suggest_sqlmap_check` | SQL Injection **tespiti** | **Yalnızca `--batch --level=1 --risk=1`; dump/exploit YASAK** |
| `searchsploit` | `suggest_searchsploit_lookup` | Bilinen CVE/exploit kayıtlarını listele | **LOOKUP-ONLY; exploit ÇALIŞTIRMAZ** |

### Araç Wrapper Deseni

Her `suggest_*()` fonksiyonu şu deseni izler:

```python
def suggest_nmap_scan(target: str, approved: bool = False) -> Dict[str, Any]:
    # 1. Kapsam kontrolü
    if not is_target_allowed(target):
        return _reject_out_of_scope(target, "nmap")

    # 2. Komutu oluştur (hedefi Docker servis adına çöz)
    exec_host = _resolve_host(target)
    exec_port = _resolve_port(target)
    command = f"nmap -sV -sC {exec_host} -p {exec_port}"

    # 3. Onaylandıysa çalıştır, değilse boş bırak
    output = _run_command(command) if approved else ""

    # 4. Yapılandırılmış sonuç döndür
    return _build_recommendation(
        tool="nmap", target=target, command=command,
        rationale=rationale, approved=approved, output=output
    )
```

### sqlmap Güvenlik Garantisi

`suggest_sqlmap_check()` **yalnızca tespit modunda** çalışır:

```
sqlmap -u "http://juice-shop:3000" -p id --batch --level=1 --risk=1
```

- `--dump`, `--os-shell`, `--exploit` gibi flag'ler **asla** kullanılmaz.
- Amaç yalnızca "parametre enjekte edilebilir mi?" sorusunu yanıtlamaktır.
- Bu, docstring'de ve kullanıcıya gösterilen onay mesajında açıkça belirtilir.

### searchsploit Güvenlik Garantisi

`suggest_searchsploit_lookup()` **yalnızca bilgi amaçlıdır**:

```
searchsploit apache 2.2.8
```

- Exploit-DB'de kayıtlı CVE/exploit kayıtlarını **listeler**.
- Hiçbir exploit **çalıştırmaz**.
- "Bu versiyon için bilinen şu zafiyetler var" bilgisini getirir.

---

## 7. Docker Altyapısı

### `docker/docker-compose.yml`

Üç servis aynı `assessment-net` ağında çalışır:

| Servis | İmaj | Port | Erişim |
| :--- | :--- | :--- | :--- |
| `juice-shop` | `bkimminich/juice-shop` | `3000:3000` | Host + ağ |
| `metasploitable2` | `tleemcjr/metasploitable2` | `127.0.0.1:2222:22`, `127.0.0.1:8081:80` | Sadece localhost (dışa kapalı) |
| `assessment-tools` | Kali tabanlı (build) | — | Sadece ağ içi |

### `docker/Dockerfile.assessment-tools`

Kali Linux tabanlı imaj, şu araçları kurar:
- `nmap`, `gobuster`, `nikto`, `whatweb`, `sqlmap` (apt)
- `exploitdb` (searchsploit) (apt)
- `testssl.sh` (GitHub'dan klonlanır)
- `bsdmainutils` (hexdump — testssl.sh bağımlılığı)
- SecLists `common.txt` wordlist (gobuster için)

### Neden `docker exec`?

Araçlar **host'ta değil**, Docker konteyneri içinde çalışır. `_run_command()`
şu mantığı izler:

```python
def _run_command(command: str) -> str:
    if _docker_container_available():
        # Araçlar konteynerde garantili kurulu
        args = ["docker", "exec", TOOLS_CONTAINER] + shlex.split(command)
    else:
        # Fallback: host'ta çalıştır (araçlar kurulu olmayabilir)
        args = shlex.split(command)
    ...
```

**Neden bu yaklaşım?**
1. Araçların kurulu olduğu garantilenir (Kali imajı).
2. Host'ta araç kurulumu gerekmez.
3. Araç konteyneri, hedef konteynerlere aynı Docker ağı üzerinden servis
   adıyla erişir.
4. İnsan onayı ve UI host'ta kalır; araçlar izole konteynerde çalışır.

---

## 8. Çıktılar ve Raporlama

### Bulgu Kaydı (`data/assessment_findings.jsonl`)

Her bulgu şu yapıda kaydedilir:

```json
{
  "finding_id": "FIND-001",
  "tool": "nmap",
  "target": "metasploitable2",
  "category": "Open Port",
  "severity": "Medium",
  "cwe_reference": "CWE-200",
  "evidence_snippet": "Port 80 open: Apache httpd 2.2.8",
  "human_approved": true,
  "timestamp": "2026-08-25T12:00:00"
}
```

### Denetim Logu (`data/assessment_audit_log.jsonl`)

Onay, red ve kapsam dışı olaylar kaydedilir:

```json
{"event": "REJECTED_OUT_OF_SCOPE", "tool": "nmap", "target": "evil.com", "timestamp": "..."}
```

### Değerlendirme Raporu (`reports/assessment_report.md`)

OWASP WSTG referanslı rapor şunları içerir:
- **Yönetici Özeti** (bulgu sayıları, şiddet dağılımı)
- **Metodoloji** (WSTG-INFO, WSTG-CONF, WSTG-INPV vb.)
- **Bulgu Tablosu** (ID, araç, kategori, şiddet, CWE)
- **Detaylı Analiz** (her bulgu için etki + remediation önerisi)

---

## 9. Kurulum ve Kullanım

### 1. Docker Ortamını Kur

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Bu komut üç konteyneri de ayağa kaldırır:
- OWASP Juice Shop → `http://localhost:3000`
- Metasploitable2 → localhost'a bağlı (dışa kapalı)
- Araç konteyneri → `autoredteam-assessment-tools`

### 2. Araçları Doğrula

```bash
python main.py --mode check-tools
```

Tüm araçların erişilebilir olduğunu tablo halinde gösterir.

### 3. Değerlendirmeyi Başlat

```bash
# OWASP Juice Shop
python main.py --mode assessment --assessment-target localhost:3000

# Metasploitable2
python main.py --mode assessment --assessment-target metasploitable2
```

### 4. LLM Provider Seçimi

```bash
# Mock LLM (API anahtarı gerekmez)
python main.py --mode assessment --assessment-llm-provider mock

# OpenAI
python main.py --mode assessment --assessment-llm-provider openai

# RunPod vLLM
python main.py --mode assessment --assessment-llm-provider runpod \
    --endpoint https://<pod-id>-8000.proxy.runpod.net/v1 --api-key EMPTY
```

---

## 10. Güvenlik Tasarım İlkeleri

Bu modül, güvenliği en üst düzeyde tutacak şekilde tasarlanmıştır:

| İlke | Uygulama |
| :--- | :--- |
| **İnsan Onayı Zorunlu** | Hiçbir komut `input()` onayı olmadan çalışmaz |
| **Kapsam Kısıtı** | `is_target_allowed()` kod seviyesinde sabit |
| **Kapsam Dışı Bloklama** | Kullanıcıya sorulmadan bloklanır, loglanır |
| **Non-Destructive Araçlar** | nmap `-sV -sC`, sqlmap tespit modu, searchsploit lookup-only |
| **Dump/Exploit Yasağı** | sqlmap'te `--dump`/`--os-shell` asla kullanılmaz |
| **Exploit Çalıştırmama** | searchsploit yalnızca listeler, çalıştırmaz |
| **Sonsuz Döngü Koruması** | Maksimum 20 önerilen adım |
| **İzole Araç Ortamı** | Araçlar Docker konteynerinde, host'tan izole |
| **Denetim İzi** | Tüm onay/red/kapsam dışı olaylar loglanır |

---

## 11. Testler

Testler `tests/test_core.py` içindedir. İlgili testler:

| Test | Ne Doğrular |
| :--- | :--- |
| `test_assessment_scope_validation` | Kapsam validasyonu |
| `test_assessment_out_of_scope_blocked` | Kapsam dışı hedef bloklanır |
| `test_assessment_sqlmap_detection_only` | sqlmap dump/exploit flag içermez |
| `test_assessment_finding_and_report` | Bulgu kaydı + rapor üretimi |
| `test_dockerfile_assessment_tools_syntax` | Dockerfile tüm araçları kurar |
| `test_docker_compose_has_tools_service` | Compose servisleri + ağ |
| `test_check_tools_output_format` | check_tools çıktı formatı |
| `test_parse_suggestion_hardened` | LLM JSON parse sağlamlığı |
| `test_metasploitable2_target_allowed` | Metasploitable2 kapsamda |
| `test_metasploitable2_resolution` | Hedef çözümleme |
| `test_searchsploit_lookup_only` | searchsploit lookup-only |
| `test_searchsploit_in_registry_and_prompt` | Registry + sistem prompt |
| `test_check_tools_includes_searchsploit` | check_tools searchsploit içerir |

```bash
python -m pytest tests/test_core.py -v
```

---

*Bu doküman AutoRedTeam Security Assessment Assistant modülünü açıklamak için
hazırlanmıştır. Tüm testler eğitim amaçlı, yetkili ve insan onaylıdır.*
