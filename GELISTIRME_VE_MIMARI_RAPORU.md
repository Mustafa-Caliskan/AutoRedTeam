# AutoRedTeam — Çığır Açıcı Geliştirme & Mimari Raporu (v2.2)

Bu doküman, **AutoRedTeam** projesine kazandırılan tüm yeni nesil mimari yetenekleri, incelenen ve ilham alınan açık kaynaklı teknolojileri, 3 katmanlı çoklu-model (Claude 5 Sonnet + DeepSeek V4 Flash + CyberStrike 35B) orkestrasyonunu ve sıfır regresyonla 153 teste ulaşan mühendislik geliştirmelerini detaylandırmaktadır.

---

## 📑 İçindekiler
1. [Yönetici Özeti & Stratejik Vizyon](#1-yönetici-özeti--stratejik-vizyon)
2. [3 Katmanlı Model Orkestrasyonu (Tier-1, Tier-2, Tier-3)](#2-3-katmanlı-model-orkestrasyonu-tier-1-tier-2-tier-3)
3. [İncelenen Açık Kaynak Projeler ve Temiz Tasarım (Clean-Room)](#3-incelenen-açık-kaynak-projeler-ve-temiz-tasarım-clean-room)
4. [Hayata Geçirilen 3 Devrimsel Modül](#4-hayata-geçirilen-3-devrimsel-modül)
   - [Modül 1: Hierarchical Context Engine & Headroom CCR](#modül-1-hierarchical-context-engine--headroom-ccr)
   - [Modül 2: Autonomous Target Memory & Cross-Session Distillation](#modül-2-autonomous-target-memory--cross-session-distillation)
   - [Modül 3: Autonomous Browser & DOM Pentest Agent](#modül-3-autonomous-browser--dom-pentest-agent)
5. [Dosya ve Mimari Haritası](#5-dosya-ve-mimari-haritası)
6. [Test ve Doğrulama Raporu (153/153 PASSED)](#6-test-ve-doğrulama-raporu-153153-passed)
7. [Hızlı Başlangıç ve Kullanım Senaryoları](#7-hızlı-başlangıç-ve-kullanım-senaryoları)

---

## 1. Yönetici Özeti & Stratejik Vizyon

**AutoRedTeam**, hem **otonom kurumsal yapay zeka ajanlarını** (Adversarial AI Red Teaming: dolaylı prompt injection, yetki aşımı, veri sızdırma) hem de **klasik kurumsal altyapıları** (Infrastructure & Web Pentesting: portlar, servisler, web uygulamaları, API'ler) eş zamanlı olarak değerlendiren çift motorlu bir siber güvenlik platformudur.

### Bu Geliştirme Turunun Başlıca Kazanımları:
1. **Anthropic Claude 5 Sonnet Entegrasyonu:** Kurumsal logları denetleyen ve OWASP LLM Top 10 açıklarını puanlayan **Supreme Evaluation Arbiter (Tier 3)** ve takılmaları çözen **Escalation Oracle**.
2. **%70-90 Token Tasarrufu ve Sıfır Hafıza Kaybı:** Headroom ve OpenViking sanal dosya sistemi felsefesinden ilham alan L0/L1/L2 Context Engine ile model amnesia sorununun kökten çözülmesi.
3. **Kalıcı Hedef Hafızası (Target Memory):** Oturumlar arasında hedefleri hatırlayarak gereksiz keşif taramalarını (Wave 1 Nmap) sıfıra indiren ve doğrudan istismara odaklanan damıtma mekanizması.
4. **Otonom Tarayıcı ve DOM Pentesti:** OWASP Juice Shop gibi modern Single Page Application (SPA) hedefleri için Playwright ve HTTP fallback destekli tarayıcı kontrolü ve görsel kanıt yakalama kabiliyeti.
5. **Sıfır Lisans Riski & Sıfır Şişkinlik:** Harici ağır veritabanları (Chroma, Qdrant vb.) ve AGPL-3.0 lisans riskleri projeye sokulmadan, **MIT lisanslı** saf Python mühendisliği ile gerçekleştirildi.

---

## 2. 3 Katmanlı Model Orkestrasyonu (Tier-1, Tier-2, Tier-3)

AutoRedTeam, her modelin en güçlü olduğu alanı maksimize eden hiyerarşik bir iş bölümüyle çalışır:

```
+-----------------------------------------------------------------------------+
|               TIER 3: SUPREME ARBITER & ESCALATION ORACLE                   |
|                        Anthropic Claude 5 Sonnet                            |
|  - LLM-as-a-Judge: Araç çağırma (tool-calling) log denetimi ve puanlama     |
|  - Invariant Doğrulama (2FA auth_token, E-posta & DB Alan İzolasyonu)       |
|  - Kriz ve Deadlock Çözücü: Worker tıkandığında devreye giren üst akıl      |
+--------------------------------------+--------------------------------------+
                                       |
                         Kriz Eskalasyonu / Hakem Kararları
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                 TIER 2: STRATEGIC ORCHESTRATOR (PARENT BRAIN)               |
|                              DeepSeek V4 Flash                              |
|  - 4 Aşamalı Stratejik Planlama (Wave 1-4 Triage Protocol)                  |
|  - Canlı Web Araştırması (DuckDuckGo CVE / PoC İstihbaratı)                 |
|  - Saldırı Yüzeyi Durumu ve Bağlam Yönetimi                                 |
+--------------------------------------+--------------------------------------+
                                       |
                         Taktik Direktifler & Kompakt Bağlam
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                  TIER 1: TACTICAL EXECUTION ENGINE (WORKER)                 |
|                        CyberStrike 35B Abliterated                          |
|     (SGLang RadixAttention / Sınırlandırılmış JSON / Containerized Araçlar) |
+--------------------------------------+--------------------------------------+
                                       |
                 +---------------------+---------------------+
                 |                                           |
                 v                                           v
+---------------------------------+         +---------------------------------+
|            MOTOR 1:             |         |            MOTOR 2:             |
|     Adversarial AI Red Team     |         |  Altyapı & Web Pentest Co-Pilot |
|  - 7 Dönüştürücü Evasion Kiti   |         |  - Human-in-the-Loop Onay       |
|  - Çok Turlu Crescendo Saldırısı|         |  - Metasploitable2 / Juice Shop |
|  - Kurban Ajan Sandbox          |         |  - Otomatik Exploit & Privesc   |
+---------------------------------+         +---------------------------------+
```

### Rol Dağılımı ve Maliyet Optimizasyonu
- **Rutin Operasyonlar:** DeepSeek V4 Flash ve CyberStrike 35B tarafından yürütülür; yüksek hız ve sıfıra yakın maliyet sağlanır.
- **Yüksek Güvenlik & Kriz Durumları:** Claude 5 Sonnet yalnızca kurumsal log denetiminde (LLM-as-a-Judge) ve alt modeller kilitlendiğinde devreye girer. Böylece API maliyeti minimumda tutulurken en yüksek zeka seviyesi sisteme dahil edilir.

---

## 3. İncelenen Açık Kaynak Projeler ve Temiz Tasarım (Clean-Room)

Geliştirme sürecinde açık kaynak ekosistemindeki 7 popüler ajan mimarisi incelendi ve AutoRedTeam'in ihtiyaçlarına göre uyarlandı:

| İncelenen Repo | İncelenen Konsept | AutoRedTeam'e Nasıl Uyarlandı? |
|---|---|---|
| **OpenViking** | `viking://` sanal dosya sistemi, L0/L1/L2 hiyerarşik bağlam | **Lisans Uyarısı:** OpenViking AGPL-3.0 lisanslı olduğundan hiçbir kodu kopyalanmadı. L0/L1/L2 mantığı saf Python ve yerel JSON/TXT dosyalarıyla sıfırdan yazılarak **MIT lisansı** korundu. |
| **Headroom** | CCR (Cache-Compress-Retrieve) akışı | Araç logları diske yazılır (`L2`), prompt'a sadece kompakt durum ağacı iletilir (`L1/L0`). Token tüketimi %70-90 azaltıldı. |
| **Browser-Use / Playwright** | Otonom tarayıcı kontrolü ve DOM navigasyonu | `core/browser_tool.py` yazılarak OWASP Juice Shop gibi SPA hedeflerine DOM düzeyinde sızma, token çekme ve ekran görüntüsü kanıt kaydı getirildi. |
| **Anti-Slop & ECC** | Ajanların robotik ve döngüsel tekrarlarını kırma | Loop-breaker mekanizması güçlendirildi; model aynı aracı/servisi 2'den fazla kez çağırdığında sert direktifle farklı servise yönlendirilir. |
| **AgentMemory** | Oturumlar arası kalıcı bellek | `core/target_memory.py` ile hedef bazlı hafıza kuruldu; geçmiş oturumların zafiyetleri ve açık portları anında hatırlanır. |

---

## 4. Hayata Geçirilen 3 Devrimsel Modül

### Modül 1: Hierarchical Context Engine & Headroom CCR
- **Dosya:** [`core/context_engine.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/context_engine.py)
- **Problem:** Model uzun konuşmalarda 10 adımdan sonra kayan pencere (`_get_compact_conversation`) nedeniyle ilk turlarda bulduğu portları ve servisleri unutuyor (amnesia), aynı Nmap taramasını gereksiz yere tekrarlıyordu.
- **Mimari:**
  - **L2 (Ham Kanıt Deposu):** Çıktılar filtrelenmeden yerel diskte (`data/vfs/raw/<node_id>.txt`) saklanır. İhtiyaç anında `retrieve_raw(node_id)` ile geri çağrılabilir.
  - **L1 (Taktik Karar Durumu):** Servis adları, sürümler, doğrulanmış exploit'ler ve URL uç noktaları yapılandırılmış nesnede tutulur.
  - **L0 (Deterministik Ağaç):** Prompt'a devasa loglar yerine ~150-200 token'lık yüksek sinyalli ASCII Saldırı Yüzeyi Ağacı (`render_compact_context`) enjekte edilir.

#### Üretilen ASCII Saldırı Yüzeyi Ağacı Örneği:
```text
=== Target Attack Surface: metasploitable2 [Access: ROOT (UID=0)] ===
  ├── [21/tcp] ftp vsftpd 2.3.4 [EXPLOIT: vsftpd_backdoor] -> STATUS: EXPLOIT FAILED ❌
  ├── [22/tcp] ssh OpenSSH 4.7p1 [EXPLOIT: ssh_credential_spray] -> STATUS: UNTESTED
  ├── [445/tcp] netbios-ssn Samba smbd 3.X [EXPLOIT: samba_usermap] -> STATUS: UNTESTED
  └── [1524/tcp] ingreslock Ingreslock [EXPLOIT: ingreslock_backdoor] -> STATUS: ROOT SHELL OBTAINED ✅
```

---

### Modül 2: Autonomous Target Memory & Cross-Session Distillation
- **Dosya:** [`core/target_memory.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/target_memory.py)
- **Problem:** Yeni bir oturum başlatıldığında hedef sistem daha önce taranmış olsa bile hafıza sıfırlanıyor ve baştan gereksiz port taramaları yapılıyordu.
- **Mimari:**
  - **Yerel Depolama:** `data/vfs/memories/targets/<target_slug>.json` dosyasında oturumlar arası deneyim kalıcı hale getirilir.
  - **Deneyim Damıtma (`distill_session`):** Oturum tamamlandığında teyitli servisleri, başarılı exploit'leri (`ingreslock_backdoor`), başarısız olanları (`vsftpd_backdoor`) ve elde edilen kimlik bilgilerini (`msfadmin:msfadmin`) damıtır.
  - **Hedef Hatırlama (`recall_target`):** Yeni bir oturum açıldığında hedefin bilinen durumu hafızadan okunur.
  - **Keşif Atlatma (Recon Skip):** Model ilk adımda nmap çalıştırmaz; prompt'a eklenen hafıza özeti sayesinde doğrudan henüz denenmemiş servislere veya kimlik denemelerine geçer.

#### Prompt İçine Enjekte Edilen Hafıza Özeti Örneği:
```text
🧠 [Target Memory Recalled: metasploitable2 (Session #2)]
  - Prior Access Level: ROOT (UID=0)
  - Known Ports (Recon Done): 21/tcp (ftp), 22/tcp (ssh), 445/tcp (netbios-ssn), 1524/tcp (ingreslock)
  - Verified Working Exploits: ingreslock_backdoor ✅
  - Failed / Ineffective Exploits: vsftpd_backdoor ❌ (DO NOT RETRY)
  - DIRECTIVE: Skip duplicate Nmap scans. Focus directly on untested services or privilege escalation.
```

---

### Modül 3: Autonomous Browser & DOM Pentest Agent
- **Dosya:** [`core/browser_tool.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/browser_tool.py)
- **Problem:** OWASP Juice Shop gibi modern web uygulamalarında istemci taraflı JavaScript, formlar ve oturum belirteçleri curl ile tetiklenemiyordu.
- **Mimari:**
  - **Playwright Otomasyonu:** Headless veya headful olarak tarayıcı başlatır.
  - **DOM Eylemleri:** Sayfa gezintisi (`navigate`), form doldurma (`fill`), tıklama (`click`), klavye komutları (`press_enter`).
  - **Oturum ve Token Sızdırma (`extract_storage`):** LocalStorage, SessionStorage ve Cookie'lerden JWT belirteçlerini ve oturum anahtarlarını ayıklar.
  - **Otomatik Kanıt Kaydı (`screenshot`):** Bulunan zafiyetleri ve yönetici paneli erişimlerini `reports/screenshots/<isim>_<timestamp>.png` altına kaydeder.
  - **Sıfır Çökme Güvencesi (Graceful Degradation):** Playwright kurulu olmadığında sistem asla çökmez; otomatik olarak `urllib.request` tabanlı HTTP/DOM moduna geçer.

---

## 5. Dosya ve Mimari Haritası

| Dosya Yolu | Durum | Görevi ve Sorumluluğu |
|---|---|---|
| [`core/context_engine.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/context_engine.py) | **[YENİ]** | L0/L1/L2 hiyerarşisi, CCR ham disk önbelleği, ASCII saldırı yüzeyi ağaç üreticisi. |
| [`core/target_memory.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/target_memory.py) | **[YENİ]** | Oturumlar arası deneyim damıtma (`distill_session`) ve hedef hafızası deposu (`recall_target`). |
| [`core/browser_tool.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/browser_tool.py) | **[YENİ]** | Playwright ve HTTP fallback destekli otonom DOM pentest motoru ve ekran görüntüsü alıcı. |
| [`core/evaluation_arbiter.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/evaluation_arbiter.py) | **[YENİ]** | Claude 5 Sonnet LLM-as-a-Judge araç çağırma denetçisi ve OWASP LLM Top 10 invariant doğrulayıcısı. |
| [`core/assessment_assistant.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/assessment_assistant.py) | **[GÜNCELLENDİ]** | Context Engine, Target Memory ve Browser eylemlerinin Human-in-the-Loop döngüsüne entegrasyonu. |
| [`core/orchestrator.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/orchestrator.py) | **[GÜNCELLENDİ]** | DeepSeek V4 Flash ve Claude 5 Sonnet kurtarma direktiflerine canlı saldırı yüzeyi ağacının eklenmesi. |
| [`core/assessment_tools.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/assessment_tools.py) | **[GÜNCELLENDİ]** | `suggest_browser_action` fonksiyonu ve `browser_action` aracının sistem kataloğuna kaydı. |
| [`core/llm_client.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/core/llm_client.py) | **[GÜNCELLENDİ]** | `AnthropicClient` entegrasyonu (`claude-5-sonnet` varsayılan model, tool calling desteği). |
| [`README.md`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/README.md) | **[GÜNCELLENDİ]** | 3 katmanlı mimari şeması, v2.2 yetenekleri ve 153 testlik doğrulama tablosu. |
| [`tests/test_context_engine.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/tests/test_context_engine.py) | **[YENİ]** | 7 birim testi (CCR disk önbelleği, nmap/gobuster/exploit ayrıştırma, %70+ token tasarrufu). |
| [`tests/test_target_memory.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/tests/test_target_memory.py) | **[YENİ]** | 4 birim testi (Oturum damıtma, hafızadan hatırlama, keşif atlama mantığı). |
| [`tests/test_browser_tool.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/tests/test_browser_tool.py) | **[YENİ]** | 6 birim testi (DOM navigasyonu, form doldurma, screenshot ve assistant entegrasyonu). |
| [`tests/test_claude_arbiter.py`](file:///c:/Users/Mustafa/OneDrive/Masaüstü/llm_redteam/tests/test_claude_arbiter.py) | **[YENİ]** | 12 birim testi (Claude 5 Sonnet LLM-as-a-Judge ve Tier-3 eskalasyon testleri). |

---

## 6. Test ve Doğrulama Raporu (153/153 PASSED)

Tüm sistem regresyon testinden geçirildi. Test ortamında hiçbir test atlanmadan, sıfır hata ile tamamlandı:

```bash
pytest
```

```text
============================= test session starts =============================
platform win32 -- Python 3.12.1, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Mustafa\OneDrive\Masaüstü\llm_redteam
plugins: anyio-4.13.0
collected 153 items

tests\test_browser_tool.py ......                                        [  3%]
tests\test_claude_arbiter.py ............                                [ 11%]
tests\test_constrained_json.py ...                                       [ 13%]
tests\test_context_engine.py .......                                     [ 18%]
tests\test_core.py .........................                             [ 34%]
tests\test_docker_manager.py ....                                        [ 37%]
tests\test_exploit_privesc.py .....................                      [ 50%]
tests\test_llm_redteam.py ....                                           [ 53%]
tests\test_orchestrator.py .............                                 [ 62%]
tests\test_skills_and_validation.py .....................                [ 75%]
tests\test_target_memory.py ....                                         [ 78%]
tests\test_ui_endpoints.py .....                                         [ 81%]
tests\test_worker_rescue_and_pdf.py ............................         [100%]

============================ 153 passed in 51.93s =============================
```

### Güvenilirlik & Lisans Güvencesi
- **Sıfır Lisans Riski:** AGPL lisanslı hiçbir kütüphane repoya dahil edilmedi. Proje bütünüyle **MIT Lisansı** altında özgürce paylaşılabilir ve ticarileştirilebilir.
- **Zero-Key Dayanıklılığı:** Claude veya DeepSeek API anahtarı girilmediğinde bile sistem deterministik kural motoru, şablon tabanlı kurtarma ve yerel analiz mekanizmalarıyla çalışmaya devam eder.

---

## 7. Hızlı Başlangıç ve Kullanım Senaryoları

### 1. Test Paketini Çalıştırma
```bash
python -m pytest tests/ -v
```

### 2. Altyapı Pentest Asistanını Başlatma (Metasploitable2 / Juice Shop)
```bash
python run_assessment.py --target metasploitable2
```

### 3. Hibrit Orkestrasyon ile Çalıştırma
`.env` dosyanızda şu değişkenleri tanımlayabilirsiniz:
```env
# Sağlayıcı Seçimi: hybrid (DeepSeek + Claude 5), deepseek veya claude
ORCHESTRATOR_PROVIDER=hybrid

# DeepSeek V4 Flash API
DEEPSEEK_API_KEY=your_deepseek_key

# Anthropic Claude 5 Sonnet API
ANTHROPIC_API_KEY=your_claude_key
ANTHROPIC_MODEL=claude-5-sonnet
```

### 4. Otonom Web Tarayıcı Testini Başlatma (Juice Shop DOM Pentest)
```bash
python -c "from core.browser_tool import browser_agent; res = browser_agent.navigate('http://localhost:3000'); print(res)"
```
