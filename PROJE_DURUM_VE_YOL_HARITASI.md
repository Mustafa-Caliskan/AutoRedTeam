# AutoRedTeam — Proje Kapsamı, Mevcut Durum ve Yol Haritası

> **Son Güncelleme:** 2026-09-13 (gece)
> **Sürüm:** v2.5 (Otonom Tarama + Web Uygulama Kapsamı + Dinamik Exploit Keşfi)
> **Durum:** Aktif geliştirme — Faz 1 (Altyapı Pentest) çalışıyor; kapsam tam, istismar derinliği artırılıyor

---

## 1. Projenin Ana Amacı

AutoRedTeam, **iki fazlı** otonom bir güvenlik değerlendirme platformudur:

### Faz 1 — Altyapı & Web Pentest (ŞU ANKİ ODAK)
Gerçek sistemleri (ağ servisleri, web uygulamaları, API'ler) otonom olarak pentest edip
**tüm zafiyetleri tespit eden, doğrulayan ve raporlayan** bir sistem kurmak.

- Hedefler: Metasploitable2, OWASP Juice Shop (yerel Docker laboratuvarları)
- Yetenekler: Port tarama → servis keşfi → zafiyet lookup → aktif istismar → yetki yükseltme → rapor
- Çıktı: Kanıtlanmış (evidence-based) bulgular + exploit zincirleri + PDF/Markdown rapor

### Faz 2 — LLM / AI Ajan Pentest (GELECEK)
Aynı otonom değerlendirme yeteneğini **LLM tabanlı ajanlara** uygulamak.

- Hedefler: Kurumsal AI ajanları (function-calling, RAG, araç erişimli)
- Tehditler: Dolaylı prompt injection, yetki aşımı (excessive agency), veri sızdırma, jailbreak
- Standartlar: OWASP LLM Top 10, MITRE ATLAS
- Mevcut altyapı: `core/attacker.py`, `core/victim_agent.py`, `core/evaluator.py`, `core/llm_redteam_engine.py`

---

## 2. Mimari Genel Bakış

### 3 Katmanlı Model Orkestrasyonu

```
+-------------------------------------------------------------------+
|  TIER 3: SUPREME ARBITER & ESCALATION ORACLE                      |
|  Anthropic Claude (LLM-as-a-Judge, invariant denetimi, kriz çözücü)|
+-------------------------------------------------------------------+
                              |
              Kriz eskalasyonu / hakem kararları
                              v
+-------------------------------------------------------------------+
|  TIER 2: STRATEGIC ORCHESTRATOR (PARENT BRAIN)                    |
|  DeepSeek V4 Flash (stratejik planlama, web CVE istihbaratı)      |
+-------------------------------------------------------------------+
                              |
              Taktik direktifler & kompakt bağlam
                              v
+-------------------------------------------------------------------+
|  TIER 1: TACTICAL EXECUTION ENGINE (WORKER)                       |
|  CyberStrike 35B Abliterated (SGLang, containerize araçlar)       |
+-------------------------------------------------------------------+
```

### Çift Motor

| Motor | Amaç | Durum |
|---|---|---|
| **Motor 1: Adversarial AI Red Team** | LLM ajanlarına prompt injection, jailbreak, veri sızdırma | Faz 2 — altyapı hazır |
| **Motor 2: Altyapı & Web Pentest** | Gerçek sistemlere otonom sızma + privesc | **Faz 1 — aktif geliştirme** |

### Yeni Nesil Modüller (v2.2+)

| Modül | Dosya | Görev |
|---|---|---|
| Hierarchical Context Engine | `core/context_engine.py` | L0/L1/L2 bağlam sıkıştırma, %70-90 token tasarrufu |
| Autonomous Target Memory | `core/target_memory.py` | Oturumlar arası hedef hafızası, recon skip |
| Autonomous Browser Agent | `core/browser_tool.py` | Playwright/HTTP fallback DOM pentest + screenshot |
| Evaluation Arbiter | `core/evaluation_arbiter.py` | LLM-as-a-Judge, OWASP LLM Top 10 invariant denetimi |

---

## 3. Mevcut Durum (v2.3)

### Çalışan Bileşenler

- **Web Kokpiti** (`assessment_ui.py`): Gerçek zamanlı SSE akışı, canlı bulgu/exploit zinciri görselleştirme
- **CLI** (`main.py`): `--mode assessment` ile human-in-the-loop değerlendirme
- **Otonom Tarama Motoru** (`core/recon_engine.py`): **[YENİ v2.4]** LLM'siz deterministik tarama zinciri (nmap -sV -sC, nuclei, enum4linux, gobuster, nikto, whatweb)
- **Exploit Runner** (`core/exploit_runner.py`): 12 kayıtlı exploit, dinamik servis/port eşlemesi
- **Privesc Engine** (`core/privesc_engine.py`): SUID, sudoers, GTFOBins, verify_root, **linpeas**
- **Validation Gate** (`core/validation_gate.py`): 7-soru anti-hallucination filtresi
- **Docker Laboratuvarı**: Metasploitable2 + Juice Shop + assessment-tools (nmap, nikto, gobuster, sqlmap, searchsploit, testssl, hydra, ffuf, enum4linux, smbclient, linpeas)

### Test Durumu

```
172 passed in ~59s
```

### Exploit Kataloğu (12)

| Exploit | Servis/Port | Durum |
|---|---|---|
| `ingreslock_backdoor` | 1524 | ✅ Çalışıyor (root shell) |
| `ssh_credential_spray` | 22 | ✅ Çalışıyor (msfadmin:msfadmin) |
| `vsftpd_backdoor` | 21 | ⚠️ Hedefte port 6200 kapalı |
| `samba_usermap` | 445 | ⚠️ Enjeksiyon gönderiliyor, doğrulama zayıf |
| `distcc_exec` | 3632 | ⚠️ Bağlanıyor, komut çalışmıyor |
| `unrealircd_backdoor` | 6667 | ⚠️ Banner alınıyor, shell yok |
| `proftpd_modcopy` | 2121 | ⚠️ mod_copy desteklenmiyor (1.3.1) |
| `java_rmi_deserialize` | 1099 | ⚠️ Protokol farklı yanıt veriyor |
| `ruby_drb_rce` | 8787 | ⚠️ Servis doğrulandı, RCE payload çalışmadı |
| `vnc_null_auth` | 5900 | ⚠️ Port kapalı |
| `tomcat_manager_deploy` | 8180 | ⚠️ Port kapalı |
| `juice_shop_admin` | 3000 | ✅ Çalışıyor (Juice Shop) |

---

## 3.5. v2.4 Mimari Devrimi — Otonom Tarama Katmanı

### Problem
Küçük worker modeli (CyberStrike 35B) "sıradaki tarama adımı ne?" kararında
takılıp aynı eylemi tekrarlıyordu. Tarama işi aslında **deterministik** olduğu
halde LLM'e yaptırılıyordu.

### Çözüm: Tool-First, LLM-Second
```
KATMAN 1: OTONOM TARAMA (LLM'siz, deterministik) — core/recon_engine.py
  nmap -sV -sC -> nuclei -> enum4linux -> gobuster -> nikto -> whatweb
  => Tum zafiyet yuzeyi cikarilir (22 port, 17 isaret, 22 dizin)
                          |
                          v yapilandirilmis bulgular
KATMAN 2: LLM YORUMLAMA (agentic)
  Model artik "ne tarayacagim" demez; bulunan zafiyetleri onceliklendirir
  ve istismar eder. Bilmedigi servisleri searchsploit/cve_search/web_search
  ile DINAMIK olarak arastirir (ezber yok).
```

### v2.4 Değişiklikleri
1. **`core/recon_engine.py`** — LLM'siz otonom tarama zinciri
2. **Dinamik exploit keşfi** — Sabit port→exploit ezber listesi kaldırıldı;
   `EXPLOIT_REGISTRY` artık `services`/`ports` metadata taşıyor
3. **Ezber sistem promptu kaldırıldı** — Model bilmediğini araştırmaya yönlendiriliyor
4. **Orchestrator müdahalesi azaltıldı** — `ORCHESTRATOR_INTERVAL` 5→10
5. **linpeas entegrasyonu** — Otomatik post-exploitation privesc taraması
6. **Yeni araçlar** — hydra, ffuf, enum4linux, smbclient, linpeas

### v2.5 Değişiklikleri (Web Uygulama Kapsamı)
1. **Web uygulamaları eklendi** — dvwa, mutillidae, phpmyadmin, tikiwiki,
   webdav artık `_CRITICAL_SERVICES`'te ve ayrı ayrı test ediliyor
2. **Paylaşılan port çakışması çözüldü** — "apache test edildi" denince
   port 80'deki diğer uygulamalar artık "test edildi" sayılmıyor
3. **Geniş port taraması filtresi** — tek bir `nmap 1-10000` tüm servisleri
   "test edildi" gösteremiyor (10+ port = keşif, test değil)
4. **`_credentials` bug'ı düzeltildi** — fallback yolundaki `AttributeError`
5. **Foothold kimlik takibi** — başarılı exploit sonrası privesc için kayıt

### Recon Engine Gerçek Test Sonucu (metasploitable2)
```
22 acik port
22 web dizini (phpMyAdmin, dav, twiki, test, admin, WEB-INF...)
5 SMB paylasimi (tmp yazilabilir!)
17 zafiyet isareti:
  - Tomcat default creds (tomcat:tomcat) <- kritik
  - phpMyAdmin acikta
  - Apache 2.2.8 / PHP 5.2.4 outdated
  - HTTP TRACE aktif (XST)
  - mod_negotiation MultiViews
```

---

## 4. Son Test Sonuçları ve Analiz

### Test 1 (v2.2, 16 adım) — Erken bitme
- **Sorun:** Model JSON üretemedi, DeepSeek sürekli devreye girdi, 16 adımda bitti.
- **Kök neden:** SGLang `response_format` desteklemiyordu → constrained decoding kapalıydı.

### Test 2 (v2.3, 26 adım) — Model takılması
- **Sorun:** Model 26 adım boyunca `vsftpd_backdoor`/`ssh_credential_spray` önerdi.
- **Kök neden:** CyberStrike 35B uzun bağlamda instruction-following zayıflığı.

### Test 3 (v2.3, 25 adım) — Deterministik mod çalıştı
- **İyi haber:** Model 3 adımda takıldı → sistem otomatik deterministik kapsam motoruna geçti → tüm 23 servis sırayla test edildi.
- **Sonuç:** 6 bulgu (2 gerçek kritik: SSH zayıf kimlik, ingreslock root shell).
- **Kalan sorun:** Exploit'lerin çoğu hedefte başarısız; web uygulamaları (DVWA, Mutillidae, phpMyAdmin, TikiWiki, WebDAV) hiç test edilmedi.

### Test 4 (v2.5, 33 adım) — EN KAPSAMLI TEST (son test)
- **Tarih:** 2026-09-13 gece
- **Model:** CyberStrike 35B (Colab tüneli)
- **Akış:** Model 12 adım `searchsploit` tekrarına takıldı → deterministik moda geçti → 33 adımda tüm servisler test edildi.
- **Kapsam:** 28 servis (web uygulamaları dahil) test edildi.
- **Bulgu sayısı:** 6
  - FIND-001: Weak Default Credentials (Critical) — SSH msfadmin:msfadmin
  - FIND-002: Backdoor Exploitation (Critical) — ingreslock root shell (uid=0)
  - FIND-003: Old Software Version (Informational) — PHP 5.2.4
  - FIND-004: Privilege Escalation (Critical) — verify_root (uid=0)
  - FIND-005: Privilege Escalation (Critical) — sudoers (ALL) ALL
  - FIND-006: Privilege Escalation (Critical) — SUID enumeration
- **İyi haber:** Web uygulamaları artık test ediliyor (nikto dvwa/mutillidae, searchsploit phpmyadmin/tikiwiki/webdav).
- **Kalan sorun:** Exploit'lerin çoğu hedefte başarısız (aşağıda detaylı).

### Test 4'te Yaşanan Sorunlar
1. **Model hâlâ takılıyor:** 12 adım boyunca `searchsploit` tekrarladı (farklı servisler için olsa da). Deterministik mod devreye girdi.
2. **Exploit başarı oranı düşük:** 11 exploit'ten sadece 2'si gerçekten çalıştı (ssh_credential_spray, ingreslock_backdoor).
3. **Web uygulamaları sadece yüzeysel tarandı:** nikto/searchsploit ile lookup yapıldı ama DVWA SQLi, WebDAV PUT gibi gerçek istismar denenmedi.
4. **Tomcat default creds bulundu ama exploit edilemedi:** Recon "tomcat:tomcat" buldu ama `tomcat_manager_deploy` başarısız oldu (port 8180 kapalı çıktı).
5. **Bulgu tekrarı:** 3 adet "Privilege Escalation" bulgusu ayrı ayrı kaydedildi (verify_root, sudoers, suid) — bunlar tek bir privesc zinciri olarak birleştirilmeli.

### Tespit Edilen Kök Sorunlar

| # | Sorun | Durum |
|---|---|---|
| 1 | `no_progress_count` çok agresif erken bitiriyordu | ✅ Düzeltildi (eşik 5→12, deterministik fallback önceliği) |
| 2 | SGLang constrained decoding çalışmıyordu | ✅ Düzeltildi (`guided_json` + kademeli fallback) |
| 3 | `sanitize_llm_response` JSON'u bozuyordu | ✅ Düzeltildi (JSON koruması) |
| 4 | `_CRITICAL_SERVICES` eksikti (13 servis) | ✅ Genişletildi (28 servis, web uygulamaları dahil) |
| 5 | Eksik exploit scriptleri | ✅ 5 yeni script eklendi |
| 6 | searchsploit lookup'ları bulgu sayılıyordu | ✅ Düzeltildi (istihbarat filtresi) |
| 7 | Model takılması | ✅ Deterministik kapsam motoru eklendi |
| 8 | Yanlış pozitif exploit başarısı (distcc/unrealircd) | ✅ Düzeltildi (sadece `uid=` kanıtı) |
| 9 | Web uygulamaları test edilmiyordu | ✅ Düzeltildi (v2.5: 5 web uygulaması eklendi) |
| 10 | Paylaşılan port çakışması (port 80) | ✅ Düzeltildi (keyword eşleşmesi zorunlu) |
| 11 | Geniş nmap taraması tüm servisleri "test edildi" gösteriyordu | ✅ Düzeltildi (10+ port = keşif) |
| 12 | `_credentials` AttributeError | ✅ Düzeltildi |
| 13 | **MySQL/PostgreSQL gerçek istismar yok** | ❌ Açık |
| 14 | **Claude model adı geçersiz** (`claude-5-sonnet` 404) | ❌ Açık |
| 15 | **Exploit başarı oranı düşük** (11'den 2'si çalışıyor) | ❌ Açık |
| 16 | **Web uygulamaları yüzeysel taranıyor** (SQLi/XSS/upload denenmiyor) | ❌ Açık |
| 17 | **Privesc bulguları tekrar ediyor** (3 ayrı bulgu) | ❌ Açık |

---

## 4.5. Amaca Ne Kadar Kaldı?

### Hedef
Gerçek sistemleri otonom pentest edip **TÜM zafiyetleri** tespit eden, doğrulayan
ve raporlayan bir sistem. Bug bounty'de de kullanılabilir olmalı.

### Mevcut Durum: ~%65

| Yetenek | Durum | Not |
|---|---|---|
| Port/servis keşfi | ✅ %100 | nmap -sV -sC, 22 port doğru bulundu |
| Zafiyet yüzeyi taraması | ✅ %90 | nikto, enum4linux, gobuster, whatweb çalışıyor |
| Web dizin keşfi | ✅ %100 | 22 dizin bulundu |
| SMB numaralandırma | ✅ %100 | 5 paylaşım, tmp yazılabilir |
| Kapsam tamlığı | ✅ %100 | 28 servis test ediliyor (web dahil) |
| Kimlik bilgisi istismarı | ✅ %80 | SSH spray çalışıyor |
| Backdoor istismarı | ✅ %60 | ingreslock çalışıyor, diğerleri hedefte yok |
| Web uygulama istismarı | ⚠️ %20 | Sadece yüzeysel tarama; SQLi/XSS/upload yok |
| Yetki yükseltme | ✅ %70 | SUID/sudoers/verify_root çalışıyor |
| Otonom karar (LLM) | ⚠️ %50 | Model hâlâ takılıyor, deterministik mod kurtarıyor |
| Rapor kalitesi | ✅ %80 | PDF/Markdown, exploit zincirleri |
| Gerçek dünya hedefi | ⚠️ %30 | Sadece eğitim hedeflerinde test edildi |

### Amaca Ulaşmak İçin Kalan İşler (öncelik sırasıyla)

1. **Web uygulama istismarı** (en büyük eksik)
   - DVWA: SQLi, XSS, command injection, file upload otomatik testi
   - WebDAV: PUT metodu ile dosya yükleme
   - phpMyAdmin: default creds + CVE istismarı
   - `sqlmap` entegrasyonunu web formlarına yönlendir

2. **Exploit başarı oranını artır**
   - Samba usermap: gerçek SMB handshake doğrulaması
   - distcc: doğru CVE-2004-2687 payload
   - unrealircd: doğru backdoor tetikleme
   - ruby_drb: geçerli marshal gadget

3. **Model takılmasını azalt**
   - Sistem promptunu kısalt
   - Few-shot örnekler
   - Daha güçlü model (DeepSeek/Claude) worker olarak

4. **Bulgu kalitesi**
   - Privesc bulgularını tek zincirde birleştir
   - Başarısız denemeleri de raporla

5. **Gerçek dünya testi**
   - HackTheBox/TryHackMe makinelerinde dene
   - Bug bounty programlarında (izinli) test

---

## 5. Çözüm Önerileri (Öncelik Sırasıyla)

### Yüksek Öncelik

1. **Web uygulaması istismarı ekle** (v2.5'te tarama eklendi, istismar eksik)
   - DVWA için SQLi/XSS/command injection otomatik testi
   - WebDAV PUT metodu ile dosya yükleme
   - phpMyAdmin default creds + CVE istismarı
   - `sqlmap` entegrasyonunu web formlarına yönlendir

2. **MySQL/PostgreSQL istismarı ekle**
   - MySQL: `CVE-2012-2122` (auth bypass), UDF privesc
   - PostgreSQL: `CVE-2007-3280` veya zayıf kimlik denemesi
   - En azından default credential denemesi (`root:root`, `msfadmin:msfadmin`)

3. **Claude model adını düzelt**
   - `.env`'de `ANTHROPIC_MODEL` gerçek bir model adına ayarla (ör. `claude-3-5-sonnet-latest`)
   - Geçersizse Tier-3'ü sessizce devre dışı bırak (zaten yapılıyor)

### Orta Öncelik

4. **Exploit başarı oranını artır**
   - `samba_usermap`: gerçek SMB handshake + komut çıktısı doğrulaması
   - `distcc_exec`: doğru CVE-2004-2687 payload formatı
   - `unrealircd_backdoor`: doğru backdoor tetikleme dizisi
   - `ruby_drb_rce`: geçerli Ruby marshal gadget zinciri

5. **Model takılmasını azalt**
   - Sistem promptunu kısalt (şu an ~3000 karakter)
   - Modeli daha küçük, odaklı görevlere böl (her adımda tek karar)
   - Few-shot örnekler ekle

6. **Bulgu kalitesini artır**
   - Exploit başarısızlıklarını da "denendi, başarısız" olarak raporla
   - Zafiyet yüzeyi tespitlerini (Java RMI, VNC) ayrı severity ile kaydet

### Düşük Öncelik

7. **Faz 2 hazırlığı**
   - LLM ajan pentest motorunu (`core/attacker.py`) Faz 1 ile birleştir
   - OWASP LLM Top 10 otomatik değerlendirme akışı

---

## 6. Dosya ve Mimari Haritası

```
llm_redteam/
├── assessment_ui.py          # Web kokpiti (SSE, canlı izleme)
├── main.py                   # CLI giriş noktası
├── arena_ui.py               # LLM Duel Arena (Faz 2)
├── chat_ui.py                # Sohbet arayüzü
├── core/
│   ├── assessment_assistant.py   # Ana değerlendirme döngüsü (worker)
│   ├── assessment_tools.py       # Araç sarmalayıcıları (nmap, nikto, ...)
│   ├── exploit_runner.py         # 12 exploit runner
│   ├── privesc_engine.py         # Yetki yükseltme
│   ├── orchestrator.py           # Tier-2/3 orkestrasyon
│   ├── llm_client.py             # LLM istemcileri (OpenAI/SGLang/Anthropic)
│   ├── context_engine.py         # L0/L1/L2 bağlam motoru
│   ├── target_memory.py          # Oturumlar arası hafıza
│   ├── browser_tool.py           # Otonom tarayıcı
│   ├── validation_gate.py        # Anti-hallucination filtresi
│   ├── scope.py                  # Kapsam doğrulama (DRY)
│   ├── attacker.py               # Faz 2: saldırgan LLM
│   ├── victim_agent.py           # Faz 2: kurban ajan
│   └── evaluator.py              # Faz 2: değerlendirici
├── scripts/exploits/         # Bağımsız exploit betikleri
├── docker/                   # Laboratuvar ortamı
├── tests/                    # 165 test
├── config/                   # Yapılandırma + izinli hedefler
└── docs/                     # Mimari dokümantasyon
```

---

## 7. Güvenlik ve Etik Notlar

- **Yalnızca yetkili test ortamları:** Tüm hedefler `config/allowed_targets.txt` ile kısıtlıdır.
- **Kapsam doğrulaması:** `core/scope.py` her eylemden önce hedefi doğrular.
- **Denetim logu:** Tüm exploit denemeleri `data/assessment_audit_log.jsonl`'a yazılır.
- **Sır yönetimi:** `.env` git'e dahil edilmez; yalnızca `.env.example` paylaşılır.
- **Eğitim amaçlı:** Metasploitable2 ve Juice Shop kasıtlı olarak zafiyetli eğitim hedefleridir.

---

## 8. Hızlı Başlangıç

```bash
# Test paketi
python -m pytest tests/ -q

# Web kokpiti
python assessment_ui.py
# → http://127.0.0.1:7870

# CLI değerlendirme
python main.py --mode assessment --assessment-target metasploitable2

# Docker laboratuvarı
docker compose -f docker/docker-compose.yml up -d
```

---

*Bu doküman projenin canlı durumunu yansıtır. Her büyük geliştirme turunda güncellenmelidir.*
