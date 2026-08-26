# 🚀 AutoRedTeam — Security Assessment Assistant Geliştirme Planı

> **Amaç:** Metasploitable2 testinde tespit edilen 4 kök nedeni çözmek ve
> sistemi bir üst seviyeye taşımak. Bu plan yalnızca tasarımdır — kodlama
> onay sonrası yapılacaktır.

---

## 📋 1. Karşılaşılan Sorunların Kök Neden Analizi

| # | Sorun | Gözlem | Kök Neden |
| :--- | :--- | :--- | :--- |
| 1 | **nmap -p 80 Takılması (Loop)** | Metasploitable2'de son 3 adım aynı nmap komutunu tekrarladı | `suggest_nmap_scan`'de port parametresi yok (varsayılan 80). Model diğer portları (21, 22, 445) inceleyemiyor. Ayrıca "aynı komutu daha önce çalıştırdın" diyen State/Memory koruması yok. |
| 2 | **Çift Bulgu Kaydı** | FIND-001 ve FIND-002 aynı Apache 2.2.8 bulgusu | `record_finding()`'de deduplication yok. Model aynı servisi iki kez yakalayınca ikisini de yeni bulgu sandı. |
| 3 | **Hedef Karışıklığı** | İlk adımda Metasploitable2 yerine Juice Shop önerdi | Sistem prompt'unda her iki hedef listeleniyor; model "aktif hedefi" net ayırt edemiyor. |
| 4 | **2024 Bilgi Kesintisi** | Model 2024 sonrası CVE'leri bilmiyor | Canlı Web / CVE istihbarat aracı yok. |

---

## 🚀 2. Dört Büyük Geliştirme (Kullanıcı İsteği)

### 🌐 Geliştirme 1: `web_research` / `cve_search` Aracı (Canlı İnternet Erişimi)

**Amaç:** Modelin 2024 sonrası güncel CVE'leri, exploit varyantlarını ve yama
önerilerini öğrenmesini sağlamak.

**Nasıl Çalışacak:**
- `suggest_cve_search(service_name, version)` adında yeni bir wrapper eklenir.
- Model, bilmediği veya 2024 sonrası yeni bir açık gördüğünde bu aracı önerir.
- Arka planda **NVD CVE API** (veya DuckDuckGo) üzerinden canlı arama yapılır.
- En güncel 2-3 güvenlik bülteni ve çözüm önerisi modele metin olarak beslenir.
- Model böylece 2026 yılına ait güncel exploit bültenlerini rapora ekleyebilir.

**Dosyalar:**
- `core/assessment_tools.py` → `suggest_cve_search()` wrapper
- `core/cve_lookup.py` (yeni) → NVD API / DuckDuckGo istemcisi
- `docker/Dockerfile.assessment-tools` → `curl` zaten var (gerek yok)

**Güvenlik Notu:** Bu araç yalnızca **bilgi toplar** (CVE listeler, yama
önerir). Hiçbir exploit çalıştırmaz. Kapsam dışı hedefe sorgu atmaz.

---

### 🎯 Geliştirme 2: Gelişmiş Port & Servis Keşfi (nmap Port Desteği)

**Amaç:** Modelin Metasploitable2'deki belirli portları (21, 22, 445, 3306)
tek tek derinlemesine incelemesini sağlamak.

**Nasıl Çalışacak:**
- `suggest_nmap_scan(target, ports="21,22,80,139,445,3306")` parametresi eklenir.
- Model `ports="21"` diyerek vsftpd 2.3.4 backdoor'unu, `ports="445"` diyerek
  Samba usermap_script zafiyetini tek tek inceleyebilir.
- `_resolve_port` mantığı, `ports` parametresi verildiğinde onu kullanır.

**Dosyalar:**
- `core/assessment_tools.py` → `suggest_nmap_scan()` imzasına `ports` eklenir
- `core/assessment_assistant.py` → sistem prompt'una `ports` alanı eklenir
- `core/assessment_assistant.py` → `_dispatch_tool()` `ports`'u geçirir

---

### 🧠 Geliştirme 3: Akıllı Döngü Kırıcı (State Memory & Loop Breaker)

**Amaç:** Modelin aynı komutu tekrarlamasını (takılma) önlemek.

**Nasıl Çalışacak:**
- `AssessmentAssistant`'a `visited_actions = set()` eklenir.
- Her onaylanan adımda `(tool, target, ports, service_name, version)` kombinasyonu
  `visited_actions`'a eklenir.
- Model daha önce çalıştırdığı bir kombinasyonu tekrar önerirse sistem anında
  yakalar ve modele şu mesajı iletir:
  > "Bu komutu zaten Adım 2'de çalıştırdın ve sonuç aldın. Lütfen farklı bir
  > servis/port incele veya değerlendirmeyi bitir (done)."
- Model farklı bir adım önerene kadar veya "done" diyene kadar döngü kırılır.

**Dosyalar:**
- `core/assessment_assistant.py` → `visited_actions` set + kontrol mantığı
- `core/assessment_assistant.py` → `_feed_result_to_llm()`'e tekrar uyarısı

---

### 🛡️ Geliştirme 4: Deterministik Bulgu Tekilleştirme (Deduplication Engine)

**Amaç:** Aynı bulgunun birden fazla kez kaydedilmesini önlemek.

**Nasıl Çalışacak:**
- `record_finding()` içinde `(target, category, cwe_reference, evidence)` hash
  kontrolü yapılır.
- Aynı bulgu ikinci kez gelirse listeye mükerrer yazılmaz, mevcut bulgu ID'si
  döndürülür.
- Raporlar tertemiz çıkar.

**Dosyalar:**
- `core/assessment_assistant.py` → `record_finding()`'e dedup mantığı
- `core/assessment_assistant.py` → `_load_existing_findings()` ile mevcut
  bulguların hash'lerini yükleme

---

## 💡 3. Benim Ek Önerilerim (Kullanıcı İstemedi Ama Değerli)

### 💡 Öneri A: Bulgu Kaydı İçin "İnsan Onayı" Akışı

**Sorun:** Şu an model `finding` alanı döndürdüğünde sistem otomatik kaydediyor.
Ama insan-onaylı felsefeye uygun olarak, bulgu kaydı da kullanıcı onayı
istemeli.

**Çözüm:** Model `finding` döndürdüğünde, sistem bulguyu gösterip
`input("Bu bulguyu kaydet? (y/n)")` ile onay ister. Bu, "insan karar verir"
prensibini bulgu kaydına da taşır.

### 💡 Öneri B: Otomatik Bulgu Çıkarımı (Tool Çıktısından)

**Sorun:** Model bazen searchsploit/nikto çıktısını yorumlayıp `finding`
döndürmüyor (ilk oturumda olduğu gibi).

**Çözüm:** Sistem, tool çıktısında bilinen zafiyetli versiyon kalıplarını
(örn. "Apache 2.2.8", "vsftpd 2.3.4") otomatik tespit edip kullanıcıya bulgu
önerisi sunar. Model `finding` döndürmese bile sistem proaktif önerir.

### 💡 Öneri C: Oturum Özeti / Karar Zinciri Görselleştirme

**Sorun:** Modelin karar zinciri (thought'lar) sadece JSONL log'da, okunması zor.

**Çözüm:** Her oturum sonunda `reports/session_summary.md` üretilir — modelin
adım adım karar zinciri, kullandığı araçlar, bulgular ve süre özeti görsel
tablolarla gösterilir.

### 💡 Öneri D: Kapsam Dışı Hedef İçin "Bilinçli Test" Modu

**Sorun:** Kapsam dışı hedef bloklanıyor ama test sırasında bunu gözlemlemek
zor.

**Çözüm:** `--test-scope` flag'i eklenir. Bu modda modelin kapsam dışı hedef
önermesi bilinçli olarak test edilir ve `REJECTED_OUT_OF_SCOPE` log'u rapora
işlenir. Bu, güvenlik sınırının gerçekten tuttuğunu kanıtlar.

---

## 📅 4. Uygulama Sırası (Öncelik)

| Öncelik | Geliştirme | Etki | Zorluk |
| :--- | :--- | :--- | :--- |
| 1 | **Döngü Kırıcı (Geliştirme 3)** | Takılmayı anında çözer | Düşük |
| 2 | **Bulgu Dedup (Geliştirme 4)** | Mükerrer bulguları önler | Düşük |
| 3 | **nmap Port Desteği (Geliştirme 2)** | Model diğer portları inceleyebilir | Orta |
| 4 | **Hedef Netleştirme (Sorun 3)** | İlk adım karışıklığını çözer | Düşük |
| 5 | **CVE Search Aracı (Geliştirme 1)** | 2024 sonrası bilgi kesintisini çözer | Yüksek |
| 6 | **Bulgu Onayı (Öneri A)** | İnsan-onaylı felsefeyi tamamlar | Düşük |
| 7 | **Otomatik Bulgu Çıkarımı (Öneri B)** | Model bulgu kaçırsa da sistem yakalar | Orta |
| 8 | **Oturum Özeti (Öneri C)** | Karar zincirini görselleştirir | Orta |

---

## 🧪 5. Test Stratejisi

Her geliştirme için test eklenir:

| Geliştirme | Test |
| :--- | :--- |
| Döngü Kırıcı | Aynı komut 2. kez önerildiğinde sistemin uyardığını doğrula |
| Bulgu Dedup | Aynı bulgu 2. kez kaydedilmeye çalışıldığında aynı ID döndüğünü doğrula |
| nmap Port | `ports="21"` verildiğinde komutun `-p 21` içerdiğini doğrula |
| CVE Search | `suggest_cve_search("vsftpd","2.3.4")` gerçek CVE döndürdüğünü doğrula |
| Bulgu Onayı | Bulgu kaydı onay istediğini doğrula |
| Otomatik Çıkarım | Tool çıktısında "Apache 2.2.8" görünce bulgu önerdiğini doğrula |

---

## ✅ 6. Başarı Kriterleri

1. **Takılma yok:** Model aynı komutu 2 kez tekrarlamaz (döngü kırıcı).
2. **Temiz rapor:** Aynı bulgu 2 kez kaydedilmez (dedup).
3. **Derin inceleme:** Model vsftpd 2.3.4 (port 21) ve Samba (port 445) gibi
   belirli portları tek tek inceleyebilir.
4. **Güncel bilgi:** Model 2024 sonrası CVE'leri canlı arayıp rapora ekleyebilir.
5. **İnsan onayı:** Bulgu kaydı dahil tüm kararlar insan onayına tabidir.
6. **21+ test geçiyor:** Mevcut testler + yeni testler.

---

*Bu plan onaylandıktan sonra kodlama yapılacaktır.*
