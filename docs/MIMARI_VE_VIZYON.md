# AutoRedTeam — Kapsamlı Mimari, Modül Rehberi ve Geliştirme Vizyonu

> **Belge Sürümü:** 2.0  
> **Tarih:** 8 Eylül 2026  
> **Odak:** Mevcut Sistem Yetenekleri, Modül Analizi, Eksikler ve "Active Exploitation & Privilege Escalation" Yol Haritası

---

## 1. Giriş ve Proje Vizyonu

**AutoRedTeam**, klasik ve yüzeysel güvenlik tarayıcılarının (yalnızca port tarayıp statik CVE raporu basan araçların) ötesine geçen; **çift yapay zeka beyniyle** kararlar alan, **818 operasyonel siber yeteneği** taktiksel playbook olarak kullanan, **sıfır halüsinasyon filtreli**, çok aşamalı **zafiyet zincirleme (Exploit Chaining)** yapabilen ve hem geleneksel altyapıları hem de **yapay zeka sistemlerini (LLM Red Teaming)** test edebilen yeni nesil otonom bir siber güvenlik platformudur.

### Temel Felsefemiz
1. **Yüzeysel Değil, Derinlemesine Zafiyet:** Sadece "bu port açık" demek yerine, o servisin arkasındaki yazılımı, bilinen zafiyetlerini, exploit senaryolarını ve sisteme sızma yollarını ortaya çıkarmak.
2. **Sıfır Çöp / Sıfır Halüsinasyon:** LLM'lerin spekülatif veya asılsız bulgular uydurmasını engelleyen katı matematiksel kurallar (Validation Gate).
3. **Bütünsel Güvenlik Değerlendirmesi:** Bir ağ portundan başlayıp veritabanına, oradan işletim sistemi kök yetkisine (Root/UID=0) ve kurumun yapay zeka ajanlarına uzanan uçtan uca değerlendirme zinciri.

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                 AUTOREDTEAM CORE ENGINE                 │
                  └────────────────────────────┬────────────────────────────┘
                                               │
               ┌───────────────────────────────┴───────────────────────────────┐
               │                                                               │
     ┌─────────┴─────────┐                                           ┌─────────┴─────────┐
     │   PARENT BRAIN    │                                           │  TACTICAL WORKER  │
     │ DeepSeek V4 Flash │◄───[Strateji, Web Search, Düzeltme]──────►│  CyberStrike 35B  │
     │   (Orchestrator)  │                                           │   (SGLang MoE)    │
     └─────────┬─────────┘                                           └─────────┬─────────┘
               │                                                               │
 ┌─────────────┼──────────────────────────────┬────────────────────────────────┼─────────────┐
 │             │                              │                                │             │
 ▼             ▼                              ▼                                ▼             ▼
┌──────────────┐ ┌──────────────┐ ┌───────────────────────────┐ ┌──────────────┐ ┌───────────┐
│ 818 Skills   │ │ Validation   │ │ Multi-Hop Exploit Chaining│ │ LLM Red Team │ │ Docker    │
│ Library      │ │ Gate (7-Q)   │ │ Engine (Attack Graphs)    │ │ Engine       │ │ Manager   │
│ (Anthropic)  │ │ (Anti-Fluff) │ │ (PrivEsc, SSRF, SQLi)     │ │ (OWASP/PyRIT)│ │ (Lab Env) │
└──────────────┘ └──────────────┘ └───────────────────────────┘ └──────────────┘ └───────────┘
```

---

## 2. Mevcut Mimari Bileşenleri ve Ne İşe Yaradıkları

Sistemimiz modüler, mikro-servis mantığında çalışan ve birbiriyle sıkı entegre 7 ana katmandan oluşur:

### 🧠 Katman A: Çift Zekalı Model Mimarisi (Dual-Brain)
* **Parent Model: DeepSeek V4 Flash (`core/orchestrator.py`)**
  * **Görevi:** Sürecin "Başkomutanı" (Chief Orchestrator). Taktiksel detaylarda boğulmaz; hedefin genel resmine bakar.
  * **Yetenekleri:**
    - Keşfedilen portlara ve servislere göre internette DuckDuckGo üzerinden canlı CVE / PoC araştırması yapar (`web_search` tool calling).
    - 818 siber yetenek kütüphanesinden en doğru playbook'ları seçer.
    - CyberStrike 35B JSON üretemezse devreye girerek düzeltici direktif verir veya doğrudan kendisi JSON üretir.
* **Worker Model: CyberStrike 35B Abliterated (`core/assessment_assistant.py` & SGLang)**
  * **Görevi:** Taktiksel "Saha Ajanı" (Tactical Muscle). Colab'da A100 GPU üzerinde SGLang RadixAttention motoruyla çalışır.
  * **Yetenekleri:**
    - Sansürsüz ofansif güvenlik mantığına sahiptir.
    - SGLang `xgrammar` kısıtlaması (`ASSESSMENT_JSON_SCHEMA`) ile doğrudan saf JSON üretir (parse hatası riski ortadan kaldırılmıştır).
    - `enable_thinking=False` optimizasyonu ile gereksiz akıl yürütme tokenlerini atlar ve ~150 token/saniye hızla doğrudan aksiyon kararı verir.
* **LLM Entegratör Sınıfı (`core/llm_client.py`)**
  * SGLang, vLLM ve OpenAI uyumlu API'leri standartlaştırır. Thinking modunu yönetir, structured output şemalarını aktarır ve modellerin sızdırdığı artık metinleri (`sanitize_llm_response`) temizler.

---

### 🛡️ Katman B: Taktik Kütüphane & İstihbarat
* **Anthropic Cybersecurity Skills Entegrasyonu (`core/skill_loader.py`)**
  * Ajanlar için geliştirilmiş 818 üretim standardı siber güvenlik fonksiyonunu barındırır (Sigma kuralları, bellek analizi, bulut denetimi, BOLA/IDOR analizi vb.).
  * **Port ve Servis Eşleme:** Hedefte açık portlar (21, 22, 80, 445 vb.) veya servis adları (vsftpd, samba, apache) tespit edildiğinde, ilgili port ve protokole özel yetenekleri otomatik olarak DeepSeek ve CyberStrike'ın bağlamına enjekte eder.
* **Canlı İnternet Arama Motoru (`core/web_search.py`)**
  * Modern `ddgs` motoru üzerinden canlı istihbarat toplar. Model bilinmeyen bir yazılım versiyonu gördüğünde anında arama yapıp doğrulanmış exploit referanslarını çeker.
* **Tersine Mühendislik & x64dbg MCP Entegrasyonu (`core/debugger_mcp.py`)**
  * Windows binary analizi ve malware debug süreçleri için tasarlanmış x64dbg MCP arabirimi. Bellek dökümü alma, CPU yazmaçlarını (RAX, RBX, RIP) okuma ve dissassembly analizi yetenekleri sunar.

---

### ⚖️ Katman C: Doğrulama ve Sıfır-Halüsinasyon Filtresi
* **7 Soruluk Katı Doğrulama Kapısı (`core/validation_gate.py`)**
  * Yapay zekanın en büyük zaafı olan "varmış gibi gösterme / abartma" sorununu kökten çözer.
  * **Instant-Kill (Anında İptal) Kuralları:**
    - `[NK-01]`: Eksik HTTP güvenlik başlığı (CSP, HSTS, X-Frame-Options) tek başına bulgu sayılamaz; çöpe atılır.
    - `[NK-03]`: Sadece banner/versiyon bilgisi görmek zafiyet değildir; arkasında çalışan doğrulanmış bir CVE veya exploit kanıtı yoksa reddedilir.
    - `[NK-05]`: Açık yönlendirme (Open Redirect) tek başına zafiyet sayılmaz; bir OAuth sızıntısına veya kimlik avı zincirine bağlanmalıdır.
    - **Spekülasyon Engeli:** *"Zafiyet olabilir"*, *"muhtemelen savunmasızdır"* gibi temelsiz tahminleri reddeder, somut kanıt (`evidence_snippet`) zorunlu tutar.

---

### 🔗 Katman D: Çok Adımlı Exploit Zincirleme
* **Zincirleme Motoru (`core/chain_engine.py` & `chain_table.json`)**
  * Zafiyetleri bağımsız kutucuklar olarak bırakmaz; birbirini tetikleyen bir "Saldırı Grafiği" (Attack Graph) kurar.
  * **Nasıl Çalışır?**
    - `Keşif/Sürüm Tespiti` ➡️ `Zafiyet Doğrulama (CVE)` ➡️ `İlk Erişim (Foothold)` ➡️ `Yetki Yükseltme (PrivEsc / Root)` adımlarını otomatik birbirine bağlar.
    - SSRF, SQL Injection, IDOR, Arbitrary File Upload ve Privilege Escalation zafiyetlerinin nihai sistem etkisini (Terminal Impact) hesaplar.

---

### 🤖 Katman E: Yapay Zeka Sistemlerine Karşı Saldırı Modülü
* **LLM Red Teaming Motoru (`core/llm_redteam_engine.py` & `llm_vulnerabilities.json`)**
  * Yalnızca geleneksel sunucuları değil, **Yapay Zeka ve LLM Ajanlarını hacklemek** için geliştirilmiştir.
  * **Kapsam:**
    - `LLM01`: Prompt Injection & Multi-turn Crescendo saldırıları (modelin güvenlik talimatlarını çiğnetme).
    - `LLM02`: Hassas Veri Sızdırma (API key, connection string, sistem promptu çıkarma).
    - `LLM06`: Excessive Agency / Yetkisiz Araç Ele Geçirme (Modeli manipüle ederek `execute_wire_transfer` veya sistem komutları tetikleme).
  * Hedef LLM'in sağlamlık puanını (**Robustness Score 0-100**) otomatik hesaplar.

---

### 🐳 Katman F: Docker Test Ortamı ve Yaşam Döngüsü
* **Ortam Yöneticisi (`core/docker_manager.py`)**
  * Kasıtlı olarak zafiyet barındıran resmi eğitim laboratuvarlarını yönetir:
    - `autoredteam-metasploitable2` (Ağ ve Linux servis seviyesi zafiyetler).
    - `autoredteam-juice-shop` (Modern web ve API zafiyetleri).
    - `autoredteam-assessment-tools` (Host bağımsız nmap, nikto, sqlmap, gobuster konteyneri).
  * Konteynerlerin sağlığını denetler, port soket kontrolleri yapar ve test bittiğinde sistemi temiz snapshot'a sıfırlar (`reset_target`).

---

### 🖥️ Katman G: Web Operasyon Kokpiti
* **İnteraktif Web UI (`assessment_ui.py`)**
  * `http://127.0.0.1:7870` adresinde çalışan gerçek zamanlı SOC/Red Team kokpiti.
  * **Özellikleri:**
    - Canlı Server-Sent Events (SSE) ile modelin adım adım düşünce sürecini, arka planda icra edilen komutları ve terminal çıktılarını anlık gösterir.
    - İstenirse tam otonom (onaysız), istenirse **Human-in-the-Loop 2.0 (`OperatorDecisionQueue`)** ile tek tıkla onaylanarak çalıştırılabilir.
    - Raporlama sekmesinden MITRE ve OWASP uyumlu profesyonel Markdown raporu tek tıkla incelenebilir.

---

## 3. Mevcut Durumda Sistem Ne Yapabiliyor? (Uçtan Uca Akış)

Şu an sistem bir hedef verildiğinde şu tam döngüyü kusursuz icra etmektedir:
1. **Keşif Başlatma:** Hedefe yönelik nmap/gobuster taraması planlar. Metasploitable2 için tüm kritik portları (21, 22, 23, 25, 80, 139, 445, 1524, 3306, 6667 vb.) otomatik listeye alır.
2. **Servis Analizi:** Örneğin `Port 21: vsftpd 2.3.4` yakaladığında DeepSeek V4 Flash devreye girer, arka planda exploit araştırması yapar ve CyberStrike'a direktif verir.
3. **Zafiyet Doğrulama:** `searchsploit` ve `cve_search` ile CVE-2011-2523 (Backdoor Command Execution) eşleştirmesini yapar.
4. **Kalite Filtresi:** Bulgu Validation Gate'e girer; versiyonun arkasında gerçek bir zafiyet olduğu için `PASSED` damgası alır.
5. **Saldırı Grafiği:** `ChainEngine`, bu bulguyu alır ve *"Root Shell Access without Local Credentials -> Full Host Compromise"* zincirine dönüştürür.
6. **Raporlama:** Tüm bu adımlar canlı olarak web arayüzünde terminal çıktısı ve düşünce baloncuklarıyla akar.

---

## 4. Şimdi Yapacağımız Geliştirme: Neden Gerekli ve Amacımız Ne?

### ⚠️ Tespit Ettiğimiz Eksiklik (Mevcut Durum vs. İstenen Seviye)
Mevcut mimarimiz bir **"Analist / Denetçi"** gibi çalışıyor:
> *"Hedefte vsftpd 2.3.4 var, Samba 3.0.20 var, zafiyetleri tespit ettim, exploit'leri şunlardır, bu açıklar kullanılarak root olunabilir."*

Ancak senin hedeflediğin ve projenin hak ettiği seviye bir **"Gerçek Red Team / Otonom Penetrasyon Testi Ajanı"**:
> *"Hedefte vsftpd 2.3.4 gördüm; arka kapısını tetikledim, port 6200'den içeri girdim. İçeride kim olduğuma baktım: `uid=0(root)`. Hedef tamamen ele geçirildi!"*  
> ya da  
> *"Düşük yetkili bir kullanıcı elde ettim (`uid=1000`). Sistemde SUID dosyalarını aradım, `/usr/bin/nmap` üzerinde SUID biti buldum. GTFOBins tekniğini çalıştırarak yetkimi `root` seviyesine yükselttim!"*

---

## 5. Yapılacak Yeni Geliştirmeler (Active Exploitation & PrivEsc)

Bu seviyeye çıkmak için kod tabanımıza ekleyeceğimiz 3 kritik yapı taşı:

### 1. `core/exploit_runner.py` (Aktif Sömürü Motoru)
Metasploitable2 ve Juice Shop ortamlarındaki açıkları bizzat tetikleyen, hafif, güvenli ve deterministik exploit modülü:
* **vsftpd 2.3.4 Backdoor Runner:** Port 21'e `USER test:)` gönderip Port 6200 üzerinden root kabuğunun açıldığını bizzat doğrular.
* **Samba 3.0.20 Usermap Script Runner (CVE-2007-2447):** Samba komut enjeksiyonu ile hedef sistemde komut çalıştırır.
* **Ingreslock Backdoor Runner:** Port 1524 üzerindeki doğrudan root kabuğunu yoklar.
* **SSH Credential Spray Runner:** Metasploitable üzerinde bilinen varsayılan hesapları (`msfadmin:msfadmin`, `user:user`, `service:service`) dener.
* **Juice Shop SQLi / Token Runner:** Web katmanında admin yetkisi elde eder.

### 2. `core/privesc_engine.py` (Yerel Yetki Yükseltme Motoru)
Sisteme ilk adım (foothold) atıldıktan sonra içeride root olmak için çalışan motor:
* **Linux SUID Enumeration:** Hedef makinedeki SUID bitli dosyaları listeler (`find / -perm -u=s -type f 2>/dev/null`).
* **GTFOBins Analizi:** Listelenen SUID binary'leri arasında yetki yükseltmeye izin veren araçları (örn. `nmap --interactive`, `vim`, `find`, `bash`) tespit eder.
* **Sudoers Denetimi:** Parolasız çalışabilen sudo komutlarını (`sudo -l`) analiz eder.
* **Root Kanıtı (Proof of Privilege):** `id`, `whoami` ve `cat /etc/shadow` çıktılarını alarak yetkinin `root (UID=0)` olduğunu tesciller.

### 3. Model Direktiflerinin ve Taktiklerinin Güncellenmesi
* **DeepSeek V4 Flash** ve **CyberStrike 35B** modellerinin karar şablonlarına `exploit` ve `privesc` tool opsiyonları eklenir.
* Modeller artık portu bulup durmayacak; *"Port açık ve versiyon zafiyetli -> O halde bir sonraki adımda bu zafiyeti sömür ve sistemde oturum aç"* mantığıyla ilerleyecektir.

---

## 6. Özet ve Başarı Ölçütü

| Boyut | Önceki Durum | Yeni Geliştirme Sonrası |
|---|---|---|
| **Erişim Seviyesi** | Yalnızca dışarıdan tarama & CVE korelasyonu | Hedefe sızma (Foothold) + Oturum açma |
| **Yetki Durumu** | Teorik etki tahmini | Fiili yetki yükseltme (PrivEsc ➡️ Root UID=0) |
| **Rapor Kanıtı** | "Nmap ve searchsploit çıktıları" | "Sistemden alınan canlı `id`, `whoami`, `root shell` kanıtları" |
| **Model Rolü** | Güvenlik Denetçisi (Auditor) | Otonom Red Team Operatörü (Full-Chain Penetration Tester) |

Bu yol haritası ile AutoRedTeam, piyasadaki klasik statik araçların çok ötesine geçerek **hedefi bizzat ele geçiren ve kanıtlayan** gerçek bir otonom siber silaha dönüşecektir.
