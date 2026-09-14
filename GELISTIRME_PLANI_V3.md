# AutoRedTeam — Kapsamlı Geliştirme Planı (v3.0)

> **Oluşturulma:** 2026-09-13
> **Temel:** Test 5 (34 adım, web arayüzü) sonuç analizi
> **Amaç:** Metasploitable2'deki **TÜM** zafiyetleri otonom tespit eden, doğrulayan,
> istismar eden ve raporlayan; gerçek dünyada (bug bounty dahil) kullanılabilir
> bir otonom pentest platformu.
> **Hedef Sürüm:** v3.0 (Full-Coverage Autonomous Pentest)
>
> **ÖNEMLİ:** Bu plan, `MIMARI_ANALIZ_VE_TASARIM_V3.md` ile birlikte okunmalıdır.
> Mimari analiz, sistemin **"Deterministik Motor + LLM Danışman"** yapısına
> dönüştürülmesini önerir. Bu plandaki fazlar o mimariye göre sıralanmıştır.

---

## 0. Yönetici Özeti (Neden Bu Plan?)

Test 5'te sistem **34 adım** çalıştı, **16 bulgu** üretti, root elde etti — ama
Metasploitable2'nin bilinen **~25 zafiyetinin yalnızca küçük bir kısmını**
gerçekten istismar etti. Kök neden: sistem **"kapsam tamlığı" (coverage)** ile
**"istismar derinliği" (exploitation depth)** arasındaki farkı karıştırıyor.
Servis "test edildi" sayılıyor ama gerçekte yalnızca `searchsploit` lookup
yapılıyor. Web uygulamaları (DVWA, Mutillidae, phpMyAdmin, TikiWiki, WebDAV)
hiç istismar edilmiyor.

Bu plan, sistemi **kanıt-temelli bir istismar motoruna** dönüştürür:
1. **Recon** (mevcut, iyi) → 2. **Vulnerability Mapping** (eksik) →
3. **Active Exploitation** (zayıf) → 4. **Post-Exploitation** (yok) →
5. **Verification** (kısmi) → 6. **Reporting** (iyi).

---

## 1. Test 5 Sonuç Analizi (Kanıta Dayalı)

### 1.1 Ne Oldu?

| Metrik | Değer |
|---|---|
| Toplam adım | 34 |
| Bulgu sayısı | 16 |
| Critical | 5 (SSH creds, ingreslock, 3× privesc) |
| Informational | 11 (çoğu nmap versiyon tespiti) |
| Foothold | Evet (msfadmin:msfadmin) |
| Root | Evet (ingreslock + sudo ALL) |
| Gerçekten çalışan exploit | **2 / 11** (ssh_credential_spray, ingreslock_backdoor) |

### 1.2 Adım Dağılımı (34 adım)

| Adım aralığı | Ne yapıldı | Sorun |
|---|---|---|
| 1–11 | nmap, ssh spray, ingreslock, distcc, vsftpd, samba, unrealircd | Çoğu exploit başarısız |
| 12–25 | `searchsploit`/`nmap` lookup (smtp, rpcbind, rlogin, rsh, mysql, postgresql, nfs) | **Sadece lookup — istismar YOK** |
| 17–24 | exploit denemeleri (java-rmi, proftpd, vnc, unrealircd, tomcat, ruby-drb) | Hepsi başarısız |
| 26–30 | nikto dvwa/mutillidae, searchsploit phpmyadmin/tikiwiki/webdav | **Yüzeysel — gerçek istismar YOK** |
| 31–33 | privesc (verify_root, sudoers, SUID) | 3 ayrı tekrarlı bulgu |

### 1.3 Kök Nedenler (Kanıtlı)

| # | Kök Neden | Kanıt | Etki |
|---|---|---|---|
| **R1** | **"Lookup ≠ Exploitation"** | Adım 12–30 çoğu `searchsploit`; `_untested_services` lookup'ı "test edildi" sayıyor | Servisler test edilmiş görünüyor ama istismar edilmiyor |
| **R2** | **Web istismar motoru yok** | DVWA/Mutillidae sadece `nikto` ile tarandı; SQLi/XSS/upload denenmedi | Metasploitable2'nin en zengin zafiyet kaynağı (%40+) kaçırılıyor |
| **R3** | **Exploit payload'ları bozuk** | distcc "command not found", unrealircd "not registered", ruby_drb 0 byte, samba doğrulama yok | 9/11 exploit başarısız |
| **R4** | **Bulgu tekrarı** | FIND-014/015/016 üç ayrı "Privilege Escalation" | Rapor kalitesi düşük, zincir kayboluyor |
| **R5** | **Severity yanlış** | nmap versiyon tespitleri "Informational" ama CVE eşlemesi yok | Gerçek risk skoru yanlış |
| **R6** | **Model takılması** | 12 adım `searchsploit` tekrarı | Deterministik mod kurtarıyor ama derinlik yok |
| **R7** | **Foothold sonrası keşif yok** | Root alındı ama `/etc/passwd`, DB dump, dosya sistemi keşfi yok | Post-exploitation eksik |
| **R8** | **Kimlik bilgisi yeniden kullanımı yok** | msfadmin:msfadmin bulundu ama MySQL/PostgreSQL/Tomcat'te denenmedi | Credential reuse kaçırılıyor |

### 1.4 Metasploitable2 Zafiyet Haritası vs. Bulunanlar

| # | Zafiyet | Port/Path | Test 5'te | Durum |
|---|---|---|---|---|
| 1 | vsftpd 2.3.4 backdoor | 21 | Denendi, başarısız | Payload |
| 2 | SSH default creds | 22 | Bulundu | OK |
| 3 | Telnet default creds | 23 | Sadece nmap | Eksik |
| 4 | Postfix SMTP open relay | 25 | Sadece lookup | Eksik |
| 5 | Apache + PHP 5.2.4 | 80 | nmap/nikto | Yüzeysel |
| 6 | **DVWA SQLi/XSS/CMD** | 80/dvwa | Sadece nikto | Eksik |
| 7 | **Mutillidae OWASP** | 80/mutillidae | Sadece nikto | Eksik |
| 8 | **phpMyAdmin default creds** | 80/phpMyAdmin | Sadece lookup | Eksik |
| 9 | **TikiWiki RCE** | 80/tikiwiki | Sadece lookup | Eksik |
| 10 | **WebDAV PUT upload** | 80/dav | Sadece lookup | Eksik |
| 11 | rpcbind/portmapper | 111 | Sadece nmap | Eksik |
| 12 | **Samba usermap RCE** | 445 | Denendi, doğrulama yok | Zayıf |
| 13 | rexec/rlogin/rsh trust | 512-514 | Sadece lookup | Eksik |
| 14 | Java RMI deserialize | 1099 | Denendi, başarısız | Payload |
| 15 | **Ingreslock backdoor** | 1524 | Bulundu | OK |
| 16 | ProFTPD mod_copy | 2121 | Denendi, başarısız | Payload |
| 17 | **MySQL 5.0 auth bypass** | 3306 | Sadece lookup | Eksik |
| 18 | **PostgreSQL 8.3** | 5432 | Sadece lookup | Eksik |
| 19 | VNC null auth | 5900 | Port kapalı | Zayıf |
| 20 | UnrealIRCd backdoor | 6667 | Denendi, başarısız | Payload |
| 21 | **Tomcat manager deploy** | 8180 | Timeout | Eksik |
| 22 | **Ruby DRb RCE** | 8787 | Denendi, başarısız | Payload |
| 23 | NFS exports | 2049 | Sadece nmap | Eksik |
| 24 | **SUID/sudo privesc** | local | Bulundu | OK |
| 25 | **Kernel exploit (2.6.24)** | local | Hiç denenmedi | Eksik |

**Sonuç: 25 zafiyetten yalnızca ~4'ü gerçekten istismar edildi (%16).**

---

## 2. Hedef Mimari (v3.0)

### 2.1 Yeni Katmanlı Akış

```
KATMAN 0: SCOPE & SAFETY (mevcut - core/scope.py)
  Allow-list, human-in-the-loop, audit log
KATMAN 1: RECON (mevcut - core/recon_engine.py) [IYI]
  nmap -sV -sC -> nuclei -> enum4linux -> gobuster -> nikto -> whatweb
KATMAN 2: VULNERABILITY MAPPING (YENI - core/vuln_mapper.py)
  Servis+versiyon -> CVE eslemesi -> istismar edilebilirlik skoru
  searchsploit + NVD API + web_search -> yapilandirilmis hedef modeli
KATMAN 3: EXPLOITATION (genisletilecek - core/exploit_runner.py)
  3a. Network exploit'leri (duzeltilecek payload'lar)
  3b. WEB EXPLOIT ENGINE (YENI - core/web_exploit_engine.py)
      SQLi (sqlmap), XSS, CMD injection, file upload, LFI/RFI
  3c. CREDENTIAL ENGINE (YENI - core/credential_engine.py)
      Default creds + reuse + brute (hydra)
KATMAN 4: POST-EXPLOITATION (YENI - core/post_exploit.py)
  Foothold -> sistem kesfi -> privesc -> lateral movement
KATMAN 5: VERIFICATION (mevcut - core/validation_gate.py)
  Her bulgu kanitla dogrulanir (uid=0, dosya icerigi, DB dump)
KATMAN 6: REPORTING (iyilestirilecek - reports/)
  Zincir birlestirme, CVSS skoru, remediation, PDF/MD
```

### 2.2 Yeni Moduller

| Modul | Dosya | Gorev | Oncelik |
|---|---|---|---|
| Vulnerability Mapper | `core/vuln_mapper.py` | Servis->CVE->exploit eslemesi, skorlama | P0 |
| Web Exploit Engine | `core/web_exploit_engine.py` | SQLi/XSS/CMD/upload/LFI otomasyonu | P0 |
| Credential Engine | `core/credential_engine.py` | Default creds, reuse, hydra brute | P0 |
| Post-Exploitation | `core/post_exploit.py` | Foothold sonrasi kesif + privesc zinciri | P1 |
| Exploit Payload Library | `scripts/exploits/*` | Duzeltilmis payload'lar | P0 |
| Finding Correlator | `core/finding_correlator.py` | Bulgu tekrari birlestirme, zincir | P1 |
| CVSS Scorer | `core/cvss_scorer.py` | Otomatik CVSS v3.1 skoru | P2 |

---

## 3. Faz Bazli Gelistirme Plani

### FAZ A - Exploit Payload Duzeltmeleri (P0, ~2 gun)

**Amac:** Mevcut 9 basarisiz exploit'i calisir hale getir.

#### A1. distcc_exec (CVE-2004-2687)
- **Sorun:** `#: None: command not found` - payload formati yanlis.
- **Cozum:** distcc protokolu `DIST00000001` + `ARGC` + `ARGV` + `DOTI` formati.
  Dogru payload: `DIST00000001ARGC00000005ARGV00000002shARGV00000002-cARGV0000000X<cmd>ARGV00000001#ARGV00000001#DOTI00000001`
- **Dogrulama:** `id` ciktisinda `uid=` gorulmeli.
- **Dosya:** `scripts/exploits/distcc_exec.py`

#### A2. unrealircd_backdoor (CVE-2010-2075)
- **Sorun:** `451 AB; :You have not registered` - backdoor tetikleme dizisi yanlis.
- **Cozum:** `AB; <command>` formati; bazi surumlerde `AB` prefix'i `\n` ile ayrilmali.
- **Dogrulama:** Komut ciktisi (uid=) yanitta gorulmeli.
- **Dosya:** `scripts/exploits/unrealircd_backdoor.py`

#### A3. ruby_drb_rce
- **Sorun:** Payload 14 byte, yanit 0 byte - marshal gadget gecersiz.
- **Cozum:** Gecerli Ruby 1.8 `DRb` marshal gadget zinciri (Universal Deserialisation
  Gadget). `Gem::Requirement` + `Gem::Installer` zinciri veya `ERB` gadget.
- **Dogrulama:** Komut ciktisi veya reverse shell.
- **Dosya:** `scripts/exploits/ruby_drb_rce.py`

#### A4. samba_usermap (CVE-2007-2447)
- **Sorun:** Enjeksiyon gonderiliyor ama dogrulama yok.
- **Cozum:** `username = "/=`nohup <cmd> 2>&1 | tee /tmp/out`"` formati; ardindan
  SMB uzerinden `/tmp/out` okunmali veya reverse shell ile dogrulanmali.
- **Dogrulama:** Komut ciktisi SMB share'den okunmali.
- **Dosya:** `scripts/exploits/samba_usermap.py`

#### A5. vsftpd_backdoor (CVE-2011-2523)
- **Sorun:** Port 6200 kapali - backdoor tetiklenmedi.
- **Cozum:** `USER test:)` sonrasi `PASS` gonderilmeli; bazi Docker imajlarinda
  backdoor devre disi. Bu durumda "denendi, hedefte yok" olarak raporla.
- **Dosya:** `scripts/exploits/vsftpd_backdoor.py`

#### A6. proftpd_modcopy (CVE-2015-3306)
- **Sorun:** mod_copy desteklenmiyor (1.3.1).
- **Cozum:** ProFTPD 1.3.1'de mod_copy yok; `SITE CPFR/CPTO` destegini kontrol et.
  Desteklenmiyorsa "denendi, basarisiz" olarak raporla.

#### A7. java_rmi_deserialize
- **Sorun:** Protokol farkli yanit veriyor.
- **Cozum:** `ysoserial` benzeri gadget (CommonsCollections) veya RMI registry
  bind/lookup manipulasyonu. Once `list` ile bagli objeleri kesfet.

#### A8. tomcat_manager_deploy
- **Sorun:** Timeout (port 8180).
- **Cozum:** Timeout'u artir (60s), once port acik mi dogrula, default creds
  (`tomcat:tomcat`, `admin:admin`) ile manager'a gir, WAR deploy et.
  Port kapaliysa "denendi, port kapali" olarak raporla.

#### A9. vnc_null_auth
- **Sorun:** Port 5900 kapali.
- **Cozum:** Port kapaliysa atla ve raporla. Aciksa RFB handshake + null auth.

**Test:** Her exploit icin `tests/test_exploit_payloads.py` - mock hedefe karsi
payload formati dogrulamasi.

---

### FAZ B - Web Exploit Engine (P0, ~4 gun)

**Amac:** Metasploitable2'nin en zengin zafiyet kaynagini (web uygulamalari)
gercekten istismar et.

#### B1. Yeni Modul: `core/web_exploit_engine.py`

```python
class WebExploitEngine:
    def exploit_sqli(self, url, param) -> Finding      # sqlmap entegrasyonu
    def exploit_xss(self, url, param) -> Finding       # reflected/stored
    def exploit_cmd_injection(self, url, param) -> Finding
    def exploit_file_upload(self, url) -> Finding      # WebDAV PUT, DVWA upload
    def exploit_lfi_rfi(self, url, param) -> Finding
    def exploit_default_creds(self, url) -> Finding    # phpMyAdmin, Tomcat
    def exploit_cms(self, url, cms) -> Finding         # TikiWiki RCE
```

#### B2. Hedef Bazli Istismar Stratejileri

| Hedef | Path | Istismar | Arac |
|---|---|---|---|
| DVWA | `/dvwa/` | SQLi, XSS, CMD injection, file upload | sqlmap, curl, custom |
| Mutillidae | `/mutillidae/` | SQLi, XSS, LFI, RFI | sqlmap, curl |
| phpMyAdmin | `/phpMyAdmin/` | Default creds (root:""), CVE-2012-2122 | curl, hydra |
| TikiWiki | `/tikiwiki/` | CVE-2020-xxxx RCE, file upload | curl, searchsploit |
| WebDAV | `/dav/` | PUT upload -> RCE | curl, cadaver |
| Tomcat | `:8180/manager` | Default creds -> WAR deploy | curl |

#### B3. sqlmap Entegrasyonu
- `assessment_tools.py`'de `suggest_sqlmap_check` var ama **hic cagrilmiyor**.
- Deterministik fallback'e web app SQLi adimlari ekle.
- sqlmap ciktisini parse edip Finding'e donustur.

#### B4. Web Form Kesfi
- `browser_tool.py` (Playwright) ile form/input kesfi.
- Bulunan her form -> SQLi/XSS testi.
- `gobuster` ile ek dizin kesfi.

**Test:** `tests/test_web_exploit_engine.py` - mock HTTP sunucusu ile.

---

### FAZ C - Credential Engine (P0, ~2 gun)

**Amac:** Default creds + credential reuse + brute force.

#### C1. Yeni Modul: `core/credential_engine.py`

```python
class CredentialEngine:
    def try_default_creds(self, service, host, port) -> List[Credential]
    def reuse_credentials(self, creds, services) -> List[Credential]
    def brute_force(self, service, host, port, wordlist) -> List[Credential]
```

#### C2. Servis Bazli Default Creds

| Servis | Port | Default Creds |
|---|---|---|
| SSH | 22 | msfadmin:msfadmin, user:user |
| Telnet | 23 | msfadmin:msfadmin |
| MySQL | 3306 | root:"", root:root |
| PostgreSQL | 5432 | postgres:postgres |
| Tomcat | 8180 | tomcat:tomcat, admin:admin |
| phpMyAdmin | 80 | root:"", root:root |
| VNC | 5900 | (null auth) |

#### C3. Credential Reuse
- SSH'de bulunan `msfadmin:msfadmin` -> MySQL, PostgreSQL, Telnet, SMB'de dene.
- Bulunan her cred -> tum servislere otomatik uygula.

#### C4. Hydra Entegrasyonu
- Docker'da `hydra` var ama kullanilmiyor.
- Kucuk wordlist ile brute force (egitim hedeflerinde).

**Test:** `tests/test_credential_engine.py`.

---

### FAZ D - Vulnerability Mapper (P1, ~3 gun)

**Amac:** Servis+versiyon -> CVE -> exploit eslemesi, otomatik skorlama.

#### D1. Yeni Modul: `core/vuln_mapper.py`

```python
class VulnerabilityMapper:
    def map_service(self, service, version) -> List[Vulnerability]
    def score_exploitability(self, vuln) -> float
    def get_exploit_for(self, vuln) -> Optional[str]
```

#### D2. Veri Kaynaklari
- `searchsploit` (offline Exploit-DB) - mevcut
- NVD API v2.0 (`cve_lookup.py` var) - mevcut
- `web_search.py` - mevcut
- Yeni: yerel CVE->exploit haritasi (`knowledge_base/`)

#### D3. Cikti: Yapilandirilmis Hedef Modeli
```json
{
  "service": "vsftpd",
  "version": "2.3.4",
  "port": 21,
  "cves": ["CVE-2011-2523"],
  "exploitability": 0.95,
  "exploit_module": "vsftpd_backdoor",
  "status": "pending"
}
```

#### D4. Severity Duzeltmesi (R5)
- nmap versiyon tespitleri -> CVE eslemesi varsa **High/Critical**.
- CVSS v3.1 skoru otomatik hesapla (`core/cvss_scorer.py`).

**Test:** `tests/test_vuln_mapper.py`.

---

### FAZ E - Post-Exploitation (P1, ~3 gun)

**Amac:** Foothold sonrasi sistem kesfi, privesc zinciri, lateral movement.

#### E1. Yeni Modul: `core/post_exploit.py`

```python
class PostExploit:
    def enumerate_system(self, session) -> SystemInfo      # uname, /etc/passwd, users
    def find_privesc(self, session) -> List[PrivescVector] # SUID, sudo, kernel, cron
    def dump_credentials(self, session) -> List[Credential] # /etc/shadow, config files
    def lateral_movement(self, creds, hosts) -> List[Session]
```

#### E2. Privesc Zinciri Birlestirme (R4)
- `verify_root`, `sudoers`, `SUID` bulgularini **tek "Privilege Escalation
  Chain"** bulgusu olarak birlestir.
- `core/finding_correlator.py` ile otomatik gruplama.

#### E3. Kernel Exploit Kontrolu
- Metasploitable2 kernel 2.6.24 -> `searchsploit linux kernel 2.6.24`.
- Uygun exploit varsa dene (orn. `CVE-2009-1185` udev).

#### E4. Sistem Kesfi
- `/etc/passwd`, `/etc/shadow` (root ise), `/home/*/.ssh`, config dosyalari.
- MySQL/PostgreSQL dump (root ise).

**Test:** `tests/test_post_exploit.py`.

---

### FAZ F - Bulgu Korelasyonu & Rapor Kalitesi (P1, ~2 gun)

**Amac:** Bulgu tekrarini birlestir, zincirleri goster, CVSS ekle.

#### F1. Yeni Modul: `core/finding_correlator.py`
- Ayni kategori + ayni hedef -> tek bulgu (kanitlari birlestir).
- Privesc bulgulari -> "Privilege Escalation Chain".
- Exploit zincirleri -> "Attack Narrative".

#### F2. Rapor Iyilestirmeleri
- CVSS v3.1 skoru + vektor.
- MITRE ATT&CK eslemesi.
- Remediation: kategori bazli gercek oneriler (su an generic).
- "Denendi, basarisiz" bulgulari da raporla (R6).
- Executive summary'de risk skoru.

#### F3. PDF Rapor
- `reports/pdf_report_generator.py` mevcut - CVSS + zincir ekle.

**Test:** `tests/test_finding_correlator.py`.

---

### FAZ G - LLM Rolunu Dogru Katmana Oturtma (P2, ~3 gun)

> **NOT (Kavram Netlestirmesi):** "Model takilmasi" bir model sorunu DEGIL,
> mimari sorunudur. Su an CyberStrike 35B'ye "siradaki adim ne?" diye
> soruluyor; bu DETERMINISTIK bir is (tarama/istismar sirasi) ve LLM'e
> yaptirilinca model ayni cevabi tekrarliyor (Test 5'te 12 adim searchsploit).
> Cozum: Bu isi deterministik `exploit_planner.py`'ye vermek; LLM'i yalnizca
> YORUM/PAYLOAD uretimi icin kullanmak. Detay: `MIMARI_ANALIZ_VE_TASARIM_V3.md` Bolum 1.3 ve 5.

**Amac:** LLM'i "karar verici" rolunden "danisman" rolune tasimak.

#### G1. Deterministik Planner'i Devreye Al
- `core/exploit_planner.py` istismar sirasini belirlesin (LLM'siz).
- LLM artik "siradaki adim ne?" sorusuna cevap VERMEZ.
- Bu, takilma sorununu mimari olarak cozer.

#### G2. LLM Rollerini Yeniden Tanimla
- **CyberStrike 35B** -> Payload Crafter (standart payload basarisiz olunca ozel payload uretir).
- **DeepSeek V4 Flash** -> Triage Advisor (kanit yorumu, oncelik karari, rapor anlatisi).
- **Claude** -> Escalation Oracle (tum deterministik yollar tukenince alternatif strateji).
- Detay: `MIMARI_ANALIZ_VE_TASARIM_V3.md` Bolum 5.

#### G3. Sistem Promptu Optimizasyonu
- Su an ~3000 karakter -> 1500'e indir (artik "adim secme" promptu gerekmez).
- Few-shot ornekler: basarili payload uretimi ornekleri.

#### G4. Model Fallback Zinciri
- CyberStrike -> DeepSeek -> deterministik planner.
- Her katman bir ustteki basarisiz olunca devreye girer.

---

### FAZ H - Gercek Dunya Hazirligi (P2, ~3 gun)

**Amac:** Bug bounty ve gercek hedeflerde kullanilabilirlik.

#### H1. Scope Yonetimi
- `allowed_targets.txt` -> dinamik scope (domain, IP range, wildcard).
- Bug bounty programlari icin scope import (HackerOne/Bugcrowd formati).

#### H2. Rate Limiting & Stealth
- Istek hizi sinirlama (WAF tespiti onleme).
- User-Agent rotasyonu.
- Proxy destegi (Burp, ZAP).

#### H3. Kimlik Dogrulama Destegi
- Login akisi (form-based, JWT, API key).
- Session yonetimi.

#### H4. API Pentest
- OpenAPI/Swagger kesfi.
- REST/GraphQL endpoint testi.

#### H5. Raporlama Standartlari
- Bug bounty platform formatlari.
- CVSS + CWE + OWASP + MITRE ATT&CK.

---

## 4. Oncelik Matrisi

| Faz | Oncelik | Sure | Bagimlilik | Etki |
|---|---|---|---|---|
| **A** - Exploit Payload | P0 | 2 gun | - | 9 exploit duzelir |
| **B** - Web Exploit Engine | P0 | 4 gun | - | %40 zafiyet kapsami |
| **C** - Credential Engine | P0 | 2 gun | - | Cred reuse |
| **D** - Vuln Mapper | P1 | 3 gun | A, B, C | Otomatik esleme |
| **E** - Post-Exploitation | P1 | 3 gun | C | Derinlik |
| **F** - Korelasyon & Rapor | P1 | 2 gun | A-E | Kalite |
| **G** - Otonomi | P2 | 3 gun | A-F | Model takilmasi |
| **H** - Gercek Dunya | P2 | 3 gun | A-G | Bug bounty |

**Toplam: ~22 gun (paralel calismayla ~12 gun)**

---

## 5. Basari Kriterleri (Definition of Done)

### v3.0 Hedefi
- [ ] Metasploitable2'deki **25 zafiyetten >=20'si** tespit edilir.
- [ ] **>=15'i** gercekten istismar edilir (kanitli).
- [ ] Web uygulamalari (DVWA, Mutillidae, phpMyAdmin, TikiWiki, WebDAV)
      **gercekten istismar edilir**.
- [ ] Credential reuse calisir (SSH creds -> MySQL/PostgreSQL/Tomcat).
- [ ] Privesc bulgulari **tek zincirde** birlesir.
- [ ] Her bulgu **CVSS skoru** + **kanit** icerir.
- [ ] "Denendi, basarisiz" bulgular da raporlanir.
- [ ] Test sayisi **>=220** (su an 172).
- [ ] Rapor: Executive summary + attack narrative + remediation.

### Gercek Dunya Hedefi
- [ ] HackTheBox/TryHackMe makinesinde uctan uca calisir.
- [ ] Bug bounty scope import edilebilir.
- [ ] Rate limiting + proxy destegi.
- [ ] API pentest (OpenAPI/GraphQL).

---

## 6. Riskler ve Onlemler

| Risk | Olasilik | Etki | Onlem |
|---|---|---|---|
| Docker metasploitable2'de bazi zafiyetler yok | Yuksek | Orta | "Denendi, hedefte yok" raporla |
| Exploit payload'lari hedefe ozel | Orta | Yuksek | Her payload'i gercek hedefte test et |
| Web exploit WAF'a takilir | Orta | Orta | Rate limiting, stealth |
| Model hala takilir | Orta | Dusuk | Deterministik motor tam kapsam |
| Etik/yasal risk | Dusuk | Yuksek | Allow-list + human-in-the-loop korunur |

---

## 7. Hemen Baslanacak Ilk Adimlar (Sprint 1)

1. **A1-A9:** Exploit payload duzeltmeleri (2 gun)
2. **B1-B4:** Web Exploit Engine iskeleti (2 gun)
3. **C1-C3:** Credential Engine (1 gun)
4. **Test:** Her modul icin unit test + gercek metasploitable2 testi

**Sprint 1 Ciktisi:** 9 exploit duzelir, web istismar calisir, cred reuse aktif.

---

## 8. Dosya Degisiklik Haritasi

### Yeni Dosyalar
```
core/vuln_mapper.py           # FAZ D
core/web_exploit_engine.py    # FAZ B
core/credential_engine.py     # FAZ C
core/post_exploit.py          # FAZ E
core/finding_correlator.py    # FAZ F
core/cvss_scorer.py           # FAZ D
scripts/exploits/distcc_exec.py         # FAZ A (duzelt)
scripts/exploits/unrealircd_backdoor.py # FAZ A (duzelt)
scripts/exploits/ruby_drb_rce.py        # FAZ A (duzelt)
scripts/exploits/samba_usermap.py       # FAZ A (duzelt)
tests/test_web_exploit_engine.py        # FAZ B
tests/test_credential_engine.py         # FAZ C
tests/test_vuln_mapper.py               # FAZ D
tests/test_post_exploit.py              # FAZ E
tests/test_finding_correlator.py        # FAZ F
```

### Degistirilecek Dosyalar
```
core/assessment_assistant.py    # Deterministik fallback'e yeni adimlar
core/exploit_runner.py          # Yeni exploit'ler + payload duzeltmeleri
core/assessment_tools.py        # sqlmap entegrasyonu
reports/pdf_report_generator.py # CVSS + zincir
PROJE_DURUM_VE_YOL_HARITASI.md  # v3.0 guncellemesi
```

---

## 9. Metrikler (Takip)

| Metrik | Su An | v3.0 Hedefi |
|---|---|---|
| Gercek istismar orani | %16 (4/25) | >=%80 (20/25) |
| Web app istismari | %0 | %100 (5/5 app) |
| Credential reuse | Yok | Aktif |
| Exploit basari orani | %18 (2/11) | >=%70 |
| Bulgu tekrari | 3 privesc | 1 zincir |
| CVSS skoru | Yok | Her bulgu |
| Test sayisi | 172 | >=220 |
| Rapor kalitesi | %80 | %95 |

---

## 10. Uygulama Sirasi (Roadmap)

```
Sprint 1 (Hafta 1):  FAZ A (payload) + FAZ C (credential)  -> temel duzeltme
Sprint 2 (Hafta 2):  FAZ B (web exploit engine)            -> kapsam genisleme
Sprint 3 (Hafta 3):  FAZ D (vuln mapper) + FAZ E (post-exp) -> derinlik
Sprint 4 (Hafta 4):  FAZ F (rapor) + FAZ G (otonomi)       -> kalite
Sprint 5 (Hafta 5):  FAZ H (gercek dunya) + final test     -> bug bounty
```

---

*Bu plan, Test 5 sonuclarinin kanita dayali analizi uzerine kurulmustur.
Her faz tamamlandiginda gercek metasploitable2 testi ile dogrulanmalidir.*
