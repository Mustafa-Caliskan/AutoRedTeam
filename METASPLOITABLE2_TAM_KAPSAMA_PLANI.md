# AutoRedTeam — Metasploitable2 Tam Kapsama Planı (v3.2)

> **Oluşturulma:** 2026-09-14
> **Mevcut Durum:** 28 zafiyetten 8'i bulunuyor (%29)
> **Hedef:** 28 zafiyetten ≥22'si bulunuyor (%80+)
> **Temel:** Test sonucu analizi (8 bulgu, otonom AI root aldı)

---

## 0. Mevcut Durum Özeti

### Bulunan 8 Zafiyet
| # | Zafiyet | Şiddet | Kaynak |
|---|---|---|---|
| 1 | SSH default creds (msfadmin:msfadmin) | Critical | Deterministik |
| 2 | Ingreslock backdoor (root shell) | Critical | Deterministik |
| 3 | Credential reuse | Critical | Deterministik |
| 4 | WebDAV File Upload | High | Deterministik |
| 5 | Privilege Escalation (SUID/sudo) | High | Deterministik |
| 6 | DVWA SQL Injection | Critical | Deterministik |
| 7 | DVWA XSS | Medium | Deterministik |
| 8 | Mutillidae LFI | High | Deterministik |

### Otonom AI Durumu
- ✅ Root alıyor (suid_enumeration → verify_root)
- ✅ Root sonrası devam ediyor (/etc/shadow okuyor)
- ❌ `web_exploit` tool'unu hiç kullanmıyor (web bulguları deterministik'ten)

### Eksik 20 Zafiyet
| # | Zafiyet | Port/Path | Sorun |
|---|---|---|---|
| 1 | vsftpd 2.3.4 backdoor | 21 | Docker'da kapalı |
| 2 | Telnet default creds | 23 | Denenmiyor |
| 3 | Postfix SMTP | 25 | Denenmiyor |
| 4 | DVWA Command Injection | 80/dvwa | Payload formatı |
| 5 | Mutillidae SQLi/XSS | 80/mutillidae | Login/form keşfi yok |
| 6 | phpMyAdmin default creds | 80/phpMyAdmin | Denenmiyor |
| 7 | TikiWiki RCE | 80/tikiwiki | Denenmiyor |
| 8 | rpcbind | 111 | Denenmiyor |
| 9 | Samba usermap | 445 | Payload bozuk |
| 10 | rexec/rlogin/rsh | 512-514 | Denenmiyor |
| 11 | Java RMI | 1099 | Payload bozuk |
| 12 | ProFTPD mod_copy | 2121 | Payload bozuk |
| 13 | MySQL 5.0 auth bypass | 3306 | Denenmiyor |
| 14 | PostgreSQL | 5432 | Denenmiyor |
| 15 | VNC null auth | 5900 | Port kapalı |
| 16 | UnrealIRCd backdoor | 6667 | Payload bozuk |
| 17 | Tomcat manager | 8180 | Denenmiyor |
| 18 | Ruby DRb RCE | 8787 | Payload bozuk |
| 19 | NFS exports | 2049 | Denenmiyor |
| 20 | Kernel exploit | local | Denenmiyor |

---

## AŞAMA 1: Web Uygulamalarını Tam Kapsama (P0, ~3 gün)

**Hedef:** +4 bulgu (DVWA CMD, Mutillidae SQLi/XSS, phpMyAdmin, TikiWiki)
**Etki:** En yüksek — Metasploitable2'nin %40'ı web

### 1.1 DVWA Command Injection
- **Sorun:** Payload formatı yanlış
- **Çözüm:** `ip=127.0.0.1; id` (POST, URL-encoded `%3B`)
- **Doğrulama:** Çıktıda `uid=` görülmeli
- **Dosya:** `core/web_exploit_engine.py` `_dvwa_cmd_injection`

### 1.2 Mutillidae SQLi/XSS
- **Sorun:** Login/form keşfi yok
- **Çözüm:**
  - Mutillidae login (anonim erişim genelde açık)
  - SQLi: `?page=user-info.php&username=...&password=...&user-info-php-submit-button=View+Account+Details`
  - XSS: `?page=set-background-color.php&color=...`
- **Dosya:** `core/web_exploit_engine.py` `exploit_mutillidae`

### 1.3 phpMyAdmin Default Creds
- **Sorun:** Denenmiyor
- **Çözüm:**
  - Login: `root:""`, `root:root`
  - CVE-2012-2122 (MySQL auth bypass)
- **Doğrulama:** phpMyAdmin paneline erişim
- **Dosya:** `core/web_exploit_engine.py` `exploit_phpmyadmin`

### 1.4 TikiWiki RCE
- **Sorun:** Denenmiyor
- **Çözüm:**
  - CVE-2020-xxxx (TikiWiki file upload RCE)
  - `tiki-editpage.php` üzerinden PHP upload
- **Doğrulama:** Upload edilen shell erişimi
- **Dosya:** `core/web_exploit_engine.py` `exploit_tikiwiki`

### 1.5 Web Exploit Engine Genişletme
```python
class WebExploitEngine:
    def exploit_dvwa(self) -> List[WebFinding]        # mevcut
    def exploit_mutillidae(self) -> List[WebFinding]  # YENİ
    def exploit_phpmyadmin(self) -> List[WebFinding]  # YENİ
    def exploit_tikiwiki(self) -> List[WebFinding]    # YENİ
    def exploit_webdav(self) -> List[WebFinding]      # mevcut
```

---

## AŞAMA 2: Veritabanı İstismarı (P0, ~2 gün)

**Hedef:** +2 bulgu (MySQL, PostgreSQL)
**Etki:** Yüksek — veri sızıntısı

### 2.1 MySQL 5.0 Auth Bypass (CVE-2012-2122)
- **Sorun:** Denenmiyor
- **Çözüm:**
  - `mysql -h target -u root -pwrong` (birden fazla deneme, auth bypass)
  - Default creds: `root:""`, `root:root`
- **Doğrulama:** `SELECT 1` çalışmalı
- **Dosya:** `core/credential_engine.py` + `core/exploit_runner.py`

### 2.2 PostgreSQL Default Creds
- **Sorun:** Denenmiyor
- **Çözüm:** `postgres:postgres`, `postgres:""`
- **Doğrulama:** `psql` bağlantısı
- **Dosya:** `core/credential_engine.py`

### 2.3 MySQL UDF Privesc
- **Sorun:** Denenmiyor
- **Çözüm:** MySQL root ise UDF ile sistem komutu
- **Dosya:** `core/privesc_engine.py`

---

## AŞAMA 3: AI'yi Web'e Yönlendir (P1, ~2 gün)

**Hedef:** AI `web_exploit` tool'unu kullansın
**Etki:** Orta — otonomi kalitesi

### 3.1 AI Prompt Güçlendirme
- **Sorun:** AI web_exploit'i görmezden geliyor
- **Çözüm:**
  - Prompt'a web dizinlerini ekle (recon'dan)
  - "Web uygulamaları bulundu: dvwa, mutillidae..." bilgisini ver
  - Rule: "If web apps are present, test them FIRST"
- **Dosya:** `core/autonomous_agent.py` `AGENT_SYSTEM_PROMPT`

### 3.2 AI Bağlamına Web Bulguları Ekle
- **Sorun:** AI web dizinlerini görmüyor
- **Çözüm:** `AgentContext`'e `web_apps` alanı ekle
- **Dosya:** `core/autonomous_agent.py` `AgentContext`

### 3.3 AI'ye Web Tool'unu Önceliklendir
- **Çözüm:** Deterministik çekirdek web bulgularını AI'ye seed olarak ver
- **Dosya:** `core/assessment_assistant.py` `_run_autonomous_agent`

---

## AŞAMA 4: Kalan Network Exploit'leri (P1, ~3 gün)

**Hedef:** +3 bulgu (Samba, UnrealIRCd, Ruby DRb)
**Etki:** Orta

### 4.1 Samba Usermap (CVE-2007-2447)
- **Sorun:** Payload gönderiliyor ama doğrulama yok
- **Çözüm:** SMB readback (smbclient) — kısmen yapıldı
- **Dosya:** `scripts/exploits/samba_usermap.py`

### 4.2 UnrealIRCd Backdoor (CVE-2010-2075)
- **Sorun:** Tetikleme dizisi yanlış
- **Çözüm:** `AB; <cmd>` (trailing `;`/`\n` kaldırıldı) — test edilecek
- **Dosya:** `scripts/exploits/unrealircd_backdoor.py`

### 4.3 Ruby DRb RCE
- **Sorun:** Marshal gadget geçersiz
- **Çözüm:** Gerçek `Gem::Requirement`+`Gem::Installer` zinciri — test edilecek
- **Dosya:** `scripts/exploits/ruby_drb_rce.py`

### 4.4 Tomcat Manager
- **Sorun:** Denenmiyor
- **Çözüm:** Default creds (`tomcat:tomcat`) + WAR deploy
- **Dosya:** `core/exploit_runner.py`

### 4.5 Java RMI
- **Sorun:** Payload bozuk
- **Çözüm:** ysoserial gadget veya registry list
- **Dosya:** `scripts/exploits/java_rmi_deserialize.py`

---

## AŞAMA 5: Post-Exploitation Derinleştirme (P2, ~2 gün)

**Hedef:** Root sonrası derin keşif
**Etki:** Orta

### 5.1 Kernel Exploit
- **Sorun:** 2.6.24 kernel denenmiyor
- **Çözüm:** `searchsploit linux kernel 2.6.24` + uygun exploit
- **Dosya:** `core/post_exploit.py`

### 5.2 Credential Dump + Crack
- **Sorun:** /etc/shadow okunuyor ama crack yok
- **Çözüm:** john/hashcat ile hash crack
- **Dosya:** `core/post_exploit.py`

### 5.3 Lateral Movement
- **Sorun:** Bulunan creds diğer servislerde denenmiyor
- **Çözüm:** Credential reuse genişlet
- **Dosya:** `core/credential_engine.py`

---

## AŞAMA 6: Rapor Kalitesi (P2, ~1 gün)

**Hedef:** Profesyonel rapor
**Etki:** Düşük

### 6.1 CVSS Skorları
- Her bulguya CVSS v3.1 skoru + vektör
- **Dosya:** `core/cvss_scorer.py` (mevcut, entegre edilecek)

### 6.2 MITRE ATT&CK Eşlemesi
- Her bulguya ATT&CK tekniği
- **Dosya:** `reports/pdf_report_generator.py`

### 6.3 Remediation
- Kategori bazlı gerçek öneriler (şu an generic)
- **Dosya:** `core/assessment_assistant.py` `_remediation_for_category`

---

## Öncelik Matrisi

| Aşama | Etki | Süre | Öncelik | Hedef Bulgu |
|---|---|---|---|---|
| 1. Web tam kapsama | Yüksek | 3 gün | P0 | +4 |
| 2. Veritabanı | Yüksek | 2 gün | P0 | +2 |
| 3. AI web yönlendirme | Orta | 2 gün | P1 | - |
| 4. Network exploit'ler | Orta | 3 gün | P1 | +3 |
| 5. Post-exploit | Orta | 2 gün | P2 | +2 |
| 6. Rapor | Düşük | 1 gün | P2 | - |

**Toplam: ~13 gün, hedef 8 → 19+ bulgu (%68)**

---

## Başarı Kriterleri

### v3.2 Hedefi
- [ ] DVWA CMD injection bulunuyor
- [ ] Mutillidae SQLi/XSS bulunuyor
- [ ] phpMyAdmin default creds bulunuyor
- [ ] TikiWiki RCE bulunuyor
- [ ] MySQL/PostgreSQL istismar ediliyor
- [ ] AI web_exploit tool'unu kullanıyor
- [ ] Samba/UnrealIRCd/Ruby DRb çalışıyor
- [ ] Kernel exploit deneniyor
- [ ] Her bulgu CVSS skoru içeriyor
- [ ] Test sayısı ≥300

### Metrikler
| Metrik | Şu An | v3.2 Hedefi |
|---|---|---|
| Bulunan zafiyet | 8/28 (%29) | 19/28 (%68) |
| Web zafiyeti | 3 | 7 |
| DB zafiyeti | 0 | 2 |
| AI web kullanımı | 0 | Aktif |
| CVSS skoru | Kısmi | Tam |

---

## Riskler ve Önlemler

| Risk | Önlem |
|---|---|
| Docker'da bazı zafiyetler yok | "Denendi, hedefte yok" raporla |
| Web payload'ları hedefe özel | Gerçek hedefte test et |
| AI web'i görmezden gelir | Prompt + bağlam güçlendir |
| Kernel exploit tehlikeli | Sadece eğitim hedefinde |
| Süre uzayabilir | Aşama aşama ilerle, her aşamayı test et |

---

## Uygulama Sırası

```
AŞAMA 1 (3 gün): Web tam kapsama
  → DVWA CMD, Mutillidae, phpMyAdmin, TikiWiki
  → Test: 8 → 12 bulgu

AŞAMA 2 (2 gün): Veritabanı
  → MySQL auth bypass, PostgreSQL creds
  → Test: 12 → 14 bulgu

AŞAMA 3 (2 gün): AI web yönlendirme
  → Prompt + bağlam güçlendir
  → Test: AI web_exploit kullanıyor mu?

AŞAMA 4 (3 gün): Network exploit'ler
  → Samba, UnrealIRCd, Ruby DRb, Tomcat, Java RMI
  → Test: 14 → 17 bulgu

AŞAMA 5 (2 gün): Post-exploit
  → Kernel, credential crack, lateral
  → Test: 17 → 19 bulgu

AŞAMA 6 (1 gün): Rapor
  → CVSS, ATT&CK, remediation
```

---

*Bu plan, 8 bulgulu test sonucunun analizi üzerine kurulmuştur.
Her aşama tamamlandığında gerçek metasploitable2 testi ile doğrulanmalıdır.*
