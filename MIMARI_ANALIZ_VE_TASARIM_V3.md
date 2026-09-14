# AutoRedTeam — Mimari Analiz ve Yeniden Tasarım (v3.0)

> **Oluşturulma:** 2026-09-13
> **Kapsam:** Mimari düzeyde derin analiz + yeniden tasarım önerisi
> **Soru:** "Kodlamaya başlamadan önce daha kapsamlı analiz ve mimari iyileştirme gerekli mi?"
> **Cevap:** **EVET — kesinlikle gerekli.** Mevcut mimari "LLM'e güvenen" bir yapı;
> asıl sorun model takılması değil, **mimarinin yanlış katmana güvenmesi**.

---

## 0. Yönetici Özeti

Mevcut sistem şu şekilde çalışıyor:

```
CyberStrike 35B (worker) → "sıradaki adım ne?" diye JSON üretir
        ↓
DeepSeek V4 Flash (orchestrator) → her 10 adımda bir strateji direktifi verir
        ↓
Sistem → adımı çalıştırır, sonucu worker'a geri besler
```

**Temel mimari sorun:** Tarama/istismar gibi **deterministik** işler LLM'e
yaptırılıyor. LLM ise olasılıksal — bu yüzden takılıyor, tekrar ediyor ve
derinlik üretemiyor. v2.4'te recon için bu ders alındı (`recon_engine.py`
LLM'siz), ama **istismar katmanı hâlâ LLM'e bağımlı.**

**Öneri:** Sistemi **"Deterministik Motor + LLM Danışman"** mimarisine çevir.
LLM artık "ne yapacağım" demez; **"bu kanıt ne anlama geliyor, sıradaki en
yüksek değerli hedef ne"** sorusuna cevap verir. İstismarın kendisi
deterministik bir **planlayıcı (planner)** tarafından yürütülür.

---

## 1. Mevcut Mimarinin Derin Analizi

### 1.1 Gerçek Akış (Kod Kanıtıyla)

| Bileşen | Dosya | Gerçek Görev |
|---|---|---|
| Worker | `assessment_assistant.py:655` `_ask_llm_for_suggestion` | Her adımda JSON öneri üretir |
| Orchestrator | `orchestrator.py:344` `direct_json_suggestion` | Worker JSON üretemezse devreye girer |
| Orchestrator (periyodik) | `assessment_assistant.py:676` | Her 10 adımda strateji direktifi |
| Rescue | `assessment_assistant.py:1060` `should_trigger_rescue` | Worker takılınca kurtarma |
| Deterministik fallback | `assessment_assistant.py:1781` `get_fallback_action_for_untested` | Test edilmemiş servisleri zorlar |
| Recon | `recon_engine.py` | LLM'siz tarama (İYİ) |

### 1.2 Kritik Mimari Sorunlar

#### SORUN M1: "Karar" ve "Yürütme" aynı katmanda
Şu an LLM hem **karar veriyor** (ne yapayım) hem de **yürütmeyi yönetiyor**
(hangi parametre, hangi payload). Oysa:
- **Karar** (önceliklendirme) → LLM'e uygun (bağlam, sezgi)
- **Yürütme** (payload, parametre, doğrulama) → deterministik olmalı

**Kanıt:** Test 5'te 34 adımın 19'u `searchsploit`/`nmap` lookup. LLM "karar"
veremediği için aynı düşük-değerli eylemi tekrarladı.

#### SORUN M2: Kapsam (coverage) ile derinlik (depth) karışık
`_untested_services()` bir servisi "test edildi" saymak için `searchsploit`
lookup'ını yeterli görüyor (`assessment_assistant.py:1708-1711` yorumu bunu
kabul ediyor ama pratikte lookup "test" sayılıyor). Sonuç: servisler
"tamamlandı" görünüyor ama istismar edilmiyor.

#### SORUN M3: İstismar motoru LLM'e bağımlı
`exploit_runner.py` 12 exploit içeriyor ama **hangi exploit'in ne zaman
deneneceğine LLM karar veriyor.** Deterministik bir "exploit planlayıcı" yok.
Bu yüzden:
- Aynı exploit tekrar deneniyor
- Başarısız exploit'ten sonra alternatif üretilmiyor
- Credential reuse gibi zincirler kurulmuyor

#### SORUN M4: Kanıt (evidence) modeli zayıf
`record_finding` kanıtı string olarak saklıyor. Yapılandırılmış kanıt yok:
- Hangi komut çalıştı?
- Çıktı neydi?
- Doğrulama nasıl yapıldı (uid=0? dosya içeriği?)
- Güven skoru ne?

Bu yüzden "başarısız" ve "başarılı" ayırt edilemiyor, bulgu tekrarı oluşuyor.

#### SORUN M5: Durum makinesi (state machine) yok
Sistem "adım adım" ilerliyor ama **pentest fazları** (recon → enum → exploit →
foothold → privesc → lateral → report) arasında geçiş mantığı yok. LLM her
adımda sıfırdan karar veriyor. Bu yüzden:
- Foothold alındıktan sonra post-exploitation'a geçilmiyor
- Privesc bulguları tekrar ediyor
- "Bitti mi?" sorusu net değil

#### SORUN M6: Model rolleri belirsiz
- CyberStrike 35B: "sansürsüz ofansif payload üretimi" deniyor ama aslında
  JSON karar üretiyor (payload değil)
- DeepSeek: "strateji" deniyor ama sadece 10 adımda bir devreye giriyor
- Claude: "hakem" deniyor ama çoğu zaman devre dışı (geçersiz model adı)

**Roller netleşmeli.**

### 1.3 Neden "Model Takılması" Bir Mimari Sorunu?

Kullanıcının sorusu: *"Faz G'deki otonomi model takılmasındaki kastını anlamadım."*

**Açıklama:** Şu an sistem şöyle çalışıyor:
1. CyberStrike 35B'ye "sıradaki adım ne?" soruluyor
2. Model bazen aynı cevabı veriyor (örn. 12 kez `searchsploit`)
3. Sistem bunu "takılma" olarak algılayıp DeepSeek'e soruyor
4. DeepSeek düzeltiyor ama sonra yine takılıyor

**Bu bir model sorunu DEĞİL, mimari sorunu.** Çünkü:
- Deterministik bir iş (tarama/istismar sırası) LLM'e soruluyor
- LLM'in işi **yorum** olmalı, **sıralama** değil
- v2.4'te recon için bu çözüldü (LLM'siz), ama istismar için çözülmedi

**Çözüm:** İstismar sırasını da deterministik bir **planner** belirlesin.
LLM sadece "bu kanıt ne anlama geliyor, hangi hedef daha değerli" desin.

---

## 2. Önerilen Yeni Mimari: "Deterministik Motor + LLM Danışman"

### 2.1 Katmanlı Sorumluluk Ayrımı

```
┌────────────────────────────────────────────────────────────────────────┐
│  KATMAN A: DETERMİNİSTİK ÇEKİRDEK (LLM YOK)                            │
│  ───────────────────────────────────────────────────────────────────── │
│  A1. Recon Engine        → tarama (mevcut, iyi)                        │
│  A2. Vuln Mapper         → servis→CVE→exploit eşlemesi (YENİ)          │
│  A3. Exploit Planner     → istismar sırası + fallback (YENİ)           │
│  A4. Credential Engine   → default creds + reuse (YENİ)                │
│  A5. Web Exploit Engine  → SQLi/XSS/upload (YENİ)                      │
│  A6. Post-Exploit Engine → foothold sonrası keşif (YENİ)               │
│  A7. Verifier            → kanıt doğrulama (YENİ)                      │
│  A8. State Machine       → pentest fazları arası geçiş (YENİ)          │
├────────────────────────────────────────────────────────────────────────┤
│  KATMAN B: LLM DANIŞMAN (yalnızca yorum/öncelik)                       │
│  ───────────────────────────────────────────────────────────────────── │
│  B1. Triage Advisor   → "bu kanıt kritik mi, sıradaki hedef ne?"       │
│  B2. Payload Crafter   → "bu hedef için özel payload üret" (CyberStrike)│
│  B3. Report Writer     → "bulguları anlatıya dönüştür" (DeepSeek)      │
│  B4. Escalation Oracle → "kriz durumunda alternatif strateji" (Claude) │
├────────────────────────────────────────────────────────────────────────┤
│  KATMAN C: ORKESTRASYON (ince koordinasyon)                            │
│  ───────────────────────────────────────────────────────────────────── │
│  C1. Assessment Orchestrator → katmanları sırayla çalıştırır           │
│  C2. Human-in-the-Loop Gate  → onay noktaları                          │
│  C3. Audit & Scope           → güvenlik (mevcut)                       │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Yeni Akış (Adım Adım)

```
1. RECON (deterministik)
   recon_engine.run_full_recon() → 22 port, 22 dizin, 17 işaret

2. VULN MAPPING (deterministik)
   vuln_mapper.map_all(services) → her servis için:
     {service, version, cves[], exploit_module, exploitability, status}

3. EXPLOIT PLANNING (deterministik)
   exploit_planner.build_plan(mapped_vulns) → öncelikli istismar listesi:
     [
       {step: 1, target: "vsftpd:21", exploit: "vsftpd_backdoor", priority: 0.95},
       {step: 2, target: "ssh:22", exploit: "credential_spray", priority: 0.90},
       {step: 3, target: "dvwa:80", exploit: "web_sqli", priority: 0.85},
       ...
     ]

4. EXPLOITATION (deterministik yürütme + LLM danışman)
   for step in plan:
     result = exploit_runner.run(step)
     if result.success:
       verifier.verify(result) → kanıt
       state_machine.transition(FOOTHOLD)
       post_exploit.enumerate() → yeni hedefler
       credential_engine.reuse() → yeni servisler
     else:
       planner.mark_failed(step)
       planner.try_alternative(step)  # LLM'den payload isteyebilir
     # LLM danışman sadece belirsizlikte devreye girer

5. POST-EXPLOITATION (deterministik)
   post_exploit.find_privesc() → SUID, sudo, kernel
   post_exploit.dump_credentials() → /etc/shadow, config
   post_exploit.lateral_movement() → yeni hostlar

6. VERIFICATION (deterministik)
   verifier.verify_all() → her bulgu kanıtlı mı?

7. REPORTING (deterministik + LLM anlatı)
   finding_correlator.correlate() → zincirler
   cvss_scorer.score() → CVSS
   report_writer.narrate() → LLM anlatı (DeepSeek)
```

### 2.3 LLM Ne Zaman Devreye Girer?

| Durum | LLM Rolü | Model |
|---|---|---|
| Belirsiz kanıt (bu gerçekten zafiyet mi?) | Triage | DeepSeek |
| Bilinmeyen servis/versiyon | Araştırma (web_search) | DeepSeek |
| Standart payload başarısız | Özel payload üret | CyberStrike |
| Kriz (tüm standart yollar tükendi) | Alternatif strateji | Claude |
| Rapor anlatısı | Doğal dil | DeepSeek |

**Kritik:** LLM artık "sıradaki adım ne?" sorusuna cevap vermez. Bu soru
deterministik planner tarafından cevaplanır.

---

## 3. Yeni Modüller (Detaylı)

### 3.1 `core/vuln_mapper.py` — Zafiyet Eşleyici

```python
@dataclass
class Vulnerability:
    service: str
    version: str
    port: int
    cves: List[str]
    exploit_module: Optional[str]
    exploitability: float  # 0.0 - 1.0
    status: str  # pending | attempted | exploited | not_vulnerable

class VulnerabilityMapper:
    def map_service(self, service: str, version: str, port: int) -> List[Vulnerability]:
        """searchsploit + NVD + yerel KB ile servis→CVE eşlemesi."""
    def score_exploitability(self, vuln: Vulnerability) -> float:
        """CVE varlığı, exploit mevcudiyeti, hedef uyumu ile skor."""
    def get_exploit_module(self, vuln: Vulnerability) -> Optional[str]:
        """CVE → yerel exploit modülü eşlemesi."""
```

**Veri kaynakları:**
- `searchsploit` (offline Exploit-DB)
- NVD API v2.0 (`cve_lookup.py`)
- Yerel `knowledge_base/cve_exploit_map.json` (YENİ)

### 3.2 `core/exploit_planner.py` — İstismar Planlayıcı

```python
@dataclass
class ExploitStep:
    step_id: int
    target: str
    port: int
    exploit_module: str
    priority: float
    status: str  # pending | running | success | failed | skipped
    attempts: int
    evidence: Optional[Evidence]

class ExploitPlanner:
    def build_plan(self, vulns: List[Vulnerability]) -> List[ExploitStep]:
        """Zafiyetleri öncelik sırasına göre istismar planına dönüştür."""
    def next_step(self) -> Optional[ExploitStep]:
        """Sıradaki denenmemiş adımı döndür."""
    def mark_result(self, step: ExploitStep, success: bool, evidence: Evidence):
        """Sonucu kaydet; başarısızsa alternatif planla."""
    def try_alternative(self, step: ExploitStep) -> Optional[ExploitStep]:
        """Başarısız adım için alternatif exploit/teknik üret."""
    def is_complete(self) -> bool:
        """Tüm adımlar denendi mi?"""
```

**Öncelik algoritması:**
```
priority = exploitability * 0.5
         + (1.0 if exploit_module else 0.0) * 0.3
         + (1.0 if port_open else 0.0) * 0.2
```

### 3.3 `core/credential_engine.py` — Kimlik Bilgisi Motoru

```python
@dataclass
class Credential:
    username: str
    password: str
    service: str
    host: str
    port: int
    source: str  # default | reuse | brute | dump

class CredentialEngine:
    def try_default_creds(self, service: str, host: str, port: int) -> List[Credential]:
        """Servis bazlı default credential dene."""
    def reuse_credentials(self, creds: List[Credential], services: List[str]) -> List[Credential]:
        """Bulunan credential'ları diğer servislerde dene."""
    def brute_force(self, service: str, host: str, port: int, wordlist: Path) -> List[Credential]:
        """hydra ile brute force (küçük wordlist)."""
    def dump_from_session(self, session) -> List[Credential]:
        """Foothold sonrası /etc/shadow, config dosyaları."""
```

### 3.4 `core/web_exploit_engine.py` — Web İstismar Motoru

```python
class WebExploitEngine:
    def discover_forms(self, url: str) -> List[Form]:
        """browser_tool ile form/input keşfi."""
    def exploit_sqli(self, url: str, param: str) -> Optional[Evidence]:
        """sqlmap entegrasyonu (detection mode)."""
    def exploit_xss(self, url: str, param: str) -> Optional[Evidence]:
        """Reflected/stored XSS testi."""
    def exploit_cmd_injection(self, url: str, param: str) -> Optional[Evidence]:
        """Command injection testi."""
    def exploit_file_upload(self, url: str) -> Optional[Evidence]:
        """WebDAV PUT, DVWA upload."""
    def exploit_lfi_rfi(self, url: str, param: str) -> Optional[Evidence]:
        """Local/Remote file inclusion."""
    def exploit_default_creds(self, url: str) -> Optional[Evidence]:
        """phpMyAdmin, Tomcat manager."""
    def exploit_cms(self, url: str, cms: str) -> Optional[Evidence]:
        """TikiWiki, WordPress vb. CVE istismarı."""
```

### 3.5 `core/post_exploit.py` — Foothold Sonrası

```python
@dataclass
class Session:
    host: str
    user: str
    privilege: str  # user | root
    method: str  # ssh | shell | web

class PostExploit:
    def enumerate_system(self, session: Session) -> SystemInfo:
        """uname, /etc/passwd, users, network, processes."""
    def find_privesc(self, session: Session) -> List[PrivescVector]:
        """SUID, sudo, kernel, cron, capabilities."""
    def dump_credentials(self, session: Session) -> List[Credential]:
        """/etc/shadow, config dosyaları, DB dump."""
    def lateral_movement(self, creds: List[Credential], hosts: List[str]) -> List[Session]:
        """Bulunan credential'larla diğer hostlara geç."""
```

### 3.6 `core/verifier.py` — Kanıt Doğrulayıcı

```python
@dataclass
class Evidence:
    command: str
    output: str
    verified: bool
    verification_method: str  # uid_check | file_content | db_dump | banner
    confidence: float  # 0.0 - 1.0

class Verifier:
    def verify_exploit(self, result: Dict) -> Evidence:
        """Exploit sonucunu kanıtla doğrula (uid=0, dosya içeriği vb.)."""
    def verify_finding(self, finding: Dict) -> Evidence:
        """Bulgunun gerçekten zafiyet olduğunu doğrula."""
    def is_false_positive(self, evidence: Evidence) -> bool:
        """Yanlış pozitif tespiti."""
```

### 3.7 `core/state_machine.py` — Pentest Faz Makinesi

```python
class Phase(Enum):
    RECON = "recon"
    VULN_MAPPING = "vuln_mapping"
    EXPLOITATION = "exploitation"
    FOOTHOLD = "foothold"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    REPORTING = "reporting"
    COMPLETE = "complete"

class AssessmentStateMachine:
    def current_phase(self) -> Phase:
    def transition(self, event: str) -> Phase:
        """Faz geçişlerini yönet (foothold → privesc vb.)."""
    def can_transition(self, to_phase: Phase) -> bool:
    def phase_progress(self) -> Dict[Phase, float]:
```

### 3.8 `core/finding_correlator.py` — Bulgu Korelasyonu

```python
class FindingCorrelator:
    def correlate(self, findings: List[Dict]) -> List[Dict]:
        """Aynı kategori/hedef bulguları birleştir."""
    def build_chains(self, findings: List[Dict]) -> List[AttackChain]:
        """Exploit zincirleri oluştur (recon → exploit → privesc)."""
    def deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """Privesc gibi tekrarlı bulguları tek zincirde birleştir."""
```

---

## 4. Mevcut Modüllerin Dönüşümü

| Mevcut | Yeni Rol | Değişiklik |
|---|---|---|
| `recon_engine.py` | Katman A1 (aynı) | Değişmez |
| `exploit_runner.py` | Katman A3'ün yürütücüsü | Planner'dan komut alır |
| `privesc_engine.py` | Katman A6'nın parçası | Post-exploit'e entegre |
| `assessment_assistant.py` | Katman C1 (orkestratör) | LLM bağımlılığı azalır |
| `orchestrator.py` | Katman B (danışman) | Sadece yorum/öncelik |
| `validation_gate.py` | Katman A7 (verifier) | Genişletilir |
| `context_engine.py` | Katman C (bağlam) | Aynı |
| `target_memory.py` | Katman C (hafıza) | Aynı |

---

## 5. LLM Rolünün Yeniden Tanımı

### 5.1 CyberStrike 35B (Sansürsüz Model)

**Eski rol:** "Sıradaki adım ne?" JSON üret
**Yeni rol:** "Bu hedef için özel payload üret" (yalnızca standart payload başarısız olunca)

```
Girdi: "vsftpd 2.3.4 hedefinde standart backdoor çalışmadı. Alternatif payload üret."
Çıktı: Özel payload / exploit kodu / teknik önerisi
```

**Neden:** Sansürsüz modelin gücü **yaratıcı payload üretimi**, karar verme değil.

### 5.2 DeepSeek V4 Flash (Orkestratör)

**Eski rol:** Her 10 adımda strateji direktifi
**Yeni rol:** Triage + araştırma + rapor anlatısı

```
Girdi: "Bu kanıt: 'uid=0(root)' — bu gerçekten kritik mi? Sıradaki en değerli hedef ne?"
Çıktı: Öncelik kararı + gerekçe
```

**Neden:** DeepSeek güçlü bir **yorumlama/önceliklendirme** modeli.

### 5.3 Claude (Hakem)

**Eski rol:** Kriz çözücü (ama çoğu zaman devre dışı)
**Yeni rol:** Escalation Oracle — yalnızca tüm deterministik yollar tükendiğinde

```
Girdi: "Tüm standart exploit'ler başarısız. Sistem takıldı. Alternatif strateji?"
Çıktı: Yaratıcı saldırı stratejisi
```

**Not:** `.env`'de geçerli model adı gerekli (`claude-3-5-sonnet-latest`).

---

## 6. Uygulama Yol Haritası (Mimari Öncelikli)

### AŞAMA 1: Deterministik Çekirdek (Hafta 1-2)
**Amaç:** LLM olmadan çalışan istismar motoru.

1. `core/vuln_mapper.py` — servis→CVE eşlemesi
2. `core/exploit_planner.py` — istismar planı + öncelik
3. `core/verifier.py` — kanıt doğrulama
4. `core/state_machine.py` — faz geçişleri
5. `exploit_runner.py` düzeltmeleri (payload'lar)

**Çıktı:** LLM olmadan recon→mapping→exploit→verify çalışır.

### AŞAMA 2: İstismar Derinliği (Hafta 3-4)
**Amaç:** Web + credential + post-exploit.

6. `core/web_exploit_engine.py`
7. `core/credential_engine.py`
8. `core/post_exploit.py`

**Çıktı:** Metasploitable2'nin %80'i istismar edilir.

### AŞAMA 3: LLM Danışman Entegrasyonu (Hafta 5)
**Amaç:** LLM'i doğru role oturt.

9. `orchestrator.py` → Triage Advisor
10. CyberStrike → Payload Crafter
11. Claude → Escalation Oracle

**Çıktı:** LLM yalnızca belirsizlikte devreye girer.

### AŞAMA 4: Rapor & Korelasyon (Hafta 6)
**Amaç:** Kaliteli rapor.

12. `core/finding_correlator.py`
13. `core/cvss_scorer.py`
14. Rapor iyileştirmeleri

**Çıktı:** Zincirli, CVSS'li, anlatılı rapor.

### AŞAMA 5: Gerçek Dünya (Hafta 7)
**Amaç:** Bug bounty hazırlığı.

15. Dinamik scope
16. Rate limiting + proxy
17. API pentest

---

## 7. Karşılaştırma: Eski vs. Yeni Mimari

| Boyut | Eski (v2.5) | Yeni (v3.0) |
|---|---|---|
| Karar veren | LLM (her adım) | Deterministik planner |
| LLM rolü | Karar + yürütme | Yorum + payload |
| Takılma riski | Yüksek | Düşük (planner deterministik) |
| Kapsam | Lookup = test | Gerçek istismar = test |
| Derinlik | Yüzeysel | Post-exploit dahil |
| Kanıt | String | Yapılandırılmış Evidence |
| Faz yönetimi | Yok | State machine |
| Bulgu tekrarı | Var | Correlator çözer |
| Ölçeklenebilirlik | LLM'e bağlı | Deterministik + LLM danışman |

---

## 8. Riskler ve Önlemler

| Risk | Önlem |
|---|---|
| Deterministik planner çok katı olabilir | LLM danışman esnekliği ekler |
| Yeni modüller mevcut testleri bozabilir | Kademeli geçiş + geriye uyumluluk |
| LLM rol değişimi prompt yeniden yazımı gerektirir | Aşama 3'te yapılır |
| Performans (çok modül) | Paralel çalıştırma + caching |
| Etik/yasal | Allow-list + human-in-the-loop korunur |

---

## 9. Sonuç ve Öneri

**Sorunuz:** "Kodlamaya başlamadan önce daha kapsamlı analiz ve mimari iyileştirme gerekli mi?"

**Cevap:** **Evet.** Mevcut mimari çalışıyor ama **yanlış katmana güveniyor**.
LLM'e deterministik işler yaptırılıyor; bu yüzden takılıyor, tekrar ediyor ve
derinlik üretemiyor.

**Öneri:** Önce **deterministik çekirdeği** kurun (Aşama 1-2), sonra LLM'i
**danışman** rolüne oturtun (Aşama 3). Bu sırayla:
1. Sistem LLM olmadan da çalışır (güvenilir)
2. LLM yalnızca değer kattığı yerde devreye girer (verimli)
3. Takılma sorunu mimari olarak çözülür (kalıcı)

**İlk adım:** `core/vuln_mapper.py` + `core/exploit_planner.py` + `core/verifier.py`
üçlüsünü kurmak. Bu üçlü, sistemin "beyni" olur ve LLM'den bağımsız çalışır.

---

*Bu doküman, mevcut kodun satır satır analizi üzerine kurulmuştur.
Her modül gerçek dosya/konum referansıyla eşleştirilmiştir.*
