# ⚠️ Yasal Uyarı ve Etik Kullanım (Disclaimer & Ethical Use)

## Türkçe

### Yalnızca Yetkili Testler İçin

**AutoRedTeam**, yalnızca **açıkça yetkilendirilmiş** sistemlerde güvenlik
değerlendirmesi yapmak için tasarlanmıştır. Bu aracı kullanmadan önce:

1. **Yazılı izin alın** — Hedef sistemin sahibinden açık yazılı yetki almalısınız.
2. **Kapsamı belirleyin** — Hangi sistemlerin test edileceğini netleştirin.
3. **Yasalara uyun** — Bulunduğunuz ülkenin siber güvenlik yasalarına uyun
   (Türkiye: TCK 243-245, ABD: CFAA, AB: NIS2).

### İzinsiz Kullanım Suçtur

Yetkisiz sistemlere karşı bu aracı kullanmak:
- **Türkiye'de:** TCK Madde 243-245 kapsamında **suçtur** (2-8 yıl hapis)
- **ABD'de:** Computer Fraud and Abuse Act (CFAA) kapsamında **suçtur**
- **AB'de:** NIS2 Direktifi ve ulusal yasalar kapsamında **suçtur**

### Yazar Sorumluluğu Reddi

Bu yazılımın yazarları:
- Aracın **kötüye kullanımından** sorumlu değildir
- Kullanıcının neden olduğu **hiçbir zarardan** sorumlu değildir
- Aracın **belirli bir amaca uygunluğu** konusunda garanti vermez

### Yerleşik Güvenlik Önlemleri

Bu proje, kötüye kullanımı önlemek için şu önlemleri içerir:

| Önlem | Dosya | Açıklama |
|---|---|---|
| **Kapsam allow-list** | `config/allowed_targets.txt` | Yalnızca açıkça izin verilen hedefler |
| **Kod seviyesi kontrol** | `core/scope.py` | `is_target_allowed()` her adımda |
| **İnsan onayı** | `assessment_ui.py` | Human-in-the-loop modu |
| **Tehlikeli komut filtresi** | `core/autonomous_agent.py` | `rm -rf /`, fork bomb vb. engellenir |
| **Denetim logu** | `data/assessment_audit_log.jsonl` | Tüm eylemler kaydedilir |
| **Varsayılan hedefler** | Docker lab | Yalnızca eğitim hedefleri (Metasploitable2, Juice Shop) |

### Etik Kullanım İlkeleri

1. ✅ **İzin al** — Her zaman yazılı yetki al
2. ✅ **Kapsamda kal** — Yalnızca izin verilen sistemleri test et
3. ✅ **Veriyi koru** — Bulduğun verileri gizli tut
4. ✅ **Bildir** — Zafiyetleri sorumlu şekilde bildir (responsible disclosure)
5. ❌ **Zarar verme** — Sisteme zarar verme, hizmeti kesme
6. ❌ **Sızdırma** — Bulguları izinsiz paylaşma

---

## English

### Authorized Testing Only

**AutoRedTeam** is designed for security assessment of **explicitly authorized**
systems only. Before using this tool:

1. **Obtain written permission** from the target system owner.
2. **Define scope** — clarify which systems will be tested.
3. **Comply with laws** — follow your jurisdiction's cybersecurity laws
   (US: CFAA, EU: NIS2, Turkey: TCK 243-245).

### Unauthorized Use is a Crime

Using this tool against unauthorized systems is a **criminal offense** under:
- **US:** Computer Fraud and Abuse Act (CFAA)
- **EU:** NIS2 Directive and national laws
- **Turkey:** Turkish Penal Code Articles 243-245

### Disclaimer of Liability

The authors of this software:
- Are **not responsible** for misuse of the tool
- Are **not liable** for any damage caused by users
- Provide **no warranty** of fitness for a particular purpose

### Built-in Safeguards

This project includes safeguards against misuse:
- Scope allow-list (`config/allowed_targets.txt`)
- Code-level scope validation (`is_target_allowed()`)
- Human-in-the-loop approval mode
- Dangerous command filter
- Audit logging
- Default targets are training labs only (Metasploitable2, Juice Shop)

### Ethical Use Principles

1. ✅ **Get permission** — always obtain written authorization
2. ✅ **Stay in scope** — only test authorized systems
3. ✅ **Protect data** — keep discovered data confidential
4. ✅ **Report responsibly** — disclose vulnerabilities responsibly
5. ❌ **Do no harm** — do not damage systems or disrupt services
6. ❌ **Do not leak** — do not share findings without permission

---

## İletişim / Contact

Güvenlik açığı bildirimi için: [GitHub Issues](https://github.com/Mustafa-Caliskan/AutoRedTeam/issues)

*Son güncelleme: 2026-09-14*
