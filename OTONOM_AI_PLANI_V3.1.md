# AutoRedTeam — Otonom AI Ajanı Planı (v3.1)

> **Oluşturulma:** 2026-09-14
> **Amaç:** AI modelinin tool'ları **kendi kullanarak** otonom sömürü yapması —
> foothold → privesc → credential dump → lateral movement → rapor.
> **Ön koşul:** v3.0 deterministik çekirdek çalışıyor (4 bulgu, 17 adım).
> **Hedef Sürüm:** v3.1 (Autonomous AI Agent)

---

## 0. Neden Bu Geliştirme?

### Mevcut Durum (v3.0)

```
DETERMİNİSTİK ÇEKİRDEK
  → Bilinen exploit'leri sırayla dener (sabit payload)
  → AI'ye sormadan çalışır

AI DANIŞMAN (pasif)
  → Başarısız exploit için "şunu dene" der
  → AMA kendisi çalıştırmaz (sadece log)
```

**Sorun:** AI öneri üretiyor ama uygulamıyor. Gerçek otonom sömürü yok.

### Hedef (v3.1)

```
OTONOM AI DÖNGÜSÜ
  1. AI: "SSH creds buldum → sudo -l çalıştır"
  2. Sistem: çalıştırır → "(ALL) ALL"
  3. AI: "sudo su ile root ol"
  4. Sistem: çalıştırır → uid=0(root)
  5. AI: "root oldum, /etc/shadow oku"
  6. Sistem: çalıştırır → hash'ler
  7. AI: "zincir tamam, raporla"
```

AI tool'ları **kendi seçer, kendi çalıştırır, sonucu görür, devam eder.**

---

## 1. Mimari

### 1.1 Yeni Bileşen: `core/autonomous_agent.py`

```
┌─────────────────────────────────────────────────────────────────┐
│  AUTONOMOUS AGENT (OODA Loop)                                   │
│                                                                 │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐ │
│   │ OBSERVE  │───>│  ORIENT  │───>│  DECIDE  │───>│   ACT    │ │
│   │ (context)│    │  (AI)    │    │  (AI)    │    │ (tools)  │ │
│   └──────────┘    └──────────┘    └──────────┘    └──────────┘ │
│        ^                                                │       │
│        └────────────────────────────────────────────────┘       │
│                     (sonuç geri besleme)                        │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 AI'ye Verilen Tool Listesi

AI şu tool'ları seçebilir:

| Tool | Açıklama | Parametreler |
|---|---|---|
| `nmap` | Port/servis tarama | ports |
| `exploit` | Bilinen exploit çalıştır | exploit_name |
| `privesc` | Yetki yükseltme tekniği | technique |
| `credential_spray` | Kimlik denemesi | service, port |
| `web_exploit` | Web istismarı | url, vuln_type |
| `sqlmap` | SQL injection | url, param |
| `post_exploit` | Foothold sonrası keşif | command |
| `done` | Değerlendirme bitti | - |

### 1.3 AI Karar Formatı (JSON)

```json
{
  "thought": "SSH creds bulundu, sudo yetkisi kontrol edeyim",
  "tool": "privesc",
  "technique": "sudoers_audit",
  "target": "metasploitable2",
  "rationale": "msfadmin:msfadmin ile sudo -l çalıştır"
}
```

---

## 2. Uygulama Planı

### FAZ 1: Autonomous Agent Çekirdeği (P0, ~2 gün)

#### 1.1 `core/autonomous_agent.py`

```python
class AutonomousAgent:
    """
    AI'nin tool'ları kendi seçip çalıştırdığı otonom sömürü döngüsü.
    """

    def __init__(self, target, llm_client, max_steps=30, auto_approve=True):
        self.target = target
        self.llm = llm_client
        self.max_steps = max_steps
        self.auto_approve = auto_approve
        self.context = AgentContext(target)
        self.history = []

    def run(self) -> List[Finding]:
        """OODA döngüsü."""
        # 1. Deterministik çekirdeği çalıştır (temiz başlangıç)
        base = self._run_deterministic_core()

        # 2. AI döngüsü
        for step in range(self.max_steps):
            # OBSERVE: mevcut durumu AI'ye ver
            prompt = self._build_agent_prompt()

            # DECIDE: AI karar verir
            action = self._ask_ai(prompt)
            if action is None or action["tool"] == "done":
                break

            # ACT: tool'u çalıştır
            result = self._execute(action)

            # ORIENT: sonucu bağlama ekle
            self.context.add_result(action, result)

            # Güvenlik: tekrar tespiti
            if self._is_stuck():
                break

        return self.context.findings
```

#### 1.2 `AgentContext` — Ajan Bağlamı

```python
@dataclass
class AgentContext:
    target: str
    findings: List[Dict] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    sessions: List[Session] = field(default_factory=list)  # foothold'lar
    privilege: str = "none"  # none | user | root
    history: List[Dict] = field(default_factory=list)

    def add_result(self, action, result):
        self.history.append({"action": action, "result": result})
        # Bulgu çıkar
        if result.get("success"):
            self.findings.append(...)
        # Credential çıkar
        if "password" in result:
            self.credentials.append(...)
        # Privilege güncelle
        if "uid=0" in result.get("output", ""):
            self.privilege = "root"
```

#### 1.3 AI Prompt'u

```
You are an autonomous penetration testing agent. You have these tools:
- nmap(ports): scan ports
- exploit(exploit_name): run known exploit
- privesc(technique): privilege escalation
- credential_spray(service, port): try credentials
- web_exploit(url, vuln_type): web exploitation
- post_exploit(command): run command on foothold
- done: finish

Current state:
- Target: metasploitable2
- Privilege: user (msfadmin:msfadmin)
- Findings: [SSH creds, ingreslock root]
- Credentials: msfadmin:msfadmin
- Sessions: SSH as msfadmin

Recent actions:
1. ssh_credential_spray -> SUCCESS (uid=1000)
2. ingreslock_backdoor -> SUCCESS (uid=0)

Decide the next action. Respond with ONLY a JSON object:
{"thought": "...", "tool": "...", "params": {...}, "rationale": "..."}
```

---

### FAZ 2: Tool Executor (P0, ~1 gün)

#### 2.1 `_execute(action)` — Tool Çalıştırıcı

```python
def _execute(self, action: Dict) -> Dict:
    tool = action.get("tool")
    params = action.get("params", {})

    if tool == "nmap":
        return suggest_nmap_scan(self.target, approved=True, ports=params.get("ports"))
    elif tool == "exploit":
        return dispatch_exploit(params["exploit_name"], self.target, approved=True)
    elif tool == "privesc":
        return dispatch_privesc(params["technique"], self.target, ...)
    elif tool == "credential_spray":
        return self._credential_spray(params)
    elif tool == "web_exploit":
        return self._web_exploit(params)
    elif tool == "post_exploit":
        return self._post_exploit(params["command"])
    else:
        return {"success": False, "error": f"unknown tool: {tool}"}
```

#### 2.2 Güvenlik Katmanları

```python
def _execute(self, action):
    # 1. Kapsam kontrolü (ZORUNLU)
    if not is_target_allowed(self.target):
        return {"success": False, "error": "out of scope"}

    # 2. Onay kontrolü
    if not self.auto_approve:
        if not self._ask_human(action):
            return {"success": False, "error": "rejected"}

    # 3. Tehlikeli komut filtresi
    if self._is_dangerous(action):
        return {"success": False, "error": "dangerous command blocked"}

    # 4. Çalıştır
    return self._dispatch(action)
```

---

### FAZ 3: Otonom Privesc Zinciri (P1, ~2 gün)

#### 3.1 Privesc Otomasyonu

AI foothold aldıktan sonra otomatik olarak:
1. `sudo -l` çalıştırır
2. SUID binary'leri tarar
3. Kernel versiyonunu kontrol eder
4. GTFOBins eşlemesi yapar
5. Uygun tekniği uygular

```python
def _autonomous_privesc(self):
    """Foothold sonrası otomatik privesc."""
    # 1. Sistem keşfi
    info = self._post_exploit("id; uname -a; sudo -l")
    # 2. AI'ye analiz ettir
    vectors = self._ask_ai_privesc(info)
    # 3. En yüksek olasılıklı tekniği dene
    for v in vectors:
        result = self._execute({"tool": "privesc", "params": v})
        if "uid=0" in result.get("output", ""):
            self.context.privilege = "root"
            break
```

#### 3.2 Credential Dump

Root olunca:
```python
def _dump_credentials(self):
    """Root sonrası credential toplama."""
    shadow = self._post_exploit("cat /etc/shadow")
    configs = self._post_exploit("find / -name '*.conf' -o -name 'config.php'")
    # AI'ye analiz ettir, yeni creds çıkar
```

---

### FAZ 4: UI Entegrasyonu (P1, ~1 gün)

#### 4.1 Yeni Buton: "🤖 Otonom AI"

```javascript
function startAutonomous() {
    eventSource = new EventSource(`/api/stream?target=${target}&mode=autonomous`);
}
```

#### 4.2 Canlı AI Akışı

UI'de AI'nin her kararı canlı görünür:
```
🤖 [AI Adım 1] thought: "SSH creds bulundu, sudo kontrol edeyim"
   tool: privesc(sudoers_audit)
   → sonuç: (ALL) ALL

🤖 [AI Adım 2] thought: "sudo ALL var, root olabilirim"
   tool: privesc(sudo_privesc)
   → sonuç: uid=0(root) ✅

🤖 [AI Adım 3] thought: "Root oldum, shadow okuyayım"
   tool: post_exploit(cat /etc/shadow)
   → sonuç: root:$1$...
```

---

### FAZ 5: Güvenlik ve Kontrol (P0, ~1 gün)

#### 5.1 Mod Ayrımı

| Mod | Onay | Kullanım |
|---|---|---|
| **Onaylı** | Her adımda insan | Gerçek hedefler |
| **Otonom** | AI kendi çalıştırır | Eğitim hedefleri (Docker) |

#### 5.2 Güvenlik Kısıtları

```python
DANGEROUS_COMMANDS = [
    "rm -rf /", "mkfs", "dd if=/dev/zero", ":(){ :|:& };:",  # fork bomb
    "shutdown", "reboot", "iptables -F",
]

def _is_dangerous(self, action):
    cmd = str(action.get("params", {}))
    return any(d in cmd for d in DANGEROUS_COMMANDS)
```

#### 5.3 Audit Log

Her AI kararı ve sonucu `data/autonomous_audit.jsonl`'e yazılır.

---

## 3. Dosya Değişiklik Haritası

### Yeni Dosyalar
```
core/autonomous_agent.py       # OODA döngüsü
core/agent_context.py          # Ajan bağlamı (opsiyonel, agent içinde de olabilir)
tests/test_autonomous_agent.py # Unit testler
```

### Değiştirilecek Dosyalar
```
core/assessment_assistant.py   # run_autonomous() metodu
assessment_ui.py               # "🤖 Otonom AI" butonu
core/llm_advisor.py            # Agent prompt'u
```

---

## 4. Başarı Kriterleri

### v3.1 Hedefi
- [ ] AI tool'ları kendi seçip çalıştırır
- [ ] Foothold → privesc zinciri otomatik
- [ ] Root sonrası credential dump otomatik
- [ ] Her AI kararı canlı UI'de görünür
- [ ] Otonom modda insan onayı yok (eğitim hedefleri)
- [ ] Onaylı modda her adım onaylanır (gerçek hedefler)
- [ ] Tehlikeli komutlar engellenir
- [ ] Audit log tutulur
- [ ] Test sayısı ≥280

### Metrikler
| Metrik | v3.0 | v3.1 Hedefi |
|---|---|---|
| Otonom adım | 0 (AI pasif) | ≥10 (AI aktif) |
| Privesc otomasyonu | Manuel | Otomatik |
| Credential dump | Yok | Otomatik |
| AI karar görünürlüğü | Log | Canlı UI |

---

## 5. Riskler ve Önlemler

| Risk | Önlem |
|---|---|
| AI tehlikeli komut çalıştırır | Komut filtresi + allow-list |
| AI sonsuz döngüye girer | Max adım + tekrar tespiti |
| AI yanlış hedefe saldırır | Kapsam kontrolü (her adımda) |
| Gerçek hedefte kaza | Otonom mod sadece eğitim hedeflerinde |
| AI maliyeti (token) | Adım limiti + bağlam sıkıştırma |

---

## 6. Uygulama Sırası

```
Sprint 1 (2 gün):  FAZ 1 - Autonomous Agent çekirdeği
Sprint 2 (1 gün):  FAZ 2 - Tool Executor
Sprint 3 (2 gün):  FAZ 3 - Otonom privesc zinciri
Sprint 4 (1 gün):  FAZ 4 - UI entegrasyonu
Sprint 5 (1 gün):  FAZ 5 - Güvenlik + test
```

**Toplam: ~7 gün**

---

## 7. Örnek Otonom Senaryo (Metasploitable2)

```
BAŞLANGIÇ: Deterministik çekirdek çalıştı
  → SSH creds: msfadmin:msfadmin
  → ingreslock: root shell

AI DÖNGÜSÜ:
  Adım 1: AI "SSH ile bağlan, sistem bilgisi topla"
    → post_exploit("id; uname -a; sudo -l")
    → uid=1000(msfadmin), Linux 2.6.24, (ALL) ALL

  Adım 2: AI "sudo ALL var, root ol"
    → privesc(sudo_privesc)
    → uid=0(root) ✅

  Adım 3: AI "Root oldum, shadow oku"
    → post_exploit("cat /etc/shadow")
    → root:$1$..., msfadmin:$1$...

  Adım 4: AI "MySQL creds ara"
    → post_exploit("cat /var/www/*/config.php")
    → mysql:root:password123

  Adım 5: AI "MySQL'e bağlan, DB dump"
    → credential_spray(mysql, 3306)
    → SUCCESS

  Adım 6: AI "Zincir tamam, raporla"
    → done

SONUÇ: 6 AI adımı, tam zincir, root + DB dump
```

---

*Bu plan, v3.0 deterministik çekirdeğin üzerine AI otonomisini ekler.
Deterministik çekirdek "temiz başlangıç" sağlar; AI "derin sömürü" yapar.*
