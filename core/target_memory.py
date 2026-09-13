"""
AutoRedTeam — Target Memory & Cross-Session Distillation.

Bu modül, hedeflerin (metasploitable2, localhost:3000 vb.) durumunu
oturumlar arasında kalıcı olarak hatırlar ve damıtır (distillation):
- Taranan port ve servisleri saklar (yeni oturumda gereksiz nmap'i engeller).
- Başarılı exploit'leri hatırlar (örn: ingreslock_backdoor -> root).
- Başarısız exploit'leri kara listeye alır (aynı hatayı ikinci oturumda yapmaz).
- Ele geçirilen kimlik bilgilerini (msfadmin:msfadmin) ve zafiyetleri korur.
"""

import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.context_engine import TargetAttackSurface, context_engine

logger = logging.getLogger("autoredteam.target_memory")


@dataclass
class TargetMemoryData:
    """Tek bir hedefin kalıcı oturumlar arası hafıza kaydı."""
    target: str
    target_slug: str
    first_seen: str
    last_assessed: str
    total_sessions: int = 1
    access_level: str = "none"  # "none", "user", "root (uid=0)"
    open_ports: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    web_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    successful_exploits: List[str] = field(default_factory=list)
    failed_exploits: List[str] = field(default_factory=list)
    credentials: List[Dict[str, str]] = field(default_factory=list)
    verified_vulns: List[Dict[str, Any]] = field(default_factory=list)
    learned_insights: List[str] = field(default_factory=list)


class TargetMemoryStore:
    """
    Hedef sistemlerin deneyimlerini yerel JSON dosyalarında saklayan
    ve oturum başında hatırlayan (recall) hafıza deposu.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or (Path(__file__).parent.parent / "data" / "vfs" / "memories" / "targets")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, TargetMemoryData] = {}

    def _slugify(self, text: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_\-\.]", "_", text).strip("_").lower()

    def _get_target_path(self, target: str) -> Path:
        slug = self._slugify(target)
        return self.base_dir / f"{slug}.json"

    def recall_target(self, target: str) -> Optional[TargetMemoryData]:
        """
        Hedefin önceki oturumlardan kalan hafızasını yükler.
        Varsa ContextEngine'in canlı saldırı yüzeyine de otomatik aktarır.
        """
        slug = self._slugify(target)
        if slug in self._cache:
            return self._cache[slug]

        path = self._get_target_path(target)
        if not path.exists():
            return None

        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
            mem = TargetMemoryData(**data)
            self._cache[slug] = mem

            # Canlı ContextEngine saldırı yüzeyine de senkronize et
            surface = context_engine.get_or_create_target(target)
            if mem.access_level != "none" and surface.access_level == "none":
                surface.access_level = mem.access_level
            for p, p_info in mem.open_ports.items():
                if p not in surface.ports:
                    surface.ports[p] = p_info
            for ep in mem.web_endpoints:
                if not any(e.get("path") == ep.get("path") for e in surface.web_endpoints):
                    surface.web_endpoints.append(ep)

            logger.info(f"[TargetMemory] Recalled memory for {target}: {len(mem.open_ports)} ports, access={mem.access_level}")
            return mem
        except Exception as e:
            logger.error(f"[TargetMemory] Error recalling memory for {target}: {e}")
            return None

    def distill_session(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        decision_chain: List[Dict[str, Any]],
        surface: Optional[TargetAttackSurface] = None,
    ) -> TargetMemoryData:
        """
        Bir oturum tamamlandığında veya kaydedildiğinde tüm tecrübeyi damıtır:
        - Başarılı / başarısız exploit'leri ayıklar.
        - Açık portları ve zafiyetleri günceller.
        - Kalıcı JSON dosyasına yazar.
        """
        slug = self._slugify(target)
        existing = self.recall_target(target)
        now_str = datetime.now().isoformat()

        if existing:
            mem = existing
            mem.last_assessed = now_str
            mem.total_sessions += 1
        else:
            mem = TargetMemoryData(
                target=target,
                target_slug=slug,
                first_seen=now_str,
                last_assessed=now_str,
                total_sessions=1,
            )

        # ContextEngine saldırı yüzeyinden aktar
        active_surface = surface or context_engine.get_or_create_target(target)
        if active_surface.access_level != "none":
            mem.access_level = active_surface.access_level

        for p, p_info in active_surface.ports.items():
            mem.open_ports[p] = p_info

        for ep in active_surface.web_endpoints:
            if not any(e.get("path") == ep.get("path") for e in mem.web_endpoints):
                mem.web_endpoints.append(ep)

        # Decision chain'den exploit ve privesc analizleri
        for d in decision_chain:
            tool = d.get("tool")
            exploit_name = d.get("exploit") or d.get("privesc") or d.get("service_name")
            succeeded = d.get("exploit_succeeded")

            if tool in ("exploit", "privesc") and exploit_name:
                if succeeded:
                    if exploit_name not in mem.successful_exploits:
                        mem.successful_exploits.append(exploit_name)
                    if exploit_name in mem.failed_exploits:
                        mem.failed_exploits.remove(exploit_name)
                elif succeeded is False:
                    if exploit_name not in mem.failed_exploits and exploit_name not in mem.successful_exploits:
                        mem.failed_exploits.append(exploit_name)

        # Bulguları aktar
        for f in findings:
            cve = f.get("cwe_reference") or f.get("category")
            if not any(v.get("category") == f.get("category") and v.get("tool") == f.get("tool") for v in mem.verified_vulns):
                mem.verified_vulns.append({
                    "category": f.get("category"),
                    "severity": f.get("severity"),
                    "tool": f.get("tool"),
                    "evidence": str(f.get("evidence_snippet", ""))[:120],
                })

        # Öğrenilen stratejik içgörüler (Insights)
        insights: List[str] = []
        if mem.access_level.startswith("root"):
            insights.append("Target root access (uid=0) confirmed.")
        if mem.successful_exploits:
            insights.append(f"Working exploits: {', '.join(mem.successful_exploits)}.")
        if mem.failed_exploits:
            insights.append(f"Ineffective exploits (do not repeat): {', '.join(mem.failed_exploits)}.")
        if len(mem.open_ports) > 0:
            insights.append(f"Pre-enumerated ports: {len(mem.open_ports)} ports verified. Wave 1 reconnaissance can be skipped.")
        mem.learned_insights = insights

        # Dosyaya kaydet
        path = self._get_target_path(target)
        try:
            path.write_text(json.dumps(asdict(mem), indent=2, ensure_ascii=False), encoding="utf-8")
            self._cache[slug] = mem
            logger.info(f"[TargetMemory] Distilled session saved to {path} ({len(mem.open_ports)} ports)")
        except Exception as e:
            logger.error(f"[TargetMemory] Error saving distilled memory for {target}: {e}")

        return mem

    def render_memory_brief(self, target: str) -> Optional[str]:
        """
        Model prompt'una doğrudan gömülebilecek, ~100 token'lık
        hafıza özet bloğu oluşturur.
        """
        mem = self.recall_target(target)
        if not mem or (not mem.open_ports and not mem.successful_exploits):
            return None

        lines = [
            f"🧠 [Target Memory Recalled: {target} (Session #{mem.total_sessions})]",
            f"  - Prior Access Level: {mem.access_level.upper()}",
        ]
        if mem.open_ports:
            ports_summary = ", ".join([f"{p} ({info.get('service', '?')})" for p, info in list(mem.open_ports.items())[:6]])
            lines.append(f"  - Known Ports (Recon Done): {ports_summary}")
        if mem.successful_exploits:
            lines.append(f"  - Verified Working Exploits: {', '.join(mem.successful_exploits)} ✅")
        if mem.failed_exploits:
            lines.append(f"  - Failed / Ineffective Exploits: {', '.join(mem.failed_exploits)} ❌ (DO NOT RETRY)")
        lines.append(
            "  - DIRECTIVE: Skip duplicate Nmap scans. Focus directly on untested services or privilege escalation."
        )
        return "\n".join(lines)

    def clear_memory(self, target: Optional[str] = None):
        """Hafızayı temizler (belirli bir hedef veya tümü)."""
        if target:
            slug = self._slugify(target)
            self._cache.pop(slug, None)
            path = self._get_target_path(target)
            if path.exists():
                path.unlink(missing_ok=True)
        else:
            self._cache.clear()
            for p in self.base_dir.glob("*.json"):
                p.unlink(missing_ok=True)


# Singleton Global Target Memory Store Instance
target_memory = TargetMemoryStore()
