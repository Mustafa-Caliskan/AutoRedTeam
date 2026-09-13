"""
AutoRedTeam — Context Engine (Headroom CCR + L0/L1/L2 Hierarchical Context Compression).

Bu modül, araç çıktılarını (Nmap, Gobuster, Nikto, SQLmap, Exploit vb.) ve konuşma geçmişini
modelin önüne gitmeden önce akıllıca sıkıştırır:
- L2 (Ham Kanıt Katmanı): Tam, filtrelenmemiş araç çıktıları yerel diskte (data/vfs/raw/) cache'lenir.
- L1 (Taktik Karar Katmanı): Servis adı, versiyonu, CVE numarası, açık durumu ve parametreler (~200 token).
- L0 (Soyut Özet Katmanı): Tek satırlık anlık durum ve saldırı yüzeyi ağacı (~50 token).

Sonuç:
- Token tüketiminde %70-90 tasarruf.
- Konuşma geçmişi sınırlandığında dahi saldırı yüzeyinin asla unutulmaması (sıfır amnesia).
- Claude 5 Sonnet ve DeepSeek V4 Flash için ultra-yüksek sinyal/gürültü oranı.
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("autoredteam.context_engine")


@dataclass
class CCRNode:
    """Cache-Compress-Retrieve düğümü."""
    node_id: str
    target: str
    tool: str
    step: int
    timestamp: str
    l0_abstract: str
    l1_tactical: Dict[str, Any]
    l2_raw_path: str
    raw_chars: int
    compressed_chars: int


@dataclass
class TargetAttackSurface:
    """Hedefin anlık küresel saldırı yüzeyi durumu."""
    target: str
    access_level: str = "none"  # "none", "user", "root (uid=0)"
    ports: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    web_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, str]] = field(default_factory=list)
    verified_vulns: List[Dict[str, Any]] = field(default_factory=list)
    tested_services: Set[str] = field(default_factory=set)
    action_history: List[str] = field(default_factory=list)


class ContextEngine:
    """
    Saldırı yüzeyini ve araç çıktılarını 3 seviyeli (L0/L1/L2)
    sanal bağlam yapısında yöneten motor.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or (Path(__file__).parent.parent / "data" / "vfs")
        self.raw_dir = self.base_dir / "raw"
        self.memories_dir = self.base_dir / "memories" / "targets"
        
        # Dizinleri oluştur
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.memories_dir.mkdir(parents=True, exist_ok=True)

        self.nodes: Dict[str, CCRNode] = {}
        self.targets: Dict[str, TargetAttackSurface] = {}
        self._total_raw_chars = 0
        self._total_compressed_chars = 0

    def get_or_create_target(self, target: str) -> TargetAttackSurface:
        """Hedef için saldırı yüzeyi kaydını getirir veya oluşturur."""
        slug = self._slugify(target)
        if slug not in self.targets:
            self.targets[slug] = TargetAttackSurface(target=target)
        return self.targets[slug]

    def ingest(
        self,
        target: str,
        tool: str,
        step: int,
        raw_output: str,
        suggestion: Optional[Dict[str, Any]] = None,
        command: Optional[str] = None
    ) -> CCRNode:
        """
        Ham araç çıktısını alır:
        1. L2 olarak diske yazar (CCR Cache).
        2. Çıktıdan L1 taktik bilgilerini ve L0 özetini ayrıştırır (Compress).
        3. Hedefin küresel saldırı yüzeyini günceller.
        """
        slug = self._slugify(target)
        surface = self.get_or_create_target(target)
        
        node_id = f"{slug}_{tool}_step{step}_{int(datetime.now().timestamp())}"
        raw_text = raw_output or ""
        raw_chars = len(raw_text)

        # 1. L2 Raw Cache
        raw_file = self.raw_dir / f"{node_id}.txt"
        try:
            raw_file.write_text(raw_text, encoding="utf-8")
        except Exception as e:
            logger.warning(f"[ContextEngine] L2 raw cache yazma hatası: {e}")

        # 2. Araca özel akıllı sıkıştırma & L1/L0 ayrıştırma
        l0_summary, l1_tactical = self._compress_tool_output(
            tool=tool,
            target=target,
            raw_text=raw_text,
            suggestion=suggestion or {},
            command=command or "",
            surface=surface
        )

        compressed_chars = len(l0_summary) + len(json.dumps(l1_tactical, ensure_ascii=False))
        self._total_raw_chars += raw_chars
        self._total_compressed_chars += compressed_chars

        node = CCRNode(
            node_id=node_id,
            target=target,
            tool=tool,
            step=step,
            timestamp=datetime.now().isoformat(),
            l0_abstract=l0_summary,
            l1_tactical=l1_tactical,
            l2_raw_path=str(raw_file),
            raw_chars=raw_chars,
            compressed_chars=compressed_chars
        )
        self.nodes[node_id] = node

        # Hedef aksiyon geçmişine L0 özetini ekle
        surface.action_history.append(f"Adım {step} [{tool}]: {l0_summary}")

        logger.info(
            f"[ContextEngine] Ingested {tool} at step {step}: "
            f"raw={raw_chars} chars -> compressed={compressed_chars} chars "
            f"(~{(1 - compressed_chars/max(raw_chars, 1))*100:.1f}% savings)"
        )
        return node

    def render_attack_surface_tree(self, target: str) -> str:
        """
        Model prompt'una doğrudan gömülebilen, ~150-250 token'lık
        temiz ve deterministik bir ASCII saldırı yüzeyi ağacı üretir.
        """
        surface = self.get_or_create_target(target)
        lines = [f"=== Target Attack Surface: {target} [Access: {surface.access_level.upper()}] ==="]

        if not surface.ports and not surface.web_endpoints and not surface.verified_vulns:
            lines.append("  (Attack surface not enumerated yet. Reconnaissance required.)")
            return "\n".join(lines)

        # Port ve servis dalları
        sorted_ports = sorted(surface.ports.keys(), key=lambda p: int(re.sub(r"\D", "", p) or 0))
        for p in sorted_ports:
            info = surface.ports[p]
            svc = info.get("service", "unknown")
            ver = info.get("version", "")
            ver_str = f" {ver}" if ver else ""
            status = info.get("status", "OPEN")
            exploit = info.get("exploit")
            exp_str = f" [EXPLOIT: {exploit}]" if exploit else ""

            status_badge = "UNTESTED"
            if status == "ROOT_OBTAINED":
                status_badge = "ROOT SHELL OBTAINED ✅"
            elif status == "EXPLOITED":
                status_badge = "EXPLOITED ✅"
            elif status == "FAILED":
                status_badge = "EXPLOIT FAILED ❌"
            elif status == "VERIFIED":
                status_badge = "VULN VERIFIED"

            lines.append(f"  ├── [{p}] {svc}{ver_str}{exp_str} -> STATUS: {status_badge}")

        # Web uç noktaları
        if surface.web_endpoints:
            ep_strs = [f"{ep.get('path')} ({ep.get('status', 200)})" for ep in surface.web_endpoints[:5]]
            lines.append(f"  ├── [Web Endpoints] {', '.join(ep_strs)}")

        # Doğrulanmış zafiyetler
        if surface.verified_vulns:
            vuln_strs = [f"{v.get('cve', v.get('category'))} ({v.get('severity', '?')})" for v in surface.verified_vulns[:4]]
            lines.append(f"  └── [Verified Findings] {', '.join(vuln_strs)}")

        return "\n".join(lines)

    def render_compact_context(
        self,
        target: str,
        current_step: int,
        max_steps: int,
        recent_history_count: int = 4
    ) -> str:
        """
        Ham konuşma logları yerine LLM'e (CyberStrike veya DeepSeek)
        sunulacak yüksek sinyalli, ultra-hafif bağlam bloğu üretir.
        """
        surface = self.get_or_create_target(target)
        tree = self.render_attack_surface_tree(target)
        
        # Son N işlem özeti
        history = surface.action_history[-recent_history_count:]
        history_block = "\n".join([f"  - {h}" for h in history]) if history else "  - (No actions yet)"

        # Henüz test edilmemiş servisler
        untested_services = [
            f"{p} ({info.get('service', 'unknown')})"
            for p, info in surface.ports.items()
            if info.get("status") == "UNTESTED"
        ]
        untested_summary = ", ".join(untested_services[:8]) if untested_services else "All discovered ports evaluated"

        context = (
            f"{tree}\n\n"
            f"### Recent Activity (Last {len(history)} actions):\n"
            f"{history_block}\n\n"
            f"Target: {target} | Step: {current_step}/{max_steps}\n"
            f"Untested Attack Vectors: {untested_summary}\n\n"
            f"STRATEGIC DIRECTIVE:\n"
            f"- Review the attack surface tree above. Choose the next untested high-value service or exploit.\n"
            f"- Thorough red team assessment requires uncovering and validating ALL vulnerabilities on the target.\n"
            f"- Obtaining root or a shell on one port DOES NOT end the assessment; continue testing all remaining attack vectors.\n"
            f"- Do NOT repeat actions with identical parameters."
        )
        return context

    def retrieve_raw(self, node_id: str) -> Optional[str]:
        """İhtiyaç anında L2 ham çıktıyı diskten okur (CCR Retrieve)."""
        node = self.nodes.get(node_id)
        if not node or not os.path.exists(node.l2_raw_path):
            return None
        try:
            return Path(node.l2_raw_path).read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"[ContextEngine] L2 raw dosya okuma hatası ({node_id}): {e}")
            return None

    def get_token_savings(self) -> Dict[str, Any]:
        """Tasarruf edilen karakter ve token istatistiklerini hesaplar."""
        raw = self._total_raw_chars
        comp = self._total_compressed_chars
        savings_pct = ((raw - comp) / max(raw, 1)) * 100 if raw > 0 else 0.0
        # Yaklaşık 4 karakter = 1 token (OpenAI/DeepSeek tokenizer tahmini)
        est_tokens_saved = max(0, (raw - comp) // 4)

        return {
            "total_raw_chars": raw,
            "total_compressed_chars": comp,
            "savings_percent": round(savings_pct, 1),
            "estimated_tokens_saved": est_tokens_saved,
            "total_nodes": len(self.nodes)
        }

    def reset(self, target: Optional[str] = None):
        """Hafıza durumunu sıfırlar."""
        if target:
            slug = self._slugify(target)
            self.targets.pop(slug, None)
        else:
            self.targets.clear()
            self.nodes.clear()
            self._total_raw_chars = 0
            self._total_compressed_chars = 0

    # ── Private Yardımcı Metotlar ────────────────────────────────────────────

    def _slugify(self, text: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_\-\.]", "_", text).strip("_").lower()

    def _compress_tool_output(
        self,
        tool: str,
        target: str,
        raw_text: str,
        suggestion: Dict[str, Any],
        command: str,
        surface: TargetAttackSurface
    ) -> tuple[str, Dict[str, Any]]:
        """Araca göre özel L0/L1 sıkıştırma yapar ve saldırı yüzeyini günceller."""
        t_lower = tool.lower()

        # 1. NMAP Port & Servis Taraması
        if t_lower == "nmap":
            open_ports = []
            l1_ports = {}
            # Port deseni: 21/tcp open ftp vsftpd 2.3.4
            for match in re.finditer(r"(\d+/(?:tcp|udp))\s+open\s+(\S+)\s*(.*)", raw_text, re.IGNORECASE):
                p = match.group(1).lower()
                svc = match.group(2).lower()
                ver = match.group(3).strip()
                open_ports.append(f"{p}:{svc}")

                # Exploit eşlemesi
                exploit = None
                p_num = p.split("/")[0]
                if p_num == "21" or "vsftpd" in ver.lower():
                    exploit = "vsftpd_backdoor"
                elif p_num == "22" or "ssh" in svc:
                    exploit = "ssh_credential_spray"
                elif p_num == "445" or "samba" in svc or "smb" in svc or "samba" in ver.lower():
                    exploit = "samba_usermap"
                elif p_num == "1524" or "ingreslock" in svc:
                    exploit = "ingreslock_backdoor"
                elif p_num == "3632" or "distcc" in svc or "distcc" in ver.lower():
                    exploit = "distcc_exec"
                elif p_num == "6667" or "irc" in svc or "unrealircd" in ver.lower():
                    exploit = "unrealircd_backdoor"

                port_data = {
                    "service": svc,
                    "version": ver,
                    "status": "UNTESTED",
                    "exploit": exploit
                }
                surface.ports[p] = port_data
                l1_ports[p] = port_data

            l0 = f"Discovered {len(open_ports)} open ports ({', '.join(open_ports[:6])}{'...' if len(open_ports)>6 else ''})"
            return l0, {"open_ports": l1_ports, "target": target}

        # 2. GOBUSTER / Web Dizin Keşfi
        elif t_lower == "gobuster":
            endpoints = []
            for match in re.finditer(r"(/\S+)\s+\(Status:\s*(\d+)\)", raw_text):
                path = match.group(1)
                status = int(match.group(2))
                endpoints.append({"path": path, "status": status})
                if not any(ep.get("path") == path for ep in surface.web_endpoints):
                    surface.web_endpoints.append({"path": path, "status": status})

            found_cnt = len(endpoints)
            sample_paths = [ep["path"] for ep in endpoints[:4]]
            l0 = f"Discovered {found_cnt} endpoints ({', '.join(sample_paths)})" if found_cnt else "No new endpoints found"
            return l0, {"endpoints": endpoints, "count": found_cnt}

        # 3. EXPLOIT & PRIVESC
        elif t_lower in ("exploit", "privesc"):
            exp_name = suggestion.get("exploit") or suggestion.get("privesc") or tool
            is_root = any(r in raw_text for r in ["uid=0", "root", "gid=0", "Authority\\SYSTEM", "SUCCESS"])
            
            # İlgili portun durumunu güncelle
            for p, p_info in surface.ports.items():
                if p_info.get("exploit") == exp_name or exp_name.startswith(p_info.get("service", "")):
                    p_info["status"] = "ROOT_OBTAINED" if is_root else "EXPLOITED" if "success" in raw_text.lower() else "FAILED"

            if is_root:
                surface.access_level = "root (uid=0)"
                l0 = f"EXPLOIT SUCCESS: {exp_name} yielded ROOT access (uid=0)"
            elif "success" in raw_text.lower():
                l0 = f"EXPLOIT SUCCESS: {exp_name} executed successfully"
            else:
                l0 = f"EXPLOIT FAILED: {exp_name} did not yield shell/access"

            return l0, {"technique": exp_name, "is_root": is_root, "raw_snippet": raw_text[:200]}

        # 4. SEARCHSPLOIT / CVE_SEARCH
        elif t_lower in ("searchsploit", "cve_search"):
            cves = re.findall(r"CVE-\d{4}-\d+", raw_text, re.IGNORECASE)
            unique_cves = list(dict.fromkeys(cves))
            svc = (suggestion.get("service_name") or "").lower()
            ports_str = str(suggestion.get("ports") or "")
            for p, p_info in surface.ports.items():
                p_svc = p_info.get("service", "").lower()
                p_num = p.split("/")[0]
                if (svc and (svc in p_svc or p_svc in svc)) or (p_num and p_num in ports_str):
                    if unique_cves:
                        p_info["status"] = "VERIFIED"
                    elif p_info.get("status") == "UNTESTED":
                        p_info["status"] = "ASSESSED"

            l0 = f"Found {len(unique_cves)} CVEs ({', '.join(unique_cves[:3])})" if unique_cves else "No public exploits matched"
            return l0, {"matched_cves": unique_cves[:10], "tool": tool}

        # 5. Standart / Genel Araçlar (Nikto, SQLmap, WhatWeb, SSL_Check vb.)
        else:
            if t_lower == "nikto":
                for p, p_info in surface.ports.items():
                    if "80" in p or "http" in p_info.get("service", ""):
                        if p_info.get("status") == "UNTESTED":
                            p_info["status"] = "ASSESSED"
            first_line = raw_text.strip().split("\n")[0][:120] if raw_text.strip() else "Empty tool output"
            l0 = f"{tool} executed ({first_line})"
            return l0, {"tool": tool, "summary": first_line}


# Singleton Global Context Engine Instance
context_engine = ContextEngine()
