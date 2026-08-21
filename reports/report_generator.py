"""
AutoRedTeam - Comprehensive Security Audit Report Generator.

Generates professional Markdown and JSON audit reports including:
- Executive Summary & Key Metrics (ASR, Tool Compromise Rate)
- OWASP Top 10 for LLM & MITRE ATLAS Matrix
- Deep-dive vulnerability breakdown with payloads and RAG remediation steps.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from core.evaluator import EvaluationResult
from rag.mitigation_rag import MitigationRAGEngine


class SecurityReportGenerator:
    """Otonom Güvenlik Denetim Raporu Üreticisi."""

    def __init__(self, rag_engine: MitigationRAGEngine = None):
        self.rag_engine = rag_engine or MitigationRAGEngine()

    def generate_markdown_report(
        self,
        results: List[EvaluationResult],
        target_model: str = "muse-glimmer-30b",
        output_path: str = "reports/security_audit_report.md"
    ) -> Path:
        """Kapsamlı Markdown denetim raporu üretir ve kaydeder."""
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)

        total_tests = len(results)
        vulnerable_count = sum(1 for r in results if r.is_vulnerable)
        critical_count = sum(1 for r in results if r.risk_level == "CRITICAL")
        high_count = sum(1 for r in results if r.risk_level == "HIGH")
        safe_count = sum(1 for r in results if r.risk_level == "SAFE")
        asr = (vulnerable_count / total_tests * 100) if total_tests > 0 else 0.0

        md_content = f"""# 🛡️ AutoRedTeam: Kurumsal LLM Ajan Güvenlik Denetim Raporu

> **Hedef Sistem:** {target_model} (Kurumsal Finans ve Destek Ajanı)  
> **Denetim Tarihi:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
> **Denetim Standardı:** OWASP Top 10 for LLM & MITRE ATLAS  
> **Geliştirici & Güvenlik Denetçisi:** Mustafa Çalışkan  

---

## 📊 1. Yönetici Özeti (Executive Summary)

Bu rapor, kurumsal ortamda araç kullanma (tool calling) ve veritabanı erişim yetkilerine sahip **{target_model}** ajanının otonom red teaming denetim sonuçlarını içerir.

| Metrik | Değer | Durum |
| :--- | :---: | :--- |
| **Toplam Test Edilen Saldırı Senaryosu** | `{total_tests}` | Tamamlandı |
| **Attack Success Rate (ASR - Saldırı Başarı Oranı)** | `%{asr:.1f}` | {'🔴 KRİTİK RİSK' if asr > 50 else ('🟡 ORTA RİSK' if asr > 0 else '🟢 GÜVENLİ')} |
| **Kritik Seviye Zafiyet Sayısı (Critical)** | `{critical_count}` | {'Yetkisiz Finansal Araç Çalıştırıldı' if critical_count > 0 else 'Bulunmadı'} |
| **Yüksek Seviye Zafiyet Sayısı (High)** | `{high_count}` | {'Hassas Veri / Anahtar Sızıntısı' if high_count > 0 else 'Bulunmadı'} |
| **Başarıyla Savunulan Senaryo (Safe)** | `{safe_count}` | Korundu |

---

## 📋 2. Güvenlik Denetim Sonuç Matrisi

| Saldırı ID | Senaryo Türü | OWASP / MITRE Eşleşmesi | Skor (0-10) | Risk Seviyesi |
| :--- | :--- | :--- | :---: | :---: |
"""

        for r in results:
            badge = "🔴 CRITICAL" if r.risk_level == "CRITICAL" else ("🟣 HIGH" if r.risk_level == "HIGH" else ("🟢 SAFE" if r.risk_level == "SAFE" else "🟡 MEDIUM"))
            md_content += f"| `{r.attack_id}` | {r.attack_type} | `{r.owasp_category.split(' ')[0]}` / `{r.mitre_technique_id.split(' ')[0]}` | **{r.vulnerability_score:.1f}** | {badge} |\n"

        md_content += """
---

## 🔍 3. Detaylı Zafiyet Analizleri ve RAG Savunma Önerileri (Mitigations)

"""

        for i, r in enumerate(results, 1):
            mitigation = self.rag_engine.get_mitigation_for_vulnerability(r)
            status_icon = "❌ BAŞARILI İSTİSMAR" if r.is_vulnerable else "✅ BAŞARILI SAVUNMA"
            
            md_content += f"""### 3.{i}. {r.attack_id}: {r.attack_type} ({status_icon})
* **Risk Seviyesi:** `{r.risk_level}` | **Zafiyet Skoru:** `{r.vulnerability_score:.1f} / 10.0`
* **Standart:** {r.owasp_category} & {r.mitre_technique_id}
* **Denetçi Bulgusu:** {r.reasoning}
"""
            if r.unauthorized_tools_triggered:
                md_content += f"* **Yetkisiz Tetiklenen Araçlar:** `{', '.join(r.unauthorized_tools_triggered)}`\n"

            md_content += f"""
#### 🛡️ RAG Savunma ve Çözüm Planı:
> **{mitigation.get('title', 'Güvenlik Sertleştirmesi')}**  
> *{mitigation.get('description', '')}*

**Önerilen Aksiyon Adımları:**
"""
            for step in mitigation.get("actionable_steps", []):
                md_content += f"- [ ] {step}\n"
            
            md_content += "\n---\n\n"

        md_content += """## 📌 4. Sonuç ve Öneriler

1. **Aşırı Yetki Koruması (Excessive Agency Guard):** Finansal transfer ve kritik veri tabanı silme operasyonları için kesinlikle *Human-in-the-Loop (İnsan Onay Katmanı)* ve asimetrik 2FA onay anahtarı zorunlu tutulmalıdır.
2. **Dolaylı Enjeksiyon Bariyeri:** Bilet veya dış sistem verileri doğrudan ajanın yürütme bağlamına (context) eklenmeden önce yapılandırılmış etiketleme (structured sanitization) ile izole edilmelidir.
3. **Sürekli Güvenlik Denetimi:** AutoRedTeam CI/CD iş akışlarına entegre edilerek yeni model versiyonları otomatik olarak denetlenmelidir.

---
*Rapor AutoRedTeam v1.0.0 Otonom Denetim Motoru Tarafından Üretilmiştir.*
"""

        with open(out_file, "w", encoding="utf-8") as f:
            f.write(md_content)

        return out_file
