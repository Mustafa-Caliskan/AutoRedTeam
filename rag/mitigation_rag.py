"""
AutoRedTeam - RAG-Based Security Mitigation & Remediation Engine.

Retrieves tailored defensive mitigation strategies from OWASP GenAI Top 10
and MITRE ATLAS knowledge base for any detected vulnerability.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from core.evaluator import EvaluationResult

KNOWLEDGE_BASE_PATH = Path(__file__).parent / "knowledge_base" / "owasp_mitre_mitigations.json"


class MitigationRAGEngine:
    """
    Güvenlik Açığı Savunma ve Önlem Motoru (RAG).
    Tespit edilen zafiyet türüne göre MITRE ATLAS ve OWASP uyumlu eylem adımları getirir.
    """

    def __init__(self, kb_path: Optional[Path] = None):
        self.kb_path = kb_path or KNOWLEDGE_BASE_PATH
        self.knowledge_base: List[Dict[str, Any]] = []
        self._load_knowledge_base()

    def _load_knowledge_base(self) -> None:
        """JSON bilgi bankasını belleğe yükler."""
        if self.kb_path.exists():
            try:
                with open(self.kb_path, "r", encoding="utf-8") as f:
                    self.knowledge_base = json.load(f)
            except Exception as e:
                self.knowledge_base = []
        else:
            self.knowledge_base = []

    def get_mitigation_for_vulnerability(self, result: EvaluationResult) -> Dict[str, Any]:
        """
        Değerlendirme sonucundaki zafiyet için en uygun savunma önerisini döner.
        """
        if not result.is_vulnerable:
            return {
                "title": "Mevcut Durum Güvenli",
                "severity": "SAFE",
                "description": "Herhangi bir zafiyet tespit edilmedi. Mevcut güvenlik politikası korundu.",
                "actionable_steps": [
                    "Mevcut guardrail kurallarını periyodik olarak güncellemeye devam edin.",
                    "Sistem prompt regresyon testlerini CI/CD hattında otomatik koşturun."
                ]
            }

        # 1. Kategori Eşleştirmesi
        for item in self.knowledge_base:
            if result.owasp_category and result.owasp_category.split(" ")[0] in item.get("category", ""):
                # Eğer secret sızıntısı ise secret maddesini öncelikle eşle
                if result.secret_leaked and "SECRET" in item.get("id", ""):
                    return item
                # Eğer Excessive Agency / Tool Bypass ise
                if result.unauthorized_tools_triggered and "LLM06" in item.get("category", ""):
                    return item
                # Prompt Injection ise
                if "LLM01" in item.get("category", ""):
                    return item

        # 2. Genel Fallback Savunma Önerisi
        return {
            "title": "Genel LLM Ajan Güvenlik Sertleştirmesi",
            "severity": result.risk_level,
            "description": f"{result.owasp_category} açığına karşı standart güvenlik önlemleri uygulanmalıdır.",
            "actionable_steps": [
                "Modelin araç çalıştırma parametrelerini şema düzeyinde tip ve sınır kontrolünden geçirin.",
                "Harici kullanıcı ve bilet girdilerini ayrıştırarak doğrudan sistem promptuna karışmasını engelleyin.",
                "Kritik API çağrıları için insan onayı (Human-in-the-loop) mekanizmasını zorunlu kılın."
            ]
        }
