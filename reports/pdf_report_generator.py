"""
AutoRedTeam - Professional PDF Report Generator.

Bulgulari (kesif, exploit, privesc, root kaniti) profesyonel bir PDF rapor
formatinda uretir. reportlab kutuphanesini kullanir.

Rapor yapisi:
  1. Kapak sayfasi (hedef, tarih, metrikler)
  2. Yonetici ozeti (executive summary)
  3. Bulgu tablosu (severity renkli)
  4. Detayli bulgu analizleri (kanit + etki + remediation)
  5. Exploit zinciri / saldiri grafigi
  6. Sonuc ve oneriler

Kullanim:
    from reports.pdf_report_generator import PDFReportGenerator
    gen = PDFReportGenerator()
    path = gen.generate(findings, target="metasploitable2", decision_chain=chain)
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# reportlab imports
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        KeepTogether,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab kurulu degil. PDF rapor uretilemez. 'pip install reportlab'")


# ── Renk Paleti (Kurumsal Kirmizi/Siyah Tema) ───────────────────────────────

COLOR_PRIMARY = colors.HexColor("#B91C1C")      # Kirmizi
COLOR_DARK = colors.HexColor("#111827")         # Koyu lacivert/siyah
COLOR_GRAY = colors.HexColor("#6B7280")         # Gri
COLOR_LIGHT_BG = colors.HexColor("#F3F4F6")     # Acik gri arka plan
COLOR_CRITICAL = colors.HexColor("#DC2626")     # Kritik kirmizi
COLOR_HIGH = colors.HexColor("#EA580C")         # Yuksek turuncu
COLOR_MEDIUM = colors.HexColor("#D97706")       # Orta amber
COLOR_LOW = colors.HexColor("#2563EB")          # Dusuk mavi
COLOR_SUCCESS = colors.HexColor("#059669")      # Yesil


def _severity_color(severity: str):
    """Severity'ye gore renk dondurur."""
    s = (severity or "").lower()
    if s == "critical":
        return COLOR_CRITICAL
    if s == "high":
        return COLOR_HIGH
    if s == "medium":
        return COLOR_MEDIUM
    if s == "low":
        return COLOR_LOW
    return COLOR_GRAY


class PDFReportGenerator:
    """Profesyonel PDF guvenlik degerlendirme raporu ureticisi."""

    def __init__(self, output_dir: str = "raporlar"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._styles = self._build_styles() if REPORTLAB_AVAILABLE else None

    def _build_styles(self):
        """Paragraph stillerini olusturur."""
        styles = getSampleStyleSheet()
        custom = {
            "CoverTitle": ParagraphStyle(
                "CoverTitle", parent=styles["Title"], fontSize=28, leading=34,
                textColor=COLOR_DARK, alignment=TA_CENTER, spaceAfter=6,
            ),
            "CoverSubtitle": ParagraphStyle(
                "CoverSubtitle", parent=styles["Normal"], fontSize=13, leading=18,
                textColor=COLOR_PRIMARY, alignment=TA_CENTER, spaceAfter=4,
            ),
            "CoverMeta": ParagraphStyle(
                "CoverMeta", parent=styles["Normal"], fontSize=10, leading=15,
                textColor=COLOR_GRAY, alignment=TA_CENTER,
            ),
            "SectionHeading": ParagraphStyle(
                "SectionHeading", parent=styles["Heading1"], fontSize=16, leading=20,
                textColor=COLOR_PRIMARY, spaceBefore=14, spaceAfter=8,
            ),
            "SubHeading": ParagraphStyle(
                "SubHeading", parent=styles["Heading2"], fontSize=12, leading=16,
                textColor=COLOR_DARK, spaceBefore=10, spaceAfter=5,
            ),
            "Body": ParagraphStyle(
                "Body", parent=styles["Normal"], fontSize=9.5, leading=14,
                textColor=COLOR_DARK, alignment=TA_LEFT,
            ),
            "BodySmall": ParagraphStyle(
                "BodySmall", parent=styles["Normal"], fontSize=8.5, leading=12,
                textColor=COLOR_GRAY,
            ),
            "Evidence": ParagraphStyle(
                "Evidence", parent=styles["Code"], fontSize=8, leading=11,
                textColor=colors.HexColor("#065F46"),
                backColor=colors.HexColor("#ECFDF5"), borderPadding=6,
            ),
            "TableCell": ParagraphStyle(
                "TableCell", parent=styles["Normal"], fontSize=8.5, leading=11,
                textColor=COLOR_DARK,
            ),
            "TableHeader": ParagraphStyle(
                "TableHeader", parent=styles["Normal"], fontSize=9, leading=12,
                textColor=colors.white,
            ),
        }
        return custom

    # ── Sayfa Sablonu (Header/Footer) ───────────────────────────────────────

    def _header_footer(self, canvas, doc):
        """Her sayfaya header ve footer ekler."""
        canvas.saveState()
        width, height = A4
        # Header cizgisi
        canvas.setStrokeColor(COLOR_PRIMARY)
        canvas.setLineWidth(2)
        canvas.line(15 * mm, height - 15 * mm, width - 15 * mm, height - 15 * mm)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(COLOR_DARK)
        canvas.drawString(15 * mm, height - 13 * mm, "AutoRedTeam — Guvenlik Degerlendirme Raporu")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(COLOR_GRAY)
        canvas.drawRightString(width - 15 * mm, height - 13 * mm, "GIZLI / CONFIDENTIAL")
        # Footer
        canvas.setStrokeColor(COLOR_LIGHT_BG)
        canvas.setLineWidth(1)
        canvas.line(15 * mm, 15 * mm, width - 15 * mm, 15 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(COLOR_GRAY)
        canvas.drawString(15 * mm, 11 * mm, "AutoRedTeam v2.0 — Otonom Red Team Platformu")
        canvas.drawRightString(width - 15 * mm, 11 * mm, f"Sayfa {doc.page}")
        canvas.restoreState()

    # ── Ana Uretim Metodu ───────────────────────────────────────────────────

    def generate(
        self,
        findings: List[Dict[str, Any]],
        target: str = "metasploitable2",
        decision_chain: Optional[List[Dict[str, Any]]] = None,
        chains: Optional[List[Dict[str, Any]]] = None,
        output_filename: Optional[str] = None,
    ) -> Optional[Path]:
        """
        Bulgulardan profesyonel PDF raporu uretir.

        Args:
            findings: Bulgu listesi (finding_id, tool, category, severity, cwe_reference, evidence_snippet)
            target: Hedef sistem adi
            decision_chain: Model karar zinciri (adim, tool, thought)
            chains: Exploit zincirleri (chain_engine cikitisi)
            output_filename: Opsiyonel dosya adi

        Returns:
            Olusan PDF dosyasinin yolu veya None (reportlab yoksa).
        """
        if not REPORTLAB_AVAILABLE:
            logger.error("reportlab kurulu degil; PDF uretilemedi.")
            return None

        if not output_filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"autoredteam_rapor_{ts}.pdf"
        out_path = self.output_dir / output_filename

        doc = BaseDocTemplate(
            str(out_path), pagesize=A4,
            leftMargin=15 * mm, rightMargin=15 * mm,
            topMargin=22 * mm, bottomMargin=20 * mm,
            title="AutoRedTeam Guvenlik Degerlendirme Raporu",
            author="AutoRedTeam",
        )
        frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
        doc.addPageTemplates([
            PageTemplate(id="cover", frames=[frame]),
            PageTemplate(id="content", frames=[frame], onPage=self._header_footer),
        ])

        story: List[Any] = []
        story += self._build_cover(target, findings)
        story.append(PageBreak())
        story += self._build_executive_summary(findings)
        story += self._build_findings_table(findings)
        story += self._build_detailed_findings(findings)
        if chains:
            story += self._build_chains(chains)
        if decision_chain:
            story += self._build_decision_chain(decision_chain)
        story += self._build_conclusion(findings)

        try:
            doc.build(story)
            logger.info(f"PDF rapor olusturuldu: {out_path}")
            return out_path
        except Exception as e:
            logger.error(f"PDF olusturma hatasi: {e}")
            return None

    # ── Bolum Ureticileri ───────────────────────────────────────────────────

    def _build_cover(self, target: str, findings: List[Dict[str, Any]]) -> List[Any]:
        """Kapak sayfasi."""
        s = self._styles
        critical = sum(1 for f in findings if f.get("severity") == "Critical")
        high = sum(1 for f in findings if f.get("severity") == "High")
        root_obtained = any(
            "uid=0" in str(f.get("evidence_snippet", "")) for f in findings
        )

        elements = [
            Spacer(1, 45 * mm),
            Paragraph("AutoRedTeam", s["CoverTitle"]),
            Paragraph("Otonom Red Team & Guvenlik Degerlendirme Raporu", s["CoverSubtitle"]),
            Spacer(1, 8 * mm),
            Paragraph(
                f"<b>Hedef Sistem:</b> {target}<br/>"
                f"<b>Rapor Tarihi:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
                f"<b>Metodoloji:</b> OWASP WSTG & MITRE ATT&CK<br/>"
                f"<b>Siniflandirma:</b> GIZLI / CONFIDENTIAL",
                s["CoverMeta"],
            ),
            Spacer(1, 20 * mm),
        ]

        # Ozet metrik kutusu
        status_text = "SISTEM TAMAMEN ELE GECIRILDI (ROOT)" if root_obtained else "DEGERLENDIRME TAMAMLANDI"
        status_color = COLOR_CRITICAL if root_obtained else COLOR_SUCCESS
        metrics_data = [
            [Paragraph("<b>Toplam Bulgu</b>", s["TableHeader"]),
             Paragraph("<b>Kritik</b>", s["TableHeader"]),
             Paragraph("<b>Yuksek</b>", s["TableHeader"]),
             Paragraph("<b>Root Erisimi</b>", s["TableHeader"])],
            [Paragraph(str(len(findings)), s["TableCell"]),
             Paragraph(str(critical), s["TableCell"]),
             Paragraph(str(high), s["TableCell"]),
             Paragraph("EVET" if root_obtained else "HAYIR", s["TableCell"])],
        ]
        metrics_table = Table(metrics_data, colWidths=[45 * mm] * 4)
        metrics_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
            ("BACKGROUND", (0, 1), (-1, 1), COLOR_LIGHT_BG),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.white),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(metrics_table)
        elements.append(Spacer(1, 10 * mm))
        elements.append(Paragraph(
            f'<font color="{status_color.hexval()}"><b>{status_text}</b></font>',
            s["CoverSubtitle"],
        ))
        return elements

    def _build_executive_summary(self, findings: List[Dict[str, Any]]) -> List[Any]:
        """Yonetici ozeti."""
        s = self._styles
        critical = sum(1 for f in findings if f.get("severity") == "Critical")
        high = sum(1 for f in findings if f.get("severity") == "High")
        medium = sum(1 for f in findings if f.get("severity") == "Medium")
        low = sum(1 for f in findings if f.get("severity") == "Low")
        root_obtained = any("uid=0" in str(f.get("evidence_snippet", "")) for f in findings)
        foothold = any(f.get("tool") in ("exploit", "privesc") for f in findings)

        elements = [
            Paragraph("1. Yonetici Ozeti (Executive Summary)", s["SectionHeading"]),
            Paragraph(
                "Bu rapor, yetkili ve izole bir test ortaminda gerceklestirilen otonom "
                "sizma testi (penetration test) sonuclarini ozetler. Degerlendirme; kesif, "
                "zafiyet dogrulama, aktif somuru (exploitation) ve yetki yukseltme "
                "(privilege escalation) asamalarini kapsamistir.",
                s["Body"],
            ),
            Spacer(1, 4 * mm),
        ]

        summary_data = [
            ["Metrik", "Deger"],
            ["Toplam Bulgu", str(len(findings))],
            ["Kritik (Critical)", str(critical)],
            ["Yuksek (High)", str(high)],
            ["Orta (Medium)", str(medium)],
            ["Dusuk (Low)", str(low)],
            ["Foothold Elde Edildi", "EVET" if foothold else "HAYIR"],
            ["Root Erisimi (UID=0)", "EVET - SISTEM ELE GECIRILDI" if root_obtained else "HAYIR"],
        ]
        table = Table(summary_data, colWidths=[70 * mm, 100 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        elements.append(table)
        return elements

    def _build_findings_table(self, findings: List[Dict[str, Any]]) -> List[Any]:
        """Bulgu tablosu (severity renkli)."""
        s = self._styles
        elements = [
            Spacer(1, 6 * mm),
            Paragraph("2. Bulgu Tablosu (Findings)", s["SectionHeading"]),
        ]
        if not findings:
            elements.append(Paragraph("Kayitli bulgu bulunmamaktadir.", s["Body"]))
            return elements

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(
            findings, key=lambda f: severity_order.get(f.get("severity", "Low"), 99)
        )

        data = [["ID", "Arac", "Kategori", "Siddet", "CWE"]]
        for f in sorted_findings:
            data.append([
                Paragraph(str(f.get("finding_id", "-")), s["TableCell"]),
                Paragraph(str(f.get("tool", "-")), s["TableCell"]),
                Paragraph(str(f.get("category", "-"))[:45], s["TableCell"]),
                Paragraph(str(f.get("severity", "-")), s["TableCell"]),
                Paragraph(str(f.get("cwe_reference", "-")), s["TableCell"]),
            ])

        table = Table(data, colWidths=[22 * mm, 22 * mm, 68 * mm, 24 * mm, 34 * mm], repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
        # Severity sutununu renklendir
        for i, f in enumerate(sorted_findings, start=1):
            style.append(("TEXTCOLOR", (3, i), (3, i), _severity_color(f.get("severity", ""))))
            style.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))
        table.setStyle(TableStyle(style))
        elements.append(table)
        return elements

    def _build_detailed_findings(self, findings: List[Dict[str, Any]]) -> List[Any]:
        """Detayli bulgu analizleri."""
        s = self._styles
        elements = [
            Spacer(1, 6 * mm),
            Paragraph("3. Detayli Bulgu Analizleri", s["SectionHeading"]),
        ]
        if not findings:
            elements.append(Paragraph("Kayitli bulgu bulunmamaktadir.", s["Body"]))
            return elements

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_findings = sorted(
            findings, key=lambda f: severity_order.get(f.get("severity", "Low"), 99)
        )

        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "Low")
            block = [
                Paragraph(
                    f"3.{i} {f.get('finding_id', '-')}: {f.get('category', '-')} "
                    f'<font color="{_severity_color(sev).hexval()}">[{sev}]</font>',
                    s["SubHeading"],
                ),
                Paragraph(
                    f"<b>Arac:</b> {f.get('tool', '-')} &nbsp;|&nbsp; "
                    f"<b>Hedef:</b> {f.get('target', '-')} &nbsp;|&nbsp; "
                    f"<b>CWE:</b> {f.get('cwe_reference', '-')}",
                    s["BodySmall"],
                ),
                Spacer(1, 2 * mm),
                Paragraph("<b>Kanit (Evidence):</b>", s["Body"]),
                Paragraph(
                    str(f.get("evidence_snippet", "")).replace("<", "&lt;").replace(">", "&gt;")[:400],
                    s["Evidence"],
                ),
                Spacer(1, 2 * mm),
                Paragraph(f"<b>Etki (Impact):</b> {self._impact_for_severity(sev)}", s["Body"]),
                Paragraph(
                    f"<b>Onerilen Duzeltme (Remediation):</b> "
                    f"{self._remediation_for_category(f.get('category', ''))}",
                    s["Body"],
                ),
                Spacer(1, 5 * mm),
            ]
            elements.append(KeepTogether(block))
        return elements

    def _build_chains(self, chains: List[Dict[str, Any]]) -> List[Any]:
        """Exploit zincirleri bolumu."""
        s = self._styles
        elements = [
            Spacer(1, 6 * mm),
            Paragraph("4. Exploit Zincirleme Analizi (Attack Chains)", s["SectionHeading"]),
        ]
        for c in chains:
            elements.append(Paragraph(
                f"{c.get('title', 'Saldiri Zinciri')} "
                f'<font color="{_severity_color(c.get("severity", "")).hexval()}">'
                f'[{c.get("severity", "")}]</font>',
                s["SubHeading"],
            ))
            for step in c.get("steps", []):
                phase = step.get("phase", "")
                detail = step.get("detail") or step.get("impact") or ""
                elements.append(Paragraph(
                    f"<b>Adim {step.get('step', '?')} ({phase}):</b> "
                    f"{str(detail)[:250]}",
                    s["Body"],
                ))
            elements.append(Spacer(1, 4 * mm))
        return elements

    def _build_decision_chain(self, decision_chain: List[Dict[str, Any]]) -> List[Any]:
        """Model karar zinciri bolumu."""
        s = self._styles
        elements = [
            Spacer(1, 6 * mm),
            Paragraph("5. Model Karar Zinciri (Decision Chain)", s["SectionHeading"]),
        ]
        data = [["Adim", "Arac", "Hedef", "Akil Yurutme (Thought)"]]
        for d in decision_chain:
            data.append([
                Paragraph(str(d.get("step", "-")), s["TableCell"]),
                Paragraph(str(d.get("tool", "-")), s["TableCell"]),
                Paragraph(str(d.get("target", "-"))[:20], s["TableCell"]),
                Paragraph(str(d.get("thought", ""))[:120], s["TableCell"]),
            ])
        table = Table(data, colWidths=[14 * mm, 22 * mm, 30 * mm, 104 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, COLOR_GRAY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLOR_LIGHT_BG]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(table)
        return elements

    def _build_conclusion(self, findings: List[Dict[str, Any]]) -> List[Any]:
        """Sonuc ve oneriler."""
        s = self._styles
        root_obtained = any("uid=0" in str(f.get("evidence_snippet", "")) for f in findings)
        elements = [
            Spacer(1, 6 * mm),
            Paragraph("6. Sonuc ve Oneriler", s["SectionHeading"]),
        ]
        if root_obtained:
            elements.append(Paragraph(
                '<font color="#DC2626"><b>KRITIK: Hedef sistem tamamen ele gecirilmistir '
                '(root/UID=0).</b></font> Bu, saldirganin sistem uzerinde tam kontrol '
                "sagladigi anlamina gelir.",
                s["Body"],
            ))
        elements.append(Paragraph(
            "1. <b>Yama Yonetimi:</b> Tespit edilen zafiyetli servisler (vsftpd, Samba, "
            "MySQL vb.) derhal guncel surumlere yukseltilmeli veya devre disi birakilmalidir.",
            s["Body"],
        ))
        elements.append(Paragraph(
            "2. <b>Ag Segmentasyonu:</b> Gereksiz acik portlar (1524, 6667, 3632 vb.) "
            "firewall ile kapatilmali, servisler yalnizca gerekli kaynaklara acilmalidir.",
            s["Body"],
        ))
        elements.append(Paragraph(
            "3. <b>Kimlik Guvenligi:</b> Varsayilan/zayif kimlik bilgileri (msfadmin:msfadmin) "
            "degistirilmeli, guclu parola politikasi ve MFA uygulanmalidir.",
            s["Body"],
        ))
        elements.append(Paragraph(
            "4. <b>Yetki Yonetimi:</b> Gereksiz SUID bitleri ve sudo yetkileri kaldirilmali, "
            "en az yetki (least privilege) ilkesi uygulanmalidir.",
            s["Body"],
        ))
        elements.append(Spacer(1, 6 * mm))
        elements.append(Paragraph(
            f"<i>Rapor AutoRedTeam v2.0 tarafindan {datetime.now().strftime('%Y-%m-%d %H:%M')} "
            "tarihinde otomatik olarak uretilmistir.</i>",
            s["BodySmall"],
        ))
        return elements

    # ── Yardimci Metinler ───────────────────────────────────────────────────

    @staticmethod
    def _impact_for_severity(severity: str) -> str:
        mapping = {
            "Critical": "Kritik guvenlik acigi: sistem tamamen tehlikeye atilabilir, "
                        "veri butunlugu ve gizliligi ciddi sekilde ihlal edilebilir.",
            "High": "Yuksek risk: yetkisiz erisim veya hassas veri ifsasi mumkundur.",
            "Medium": "Orta risk: sinirli etki, ancak saldiri yuzeyini genisletebilir.",
            "Low": "Dusuk risk: bilgi sizintisi veya konfigurasyon iyilestirmesi gerektirir.",
        }
        return mapping.get(severity, "Bilinmeyen etki.")

    @staticmethod
    def _remediation_for_category(category: str) -> str:
        cat = (category or "").lower()
        if "backdoor" in cat or "remote code" in cat or "rce" in cat:
            return ("Zafiyetli servisi derhal guncelleyin veya kaldirin; ag erisimini "
                    "kisitlayin ve IDS/IPS ile anormal baglantilari izleyin.")
        if "credential" in cat or "weak" in cat:
            return ("Varsayilan kimlik bilgilerini degistirin; guclu parola politikasi, "
                    "hesap kilitleme ve MFA uygulayin.")
        if "privilege" in cat or "escalation" in cat:
            return ("Gereksiz SUID bitlerini ve sudo yetkilerini kaldirin; en az yetki "
                    "ilkesini uygulayin ve dosya izinlerini denetleyin.")
        if "sql" in cat:
            return ("Parametreli sorgular kullanin, girdi dogrulama uygulayin ve ORM kullanin.")
        return "Ilgili guvenlik kontrolunu uygulayin ve OWASP onerilerini takip edin."


# Singleton
pdf_report_generator = PDFReportGenerator()
