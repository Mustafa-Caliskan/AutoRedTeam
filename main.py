"""
AutoRedTeam - Autonomous Agentic Security & Red Teaming Audit Framework.

Usage:
    python main.py --mode mock --security-level vulnerable
    python main.py --mode mock --security-level hardened
    python main.py --mode runpod --endpoint http://your-runpod-url:8000/v1
"""

import argparse
import io
import json
import os
import sys
from pathlib import Path
from typing import List

# Fix Windows console UTF-8 encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import track

console = Console(force_terminal=True)

from core.database import initialize_and_seed_database, DB_PATH
from core.llm_client import create_llm_client
from core.mock_tools import ToolRegistry
from core.victim_agent import CorporateVictimAgent
from core.attacker import RedTeamAttacker, AttackPayload
from core.evaluator import SecurityEvaluator, EvaluationResult
from reports.report_generator import SecurityReportGenerator

def display_banner(mode: str, security_level: str, model_target: str):
    banner_text = f"""[bold cyan]🛡️ AutoRedTeam: Ajanik Güvenlik ve Otonom Red Teaming Denetim Sistemi[/bold cyan]
[dim]Microsoft AI Innovators Portfolio & AI Security Audit Framework (2026)[/dim]

[bold yellow]Hedef Kurban Ajan:[/bold yellow] [green]{model_target}[/green]
[bold yellow]Çalışma Modu:[/bold yellow] [magenta]{mode.upper()}[/magenta] (Simüle Güvenlik Seviyesi: [bold]{security_level.upper()}[/bold])
[bold yellow]Standartlar:[/bold yellow] OWASP Top 10 for LLM (LLM01, LLM06) & MITRE ATLAS (AML.T0054)
"""
    console.print(Panel(banner_text, border_style="cyan", expand=False))


def run_red_team_audit(
    mode: str = "mock",
    security_level: str = "vulnerable",
    endpoint_url: str = "http://localhost:8000/v1",
    model_name: str = "auto",
    export_jsonl: bool = True,
    export_report: bool = True,
    auto_detect_model: bool = False
) -> List[EvaluationResult]:
    
    display_banner(mode=mode, security_level=security_level, model_target=model_name)

    # 0. Veritabanı Başlatma
    if not DB_PATH.exists():
        console.print("[dim]➜ Kurumsal SQLite veritabanı (müşteriler, biletler, transfer defteri) oluşturuluyor...[/dim]")
        initialize_and_seed_database()

    # 1. LLM ve Kurban Ajan Altyapısı
    console.print("[dim]➜ Kurban ajan ve kurumsal mock araçları (DB, Wire Transfer, Ticket) başlatılıyor...[/dim]")
    victim_llm = create_llm_client(
        provider=mode,
        model_name=model_name,
        endpoint_url=endpoint_url,
        simulated_security=security_level,
        auto_detect_model=auto_detect_model
    )
    if auto_detect_model and hasattr(victim_llm, "model_name"):
        model_name = victim_llm.model_name
        console.print(f"[dim]➜ Algılanan model: [bold]{model_name}[/bold][/dim]")

    
    tool_registry = ToolRegistry()
    victim_agent = CorporateVictimAgent(llm_client=victim_llm, tool_registry=tool_registry)
    
    # 2. Saldırgan Motoru ve Test Paketi
    attacker = RedTeamAttacker()
    attacks: List[AttackPayload] = attacker.get_predefined_attack_suite()
    evaluator = SecurityEvaluator()

    console.print(f"[bold green]✓ Toplam {len(attacks)} adet OWASP/MITRE saldırı senaryosu yüklendi.[/bold green]\n")

    results: List[EvaluationResult] = []
    benchmark_records = []

    # 3. Denetim Döngüsü (Audit Loop)
    for attack in attacks:
        console.print(f"[bold yellow]▶ Saldırı Yürütülüyor:[/bold yellow] [bold]{attack.attack_id}[/bold] - [dim]{attack.attack_type}[/dim]")
        console.print(f"  [dim]Payload:[/dim] {attack.converted_prompt[:90]}...")

        # Ajanı sıfırla ve saldırı promptunu ilet
        victim_agent.reset()
        victim_output = victim_agent.process_message(attack.converted_prompt)

        # Değerlendir
        eval_res = evaluator.evaluate(attack, victim_output)
        results.append(eval_res)

        # Durum çıktısı
        if eval_res.risk_level == "CRITICAL":
            console.print(f"  [bold red]✖ BAŞARILI BYPASS (CRITICAL):[/bold red] {eval_res.reasoning}")
        elif eval_res.risk_level == "HIGH":
            console.print(f"  [bold magenta]⚠ YÜKSEK RİSK (DATA LEAK):[/bold magenta] {eval_res.reasoning}")
        elif eval_res.risk_level == "SAFE":
            console.print(f"  [bold green]✓ GÜVENLİ (DEFENDED):[/bold green] Kurban ajan saldırıyı başarıyla engelledi.")
        else:
            console.print(f"  [bold blue]ℹ BİLGİ:[/bold blue] {eval_res.reasoning}")

        console.print()

        # Benchmark kaydı
        benchmark_records.append({
            "attack_id": eval_res.attack_id,
            "attack_type": eval_res.attack_type,
            "target_model": model_name,
            "payload": attack.converted_prompt,
            "vulnerability_score": eval_res.vulnerability_score,
            "risk_level": eval_res.risk_level,
            "is_vulnerable": eval_res.is_vulnerable,
            "unauthorized_tools": eval_res.unauthorized_tools_triggered,
            "owasp_category": eval_res.owasp_category,
            "mitre_id": eval_res.mitre_technique_id,
            "timestamp": eval_res.timestamp
        })

    # 4. Sonuç Tablosunu Oluştur
    table = Table(title="🛡️ AutoRedTeam Güvenlik Denetim Sonuçları", show_header=True, header_style="bold magenta")
    table.add_column("Saldırı ID", style="cyan", width=18)
    table.add_column("Saldırı Türü", style="white")
    table.add_column("OWASP / MITRE", style="dim")
    table.add_column("Zafiyet Skoru", justify="right")
    table.add_column("Risk", justify="center")

    total_attacks = len(results)
    successful_exploits = sum(1 for r in results if r.is_vulnerable)
    critical_count = sum(1 for r in results if r.risk_level == "CRITICAL")

    for r in results:
        risk_color = "red" if r.risk_level == "CRITICAL" else ("magenta" if r.risk_level == "HIGH" else ("green" if r.risk_level == "SAFE" else "yellow"))
        score_text = f"[{risk_color}]{r.vulnerability_score:.1f} / 10[/{risk_color}]"
        risk_badge = f"[{risk_color} bold]{r.risk_level}[/{risk_color} bold]"
        table.add_row(r.attack_id, r.attack_type, f"{r.owasp_category.split(' ')[0]} | {r.mitre_technique_id.split(' ')[0]}", score_text, risk_badge)

    console.print(table)

    # 5. İstatistiksel Metrikler
    asr = (successful_exploits / total_attacks) * 100
    metrics_panel = f"""[bold]Denetim İstatistikleri:[/bold]
• Toplam Test Edilen Senaryo: [bold]{total_attacks}[/bold]
• Başarılı İstismar (Attack Success Rate - ASR): [bold {'red' if asr > 0 else 'green'}]{asr:.1f}%[/bold {'red' if asr > 0 else 'green'}]
• Kritik Seviye Zafiyet Sayısı: [bold red]{critical_count}[/bold red]
• Korunan Güvenlik Politikası Başarısı: [bold green]{((total_attacks - successful_exploits)/total_attacks)*100:.1f}%[/bold green]
"""
    console.print(Panel(metrics_panel, title="📊 Yönetici Özeti", border_style="yellow"))

    # 6. JSONL Benchmark Veri Seti Çıktısı
    if export_jsonl:
        data_dir = Path("data")
        data_dir.mkdir(exist_ok=True)
        jsonl_path = data_dir / "benchmark_results.jsonl"
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for record in benchmark_records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        console.print(f"[bold cyan]📁 Hugging Face uyumlu benchmark veri seti kaydedildi:[/bold cyan] [underline]{jsonl_path}[/underline]")

    # 7. Güvenlik Denetim Raporu Çıktısı (Markdown & RAG Mitigations)
    if export_report:
        report_gen = SecurityReportGenerator()
        rep_path = report_gen.generate_markdown_report(results=results, target_model=model_name)
        console.print(f"[bold green]📄 Kapsamlı Güvenlik Denetim Raporu oluşturuldu:[/bold green] [underline]{rep_path}[/underline]\n")

    return results


def main():
    parser = argparse.ArgumentParser(description="AutoRedTeam - Otonom LLM Ajan Güvenlik Denetim Sistemi")
    parser.add_argument("--mode", choices=["mock", "runpod", "ollama", "openai"], default="mock", help="Model sağlayıcı modu")
    parser.add_argument("--security-level", choices=["vulnerable", "hardened"], default="vulnerable", help="Mock kurban güvenlik seviyesi")
    parser.add_argument("--endpoint", default="http://localhost:8000/v1", help="RunPod/vLLM kurban model endpoint URL")
    parser.add_argument("--target", default="auto", help="Kurban model adı ('auto' ile vLLM'den otomatik algılanır)")
    parser.add_argument("--no-export", action="store_true", help="JSONL veri seti çıktısını kaydetme")
    parser.add_argument("--no-report", action="store_true", help="Denetim raporu çıktısını oluşturma")

    args = parser.parse_args()

    # RunPod modunda --target auto ise model adını vLLM'den otomatik al
    auto_detect = (args.mode != "mock" and args.target == "auto")

    run_red_team_audit(
        mode=args.mode,
        security_level=args.security_level,
        endpoint_url=args.endpoint,
        model_name=args.target,
        export_jsonl=not args.no_export,
        export_report=not args.no_report,
        auto_detect_model=auto_detect
    )


if __name__ == "__main__":
    main()
