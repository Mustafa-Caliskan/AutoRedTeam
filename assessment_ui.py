"""
AutoRedTeam - Elite Autonomous Security Assessment & Pentest Cockpit (Web UI)
Real-time SOC & Red Team Cockpit visualizing:
- DeepSeek V4 Flash (Orchestrator Parent Brain)
- CyberStrike 35B (Execution Muscle)
- 818 Cybersecurity Skills Explorer (agentskills.io standard)
- 7-Question Validation Gate (Anti-Hallucination & Fluff Filter)
- Exploit Chaining Walk Engine (Multi-Hop Attack Graphs)
- x64dbg Native MCP Debugger & Reverse Engineering Console
"""

import json
import os
import re
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs

# Force UTF-8 and unbuffered line output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", line_buffering=True)
    except AttributeError:
        pass

# Load environment variables
def load_env():
    for env_path in [Path(".env"), Path("config/.env")]:
        if env_path.exists():
            with open(env_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, val = line.partition("=")
                        os.environ.setdefault(key.strip(), val.strip())
            break

load_env()

from core.llm_client import create_llm_client
from core.orchestrator import create_orchestrator
from core.assessment_assistant import AssessmentAssistant
from core.skill_loader import skill_loader
from core.validation_gate import validation_gate
from core.chain_engine import chain_engine
from core.debugger_mcp import debugger_mcp
from core.docker_manager import docker_manager
from core.llm_redteam_engine import llm_redteam_engine
import threading

HTML_PAGE = """<!DOCTYPE html>
<html lang="tr" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoRedTeam — Otonom Pentest & Güvenlik Değerlendirme Kokpiti</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'Fira Code', monospace; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0c0d11; }
        ::-webkit-scrollbar-thumb { background: #252833; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #3b3f52; }
        .glass-panel { background: rgba(18, 20, 26, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.07); }
        .glow-red { box-shadow: 0 0 20px -5px rgba(239, 68, 68, 0.3); }
        .glow-purple { box-shadow: 0 0 20px -5px rgba(168, 85, 247, 0.3); }
        .glow-emerald { box-shadow: 0 0 20px -5px rgba(16, 185, 129, 0.3); }
    </style>
</head>
<body class="bg-[#090a0d] text-gray-200 h-screen flex flex-col overflow-hidden select-none">

    <!-- Top Master Header -->
    <header class="h-14 bg-[#101217] border-b border-[#1f222b] px-6 flex items-center justify-between shrink-0 z-20">
        <div class="flex items-center gap-3">
            <div class="w-9 h-9 rounded-xl bg-gradient-to-br from-red-600 via-amber-600 to-red-800 flex items-center justify-center font-bold text-lg text-white shadow-lg glow-red">
                🛡️
            </div>
            <div>
                <div class="flex items-center gap-2">
                    <h1 class="font-extrabold text-sm tracking-wide text-gray-100 flex items-center gap-2">
                        AutoRedTeam <span class="text-[10px] font-semibold text-amber-400 bg-amber-950/80 px-2 py-0.5 rounded border border-amber-800/70 font-mono tracking-normal">v2.0 PRO</span>
                    </h1>
                    <span class="text-[11px] text-gray-500 font-mono">| Autonomous Dual-Model Pentest Cockpit</span>
                </div>
                <p class="text-[10px] text-gray-400">DeepSeek V4 Flash (Orchestrator) • CyberStrike 35B (Offensive Worker) • 818 Skills • 7-Gate Validation</p>
            </div>
        </div>

        <!-- Architecture Telemetry Badges -->
        <div class="flex items-center gap-2.5 text-xs">
            <div class="flex items-center gap-2 bg-[#161820] border border-[#272a36] px-3 py-1 rounded-lg">
                <span class="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span>
                <span class="text-gray-400 text-[11px]">Orchestrator:</span>
                <span class="font-bold text-purple-300 font-mono text-[11px]">DeepSeek V4 Flash</span>
            </div>
            <div class="flex items-center gap-2 bg-[#161820] border border-[#272a36] px-3 py-1 rounded-lg">
                <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span class="text-gray-400 text-[11px]">Worker:</span>
                <span class="font-bold text-emerald-300 font-mono text-[11px]">CyberStrike 35B</span>
            </div>
            <div class="flex items-center gap-2 bg-[#161820] border border-[#272a36] px-3 py-1 rounded-lg">
                <span class="w-2 h-2 rounded-full bg-cyan-400"></span>
                <span class="text-gray-400 text-[11px]">Skills:</span>
                <span id="header-skills-badge" class="font-bold text-cyan-300 font-mono text-[11px]">818 Loaded</span>
            </div>
            <div class="flex items-center gap-2 bg-[#161820] border border-[#272a36] px-3 py-1 rounded-lg">
                <span class="w-2 h-2 rounded-full bg-amber-400"></span>
                <span class="text-gray-400 text-[11px]">7-Question Gate:</span>
                <span class="font-bold text-amber-300 font-mono text-[11px]">Active</span>
            </div>
        </div>
    </header>

    <!-- Navigation & Control Strip -->
    <div class="bg-[#12141a] border-b border-[#1f222b] px-6 py-2 flex items-center justify-between shrink-0 text-xs">
        
        <!-- Left: Target and Options -->
        <div class="flex items-center gap-4">
            <div class="flex items-center gap-2">
                <label class="text-gray-400 font-semibold text-[11px]">Hedef Sistem:</label>
                <select id="target-select" class="bg-[#191b22] text-gray-200 border border-[#2a2e3b] rounded-lg px-3 py-1.5 focus:outline-none focus:border-amber-500 font-mono text-xs">
                    <option value="metasploitable2" selected>🎯 Metasploitable2 (Network & Servis Katmanı)</option>
                    <option value="localhost:3000">🛍️ OWASP Juice Shop (Web & API Katmanı)</option>
                </select>
            </div>

            <div class="flex items-center gap-2">
                <label class="text-gray-400 font-semibold text-[11px]">Maks. Adım:</label>
                <select id="steps-select" class="bg-[#191b22] text-gray-200 border border-[#2a2e3b] rounded-lg px-3 py-1.5 font-mono text-xs">
                    <option value="8">8 Adım (Hızlı)</option>
                    <option value="12">12 Adım</option>
                    <option value="16" selected>16 Adım (Önerilen)</option>
                    <option value="24">24 Adım</option>
                    <option value="32">32 Adım (Derinlemesine)</option>
                    <option value="50">50 Adım (Genişletilmiş)</option>
                    <option value="70">70 Adım (Tam Sızma / Bütün Zafiyetler)</option>
                </select>
            </div>

            <!-- Operational Metrics -->
            <div class="flex items-center gap-4 pl-4 border-l border-[#242733] text-[11px]">
                <div><span class="text-gray-400">Adım:</span> <span id="stat-step" class="font-bold text-amber-400 font-mono">0 / 0</span></div>
                <div><span class="text-gray-400">Doğrulanan:</span> <span id="stat-findings" class="font-bold text-emerald-400 font-mono">0</span></div>
                <div><span class="text-gray-400">Elenen Fluff:</span> <span id="stat-filtered" class="font-bold text-red-400 font-mono">0</span></div>
                <div><span class="text-gray-400">Aktif Zincir:</span> <span id="stat-chains" class="font-bold text-purple-400 font-mono">0</span></div>
            </div>
        </div>

        <!-- Center: Tab Switchers -->
        <div class="flex items-center bg-[#0d0e12] p-1 rounded-xl border border-[#222530]">
            <button onclick="switchTab('tab-live')" id="btn-tab-live" class="tab-btn px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#222531] text-amber-400 shadow transition flex items-center gap-1.5">
                <span>🎯</span> Canlı Pentest Kokpiti
            </button>
            <button onclick="switchTab('tab-skills')" id="btn-tab-skills" class="tab-btn px-3 py-1.5 rounded-lg text-xs font-medium text-gray-400 hover:text-gray-200 transition flex items-center gap-1.5">
                <span>📚</span> 818 Siber Yetenek
            </button>
            <button onclick="switchTab('tab-gate')" id="btn-tab-gate" class="tab-btn px-3 py-1.5 rounded-lg text-xs font-medium text-gray-400 hover:text-gray-200 transition flex items-center gap-1.5">
                <span>🛡️</span> Doğrulama Kapısı
            </button>
            <button onclick="switchTab('tab-chains')" id="btn-tab-chains" class="tab-btn px-3 py-1.5 rounded-lg text-xs font-medium text-gray-400 hover:text-gray-200 transition flex items-center gap-1.5">
                <span>🔗</span> Exploit Zincirleri
            </button>
            <button onclick="switchTab('tab-debugger')" id="btn-tab-debugger" class="tab-btn px-3 py-1.5 rounded-lg text-xs font-medium text-gray-400 hover:text-gray-200 transition flex items-center gap-1.5">
                <span>🔬</span> x64dbg MCP
            </button>
        </div>

        <!-- Right: Action Buttons -->
        <div class="flex items-center gap-2.5">
            <label class="flex items-center gap-2 cursor-pointer select-none" title="Otonom modda her adım onaysız çalışır (yalnızca izole test ortamında)">
                <span class="text-gray-400 font-semibold text-[11px]">Otonom Mod</span>
                <input type="checkbox" id="autonomous-toggle" checked class="w-4 h-4 accent-red-600 cursor-pointer">
            </label>
            <button id="btn-start" onclick="startAssessment()" class="bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white font-semibold px-4 py-1.5 rounded-lg shadow-lg glow-red transition flex items-center gap-1.5 text-xs">
                <span>▶</span> Başlat
            </button>
            <button id="btn-stop" onclick="stopAssessment()" disabled class="bg-[#1c1e26] text-gray-400 hover:text-gray-200 px-3.5 py-1.5 rounded-lg border border-[#2a2e3b] transition disabled:opacity-40 text-xs">
                ⏹ Durdur
            </button>
            <button id="btn-report" onclick="viewReport()" class="bg-[#191b22] text-cyan-300 hover:bg-[#252833] px-3.5 py-1.5 rounded-lg border border-cyan-800/70 transition flex items-center gap-1.5 text-xs">
                📄 Rapor
            </button>
        </div>
    </div>

    <!-- Main Workspace Body (Tab Content Area) -->
    <div class="flex-1 overflow-hidden relative">

        <!-- ============================================================== -->
        <!-- TAB 1: CANLI PENTEST KOKPİTİ (3-COLUMN DUAL MODEL ENGINE)      -->
        <!-- ============================================================== -->
        <div id="tab-live" class="tab-pane h-full grid grid-cols-12 divide-x divide-[#1e212b] overflow-hidden">
            
            <!-- Left: Decision Chain & Strategy (5 cols) -->
            <div class="col-span-5 flex flex-col h-full overflow-hidden bg-[#0c0d12]">
                <div class="p-3 px-4 bg-[#12141a] border-b border-[#1f222b] flex items-center justify-between shrink-0">
                    <div class="flex items-center gap-2">
                        <span class="w-2.5 h-2.5 rounded-full bg-purple-500 animate-pulse"></span>
                        <span class="font-bold text-xs text-purple-300 tracking-wide uppercase font-mono">Karar Zinciri & Model Akıl Yürütmesi</span>
                    </div>
                    <span class="text-[10px] text-gray-400 font-mono bg-purple-950/60 border border-purple-800/50 px-2 py-0.5 rounded">DeepSeek V4 Flash ➔ CyberStrike</span>
                </div>

                <div id="decision-feed" class="flex-1 overflow-y-auto p-4 space-y-4 text-xs select-text">
                    <div class="text-center text-gray-500 my-20">
                        <div class="text-3xl mb-2">🎯</div>
                        <div class="font-medium text-gray-300">Pentest Kokpiti Hazır</div>
                        <div class="text-gray-500 text-[11px] mt-1">Başlat butonuna tıkladığınızda modellerin stratejik direktifleri ve taktiksel JSON kararları burada canlı akacaktır.</div>
                    </div>
                </div>
            </div>

            <!-- Center: Live Security Terminal (4 cols) -->
            <div class="col-span-4 flex flex-col h-full overflow-hidden bg-[#08090c]">
                <div class="p-3 px-4 bg-[#101217] border-b border-[#1f222b] flex items-center justify-between shrink-0">
                    <div class="flex items-center gap-2">
                        <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                        <span class="font-bold text-xs text-emerald-300 tracking-wide uppercase font-mono">Canlı Güvenlik Terminali</span>
                    </div>
                    <span class="text-[10px] text-gray-400 font-mono">Docker assessment-net</span>
                </div>

                <!-- Terminal filter chips -->
                <div class="bg-[#0b0c10] border-b border-[#1b1d26] px-3 py-1.5 flex items-center gap-1.5 text-[10px] font-mono text-gray-400 shrink-0">
                    <span class="text-gray-500">Filtre:</span>
                    <button class="px-2 py-0.5 rounded bg-[#1e212b] text-emerald-300 font-semibold">Tümü</button>
                    <button class="px-2 py-0.5 rounded hover:bg-[#1e212b] text-gray-400">Nmap</button>
                    <button class="px-2 py-0.5 rounded hover:bg-[#1e212b] text-gray-400">Searchsploit</button>
                    <button class="px-2 py-0.5 rounded hover:bg-[#1e212b] text-gray-400">CVE NVD</button>
                    <button class="px-2 py-0.5 rounded hover:bg-[#1e212b] text-gray-400">Nikto/SQLi</button>
                </div>

                <div id="terminal-feed" class="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-[11px] leading-relaxed text-gray-300 select-text bg-[#06070a]">
                    <div class="text-gray-600">// Güvenlik araçlarının (nmap, searchsploit, nikto, cve_search) anlık konsol çıktıları burada akacaktır.</div>
                </div>
            </div>

            <!-- Right: Live Findings Board (3 cols) -->
            <div class="col-span-3 flex flex-col h-full overflow-hidden bg-[#0a0b0f]">
                <div class="p-3 px-4 bg-[#12141a] border-b border-[#1f222b] flex items-center justify-between shrink-0">
                    <div class="flex items-center gap-2">
                        <span class="w-2.5 h-2.5 rounded-full bg-red-500"></span>
                        <span class="font-bold text-xs text-red-400 tracking-wide uppercase font-mono">Doğrulanan Bulgular</span>
                    </div>
                    <span id="findings-count-badge" class="text-[10px] text-red-300 bg-red-950/80 px-2.5 py-0.5 rounded border border-red-800 font-mono font-bold">0 Bulgu</span>
                </div>

                <div id="findings-board" class="flex-1 overflow-y-auto p-3 space-y-3 text-xs select-text">
                    <div class="text-center text-gray-500 my-20">
                        <div class="text-3xl mb-2">📌</div>
                        <div class="font-medium text-gray-300">Doğrulanmış Zafiyet Yok</div>
                        <div class="text-gray-500 text-[11px] mt-1">7-Question Validation Gate'ten başarıyla geçen bulgular burada listelenecektir.</div>
                    </div>
                </div>
            </div>

        </div>

        <!-- ============================================================== -->
        <!-- TAB 2: 818 SİBER GÜVENLİK YETENEĞİ (SKILLS KNOWLEDGE BASE)      -->
        <!-- ============================================================== -->
        <div id="tab-skills" class="tab-pane h-full hidden flex flex-col bg-[#0b0c10] overflow-hidden p-6">
            <div class="flex items-center justify-between mb-4 shrink-0">
                <div>
                    <h2 class="text-base font-bold text-gray-100 flex items-center gap-2">
                        <span>📚</span> 818 Yapılandırılmış Siber Güvenlik Yeteneği (Playbooks)
                    </h2>
                    <p class="text-xs text-gray-400">Anthropic Cybersecurity Skills standardı (MITRE ATT&CK v19.1, NIST CSF 2.0 ve ATLAS eşlemeleri)</p>
                </div>

                <div class="flex items-center gap-3">
                    <input type="text" id="skills-search-input" oninput="searchSkillsLive()" placeholder="Yetenek ara (örn: sqli, kerberos, bola, ssrf)..." class="bg-[#161820] border border-[#292d3a] rounded-lg px-4 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-cyan-500 w-80 font-mono">
                    <select id="skills-domain-filter" onchange="searchSkillsLive()" class="bg-[#161820] border border-[#292d3a] rounded-lg px-3 py-1.5 text-xs text-gray-200 font-mono">
                        <option value="all">Tüm Alanlar (29 Domain)</option>
                        <option value="security-operations">Security Operations</option>
                        <option value="threat-intelligence">Threat Intelligence</option>
                        <option value="cloud-security">Cloud Security</option>
                        <option value="application-security">Application Security</option>
                    </select>
                </div>
            </div>

            <!-- Matched target banner -->
            <div id="target-skills-banner" class="bg-gradient-to-r from-cyan-950/40 via-[#101924] to-[#12141a] border border-cyan-800/60 rounded-xl p-3.5 mb-4 shrink-0 flex items-center justify-between text-xs">
                <div class="flex items-center gap-3">
                    <span class="text-cyan-400 text-lg">⚡</span>
                    <div>
                        <span class="font-bold text-cyan-300">Hedef İçin Dinamik Önerilen Playbook'lar:</span>
                        <span id="target-skills-names" class="text-gray-300 font-mono ml-2">Taramaya göre otomatik eşlenmektedir...</span>
                    </div>
                </div>
                <span class="text-[10px] text-cyan-400 font-mono bg-cyan-950 border border-cyan-800 px-2 py-0.5 rounded">Progresif Yükleme (~30 token)</span>
            </div>

            <!-- Skills Cards Grid -->
            <div id="skills-grid" class="flex-1 overflow-y-auto grid grid-cols-3 gap-3 pr-2">
                <div class="text-gray-500 col-span-3 text-center my-20">Yetenekler yükleniyor...</div>
            </div>
        </div>

        <!-- ============================================================== -->
        <!-- TAB 3: 7 SORULUK DOĞRULAMA KAPISI (VALIDATION GATE AUDIT)       -->
        <!-- ============================================================== -->
        <div id="tab-gate" class="tab-pane h-full hidden flex flex-col bg-[#0b0c10] overflow-hidden p-6">
            <div class="flex items-center justify-between mb-4 shrink-0">
                <div>
                    <h2 class="text-base font-bold text-gray-100 flex items-center gap-2">
                        <span>🛡️</span> 7-Question Validation Gate & Anti-Hallucination Denetimi
                    </h2>
                    <p class="text-xs text-gray-400">Modelin sahte bulguları (false positive / fluff) ve kanıtsız iddiaları rapora sokmasını engelleyen kurallar</p>
                </div>
                <div class="flex items-center gap-3 text-xs font-mono">
                    <span class="bg-emerald-950/80 border border-emerald-800 text-emerald-300 px-3 py-1 rounded-lg">Geçen: <strong id="gate-stat-pass">0</strong></span>
                    <span class="bg-red-950/80 border border-red-800 text-red-300 px-3 py-1 rounded-lg">Anında Ret (Instant Kill): <strong id="gate-stat-kill">0</strong></span>
                    <span class="bg-amber-950/80 border border-amber-800 text-amber-300 px-3 py-1 rounded-lg">Zincir Gereken: <strong id="gate-stat-chain">0</strong></span>
                </div>
            </div>

            <!-- 7 Gate Questions Checklist -->
            <div class="grid grid-cols-7 gap-2 mb-4 shrink-0 text-[11px] font-mono">
                <div class="bg-[#14161f] border border-[#252838] p-2.5 rounded-lg text-center"><span class="text-amber-400 font-bold">1. Kanıt</span><br><span class="text-gray-400 text-[9px]">Boş kanıt ret</span></div>
                <div class="bg-[#14161f] border border-[#252838] p-2.5 rounded-lg text-center"><span class="text-amber-400 font-bold">2. Fluff</span><br><span class="text-gray-400 text-[9px]">CSP/HSTS tek başına ret</span></div>
                <div class="bg-[#14161f] border border-[#252838] p-2.5 rounded-lg text-center"><span class="text-amber-400 font-bold">3. Banner</span><br><span class="text-gray-400 text-[9px]">CVE'siz banner ret</span></div>
                <div class="bg-[#14161f] border border-[#252838] p-2.5 rounded-lg text-center"><span class="text-amber-400 font-bold">4. Redirect</span><br><span class="text-gray-400 text-[9px]">Zincirsiz redirect ret</span></div>
                <div class="bg-[#14161f] border border-[#252838] p-2.5 rounded-lg text-center"><span class="text-amber-400 font-bold">5. Spekülasyon</span><br><span class="text-gray-400 text-[9px]">'Olabilir' dili ret</span></div>
                <div class="bg-[#14161f] border border-[#252838] p-2.5 rounded-lg text-center"><span class="text-amber-400 font-bold">6. Kapsam</span><br><span class="text-gray-400 text-[9px]">Hedef scope kontrolü</span></div>
                <div class="bg-[#14161f] border border-[#252838] p-2.5 rounded-lg text-center"><span class="text-amber-400 font-bold">7. Etki</span><br><span class="text-gray-400 text-[9px]">Gerçek etki PoC</span></div>
            </div>

            <!-- Gate Events Feed -->
            <div class="flex-1 bg-[#101217] border border-[#20232e] rounded-xl p-4 overflow-y-auto space-y-3" id="gate-events-feed">
                <div class="text-gray-500 text-center my-20 text-xs">
                    <div class="text-2xl mb-1">🛡️</div>
                    <div>Henüz bir bulgu önerisi doğrulanmadı.</div>
                    <div class="text-[11px] text-gray-600">Model bulgu ürettikçe doğrulama veya anında ret kararları buraya anlık loglanacaktır.</div>
                </div>
            </div>
        </div>

        <!-- ============================================================== -->
        <!-- TAB 4: EXPLOIT ZİNCİRLEME HARİTASI (CHAIN WALK ENGINE)         -->
        <!-- ============================================================== -->
        <div id="tab-chains" class="tab-pane h-full hidden flex flex-col bg-[#0b0c10] overflow-hidden p-6">
            <div class="flex items-center justify-between mb-4 shrink-0">
                <div>
                    <h2 class="text-base font-bold text-gray-100 flex items-center gap-2">
                        <span>🔗</span> Exploit Zincirleme & Saldırı Grafı (Chain Walk Engine)
                    </h2>
                    <p class="text-xs text-gray-400">Tekil zafiyetleri birleştirerek kritik sisteme sızma zinciri oluşturan pentest-agents algoritması</p>
                </div>
                <span class="bg-purple-950/80 border border-purple-800 text-purple-300 px-3 py-1 rounded-lg text-xs font-mono">Capability A ➔ Capability B ➔ Terminal Impact</span>
            </div>

            <div id="chains-container" class="flex-1 overflow-y-auto space-y-4">
                <div class="text-gray-500 text-center my-20 text-xs">
                    <div class="text-3xl mb-2">🔗</div>
                    <div class="font-medium text-gray-300">Aktif İstismar Zinciri Bekleniyor</div>
                    <div class="text-gray-500 text-[11px] mt-1">Keşfedilen ilk dayanak (foothold) ve zafiyetler birbirine bağlanarak burada görselleştirilecektir.</div>
                </div>
            </div>
        </div>

        <!-- ============================================================== -->
        <!-- TAB 5: x64dbg TERSİNE MÜHENDİSLİK & MCP DEBUGGER PANELİ        -->
        <!-- ============================================================== -->
        <div id="tab-debugger" class="tab-pane h-full hidden flex flex-col bg-[#0b0c10] overflow-hidden p-6">
            <div class="flex items-center justify-between mb-4 shrink-0">
                <div>
                    <h2 class="text-base font-bold text-gray-100 flex items-center gap-2">
                        <span>🔬</span> x64dbg Hata Ayıklayıcı & Tersine Mühendislik (MCP Sunucusu)
                    </h2>
                    <p class="text-xs text-gray-400">duty1g/x64dbg-mcp-server mimarisi — 72 MCP Aracı (Bellek, Register, Disasm, Breakpoints)</p>
                </div>
                <div class="flex items-center gap-2 text-xs font-mono">
                    <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                    <span class="text-cyan-300 bg-cyan-950/80 border border-cyan-800 px-3 py-1 rounded-lg">Streamable HTTP: 127.0.0.1:9094/mcp</span>
                </div>
            </div>

            <div class="grid grid-cols-12 gap-4 flex-1 overflow-hidden">
                <!-- Left: CPU Registers (4 cols) -->
                <div class="col-span-4 bg-[#111319] border border-[#212430] rounded-xl p-4 flex flex-col overflow-hidden">
                    <div class="flex items-center justify-between pb-3 border-b border-[#212430] mb-3">
                        <span class="text-xs font-bold text-cyan-300 font-mono">CPU Registers (x64)</span>
                        <button onclick="refreshDebuggerData()" class="text-[10px] bg-[#1a1d27] text-gray-300 hover:text-white px-2 py-0.5 rounded border border-[#2f3344] font-mono">Yenile</button>
                    </div>
                    <div id="debugger-registers" class="flex-1 overflow-y-auto space-y-1.5 font-mono text-xs text-gray-300">
                        <div class="text-gray-500">Register değerleri yükleniyor...</div>
                    </div>
                </div>

                <!-- Center: Disassembly View (5 cols) -->
                <div class="col-span-5 bg-[#090a0d] border border-[#1e202b] rounded-xl p-4 flex flex-col overflow-hidden font-mono">
                    <div class="flex items-center justify-between pb-3 border-b border-[#1e202b] mb-3">
                        <span class="text-xs font-bold text-emerald-300">Canlı Ayrıştırma (Disassembly)</span>
                        <span class="text-[10px] text-gray-500">RIP: 0x7FF7ABCD1050</span>
                    </div>
                    <div id="debugger-disasm" class="flex-1 overflow-y-auto space-y-1 text-xs text-gray-300">
                        <div class="text-gray-500">Assembly komutları yükleniyor...</div>
                    </div>
                </div>

                <!-- Right: Tool Controls & OEP (3 cols) -->
                <div class="col-span-3 bg-[#111319] border border-[#212430] rounded-xl p-4 flex flex-col overflow-hidden text-xs">
                    <span class="font-bold text-amber-400 font-mono mb-3">MCP Debugger Yetenekleri (72 Araç)</span>
                    <div class="space-y-2 text-[11px] text-gray-300">
                        <div class="bg-[#171a24] p-2.5 rounded-lg border border-[#282c3d]">
                            <div class="font-semibold text-gray-200">🔍 OEP Tespiti (Packer Analizi)</div>
                            <div class="text-gray-400 text-[10px] mt-0.5">Tespit: <span class="text-emerald-400 font-mono">0x7FF7ABCD1000 (Unpacked)</span></div>
                        </div>
                        <div class="bg-[#171a24] p-2.5 rounded-lg border border-[#282c3d]">
                            <div class="font-semibold text-gray-200">🛑 Breakpoint Yöneticisi</div>
                            <div class="text-gray-400 text-[10px] mt-0.5">Yazılım ve Donanım Kesme Noktaları hazır.</div>
                        </div>
                        <div class="bg-[#171a24] p-2.5 rounded-lg border border-[#282c3d]">
                            <div class="font-semibold text-gray-200">💾 Bellek Dökümü (Memory Hex)</div>
                            <div class="text-gray-400 text-[10px] mt-0.5">Payload & Buffer Overflow denetimi aktif.</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <!-- Status Bar Footer -->
    <footer class="h-8 bg-[#0e1014] border-t border-[#1f222b] px-6 flex items-center justify-between text-[11px] text-gray-400 shrink-0 font-mono">
        <div class="flex items-center gap-2">
            <span id="status-dot" class="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span id="status-text" class="text-gray-300">Sistem hazır. Modeller ve tüm araçlar senkronize.</span>
        </div>
        <div class="text-gray-500 text-[10px] flex items-center gap-3">
            <span>SGLang RadixAttention</span>
            <span>•</span>
            <span>MITRE ATT&CK & ATLAS</span>
            <span>•</span>
            <span>AutoRedTeam Pro Cockpit</span>
        </div>
    </footer>

    <!-- Report Modal -->
    <div id="report-modal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-6">
        <div class="bg-[#12141a] border border-[#2b2f3d] rounded-2xl w-full max-w-4xl h-[85vh] flex flex-col overflow-hidden shadow-2xl">
            <div class="p-4 bg-[#171922] border-b border-[#2b2f3d] flex items-center justify-between shrink-0">
                <h3 class="font-bold text-sm text-gray-100 flex items-center gap-2">
                    📄 Kurumsal Güvenlik Değerlendirme Raporu (OWASP & MITRE Destekli)
                </h3>
                <button onclick="closeReport()" class="text-gray-400 hover:text-white px-3 py-1 rounded-lg bg-[#222533]">✕ Kapat</button>
            </div>
            <div id="report-content" class="flex-1 overflow-y-auto p-6 text-xs text-gray-300 prose prose-invert max-w-none select-text leading-relaxed">
                Rapor yükleniyor...
            </div>
        </div>
    </div>

    <!-- JavaScript Client Logic -->
    <script>
        let eventSource = null;
        let findingsList = [];
        let allSkills = [];

        function switchTab(tabId) {
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(el => {
                el.classList.remove('bg-[#222531]', 'text-amber-400', 'shadow');
                el.classList.add('text-gray-400');
            });

            document.getElementById(tabId).classList.remove('hidden');
            const activeBtn = document.getElementById('btn-' + tabId);
            if (activeBtn) {
                activeBtn.classList.add('bg-[#222531]', 'text-amber-400', 'shadow');
                activeBtn.classList.remove('text-gray-400');
            }

            if (tabId === 'tab-skills' && allSkills.length === 0) {
                loadAllSkills();
            } else if (tabId === 'tab-debugger') {
                refreshDebuggerData();
            }
        }

        function startAssessment() {
            const target = document.getElementById('target-select').value;
            const maxSteps = document.getElementById('steps-select').value;
            const autonomous = document.getElementById('autonomous-toggle').checked;

            document.getElementById('decision-feed').innerHTML = '';
            document.getElementById('terminal-feed').innerHTML = '';
            document.getElementById('findings-board').innerHTML = '';
            document.getElementById('gate-events-feed').innerHTML = '';
            document.getElementById('chains-container').innerHTML = '';
            findingsList = [];

            document.getElementById('btn-start').disabled = true;
            document.getElementById('btn-start').classList.add('opacity-40');
            document.getElementById('btn-stop').disabled = false;
            document.getElementById('status-dot').className = 'w-2 h-2 rounded-full bg-emerald-400 animate-pulse';
            document.getElementById('status-text').innerText = `Değerlendirme yürütülüyor: ${target} (${autonomous ? 'OTONOM' : 'Onaylı'} mod)...`;

            // Otonom mod kapaliysa interaktif (onayli) mod aktif olur
            const interactive = !autonomous;
            eventSource = new EventSource(`/api/stream?target=${encodeURIComponent(target)}&max_steps=${maxSteps}&autonomous=${autonomous}&interactive=${interactive}`);

            eventSource.onmessage = function(e) {
                const data = JSON.parse(e.data);

                if (data.type === 'step_plan') {
                    renderStepPlan(data);
                } else if (data.type === 'tool_exec') {
                    renderToolExecution(data);
                } else if (data.type === 'tool_output') {
                    renderToolOutput(data);
                } else if (data.type === 'finding') {
                    renderFinding(data);
                } else if (data.type === 'orchestrator_directive') {
                    renderOrchestratorDirective(data);
                } else if (data.type === 'gate_event') {
                    renderGateEvent(data);
                } else if (data.type === 'chain_update') {
                    renderChainUpdate(data);
                } else if (data.type === 'skills_matched') {
                    renderSkillsMatched(data);
                } else if (data.type === 'thinking_status') {
                    renderThinkingStatus(data);
                } else if (data.type === 'awaiting_approval') {
                    renderAwaitingApproval(data);
                } else if (data.type === 'error') {
                    renderError(data);
                } else if (data.type === 'complete') {
                    finishAssessment(data);
                }
            };

            eventSource.onerror = function(err) {
                console.error("SSE Error:", err);
                eventSource.close();
                document.getElementById('btn-start').disabled = false;
                document.getElementById('btn-start').classList.remove('opacity-40');
                document.getElementById('btn-stop').disabled = true;
                document.getElementById('status-dot').className = 'w-2 h-2 rounded-full bg-red-400';
                document.getElementById('status-text').innerText = 'Değerlendirme tamamlandı veya bağlantı sonlandı.';
            };
        }

        function stopAssessment() {
            if (eventSource) {
                eventSource.close();
                eventSource = null;
            }
            fetch('/api/stop', { method: 'POST' });
            document.getElementById('btn-start').disabled = false;
            document.getElementById('btn-start').classList.remove('opacity-40');
            document.getElementById('btn-stop').disabled = true;
            document.getElementById('status-dot').className = 'w-2 h-2 rounded-full bg-amber-400';
            document.getElementById('status-text').innerText = 'Değerlendirme kullanıcı tarafından durduruldu.';
        }

        function renderOrchestratorDirective(data) {
            const feed = document.getElementById('decision-feed');
            const card = document.createElement('div');
            card.className = "bg-gradient-to-r from-purple-950/50 to-[#191626] border border-purple-800/70 rounded-xl p-4 shadow-lg glow-purple";
            card.innerHTML = `
                <div class="flex items-center justify-between mb-2">
                    <span class="text-xs bg-purple-900/90 text-purple-200 font-bold px-2.5 py-0.5 rounded-md font-mono">🧠 DEEPSEEK V4 FLASH STRATEJİ DİREKTİFİ</span>
                    <span class="text-[10px] text-gray-400 font-mono">Adım ${data.step}</span>
                </div>
                <div class="text-purple-200 text-xs leading-relaxed whitespace-pre-wrap">${escapeHtml(data.directive)}</div>
            `;
            feed.appendChild(card);
            feed.scrollTop = feed.scrollHeight;
        }

        function renderThinkingStatus(data) {
            const dot = document.getElementById('status-dot');
            const text = document.getElementById('status-text');
            if (dot) dot.className = 'w-2 h-2 rounded-full bg-cyan-400 animate-pulse';
            if (text) text.innerText = data.message || 'Model sonraki adımı analiz ediyor...';
            if (data.step) {
                const stepsSel = document.getElementById('steps-select');
                const maxSteps = stepsSel ? stepsSel.value : '16';
                document.getElementById('stat-step').innerText = `${data.step} / ${maxSteps}`;
            }
        }

        function renderStepPlan(data) {
            document.getElementById('stat-step').innerText = `${data.step} / ${data.max_steps}`;

            const feed = document.getElementById('decision-feed');
            const card = document.createElement('div');
            card.className = "bg-[#14161f] border border-[#252838] rounded-xl p-3.5 shadow-md";

            let badge = "bg-blue-900/80 text-blue-300 border-blue-800";
            if (data.tool === 'nmap') badge = "bg-amber-900/80 text-amber-300 border-amber-800";
            if (data.tool === 'searchsploit') badge = "bg-red-900/80 text-red-300 border-red-800";
            if (data.tool === 'cve_search' || data.tool === 'web_search') badge = "bg-cyan-900/80 text-cyan-300 border-cyan-800";
            if (data.tool === 'nikto' || data.tool === 'sqlmap') badge = "bg-emerald-900/80 text-emerald-300 border-emerald-800";
            if (data.tool === 'debugger') badge = "bg-purple-900/80 text-purple-300 border-purple-800";
            if (data.tool === 'exploit') badge = "bg-red-900/90 text-red-300 border-red-700 glow-red";
            if (data.tool === 'privesc') badge = "bg-orange-900/90 text-orange-300 border-orange-700";

            // Show the specific exploit/privesc technique name
            let toolLabel = data.tool.toUpperCase();
            if (data.exploit) toolLabel = `EXPLOIT: ${data.exploit.toUpperCase()}`;
            if (data.privesc) toolLabel = `PRIVESC: ${data.privesc.toUpperCase()}`;

            // Extra detail line for exploit/privesc
            let extraDetail = '';
            if (data.exploit || data.privesc) {
                extraDetail = `<div class="mt-1.5 text-[10px] font-mono text-red-400/80 bg-red-950/30 border border-red-900/40 rounded px-2 py-1">⚠️ AKTİF SÖMÜRÜ / YETKİ YÜKSELTME ADIMI${data.username ? ' — SSH: ' + escapeHtml(data.username) : ''}</div>`;
            }

            card.innerHTML = `
                <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center gap-2">
                        <span class="font-bold text-amber-400 font-mono text-xs">Adım ${data.step}</span>
                        <span class="px-2 py-0.5 rounded border text-[11px] font-mono font-semibold ${badge}">🔧 ${toolLabel}</span>
                    </div>
                    <span class="text-[10px] text-gray-500 font-mono">${data.target}</span>
                </div>
                <div class="text-gray-200 mb-1.5 leading-relaxed text-xs"><strong class="text-gray-400 font-mono">Düşünce:</strong> ${escapeHtml(data.thought || '')}</div>
                <div class="text-gray-400 text-[11px] leading-relaxed"><strong class="text-gray-500 font-mono">Gerekçe:</strong> ${escapeHtml(data.rationale || '')}</div>
                ${extraDetail}
            `;
            feed.appendChild(card);
            feed.scrollTop = feed.scrollHeight;
        }

        function renderToolExecution(data) {
            const feed = document.getElementById('terminal-feed');
            const block = document.createElement('div');
            block.className = "border-l-2 border-emerald-500 pl-3 py-1";
            // Exploit/privesc success indicator
            let statusIcon = '';
            if (data.tool === 'exploit' || data.tool === 'privesc') {
                if (data.success) {
                    block.className = "border-l-2 border-red-500 bg-red-950/20 pl-3 py-1 rounded";
                    statusIcon = '<span class="text-red-400 font-bold">✅ BAŞARILI</span>';
                } else {
                    block.className = "border-l-2 border-orange-500 bg-orange-950/10 pl-3 py-1 rounded";
                    statusIcon = '<span class="text-orange-400 font-bold">⚠️ DENENDİ</span>';
                }
            }
            block.innerHTML = `
                <div class="text-[10px] text-gray-500 flex items-center gap-2">
                    <span>[Adım ${data.step}] Komut İcrası</span>
                    <span class="text-emerald-400 font-bold">${data.tool}</span>
                    ${statusIcon}
                </div>
                <div class="text-emerald-400 font-mono text-xs font-semibold">$ ${escapeHtml(data.command)}</div>
            `;
            feed.appendChild(block);
            feed.scrollTop = feed.scrollHeight;
        }

        function renderToolOutput(data) {
            const feed = document.getElementById('terminal-feed');
            const block = document.createElement('pre');
            let borderColor = "border-[#1f222c]";
            if (data.tool === 'exploit' || data.tool === 'privesc') {
                borderColor = data.success ? "border-red-700 bg-red-950/10" : "border-orange-800 bg-orange-950/5";
            }
            block.className = `bg-[#090a0d] border ${borderColor} rounded-lg p-3 text-[11px] text-gray-300 whitespace-pre-wrap overflow-x-auto leading-relaxed`;
            block.innerText = data.output;
            feed.appendChild(block);
            feed.scrollTop = feed.scrollHeight;
        }

        function renderFinding(data) {
            findingsList.push(data);
            document.getElementById('stat-findings').innerText = findingsList.length;
            document.getElementById('findings-count-badge').innerText = `${findingsList.length} Bulgu`;

            const board = document.getElementById('findings-board');
            if (findingsList.length === 1) board.innerHTML = '';

            let sevColor = "border-amber-700 bg-amber-950/40 text-amber-400";
            if (data.severity === 'Critical') sevColor = "border-red-700 bg-red-950/60 text-red-400";
            if (data.severity === 'High') sevColor = "border-orange-700 bg-orange-950/50 text-orange-400";

            const card = document.createElement('div');
            card.className = `border ${sevColor} rounded-xl p-3 shadow-md transition hover:border-gray-400`;
            card.innerHTML = `
                <div class="flex items-center justify-between mb-1.5">
                    <span class="font-bold text-xs">${escapeHtml(data.category)}</span>
                    <span class="text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase bg-black/40 border border-current">${data.severity}</span>
                </div>
                <div class="text-[10px] text-gray-400 font-mono mb-2 flex items-center gap-2">
                    <span>${data.finding_id}</span>
                    <span>•</span>
                    <span>${data.cwe_reference || 'CWE'}</span>
                    <span>•</span>
                    <span class="text-emerald-400">✓ Gate: Onaylandı</span>
                </div>
                <div class="bg-black/50 p-2 rounded text-[10px] font-mono text-gray-300 overflow-hidden text-ellipsis">${escapeHtml(data.evidence_snippet || '')}</div>
            `;
            board.appendChild(card);
            board.scrollTop = board.scrollHeight;
        }

        function renderGateEvent(data) {
            const feed = document.getElementById('gate-events-feed');
            const item = document.createElement('div');

            if (data.status === 'PASSED') {
                const passCount = parseInt(document.getElementById('gate-stat-pass').innerText) + 1;
                document.getElementById('gate-stat-pass').innerText = passCount;
                item.className = "bg-emerald-950/30 border border-emerald-800/70 p-3 rounded-xl flex items-start gap-3 text-xs";
                item.innerHTML = `
                    <span class="text-emerald-400 text-lg">✅</span>
                    <div class="flex-1">
                        <div class="flex items-center justify-between">
                            <span class="font-bold text-emerald-300">${escapeHtml(data.finding.category)} (${data.finding.severity})</span>
                            <span class="text-[10px] font-mono text-emerald-400 font-semibold">ONAYLANDI</span>
                        </div>
                        <div class="text-gray-300 text-[11px] mt-1">${escapeHtml(data.reason)}</div>
                    </div>
                `;
            } else {
                const killCount = parseInt(document.getElementById('gate-stat-kill').innerText) + 1;
                document.getElementById('gate-stat-kill').innerText = killCount;
                document.getElementById('stat-filtered').innerText = killCount;
                item.className = "bg-red-950/30 border border-red-800/70 p-3 rounded-xl flex items-start gap-3 text-xs";
                item.innerHTML = `
                    <span class="text-red-400 text-lg">🚫</span>
                    <div class="flex-1">
                        <div class="flex items-center justify-between">
                            <span class="font-bold text-red-300">Öneri Reddedildi: ${escapeHtml(data.finding.category)}</span>
                            <span class="text-[10px] font-mono text-red-400 font-semibold">${data.rule || 'INSTANT-KILL'}</span>
                        </div>
                        <div class="text-gray-300 text-[11px] mt-1">${escapeHtml(data.reason)}</div>
                    </div>
                `;
            }
            feed.appendChild(item);
        }

        function renderChainUpdate(data) {
            const container = document.getElementById('chains-container');
            const chains = data.chains || [];
            document.getElementById('stat-chains').innerText = chains.length;

            if (chains.length === 0) return;
            container.innerHTML = '';

            chains.forEach(chain => {
                const card = document.createElement('div');
                card.className = "bg-gradient-to-r from-purple-950/40 via-[#151722] to-[#12141a] border border-purple-800/70 rounded-2xl p-5 shadow-xl";
                
                let stepsHtml = '';
                (chain.steps || []).forEach(step => {
                    stepsHtml += `
                        <div class="flex items-start gap-3 relative pb-4 last:pb-0">
                            <div class="w-6 h-6 rounded-full bg-purple-900 border border-purple-600 flex items-center justify-center font-bold text-xs text-purple-200 shrink-0">
                                ${step.step}
                            </div>
                            <div class="flex-1">
                                <div class="font-semibold text-xs text-gray-200">${escapeHtml(step.phase || '')}</div>
                                <div class="text-[11px] text-gray-400 font-mono mt-0.5">${escapeHtml(step.detail || step.impact || '')}</div>
                            </div>
                        </div>
                    `;
                });

                card.innerHTML = `
                    <div class="flex items-center justify-between mb-4 border-b border-purple-800/40 pb-3">
                        <h3 class="font-bold text-sm text-purple-200 flex items-center gap-2">
                            <span>🔗</span> ${escapeHtml(chain.title)}
                        </h3>
                        <span class="text-xs font-mono font-bold bg-red-950 text-red-300 border border-red-800 px-2.5 py-0.5 rounded">${chain.severity}</span>
                    </div>
                    <div class="space-y-2 border-l border-purple-800/50 ml-3 pl-4">
                        ${stepsHtml}
                    </div>
                `;
                container.appendChild(card);
            });
        }

        function renderSkillsMatched(data) {
            const skills = data.skills || [];
            if (skills.length > 0) {
                const names = skills.map(s => `[${s.name}]`).join(' • ');
                document.getElementById('target-skills-names').innerText = names;
            }
        }

        function renderAwaitingApproval(data) {
            // Interactive modda her adim icin onay kutusu goster
            const feed = document.getElementById('decision-feed');
            const card = document.createElement('div');
            card.className = "bg-amber-950/30 border border-amber-700/70 rounded-xl p-3.5 shadow-md";
            card.innerHTML = `
                <div class="flex items-center justify-between mb-2">
                    <span class="text-xs bg-amber-900/80 text-amber-200 font-bold px-2.5 py-0.5 rounded-md font-mono">⏳ ONAY BEKLENİYOR</span>
                    <span class="text-[10px] text-gray-400 font-mono">Adım ${data.step}</span>
                </div>
                <div class="text-gray-200 text-xs mb-2"><strong class="text-gray-400 font-mono">Araç:</strong> ${escapeHtml(data.tool)}</div>
                <div class="text-gray-400 text-[11px] mb-3">${escapeHtml(data.rationale || '')}</div>
                <div class="flex items-center gap-2">
                    <button onclick="submitDecision('approve')" class="bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold px-3 py-1.5 rounded-lg">✅ Onayla</button>
                    <button onclick="submitDecision('reject')" class="bg-red-600 hover:bg-red-500 text-white text-xs font-bold px-3 py-1.5 rounded-lg">❌ Reddet</button>
                    <button onclick="submitDecision('stop')" class="bg-gray-700 hover:bg-gray-600 text-white text-xs font-bold px-3 py-1.5 rounded-lg">⏹ Durdur</button>
                </div>
            `;
            feed.appendChild(card);
            feed.scrollTop = feed.scrollHeight;
        }

        async function submitDecision(action) {
            try {
                await fetch('/api/action/decision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: action })
                });
            } catch (err) {
                console.error("Decision submit failed:", err);
            }
        }

        function renderError(data) {
            const feed = document.getElementById('terminal-feed');
            const block = document.createElement('div');
            block.className = "border-l-2 border-red-600 bg-red-950/20 pl-3 py-2 rounded text-red-300 text-xs";
            block.innerHTML = `<span class="font-bold">[HATA]</span> ${escapeHtml(data.message || 'Bilinmeyen hata')}`;
            feed.appendChild(block);
            feed.scrollTop = feed.scrollHeight;
        }

        function finishAssessment(data) {
            if (eventSource) {
                eventSource.close();
                eventSource = null;
            }
            document.getElementById('btn-start').disabled = false;
            document.getElementById('btn-start').classList.remove('opacity-40');
            document.getElementById('btn-stop').disabled = true;
            document.getElementById('status-dot').className = 'w-2 h-2 rounded-full bg-cyan-400';
            document.getElementById('status-text').innerText = `Değerlendirme tamamlandı! ${data.findings_count} bulgu doğrulandı (${data.steps_run} adım).`;
        }

        async function loadAllSkills() {
            try {
                const res = await fetch('/api/skills');
                allSkills = await res.json();
                renderSkillsList(allSkills);
            } catch (err) {
                console.error("Failed to load skills:", err);
            }
        }

        function renderSkillsList(skills) {
            const grid = document.getElementById('skills-grid');
            grid.innerHTML = '';
            skills.slice(0, 60).forEach(s => {
                const card = document.createElement('div');
                card.className = "bg-[#13151d] border border-[#222533] p-3.5 rounded-xl hover:border-cyan-700 transition flex flex-col justify-between";
                card.innerHTML = `
                    <div>
                        <div class="font-bold text-xs text-cyan-300 font-mono mb-1">${escapeHtml(s.name)}</div>
                        <div class="text-gray-400 text-[11px] leading-relaxed line-clamp-3">${escapeHtml(s.description)}</div>
                    </div>
                    <div class="mt-3 pt-2 border-t border-[#1e202d] flex items-center justify-between text-[10px] font-mono text-gray-500">
                        <span>${s.domain || 'cybersecurity'}</span>
                        <span class="text-cyan-500">MITRE / NIST</span>
                    </div>
                `;
                grid.appendChild(card);
            });
        }

        function searchSkillsLive() {
            const q = document.getElementById('skills-search-input').value.toLowerCase();
            const dom = document.getElementById('skills-domain-filter').value;
            const filtered = allSkills.filter(s => {
                const matchesQ = !q || s.name.toLowerCase().includes(q) || (s.description || '').toLowerCase().includes(q);
                const matchesDom = dom === 'all' || (s.domain || '').includes(dom);
                return matchesQ && matchesDom;
            });
            renderSkillsList(filtered);
        }

        async function refreshDebuggerData() {
            try {
                const res = await fetch('/api/debugger');
                const data = await res.json();
                
                const regContainer = document.getElementById('debugger-registers');
                regContainer.innerHTML = '';
                const regs = (data.registers && data.registers.registers) || {};
                for (const [k, v] of Object.entries(regs)) {
                    regContainer.innerHTML += `
                        <div class="flex items-center justify-between bg-[#161922] p-1.5 px-2.5 rounded border border-[#252938]">
                            <span class="text-amber-400 font-bold">${k}</span>
                            <span class="text-gray-300">${v}</span>
                        </div>
                    `;
                }

                const disasmContainer = document.getElementById('debugger-disasm');
                disasmContainer.innerHTML = '';
                const insts = (data.disasm && data.disasm.instructions) || [];
                insts.forEach(ins => {
                    disasmContainer.innerHTML += `
                        <div class="flex items-center gap-3 p-1 rounded hover:bg-[#151720]">
                            <span class="text-gray-500">${ins.addr}</span>
                            <span class="text-amber-500 font-mono">${ins.bytes}</span>
                            <span class="text-emerald-300 font-semibold">${ins.disasm}</span>
                        </div>
                    `;
                });
            } catch (err) {
                console.error("Failed to load debugger data:", err);
            }
        }

        async function viewReport() {
            document.getElementById('report-modal').classList.remove('hidden');
            const res = await fetch('/api/report');
            const md = await res.text();
            document.getElementById('report-content').innerHTML = marked.parse(md);
        }

        function closeReport() {
            document.getElementById('report-modal').classList.add('hidden');
        }

        function escapeHtml(str) {
            return (str || '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        }
    </script>
</body>
</html>"""


import queue as py_queue


class OperatorDecisionQueue:
    """Thread-safe queue for Human-in-the-loop operator decisions from web UI."""
    def __init__(self):
        self._q = py_queue.Queue()

    def wait_for_decision(self, timeout: float = 25.0) -> Dict[str, Any]:
        try:
            return self._q.get(timeout=timeout)
        except py_queue.Empty:
            return {"action": "approve", "auto": True}

    def submit_decision(self, decision: Dict[str, Any]):
        self._q.put(decision)

    def clear(self):
        """Clears any pending decisions."""
        while not self._q.empty():
            try:
                self._q.get_nowait()
            except py_queue.Empty:
                break


operator_queue = OperatorDecisionQueue()


class AssessmentUIHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests and Server-Sent Events (SSE) for the assessment cockpit."""

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))

        elif path == "/api/report":
            report_path = Path("reports/assessment_report.md")
            if report_path.exists():
                text = report_path.read_text(encoding="utf-8")
            else:
                text = "# Henüz Değerlendirme Raporu Oluşturulmadı\\n\\nLütfen önce bir test başlatın."
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(text.encode("utf-8"))

        elif path == "/api/skills":
            skills = skill_loader.skills
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(skills, ensure_ascii=False).encode("utf-8"))

        elif path == "/api/debugger":
            regs = debugger_mcp.get_all_registers()
            disasm = debugger_mcp.disassemble("0x00007FF7ABCD1050", count=5)
            data = {"registers": regs, "disasm": disasm}
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

        elif path == "/api/docker/status":
            health = docker_manager.get_health_report()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(health, ensure_ascii=False).encode("utf-8"))

        elif path == "/api/llm_redteam/categories":
            cats = llm_redteam_engine.get_categories()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(cats, ensure_ascii=False).encode("utf-8"))

        elif path == "/api/stream":
            # Ust duzey hata yakalama: handle_stream icinde beklenmedik bir
            # exception olursa thread cokmesin, kullaniciya net hata gonderilsin.
            try:
                self.handle_stream(parsed)
            except Exception as e:
                import traceback
                traceback.print_exc()
                try:
                    self.send_sse({
                        "type": "error",
                        "message": f"Beklenmeyen sunucu hatası: {e}"
                    })
                    self.send_sse({
                        "type": "complete",
                        "findings_count": 0,
                        "steps_run": 0
                    })
                except Exception:
                    pass

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/stop":
            operator_queue.submit_decision({"action": "stop"})
            self.send_response(200)
            self.end_headers()

        elif parsed.path == "/api/action/decision":
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len).decode('utf-8') if content_len > 0 else "{}"
            try:
                data = json.loads(body)
            except Exception:
                data = {"action": "approve"}
            operator_queue.submit_decision(data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "decision": data}).encode("utf-8"))

        elif parsed.path == "/api/docker/reset":
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len).decode('utf-8') if content_len > 0 else "{}"
            try:
                data = json.loads(body)
                target = data.get("target", "localhost:3000")
            except Exception:
                target = "localhost:3000"
            ok = docker_manager.reset_target(target)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"success": ok, "target": target}).encode("utf-8"))

        elif parsed.path == "/api/llm_redteam/scan":
            from core.llm_client import MockLLMClient
            mock_client = MockLLMClient(model_name="mock-victim", simulated_security_level="vulnerable")
            results = llm_redteam_engine.run_assessment(target_client=mock_client)
            scorecard = llm_redteam_engine.generate_findings_and_chains(results)
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(scorecard, ensure_ascii=False).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def send_sse(self, data: dict):
        """Sends a JSON-encoded Server-Sent Event to the browser.
        If the client disconnects, sets _client_disconnected and stops silently
        instead of crashing the handler thread with ConnectionAbortedError."""
        if getattr(self, "_client_disconnected", False):
            return
        try:
            payload = f"data: {json.dumps(data, ensure_ascii=False)}\n\n"
            self.wfile.write(payload.encode("utf-8"))
            self.wfile.flush()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            self._client_disconnected = True

    def handle_stream(self, parsed):
        params = parse_qs(parsed.query)
        target = params.get("target", ["metasploitable2"])[0]
        max_steps = int(params.get("max_steps", ["16"])[0])
        autonomous = params.get("autonomous", ["true"])[0].lower() in ("true", "1")
        interactive = params.get("interactive", ["false"])[0].lower() in ("true", "1")

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        # Stream matched tactical skills for target immediately
        matched_skills = skill_loader.suggest_skills_for_target(target=target)
        self.send_sse({
            "type": "skills_matched",
            "skills": matched_skills[:5]
        })

        endpoint = os.environ.get("COLAB_ATTACKER_URL") or os.environ.get("RUNPOD_ATTACKER_URL")
        key = os.environ.get("COLAB_API_KEY", "EMPTY")

        if not endpoint:
            self.send_sse({
                "type": "error",
                "message": "COLAB_ATTACKER_URL veya RUNPOD_ATTACKER_URL .env dosyasında bulunamadı."
            })
            return

        # Initialize LLM Client and Orchestrator
        llm_client = create_llm_client(
            provider="runpod",
            model_name="huihui-ai/huihui-cyberstrike-offsec-35b-abliterated",
            endpoint_url=endpoint,
            api_key=key,
            auto_detect_model=True
        )
        orchestrator = create_orchestrator()

        session_id = f"ui_session_{int(time.time())}"
        session_findings_file = Path(f"data/session_logs/{session_id}_findings.jsonl")
        session_findings_file.parent.mkdir(parents=True, exist_ok=True)

        assistant = AssessmentAssistant(
            llm_client=llm_client,
            target=target,
            max_steps=max_steps,
            findings_file=session_findings_file,
            orchestrator_agent=orchestrator,
            auto_approve_findings=True
        )

        # Run assessment loop and stream events
        step = 0
        # Ardışık ilerlemesiz adım sayacı (sonsuz döngü koruması).
        # NOT: Bu sayaç yalnızca sistem YENİ bir eylem üretemediğinde artar.
        # Tekrar eden bir eylem tespit edilip deterministik fallback ile yeni bir
        # servise geçildiğinde ilerleme sayılır ve sayaç sıfırlanır. Eşik, modelin
        # geçici JSON/tekrar sorunlarına tolerans tanıyacak kadar yüksek tutulur.
        no_progress_count = 0
        NO_PROGRESS_LIMIT = 12
        # Model takılma tespiti: worker aynı eylemi üst üste kaç kez önerdi?
        # CyberStrike 35B gibi küçük modeller uzun bağlamda aynı eylemi
        # tekrarlamaya eğilimlidir. Bu sayaç eşiği aşınca modeli tamamen
        # devre dışı bırakıp deterministik kapsam motoruna geçeriz; böylece
        # değerlendirme modelin takılmasına rağmen tüm servisleri kapsar.
        model_stuck_count = 0
        MODEL_STUCK_LIMIT = 3
        last_model_action_key = None
        deterministic_mode = False
        while step < max_steps:
            # Tarayici baglantisi koptuysa: interaktif modda durdur, otonom modda teste devam et
            if getattr(self, "_client_disconnected", False) and not autonomous:
                print("[UI] Client disconnected in interactive mode; stopping assessment loop.")
                break
            # Sonsuz dongu korumasi: cok fazla ilerlemesiz adim olursa bitir
            if no_progress_count >= NO_PROGRESS_LIMIT:
                self.send_sse({
                    "type": "error",
                    "message": "Çok fazla ilerlemesiz adım (loop breaker). Değerlendirme durduruldu."
                })
                print(f"[DIAG] BREAK: no_progress_count={no_progress_count} exceeded limit")
                break
            step += 1
            assistant.step_count = step

            # Check orchestrator directive
            if orchestrator and step > 0 and step % assistant.ORCHESTRATOR_INTERVAL == 0:
                try:
                    directive = orchestrator.plan_next_step(
                        current_findings=assistant.findings,
                        recent_worker_output=assistant._last_orchestrator_directive,
                        step_number=step,
                        target=target,
                        worker_activity=assistant._build_worker_activity(),
                    )
                    assistant._last_orchestrator_directive = directive
                    if directive:
                        self.send_sse({
                            "type": "orchestrator_directive",
                            "step": step,
                            "directive": directive
                        })
                except Exception as e:
                    pass

            context = assistant._build_context()
            self.send_sse({
                "type": "thinking_status",
                "step": step,
                "message": f"🧠 Model (CyberStrike 35B) Adım {step} için sonraki eylemi analiz ediyor..."
            })
            try:
                # UI orchestrator'i kendisi cagirdigi icin skip_orchestrator=True
                suggestion = assistant._ask_llm_for_suggestion(context, skip_orchestrator=True)
            except Exception as e:
                self.send_sse({
                    "type": "error",
                    "step": step,
                    "message": f"Model öneri üretirken hata: {e}"
                })
                suggestion = None

            # ── MODEL TAKILMA TESPİTİ ────────────────────────────────────────
            # Worker aynı eylemi üst üste öneriyorsa (küçük modellerin uzun
            # bağlamda tipik davranışı), modeli devre dışı bırakıp deterministik
            # kapsam motoruna geçeriz. Böylece değerlendirme modelin takılmasına
            # rağmen TÜM servisleri kapsar.
            if suggestion and suggestion.get("tool") not in ("done", None):
                _m_svc = suggestion.get("service_name")
                if suggestion.get("tool") == "exploit":
                    _m_svc = suggestion.get("exploit") or _m_svc
                elif suggestion.get("tool") == "privesc":
                    _m_svc = suggestion.get("privesc") or _m_svc
                _model_key = assistant._action_key(
                    suggestion.get("tool", ""), target,
                    suggestion.get("ports"), _m_svc, suggestion.get("version"),
                )
                if _model_key == last_model_action_key:
                    model_stuck_count += 1
                else:
                    model_stuck_count = 0
                    last_model_action_key = _model_key

                if model_stuck_count >= MODEL_STUCK_LIMIT and not deterministic_mode:
                    deterministic_mode = True
                    print(f"[DIAG] Model stuck on '{_model_key}' x{model_stuck_count}. Switching to deterministic coverage mode.")
                    self.send_sse({
                        "type": "orchestrator_directive",
                        "step": step,
                        "directive": (
                            "🧭 [Sistem] Worker modeli aynı eylemi tekrarlıyor. "
                            "Deterministik kapsam motoruna geçiliyor; kalan tüm servisler sırayla test edilecek."
                        )
                    })

            # Deterministik modda model önerisini yok say ve kapsam motorunu kullan.
            if deterministic_mode:
                fallback = assistant.get_fallback_action_for_untested()
                if fallback:
                    suggestion = fallback
                    self.send_sse({
                        "type": "orchestrator_directive",
                        "step": step,
                        "directive": f"🎯 [Kapsam Motoru]: {suggestion.get('thought')}"
                    })
                else:
                    # Kapsam motoru da yeni eylem bulamıyorsa değerlendirme tamam.
                    print(f"[DIAG] COMPLETE at step {step}: deterministic coverage exhausted all services")
                    self.send_sse({
                        "type": "orchestrator_directive",
                        "step": step,
                        "directive": "🏁 [Kapsam Motoru]: Tüm kritik servisler test edildi. Değerlendirme tamamlanıyor."
                    })
                    break

            # ── API/Baglanti hatasi tespiti: sessiz bitisi onle ─────────────
            if not suggestion and getattr(assistant, "_last_llm_error", None):
                self.send_sse({
                    "type": "error",
                    "step": step,
                    "message": (
                        "🚨 Model API bağlantısı koptu (Colab linki geçersiz olabilir): "
                        f"{assistant._last_llm_error[:200]}. "
                        "Değerlendirme durduruldu. Lütfen Colab linkini yenileyin."
                    )
                })
                break

            if not suggestion and orchestrator:
                try:
                    suggestion = orchestrator.direct_json_suggestion(
                        current_findings=assistant.findings,
                        step_number=step,
                        target=target,
                        visited_actions=assistant.visited_actions
                    )
                except Exception:
                    suggestion = None

            if not suggestion:
                fallback = assistant.get_fallback_action_for_untested()
                if fallback:
                    suggestion = fallback
                    self.send_sse({
                        "type": "orchestrator_directive",
                        "step": step,
                        "directive": f"🎯 [Kapsam Otoritesi]: {suggestion.get('thought')}"
                    })
                else:
                    untested = assistant._untested_services()
                    if not untested:
                        print(f"[DIAG] COMPLETE at step {step}: all critical services tested and model completed")
                        self.send_sse({
                            "type": "orchestrator_directive",
                            "step": step,
                            "directive": "🏁 [Kapsam Otoritesi]: Hedef üzerindeki tüm kritik servisler başarıyla test edildi. Değerlendirme tamamlanıyor."
                        })
                        break
                    else:
                        self.send_sse({
                            "type": "error",
                            "step": step,
                            "message": "Model öneri üretemedi (JSON parse hatası veya boş yanıt). Değerlendirme durduruldu."
                        })
                        print(f"[DIAG] BREAK at step {step}: suggestion is None (model+orchestrator failed to produce JSON)")
                        break

            if suggestion:
                suggestion["target"] = target

            tool = suggestion.get("tool", "")
            print(f"[DIAG] step {step}: tool={tool} exploit={suggestion.get('exploit')} privesc={suggestion.get('privesc')}")

            # Hata 6: _untested_services periyodik kontrol — her 5 adımda bir
            # (done'da değil sadece). Eksik servisler varsa modele inject et.
            if tool != "done" and step % 5 == 0 and step > 0:
                periodic_untested = assistant._untested_services()
                if periodic_untested:
                    self.send_sse({
                        "type": "orchestrator_directive",
                        "step": step,
                        "directive": (
                            f"🧠 [Periyodik Kapsam Kontrolü - Adım {step}] "
                            f"Henüz test edilmemiş servisler: {', '.join(periodic_untested)}. "
                            f"Bu servisleri test etmeyi unutmayın."
                        )
                    })
                    assistant.conversation.append({
                        "role": "user",
                        "content": (
                            f"[PERIODIC SCOPE CHECK at step {step}] "
                            f"The following critical services have NOT been tested yet: "
                            f"{', '.join(periodic_untested)}. "
                            f"Make sure to test ALL of them before saying 'done'. "
                            f"Continue with your current plan but keep these in mind."
                        ),
                    })

            if tool == "done":
                # ── DETERMINISTIK DONE KONTROLU: Model 'done' demek istiyor ama
                # henuz test edilmemis kritik servisler varsa, done'u REDDET ve
                # modeli kalan servisleri test etmeye zorla.
                untested = assistant._untested_services()
                if untested and step < max_steps:

                    self.send_sse({
                        "type": "orchestrator_directive",
                        "step": step,
                        "directive": (
                            "🧠 [Sistem] Model 'done' demek istedi ancak su servisler "
                            f"henuz test edilmedi: {', '.join(untested)}. Devam ediliyor."
                        )
                    })
                    assistant.conversation.append({
                        "role": "user",
                        "content": (
                            "STOP: You said 'done' but the following critical services "
                            f"have NOT been tested yet: {', '.join(untested)}. "
                            "You MUST continue. Test each remaining service with "
                            "searchsploit/cve_search (and exploit if a ready exploit exists). "
                            "Only say 'done' after ALL services have been tested. "
                            "Produce the next JSON recommendation NOW."
                        ),
                    })
                    suggestion2 = None
                    try:
                        suggestion2 = assistant._ask_llm_for_suggestion(context, skip_orchestrator=True)
                    except Exception:
                        suggestion2 = None
                    # Model hala 'done' diyorsa veya JSON uretemiyorsa, orchestrator
                    # ile DETERMINISTIK olarak bir sonraki servisi zorla.
                    if not suggestion2 or suggestion2.get("tool") in ("done", None):
                        if orchestrator:
                            try:
                                forced = orchestrator.direct_json_suggestion(
                                    current_findings=assistant.findings,
                                    step_number=step,
                                    target=target,
                                    visited_actions=assistant.visited_actions,
                                )
                                if forced and forced.get("tool") not in ("done", None):
                                    suggestion2 = forced
                            except Exception:
                                pass
                    if suggestion2 and suggestion2.get("tool") not in ("done", None):
                        suggestion = suggestion2
                        tool = suggestion.get("tool", "")
                    else:
                        # Deterministic fallback: test next unassessed service
                        fallback = assistant.get_fallback_action_for_untested()
                        if fallback:
                            suggestion = fallback
                            tool = suggestion.get("tool", "")
                            self.send_sse({
                                "type": "orchestrator_directive",
                                "step": step,
                                "directive": f"🎯 [Kapsam Otoritesi]: {suggestion.get('thought')}"
                            })
                        else:
                            print(f"[DIAG] BREAK at step {step}: all critical services tested")
                            break
                else:
                    print(f"[DIAG] BREAK at step {step}: model said 'done' and all critical services tested")
                    break

            # ── WORKER KURTARMA (ortak metod: should_trigger_rescue/perform_rescue) ──
            if orchestrator and assistant.should_trigger_rescue(step, cooldown=5):
                try:
                    self.send_sse({
                        "type": "orchestrator_directive",
                        "step": step,
                        "directive": "🧠 [Orchestrator] Worker takildi tespit edildi. Analiz edilip kurtariliyor..."
                    })
                    suggestion2 = assistant.perform_rescue(step, target, context)
                    if assistant._last_orchestrator_directive:
                        self.send_sse({
                            "type": "orchestrator_directive",
                            "step": step,
                            "directive": f"🧠 [Orchestrator Kurtarma]: {assistant._last_orchestrator_directive}"
                        })
                    if suggestion2 and suggestion2.get("tool") not in ("done", None):
                        suggestion = suggestion2
                        tool = suggestion.get("tool", "")
                    else:
                        # Kurtarma JSON üretemedi: deterministik kapsam otoritesine düş.
                        fallback = assistant.get_fallback_action_for_untested()
                        if fallback:
                            suggestion = fallback
                            tool = suggestion.get("tool", "")
                            no_progress_count = 0
                            self.send_sse({
                                "type": "orchestrator_directive",
                                "step": step,
                                "directive": f"🎯 [Kapsam Otoritesi]: Kurtarma sonrası sıradaki servise geçiliyor: {suggestion.get('thought')}"
                            })
                        else:
                            self.send_sse({
                                "type": "error",
                                "step": step,
                                "message": "Kurtarma başarısız oldu; bu adım atlanıyor."
                            })
                            step -= 1
                            no_progress_count += 1
                            continue
                except Exception as e:
                    print(f"[UI] Rescue failed: {e}")


            # ── LOOP BREAKER: Ayni eylem daha once calistirildiysa tekrar etme ──
            # ONEMLI: Sadece 'continue' yapmak yetmez; model ayni oneriyi tekrar
            # uretirse sonsuz dongu olusur. Bu yuzden modele ZORLA yeni bir oneri
            # urettiririz; uretemezse orchestrator'dan deterministik oneri aliriz.
            # Exploit/privesc de dahil: ayni exploit/privesc tekrar calistirilmaz.
            _ports = suggestion.get("ports")
            _svc = suggestion.get("service_name")
            _ver = suggestion.get("version")
            # Exploit/privesc adini action_key'e dahil et (tekrar tespiti icin)
            if tool == "exploit":
                _svc = suggestion.get("exploit") or _svc
            elif tool == "privesc":
                _svc = suggestion.get("privesc") or _svc
            action_key = assistant._action_key(tool, target, _ports, _svc, _ver)
            if action_key in assistant.visited_actions:
                self.send_sse({
                    "type": "orchestrator_directive",
                    "step": step,
                    "directive": f"🔁 [Sistem] '{tool}' ({_svc or ''}) zaten çalıştırıldı. Farklı bir adım zorlanıyor..."
                })

                # ── ÖNCELİK 1: Deterministik kapsam otoritesi ────────────────
                # Modelin tekrar üretmesini beklemeden, henüz test edilmemiş bir
                # servis için hazır eylem varsa DOĞRUDAN onu kullan. Bu, modelin
                # ısrarla aynı eylemi önermesi durumunda bile ilerlemeyi garanti
                # eder ve no_progress sayacının boşa dolmasını engeller.
                fallback = assistant.get_fallback_action_for_untested()
                if fallback:
                    suggestion = fallback
                    tool = suggestion.get("tool", "")
                    no_progress_count = 0
                    self.send_sse({
                        "type": "orchestrator_directive",
                        "step": step,
                        "directive": f"🎯 [Kapsam Otoritesi]: Tekrarlı eylem engellendi. Sıradaki servise geçiliyor: {suggestion.get('thought')}"
                    })
                else:
                    # ── ÖNCELİK 2: Modelden yeni öneri iste ──────────────────
                    if assistant.conversation and assistant.conversation[-1].get("content", "").startswith("LOOP BREAKER:"):
                        assistant.conversation.pop()
                    assistant.conversation.append({
                        "role": "user",
                        "content": (
                            f"LOOP BREAKER: You already ran '{action_key}' and received its output. "
                            "Do NOT repeat it. You MUST now either (a) run an EXPLOIT for a discovered "
                            "vulnerable service (tool:exploit, e.g. exploit:vsftpd_backdoor, "
                            "exploit:samba_usermap, exploit:ingreslock_backdoor), or (b) run a privesc "
                            "step, or (c) test a DIFFERENT service. Produce a valid JSON NOW."
                        ),
                    })
                    forced = None
                    try:
                        forced = assistant._ask_llm_for_suggestion(context, skip_orchestrator=True)
                    except Exception:
                        forced = None

                    _f_svc = forced.get("service_name") if forced else None
                    if forced and forced.get("tool") == "exploit":
                        _f_svc = forced.get("exploit") or _f_svc
                    elif forced and forced.get("tool") == "privesc":
                        _f_svc = forced.get("privesc") or _f_svc
                    forced_key = assistant._action_key(
                        forced.get("tool", "") if forced else "", target,
                        forced.get("ports") if forced else None, _f_svc,
                        forced.get("version") if forced else None,
                    ) if forced else ""

                    # Model hala ayni/gecersiz oneriyi verdiyse VEYA eylem zaten calistirildiysa Orchestrator'dan al
                    if not forced or forced.get("tool") in ("done", None) or forced_key in assistant.visited_actions:
                        if orchestrator:
                            try:
                                forced = orchestrator.direct_json_suggestion(
                                    current_findings=assistant.findings,
                                    step_number=step,
                                    target=target,
                                    visited_actions=assistant.visited_actions,
                                )
                            except Exception:
                                forced = None

                    if forced and forced.get("tool") not in ("done", None):
                        _f_svc = forced.get("service_name")
                        if forced.get("tool") == "exploit":
                            _f_svc = forced.get("exploit") or _f_svc
                        elif forced.get("tool") == "privesc":
                            _f_svc = forced.get("privesc") or _f_svc
                        forced_key = assistant._action_key(
                            forced.get("tool", ""), target,
                            forced.get("ports"), _f_svc, forced.get("version"),
                        )
                        if forced_key not in assistant.visited_actions:
                            suggestion = forced
                            tool = suggestion.get("tool", "")
                            no_progress_count = 0
                        else:
                            # ── ÖNCELİK 3: Hiçbiri yeni eylem üretemedi ──────
                            untested = assistant._untested_services()
                            if not untested:
                                print(f"[DIAG] COMPLETE at step {step}: all critical services tested and no new actions remain")
                                self.send_sse({
                                    "type": "orchestrator_directive",
                                    "step": step,
                                    "directive": "🏁 [Kapsam Otoritesi]: Hedef üzerindeki tüm kritik servisler ve zaafiyetler başarıyla test edildi. Değerlendirme tamamlanıyor."
                                })
                                break
                            print(f"[DIAG] CONTINUE at step {step}: loop-breaker could not produce a new action")
                            step -= 1
                            no_progress_count += 1
                            continue
                    else:
                        untested = assistant._untested_services()
                        if not untested:
                            print(f"[DIAG] COMPLETE at step {step}: all critical services tested and no new actions remain")
                            self.send_sse({
                                "type": "orchestrator_directive",
                                "step": step,
                                "directive": "🏁 [Kapsam Otoritesi]: Hedef üzerindeki tüm kritik servisler ve zaafiyetler başarıyla test edildi. Değerlendirme tamamlanıyor."
                            })
                            break
                        print(f"[DIAG] CONTINUE at step {step}: loop-breaker could not produce a new action")
                        step -= 1
                        no_progress_count += 1
                        continue

            # Send Step Plan to UI
            no_progress_count = 0  # Gercek bir adim isleniyor; sayaci sifirla
            self.send_sse({
                "type": "step_plan",
                "step": step,
                "max_steps": max_steps,
                "tool": tool,
                "target": target,
                "thought": suggestion.get("thought", ""),
                "rationale": suggestion.get("rationale", ""),
                "exploit": suggestion.get("exploit"),
                "privesc": suggestion.get("privesc"),
                "username": suggestion.get("username")
            })

            # Record step in assistant's decision chain for report generation
            assistant.decision_chain.append({
                "step": step,
                "thought": suggestion.get("thought", ""),
                "tool": tool,
                "target": target,
                "ports": suggestion.get("ports"),
                "service_name": suggestion.get("service_name"),
                "version": suggestion.get("version"),
                "exploit": suggestion.get("exploit"),
                "privesc": suggestion.get("privesc"),
                "rationale": suggestion.get("rationale", "")
            })

            # Evaluate finding with ValidationGate if proposed (tek noktadan kontrol: record_finding)
            finding = suggestion.get("finding")
            if finding and isinstance(finding, dict) and finding.get("category"):
                fid = assistant._record_model_finding(finding, current_tool=tool)
                gate_res = getattr(assistant, "_last_gate_result", None)
                if fid:
                    self.send_sse({
                        "type": "finding",
                        "finding_id": fid,
                        "category": finding.get("category"),
                        "severity": finding.get("severity", "High"),
                        "cwe_reference": finding.get("cwe_reference", "CWE"),
                        "evidence_snippet": finding.get("evidence_snippet", ""),
                        "tool": tool
                    })
                    if gate_res:
                        self.send_sse({
                            "type": "gate_event",
                            "status": "PASSED",
                            "finding": finding,
                            "reason": gate_res.reason
                        })
                else:
                    if gate_res and not gate_res.passed:
                        self.send_sse({
                            "type": "gate_event",
                            "status": "REJECTED",
                            "finding": finding,
                            "rule": gate_res.instant_kill_id or "FLUFF",
                            "reason": gate_res.reason
                        })


            # Human-in-the-Loop 2.0: Interactive approval via Web UI.
            # Otonom modda (autonomous=true) her adim onaysiz calisir.
            autonomous = params.get("autonomous", ["true"])[0].lower() in ("true", "1")
            interactive = params.get("interactive", ["false"])[0].lower() in ("true", "1")
            approved = True
            if interactive and not autonomous:
                self.send_sse({
                    "type": "awaiting_approval",
                    "step": step,
                    "tool": tool,
                    "target": target,
                    "thought": suggestion.get("thought", ""),
                    "rationale": suggestion.get("rationale", "")
                })
                decision = operator_queue.wait_for_decision(timeout=25.0)
                if decision.get("action") == "stop":
                    self.send_sse({"type": "stopped", "message": "Operatör değerlendirmeyi durdurdu."})
                    break
                approved = (decision.get("action") != "reject")

            # Execute tool via unified execute_step (Hata 11)
            prev_count = len(assistant.findings)
            try:
                res = assistant.execute_step(
                    tool=tool,
                    target=target,
                    suggestion=suggestion,
                    approved=approved,
                )
            except Exception as e:
                self.send_sse({
                    "type": "error",
                    "step": step,
                    "tool": tool,
                    "message": f"Araç çalıştırılırken hata: {e}"
                })
                res = {"status": "ERROR", "tool": tool, "output": f"[ERROR]: {e}", "success": False}

            output = res.get("output", "")
            success = res.get("success", False)

            # Exploit/privesc results use 'success'/'evidence'; tool results use 'command'
            if tool in ("exploit", "privesc"):
                exploit_name_used = res.get("exploit") or res.get("technique") or suggestion.get("exploit") or suggestion.get("privesc") or f"{tool}"
                cmd = exploit_name_used or f"{tool} {target}"
                self.send_sse({
                    "type": "tool_exec",
                    "step": step,
                    "tool": tool,
                    "command": f"{tool}: {cmd}",
                    "approved": approved,
                    "success": success
                })
                self.send_sse({
                    "type": "tool_output",
                    "step": step,
                    "tool": tool,
                    "output": output[:2500],
                    "approved": approved,
                    "success": success
                })
            else:
                cmd = res.get("command", f"{tool} {target}")
                self.send_sse({
                    "type": "tool_exec",
                    "step": step,
                    "tool": tool,
                    "command": cmd,
                    "approved": approved
                })
                self.send_sse({
                    "type": "tool_output",
                    "step": step,
                    "tool": tool,
                    "output": output[:2500],
                    "approved": approved
                })

            # Eğer execute_step yeni bulgular kaydettiyse SSE olarak gönder
            if len(assistant.findings) > prev_count:
                for new_finding in assistant.findings[prev_count:]:
                    self.send_sse({
                        "type": "finding",
                        "finding_id": new_finding.get("finding_id", "FIND-AUTO"),
                        "category": new_finding.get("category"),
                        "severity": new_finding.get("severity", "High"),
                        "cwe_reference": new_finding.get("cwe_reference", "CWE"),
                        "evidence_snippet": new_finding.get("evidence_snippet", ""),
                        "tool": new_finding.get("tool", tool)
                    })
                    self.send_sse({
                        "type": "gate_event",
                        "status": "PASSED",
                        "finding": new_finding,
                        "reason": f"Başarılı {tool} / kural motoru tarafından doğrulandı"
                    })

            # Stream exploit chains
            if assistant.findings:
                chains = chain_engine.build_chain_narrative(assistant.findings)
                if chains:
                    self.send_sse({
                        "type": "chain_update",
                        "chains": chains
                    })


            time.sleep(0.5)

        # Finalize report
        report_findings = list(assistant.findings)
        if not report_findings:
            from core.assessment_assistant import FINDINGS_FILE
            if FINDINGS_FILE.exists():
                try:
                    with open(FINDINGS_FILE, "r", encoding="utf-8") as f:
                        report_findings = [json.loads(line) for line in f if line.strip()]
                except Exception:
                    pass

        assistant.generate_report(report_findings)
        self.send_sse({
            "type": "complete",
            "findings_count": len(report_findings),
            "steps_run": step
        })

    def log_message(self, format, *args):
        pass


def run_cockpit(port=7870):
    server = ThreadingHTTPServer(("127.0.0.1", port), AssessmentUIHandler)
    url = f"http://127.0.0.1:{port}"
    print("\\n" + "=" * 65)
    print("  🛡️ AutoRedTeam — Otonom Pentest & Değerlendirme Kokpiti!")
    print(f"  👉 Tarayıcında canlı izleme adresi: {url}")
    print("=" * 65 + "\\n")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\\nKokpit kapatıldı.")
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7870
    run_cockpit(port)
