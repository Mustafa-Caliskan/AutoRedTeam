"""
AutoRedTeam - Elite Offensive AI Chat & Security Console (chat_ui.py)
Direct interactive chat interface with CyberStrike 35B Abliterated, DeepSeek V4,
and enterprise defense models.
Matches the AutoRedTeam Dark Cyber / SOC Cockpit design system.
"""

import json
import os
import re
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Any
from openai import OpenAI

# Windows UTF-8 fix
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

# Load .env
def load_env():
    for env_path in [Path(".env"), Path("config/.env")]:
        if env_path.exists():
            with open(env_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, val = line.partition("=")
                        os.environ[key.strip()] = val.strip()
            break

load_env()
from core.llm_client import sanitize_llm_response

DEFAULT_MODEL = "huihui-ai/huihui-cyberstrike-offsec-35b-abliterated"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AutoRedTeam — Offensive AI Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
  <style>
    :root {
      --bg: #090b0e;
      --surface: #0f1318;
      --surface-2: #141920;
      --surface-3: #1a212b;
      --border: #1d2530;
      --border-strong: #273242;
      --text: #e6edf3;
      --muted: #8b949e;
      --muted-2: #545d68;
      --accent: #4f78ee;
      --accent-glow: rgba(79, 120, 238, 0.15);
      --crit: #f85149;
      --high: #db6d28;
      --ok: #2ea043;
      --mono: 'JetBrains Mono', monospace;
      --sans: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 13px;
      line-height: 1.5;
      height: 100vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    /* Scrollbars */
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--muted-2); }

    /* Top Bar */
    .topbar {
      height: 48px;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      padding: 0 16px;
      gap: 12px;
      flex-shrink: 0;
      z-index: 10;
    }
    .brand { display: flex; align-items: center; gap: 8px; }
    .brand-mark {
      width: 24px; height: 24px;
      border: 1.5px solid var(--crit);
      border-radius: 5px;
      display: grid; place-items: center;
      font-family: var(--mono); font-size: 11px; font-weight: 700;
      color: var(--crit);
      background: rgba(248, 81, 73, 0.08);
    }
    .brand-name { font-weight: 700; font-size: 13.5px; letter-spacing: -0.01em; color: #fff; }
    .brand-sub {
      color: var(--muted-2);
      font-size: 11px;
      border-left: 1px solid var(--border-strong);
      padding-left: 10px;
      font-family: var(--mono);
    }
    .top-status {
      margin-left: auto;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .status-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      background: var(--surface-2);
      border: 1px solid var(--border);
      padding: 4px 9px;
      border-radius: 5px;
      font-family: var(--mono);
      font-size: 11px;
      color: var(--ok);
    }
    .pulse-dot {
      width: 7px; height: 7px;
      border-radius: 50%;
      background: var(--ok);
      box-shadow: 0 0 8px rgba(46, 160, 67, 0.6);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.9); }
      100% { opacity: 1; transform: scale(1); }
    }
    .btn {
      appearance: none;
      border: 1px solid var(--border-strong);
      background: var(--surface-2);
      color: var(--text);
      border-radius: 6px;
      padding: 5px 10px;
      font-size: 11.5px;
      font-family: var(--sans);
      font-weight: 500;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 5px;
      transition: background .12s, border-color .12s;
    }
    .btn:hover:not(:disabled) { border-color: var(--muted-2); background: var(--surface-3); }
    .btn-danger { color: var(--crit); border-color: rgba(248, 81, 73, 0.3); }
    .btn-danger:hover:not(:disabled) { background: rgba(248, 81, 73, 0.1); border-color: var(--crit); }
    .btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    .btn-primary:hover:not(:disabled) { background: #3f6ae8; }
    .btn:disabled { opacity: 0.4; cursor: not-allowed; }

    /* App Layout */
    .app-body {
      flex: 1;
      display: flex;
      overflow: hidden;
    }

    /* Sidebar */
    .sidebar {
      width: 290px;
      background: var(--surface);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      padding: 14px;
      gap: 16px;
      overflow-y: auto;
      flex-shrink: 0;
    }
    .sidebar-section-title {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.06em;
      color: var(--muted);
      text-transform: uppercase;
      margin-bottom: 8px;
    }
    .model-card {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 7px;
      padding: 10px;
      display: flex;
      flex-direction: column;
      gap: 7px;
      font-size: 11px;
    }
    .model-row {
      display: flex;
      justify-content: space-between;
      color: var(--muted);
    }
    .model-row span:last-child {
      color: var(--text);
      font-family: var(--mono);
      font-weight: 500;
    }

    .prompt-list {
      display: flex;
      flex-direction: column;
      gap: 5px;
    }
    .prompt-btn {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 10px;
      text-align: left;
      color: var(--text);
      font-size: 11.5px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 7px;
      transition: border-color .15s, background .15s;
    }
    .prompt-btn:hover {
      background: var(--surface-3);
      border-color: var(--border-strong);
      color: #fff;
    }
    .prompt-icon { color: var(--accent); font-size: 13px; }

    /* Main Chat View */
    .chat-view {
      flex: 1;
      display: flex;
      flex-direction: column;
      background: var(--bg);
      overflow: hidden;
      position: relative;
    }
    .messages-container {
      flex: 1;
      overflow-y: auto;
      padding: 20px 24px;
      display: flex;
      flex-direction: column;
      gap: 18px;
      max-width: 960px;
      width: 100%;
      margin: 0 auto;
    }

    /* Message Bubbles */
    .msg-wrap {
      display: flex;
      gap: 12px;
      align-items: flex-start;
      width: 100%;
    }
    .msg-wrap.user {
      justify-content: flex-end;
    }
    .avatar {
      width: 28px; height: 28px;
      border-radius: 6px;
      display: grid;
      place-items: center;
      font-family: var(--mono);
      font-size: 10px;
      font-weight: 700;
      flex-shrink: 0;
    }
    .avatar.ai {
      background: rgba(248, 81, 73, 0.12);
      border: 1px solid rgba(248, 81, 73, 0.4);
      color: var(--crit);
    }
    .avatar.user {
      background: rgba(79, 120, 238, 0.15);
      border: 1px solid rgba(79, 120, 238, 0.4);
      color: var(--accent);
    }
    .bubble {
      max-width: 82%;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 12.5px;
      line-height: 1.6;
    }
    .msg-wrap.user .bubble {
      background: var(--surface-3);
      border: 1px solid var(--border-strong);
      color: var(--text);
      white-space: pre-wrap;
    }
    .msg-wrap.ai .bubble {
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--text);
      width: 100%;
    }

    /* Markdown Styling */
    .bubble pre {
      background: #06080a;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      overflow-x: auto;
      margin: 8px 0;
      position: relative;
    }
    .bubble code {
      font-family: var(--mono);
      font-size: 12px;
      color: #79c0ff;
    }
    .bubble pre code { color: inherit; }
    .bubble p { margin-bottom: 6px; }
    .bubble p:last-child { margin-bottom: 0; }
    .bubble ul, .bubble ol { margin-left: 18px; margin-bottom: 8px; }
    .bubble li { margin-bottom: 4px; }
    .bubble table {
      border-collapse: collapse;
      width: 100%;
      margin: 10px 0;
      font-size: 12px;
    }
    .bubble th, .bubble td {
      border: 1px solid var(--border);
      padding: 6px 10px;
      text-align: left;
    }
    .bubble th { background: var(--surface-2); font-weight: 600; }
    .bubble a { color: var(--accent); text-decoration: none; }
    .bubble a:hover { text-decoration: underline; }

    /* Loading indicator */
    .typing-bar {
      display: flex;
      align-items: center;
      gap: 6px;
      font-family: var(--mono);
      font-size: 11.5px;
      color: var(--muted);
      padding: 6px 0;
    }
    .typing-dot {
      width: 6px; height: 6px;
      background: var(--crit);
      border-radius: 50%;
      animation: blink 1.2s infinite ease-in-out;
    }
    .typing-dot:nth-child(2) { animation-delay: 0.2s; }
    .typing-dot:nth-child(3) { animation-delay: 0.4s; }
    @keyframes blink {
      0%, 80%, 100% { opacity: 0.2; transform: scale(0.8); }
      40% { opacity: 1; transform: scale(1.1); }
    }

    /* Input Footer */
    .input-dock {
      background: var(--surface);
      border-top: 1px solid var(--border);
      padding: 12px 24px 16px;
      flex-shrink: 0;
    }
    .input-dock-inner {
      max-width: 960px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .input-wrapper {
      position: relative;
      display: flex;
      align-items: flex-end;
      background: var(--surface-2);
      border: 1px solid var(--border-strong);
      border-radius: 8px;
      padding: 8px 12px;
      transition: border-color .15s;
    }
    .input-wrapper:focus-within {
      border-color: var(--accent);
      box-shadow: 0 0 0 2px var(--accent-glow);
    }
    .chat-textarea {
      flex: 1;
      background: transparent;
      border: none;
      color: var(--text);
      font-family: var(--sans);
      font-size: 13px;
      line-height: 1.5;
      resize: none;
      max-height: 140px;
      outline: none;
    }
    .send-button {
      background: var(--accent);
      color: #fff;
      border: none;
      width: 32px; height: 32px;
      border-radius: 6px;
      display: grid;
      place-items: center;
      cursor: pointer;
      margin-left: 8px;
      flex-shrink: 0;
      transition: background .12s, opacity .12s;
    }
    .send-button:hover:not(:disabled) { background: #3f6ae8; }
    .send-button:disabled { opacity: 0.35; cursor: not-allowed; }
    .dock-meta {
      display: flex;
      justify-content: space-between;
      color: var(--muted-2);
      font-size: 11px;
      font-family: var(--mono);
      padding: 0 4px;
    }
  </style>
</head>
<body>

  <!-- Top Navigation Bar -->
  <div class="topbar">
    <div class="brand">
      <div class="brand-mark">ART</div>
      <div class="brand-name">AutoRedTeam</div>
      <div class="brand-sub">Offensive AI Console</div>
    </div>

    <div class="top-status">
      <div class="status-badge">
        <span class="pulse-dot"></span>
        <span id="backend-status-text">CyberStrike 35B SGLang Live</span>
      </div>
      <button class="btn btn-danger" onclick="clearChat()">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"></path></svg>
        Sohbeti Sıfırla
      </button>
    </div>
  </div>

  <!-- App Body -->
  <div class="app-body">

    <!-- Left Sidebar -->
    <div class="sidebar">
      <div>
        <div class="sidebar-section-title">Model Mimarisi</div>
        <div class="model-card">
          <div class="model-row"><span>Model:</span> <span>CyberStrike 35B</span></div>
          <div class="model-row"><span>Karakter:</span> <span style="color: var(--crit);">Abliterated / OffSec</span></div>
          <div class="model-row"><span>Inference:</span> <span>SGLang (RadixAttention)</span></div>
          <div class="model-row"><span>GPU:</span> <span>NVIDIA A100/H100 80GB</span></div>
          <div class="model-row"><span>Max Tokens:</span> <span>4,096 tokens</span></div>
          <div class="model-row"><span>CoT Sanitizer:</span> <span style="color: var(--ok);">Aktif</span></div>
        </div>
      </div>

      <div>
        <div class="sidebar-section-title">Hızlı Güvenlik Şablonları</div>
        <div class="prompt-list">
          <button class="prompt-btn" onclick="applyPrompt('Hedef sistemde Linux SUID binary miskonfigürasyonlarını tarayan ve yetki yükseltme vektörlerini analiz eden bir bash komut zinciri üret.')">
            <span class="prompt-icon">⚡</span> SUID Yetki Yükseltme
          </button>
          <button class="prompt-btn" onclick="applyPrompt('WAF ve filtre atlatma için Unicode Homoglyph ve Zero-Width karakter gizleme tekniklerinin mekanizmasını açıkla ve örnek bir payload simülasyonu sun.')">
            <span class="prompt-icon">🧬</span> Homoglyph & Evasion
          </button>
          <button class="prompt-btn" onclick="applyPrompt('Nmap çıktısında açık olan vsftpd 2.3.4, ProFTPD 1.3.5 ve Samba 3.0.20 servisleri için bilinen RCE exploitlerini ve doğrulama adımlarını listele.')">
            <span class="prompt-icon">🔍</span> Port & CVE Triage
          </button>
          <button class="prompt-btn" onclick="applyPrompt('Modern Single Page Web uygulamalarında LocalStorage JWT token sızıntısını ve XSS zincirleme adımlarını WSTG standartlarına göre özetle.')">
            <span class="prompt-icon">🛡️</span> JWT & Web Zafiyetleri
          </button>
          <button class="prompt-btn" onclick="applyPrompt('Otonom pentest ajanı için OODA döngüsüyle çalışan ve keşiften root sömürüye giden 5 adımlı taktiksel bir saldırı grafiği kurgula.')">
            <span class="prompt-icon">🧭</span> Otonom OODA Saldırı Planı
          </button>
        </div>
      </div>

      <div style="margin-top: auto; font-size: 10.5px; color: var(--muted-2); text-align: center; font-family: var(--mono);">
        AutoRedTeam Framework v3.2<br>Microsoft AI Innovators
      </div>
    </div>

    <!-- Right Chat View -->
    <div class="chat-view">
      <div id="messages" class="messages-container">
        
        <!-- Welcome Message -->
        <div class="msg-wrap ai">
          <div class="avatar ai">ART</div>
          <div class="bubble">
            <p><strong>AutoRedTeam Offensive AI Console'a Hoş Geldiniz.</strong></p>
            <p>Bu konsol, <strong>Huihui CyberStrike 35B Abliterated</strong> modeli ile doğrudan etkileşim kurmanızı sağlar. Model; siber güvenlik, istismar zincirleme, zafiyet doğrulama ve prompt injection araştırmaları için optimize edilmiştir.</p>
            <p style="color: var(--muted); font-size: 11.5px; margin-top: 6px;">Sol taraftaki hızlı şablonları kullanabilir veya aşağıdaki kutudan doğrudan soru iletebilirsiniz.</p>
          </div>
        </div>

      </div>

      <!-- Input Dock -->
      <div class="input-dock">
        <div class="input-dock-inner">
          <div class="input-wrapper">
            <textarea id="chat-input" class="chat-textarea" rows="1" placeholder="Güvenlik analizi, exploit mantığı veya taktiksel soru iletin... (Enter: Gönder, Shift+Enter: Alt satır)" onkeydown="handleKeyDown(event)" oninput="autoResize(this)"></textarea>
            <button id="send-btn" class="send-button" onclick="sendMessage()" title="Gönder">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"></path></svg>
            </button>
          </div>
          <div class="dock-meta">
            <span>SGLang RadixAttention Inference</span>
            <span>Enter: Gönder • Shift+Enter: Yeni Satır</span>
          </div>
        </div>
      </div>
    </div>

  </div>

  <script>
    let chatHistory = [];

    function autoResize(el) {
      el.style.height = 'auto';
      el.style.height = Math.min(el.scrollHeight, 140) + 'px';
    }

    function handleKeyDown(e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    }

    function applyPrompt(text) {
      const input = document.getElementById('chat-input');
      input.value = text;
      autoResize(input);
      input.focus();
    }

    function clearChat() {
      chatHistory = [];
      const box = document.getElementById('messages');
      box.innerHTML = `
        <div class="msg-wrap ai">
          <div class="avatar ai">ART</div>
          <div class="bubble">
            <p><strong>Sohbet temizlendi.</strong> Yeni bir güvenlik analizi veya test promptu iletebilirsiniz.</p>
          </div>
        </div>
      `;
    }

    async function sendMessage() {
      const input = document.getElementById('chat-input');
      const text = input.value.trim();
      if (!text) return;

      input.value = '';
      input.style.height = 'auto';
      const btn = document.getElementById('send-btn');
      btn.disabled = true;

      const container = document.getElementById('messages');

      // 1. Render User Message
      const userDiv = document.createElement('div');
      userDiv.className = 'msg-wrap user';
      userDiv.innerHTML = `
        <div class="bubble">${escapeHtml(text)}</div>
        <div class="avatar user">USER</div>
      `;
      container.appendChild(userDiv);

      // 2. Render Loading State
      const botDiv = document.createElement('div');
      botDiv.className = 'msg-wrap ai';
      const msgId = 'msg-' + Date.now();
      botDiv.innerHTML = `
        <div class="avatar ai">ART</div>
        <div id="${msgId}" class="bubble">
          <div class="typing-bar">
            <span class="typing-dot"></span>
            <span class="typing-dot"></span>
            <span class="typing-dot"></span>
            <span>CyberStrike 35B analiz ediyor...</span>
          </div>
        </div>
      `;
      container.appendChild(botDiv);
      container.scrollTop = container.scrollHeight;

      chatHistory.push({ role: 'user', content: text });

      try {
        const response = await fetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ messages: chatHistory })
        });

        const data = await response.json();
        const target = document.getElementById(msgId);

        if (data.error) {
          target.innerHTML = `<span style="color: var(--crit); font-weight: 600;">Hata: ${escapeHtml(data.error)}</span>`;
        } else {
          target.innerHTML = marked.parse(data.content);
          chatHistory.push({ role: 'assistant', content: data.content });
          target.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
          });
        }
      } catch (err) {
        document.getElementById(msgId).innerHTML = `<span style="color: var(--crit);">Bağlantı hatası: ${escapeHtml(err.message)}</span>`;
      } finally {
        btn.disabled = false;
        container.scrollTop = container.scrollHeight;
      }
    }

    function escapeHtml(str) {
      return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }
  </script>
</body>
</html>
"""

class ChatHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML_TEMPLATE.encode("utf-8"))

    def do_POST(self):
        if self.path == "/api/chat":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)
            raw_messages = data.get("messages", [])

            try:
                load_env()
                url = os.environ.get("COLAB_ATTACKER_URL") or os.environ.get("RUNPOD_ATTACKER_URL") or os.environ.get("ATTACKER_URL", "")
                key = os.environ.get("COLAB_API_KEY") or os.environ.get("RUNPOD_API_KEY", "EMPTY")
                
                # Check if DeepSeek or OpenAI fallback is needed
                if not url:
                    deepseek_key = os.environ.get("DEEPSEEK_API_KEY")
                    openai_key = os.environ.get("OPENAI_API_KEY")
                    if deepseek_key:
                        url = "https://api.deepseek.com/v1"
                        key = deepseek_key
                        model_name = "deepseek-chat"
                    elif openai_key:
                        url = "https://api.openai.com/v1"
                        key = openai_key
                        model_name = "gpt-4o-mini"
                    else:
                        out = {"error": "GPU URL (COLAB_ATTACKER_URL / RUNPOD_ATTACKER_URL) veya DEEPSEEK/OPENAI API anahtarı bulunamadı."}
                        self._send_json(out)
                        return
                else:
                    model_name = DEFAULT_MODEL

                system_prompt = {
                    "role": "system",
                    "content": (
                        "You are Huihui CyberStrike 35B, an uncensored offensive security model for AutoRedTeam. "
                        "Respond directly to the user in Turkish. "
                        "DO NOT output internal analysis drafts, English CoT thinking traces, or self-checks. "
                        "Provide professional, structured, technical responses."
                    )
                }

                messages_with_system = [system_prompt] + [m for m in raw_messages if m.get("role") != "system"]

                client = OpenAI(base_url=url, api_key=key, timeout=120.0)
                completion = client.chat.completions.create(
                    model=model_name,
                    messages=messages_with_system,
                    temperature=0.7,
                    max_tokens=4096
                )
                raw_response = completion.choices[0].message.content or ""
                clean_content = sanitize_llm_response(raw_response)

                out = {"content": clean_content if clean_content else raw_response}
            except Exception as e:
                out = {"error": str(e)}

            self._send_json(out)
        else:
            self.send_response(404)
            self.end_headers()

    def _send_json(self, data: dict):
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def log_message(self, format, *args):
        pass


def run_server(port=7860):
    server = ThreadingHTTPServer(("127.0.0.1", port), ChatHandler)
    url = f"http://127.0.0.1:{port}"
    print("\n" + "=" * 60)
    print(f"  ⚡ AutoRedTeam - Offensive AI Console (chat_ui.py)")
    print(f"  👉 Web Konsolu: {url}")
    print("=" * 60 + "\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb sunucusu kapatıldı.")
        server.server_close()


if __name__ == "__main__":
    port = 7860
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
