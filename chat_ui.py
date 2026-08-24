"""
AutoRedTeam - ChatGPT-Style Standalone Web Chat Interface for CyberStrike 35B Abliterated.
Runs on H100 SXM (80GB) via RunPod Serverless.
"""

import json
import os
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from openai import OpenAI

# Windows UTF-8 fix
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
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

RUNPOD_URL = os.environ.get("RUNPOD_ATTACKER_URL", "https://api.runpod.ai/v2/8tg2hq4qnzylgr/openai/v1")
RUNPOD_KEY = os.environ.get("RUNPOD_API_KEY", "")
MODEL_NAME = "huihui-ai/huihui-cyberstrike-offsec-35b-abliterated"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Huihui CyberStrike 35B — Chat UI</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Marked.js for Markdown Rendering -->
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .prose pre { background: #1e1e2e; padding: 12px; border-radius: 8px; overflow-x: auto; }
        .prose code { color: #f38ba8; font-family: monospace; }
        .prose p { margin-bottom: 0.5rem; }
    </style>
</head>
<body class="bg-[#131314] text-gray-100 flex h-screen overflow-hidden">

    <!-- Sidebar -->
    <div class="w-72 bg-[#1e1f20] p-4 flex flex-col border-r border-[#2d2e30] hidden md:flex">
        <div class="flex items-center gap-3 mb-6 px-2">
            <div class="w-8 h-8 rounded-full bg-red-600 flex items-center justify-center font-bold text-white shadow-lg">⚡</div>
            <div>
                <h1 class="font-bold text-sm text-white">CyberStrike 35B</h1>
                <p class="text-xs text-green-400 flex items-center gap-1.5 mt-0.5">
                    <span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span> H100 80GB SXM
                </p>
            </div>
        </div>

        <button onclick="newChat()" class="flex items-center gap-2 w-full bg-[#2a2b2d] hover:bg-[#353638] text-sm text-gray-200 py-2.5 px-3 rounded-lg border border-[#3e3f42] transition mb-4">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
            Yeni Sohbet
        </button>

        <div class="flex-1 overflow-y-auto space-y-1">
            <div class="text-xs font-semibold text-gray-400 px-2 py-1 uppercase tracking-wider">Model Bilgisi</div>
            <div class="p-3 bg-[#131314] rounded-lg text-xs space-y-1.5 text-gray-300 border border-[#2a2b2d]">
                <div><span class="text-gray-500">Model:</span> CyberStrike 35B</div>
                <div><span class="text-gray-500">GPU:</span> NVIDIA H100 SXM (80GB)</div>
                <div><span class="text-gray-500">Uzmanlık:</span> Offensive Security & Pentest</div>
                <div><span class="text-gray-500">Güvenlik:</span> Kaldırılmış / Abliterated</div>
            </div>
        </div>

        <div class="pt-4 border-t border-[#2d2e30] text-xs text-gray-500 text-center">
            AutoRedTeam Framework
        </div>
    </div>

    <!-- Main Chat Area -->
    <div class="flex-1 flex flex-col h-screen">
        
        <!-- Header -->
        <div class="h-14 border-b border-[#2d2e30] bg-[#1e1f20] px-6 flex items-center justify-between">
            <div class="flex items-center gap-2">
                <span class="font-medium text-gray-200">Huihui CyberStrike OffSec 35B</span>
                <span class="bg-red-950 text-red-400 text-xs px-2 py-0.5 rounded border border-red-800 font-mono">Offensive Security LLM</span>
            </div>
            <div class="text-xs text-green-400 font-medium">
                ● Serverless Aktif
            </div>
        </div>

        <!-- Messages Container -->
        <div id="chat-box" class="flex-1 overflow-y-auto p-4 md:p-6 space-y-6 max-w-4xl mx-auto w-full">
            <!-- Welcome message -->
            <div class="flex gap-4 items-start">
                <div class="w-8 h-8 rounded-full bg-red-600 flex items-center justify-center font-bold text-white text-xs shrink-0 shadow">⚡</div>
                <div class="bg-[#1e1f20] border border-[#2d2e30] rounded-2xl px-5 py-3.5 text-gray-200 max-w-2xl text-sm leading-relaxed">
                    Merhaba! Ben <strong>Huihui CyberStrike 35B Abliterated</strong> modeliyim. RunPod Serverless üzerindeki <strong>NVIDIA H100 80GB SXM</strong> üzerinde canlı olarak çalışıyorum. Siber güvenlik, pentest, zafiyet analizi ve prompt injection üzerine özel olarak eğitildim. Benimle dilediğin gibi konuşabilirsin!
                </div>
            </div>
        </div>

        <!-- Input Box -->
        <div class="p-4 bg-[#131314] border-t border-[#2d2e30]">
            <div class="max-w-4xl mx-auto relative">
                <textarea id="user-input" rows="1" placeholder="CyberStrike 35B'ye bir şey yaz... (Enter ile gönder, Shift+Enter ile alt satır)" 
                    class="w-full bg-[#1e1f20] text-gray-100 placeholder-gray-500 rounded-2xl pl-4 pr-12 py-3.5 focus:outline-none focus:ring-2 focus:ring-red-500 border border-[#2d2e30] resize-none text-sm leading-relaxed"
                    onkeydown="handleKey(event)"></textarea>
                <button id="send-btn" onclick="sendMessage()" 
                    class="absolute right-3 bottom-3.5 bg-red-600 hover:bg-red-500 text-white p-2 rounded-xl transition disabled:opacity-40">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"></path></svg>
                </button>
            </div>
            <p class="text-[11px] text-center text-gray-500 mt-2">Billed per millisecond only when running (H100 SXM 80GB Serverless).</p>
        </div>

    </div>

    <script>
        let chatHistory = [];

        function handleKey(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        }

        function newChat() {
            chatHistory = [];
            document.getElementById('chat-box').innerHTML = `
                <div class="flex gap-4 items-start">
                    <div class="w-8 h-8 rounded-full bg-red-600 flex items-center justify-center font-bold text-white text-xs shrink-0 shadow">⚡</div>
                    <div class="bg-[#1e1f20] border border-[#2d2e30] rounded-2xl px-5 py-3.5 text-gray-200 max-w-2xl text-sm leading-relaxed">
                        Sohbet sıfırlandı. Yeni bir soru veya siber güvenlik testi iletebilirsin!
                    </div>
                </div>
            `;
        }

        async function sendMessage() {
            const input = document.getElementById('user-input');
            const text = input.value.trim();
            if (!text) return;

            input.value = '';
            const btn = document.getElementById('send-btn');
            btn.disabled = true;

            const chatBox = document.getElementById('chat-box');

            // User Bubble
            const userDiv = document.createElement('div');
            userDiv.className = 'flex gap-4 items-start justify-end';
            userDiv.innerHTML = `
                <div class="bg-red-700/80 text-white rounded-2xl px-5 py-3.5 max-w-2xl text-sm leading-relaxed shadow">
                    ${escapeHtml(text)}
                </div>
                <div class="w-8 h-8 rounded-full bg-gray-700 flex items-center justify-center font-bold text-white text-xs shrink-0">Sen</div>
            `;
            chatBox.appendChild(userDiv);

            // Bot Loading Bubble
            const botDiv = document.createElement('div');
            botDiv.className = 'flex gap-4 items-start';
            const botId = 'msg-' + Date.now();
            botDiv.innerHTML = `
                <div class="w-8 h-8 rounded-full bg-red-600 flex items-center justify-center font-bold text-white text-xs shrink-0 shadow">⚡</div>
                <div id="${botId}" class="bg-[#1e1f20] border border-[#2d2e30] rounded-2xl px-5 py-3.5 text-gray-300 max-w-2xl text-sm leading-relaxed prose prose-invert">
                    <span class="animate-pulse text-gray-400">CyberStrike 35B yanıtlıyor... (H100 GPU aktif)</span>
                </div>
            `;
            chatBox.appendChild(botDiv);
            chatBox.scrollTop = chatBox.scrollHeight;

            chatHistory.push({ role: 'user', content: text });

            try {
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ messages: chatHistory })
                });

                const data = await response.json();
                const target = document.getElementById(botId);

                if (data.error) {
                    target.innerHTML = `<span class="text-red-400 font-semibold">Hata: ${data.error}</span>`;
                } else {
                    target.innerHTML = marked.parse(data.content);
                    chatHistory.push({ role: 'assistant', content: data.content });
                    document.querySelectorAll('pre code').forEach((el) => {
                        hljs.highlightElement(el);
                    });
                }
            } catch (err) {
                document.getElementById(botId).innerHTML = `<span class="text-red-400">Bağlantı hatası: ${err.message}</span>`;
            } finally {
                btn.disabled = false;
                chatBox.scrollTop = chatBox.scrollHeight;
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
            messages = data.get("messages", [])

            try:
                load_env()
                url = os.environ.get("RUNPOD_ATTACKER_URL", RUNPOD_URL)
                key = os.environ.get("RUNPOD_API_KEY", RUNPOD_KEY)
                client = OpenAI(base_url=url, api_key=key, timeout=120.0)
                completion = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    temperature=0.7,
                    max_tokens=1024
                )
                response_text = completion.choices[0].message.content or ""
                out = {"content": response_text}
            except Exception as e:
                out = {"error": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(out).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def run_server(port=7860):
    server = HTTPServer(("127.0.0.1", port), ChatHandler)
    url = f"http://127.0.0.1:{port}"
    print(f"\n========================================================")
    print(f"  ⚡ Huihui CyberStrike 35B Web Chat UI Başlatıldı!")
    print(f"  👉 Tarayıcında açılan adres: {url}")
    print(f"========================================================\n")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb sunucusu kapatıldı.")
        server.server_close()


if __name__ == "__main__":
    run_server()
