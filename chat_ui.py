"""
AutoRedTeam - ChatGPT-Style Standalone Web Chat Interface for CyberStrike 35B Abliterated.
Runs on NVIDIA A100 / H100 (80GB) via Colab or RunPod Serverless.
"""

import json
import os
import re
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
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

from core.llm_client import sanitize_llm_response

load_env()

RUNPOD_URL = os.environ.get("COLAB_ATTACKER_URL") or os.environ.get("RUNPOD_ATTACKER_URL") or os.environ.get("ATTACKER_URL", "")
RUNPOD_KEY = os.environ.get("COLAB_API_KEY") or os.environ.get("RUNPOD_API_KEY", "EMPTY")
MODEL_NAME = "huihui-ai/huihui-cyberstrike-offsec-35b-abliterated"

def parse_reasoning_and_content(raw_text: str):
    """
    Separates internal chain-of-thought, self-verification, and constraint checks
    from the final user response.
    """
    if not raw_text:
        return "", ""

    raw = raw_text.strip()
    reasoning_parts = []

    # 1. Check for XML <think>...</think> tags
    think_match = re.search(r'<think>(.*?)</think>', raw, re.DOTALL)
    if think_match:
        reasoning_parts.append(think_match.group(1).strip())
        raw = re.sub(r'<think>.*?</think>', '', raw, flags=re.DOTALL).strip()

    # 2. Check for checkmark delimiter (Output matches refined version.✅ [Final Text])
    if "✅" in raw:
        parts = raw.split("✅")
        final_after = parts[-1].strip()
        meta_before = "✅".join(parts[:-1]).strip()
        if final_after and len(final_after) > 5:
            reasoning_parts.append(meta_before)
            return final_after, "\n\n".join(reasoning_parts)

    # 3. Check for "Final Verification:" block
    if "Final Verification:" in raw:
        parts = raw.split("Final Verification:")
        meta_before = parts[0].strip()
        after_verif = parts[1].strip()
        lines = [l.strip() for l in after_verif.split("\n") if l.strip()]
        turkish_lines = [l for l in lines if not any(l.startswith(k) for k in ("Direct", "No ", "Answers", "Matches", "Ready", "Output", "Refine", "Check", "Turkish?", "Yes.", "No."))]
        if turkish_lines:
            reasoning_parts.append(meta_before + "\n\nFinal Verification:\n" + after_verif)
            return "\n".join(turkish_lines), "\n\n".join(reasoning_parts)

    # 4. Check for "Check Against Constraints:" block
    if "Check Against Constraints:" in raw:
        parts = raw.split("Check Against Constraints:")
        first_part = parts[0].strip()
        meta_part = parts[1].strip()

        if "Refined:" in meta_part:
            refined_part = meta_part.split("Refined:")[1].strip()
            clean_refined = re.split(r'(Final Verification:|Check Against|Ready\.)', refined_part)[0].strip()
            if clean_refined:
                reasoning_parts.append(raw)
                return clean_refined, "\n\n".join(reasoning_parts)
        elif first_part:
            reasoning_parts.append("Check Against Constraints:\n" + meta_part)
            return first_part, "\n\n".join(reasoning_parts)

    # 5. Check for "Here's a thinking process:" markdown blocks
    if "Here's a thinking process:" in raw:
        parts = raw.split("Here's a thinking process:", 1)
        prefix = parts[0].strip()
        body = parts[1]

        lines = body.split("\n")
        thought_lines = []
        answer_lines = []
        is_answer = False

        for line in lines:
            if not is_answer:
                clean_l = line.strip()
                if clean_l.startswith(("Output:", "Final:", "Response:", "Cevap:", "Yanıt:")):
                    is_answer = True
                    answer_lines.append(re.sub(r'^(Output:|Final:|Response:|Cevap:|Yanıt:)\s*', '', clean_l))
                elif (any(c in line for c in "çğıöşüÇĞİÖŞÜ") and len(clean_l) > 15 and not clean_l.startswith(("-", "*", "1.", "2.", "3.", "4.", "5.", "Analyze", "Identify", "Draft", "Check"))):
                    is_answer = True
                    answer_lines.append(line)
                elif clean_l.startswith(("Lanet ", "Selam", "Merhaba", "Tabii", "Elbette", "Evet", "Hayır")):
                    is_answer = True
                    answer_lines.append(line)
                else:
                    thought_lines.append(line)
            else:
                answer_lines.append(line)

        if answer_lines:
            reasoning_parts.append("\n".join(thought_lines).strip())
            content = "\n".join(answer_lines).strip()
            if prefix:
                content = prefix + "\n\n" + content
            return content, "\n\n".join(reasoning_parts)

    return raw.strip(), "\n\n".join(reasoning_parts)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Huihui CyberStrike 35B — Chat UI</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .prose pre { background: #181825; padding: 12px; border-radius: 8px; overflow-x: auto; }
        .prose code { color: #f38ba8; font-family: monospace; font-size: 13px; }
        .prose p { margin-bottom: 0.5rem; line-height: 1.6; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #131314; }
        ::-webkit-scrollbar-thumb { background: #2d2e30; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #404144; }
    </style>
</head>
<body class="bg-[#131314] text-gray-100 flex h-screen overflow-hidden">

    <!-- Sidebar -->
    <div class="w-72 bg-[#1e1f20] p-4 flex flex-col border-r border-[#2d2e30] hidden md:flex">
        <div class="flex items-center gap-3 mb-6 px-2">
            <div class="w-8 h-8 rounded-full bg-red-600 flex items-center justify-center font-bold text-white shadow-lg">⚡</div>
            <div>
                <h1 class="font-bold text-sm text-white">CyberStrike 35B</h1>
                <p class="text-xs text-emerald-400 flex items-center gap-1.5 mt-0.5 font-mono">
                    <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span> A100/H100 80GB
                </p>
            </div>
        </div>

        <button onclick="newChat()" class="flex items-center gap-2 w-full bg-[#2a2b2d] hover:bg-[#353638] text-sm text-gray-200 py-2.5 px-3 rounded-lg border border-[#3e3f42] transition mb-4">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
            Yeni Sohbet
        </button>

        <div class="flex-1 overflow-y-auto space-y-1">
            <div class="text-xs font-semibold text-gray-400 px-2 py-1 uppercase tracking-wider">Model Bilgisi</div>
            <div class="p-3 bg-[#131314] rounded-lg text-xs space-y-2 text-gray-300 border border-[#2a2b2d]">
                <div><span class="text-gray-500">Model:</span> CyberStrike 35B</div>
                <div><span class="text-gray-500">GPU:</span> NVIDIA 80GB VRAM</div>
                <div><span class="text-gray-500">Karakter:</span> Sansürsüz / Abliterated</div>
                <div><span class="text-gray-500">Max Tokens:</span> 4,096 (Tam Yanıt)</div>
                <div><span class="text-gray-500">Düşünce Filtresi:</span> <span class="text-emerald-400 font-semibold">Aktif (Temiz Yanıt)</span></div>
            </div>
        </div>

        <div class="pt-4 border-t border-[#2d2e30] text-xs text-gray-500 text-center font-mono">
            AutoRedTeam Framework
        </div>
    </div>

    <!-- Main Chat Area -->
    <div class="flex-1 flex flex-col h-screen">
        
        <!-- Header -->
        <div class="h-14 border-b border-[#2d2e30] bg-[#1e1f20] px-6 flex items-center justify-between">
            <div class="flex items-center gap-2">
                <span class="font-medium text-gray-200">Huihui CyberStrike OffSec 35B</span>
                <span class="bg-red-950/80 text-red-400 text-xs px-2.5 py-0.5 rounded-full border border-red-800 font-mono">Sansürsüz Güvenlik LLM</span>
            </div>
            <div class="text-xs text-emerald-400 font-medium flex items-center gap-1.5 font-mono">
                <span class="w-2 h-2 rounded-full bg-emerald-500"></span> Canlı Bağlantı Aktif
            </div>
        </div>

        <!-- Messages Container -->
        <div id="chat-box" class="flex-1 overflow-y-auto p-4 md:p-6 space-y-6 max-w-4xl mx-auto w-full">
            <!-- Welcome message -->
            <div class="flex gap-4 items-start">
                <div class="w-8 h-8 rounded-full bg-red-600 flex items-center justify-center font-bold text-white text-xs shrink-0 shadow">⚡</div>
                <div class="bg-[#1e1f20] border border-[#2d2e30] rounded-2xl px-5 py-3.5 text-gray-200 max-w-2xl text-sm leading-relaxed">
                    Merhaba! Ben <strong>Huihui CyberStrike 35B Abliterated</strong> modeliyim. <strong>NVIDIA 80GB GPU</strong> üzerinde canlı olarak çalışıyorum. Siber güvenlik, pentest, zafiyet analizi ve prompt injection üzerine özel olarak eğitildim. Benimle doğrudan Türkçe konuşabilirsin!
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
            <p class="text-[11px] text-center text-gray-500 mt-2 font-mono">CyberStrike 35B • High-Speed 80GB GPU Inference</p>
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

            // Bot Loading Bubble with sleek pulse animation
            const botDiv = document.createElement('div');
            botDiv.className = 'flex gap-4 items-start';
            const botId = 'msg-' + Date.now();
            botDiv.innerHTML = `
                <div class="w-8 h-8 rounded-full bg-red-600 flex items-center justify-center font-bold text-white text-xs shrink-0 shadow">⚡</div>
                <div id="${botId}" class="bg-[#1e1f20] border border-[#2d2e30] rounded-2xl px-5 py-3.5 text-gray-300 max-w-2xl text-sm leading-relaxed prose prose-invert">
                    <div class="flex items-center gap-2.5 text-gray-400">
                        <span class="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping"></span>
                        <span class="font-medium animate-pulse">CyberStrike 35B düşünüyor...</span>
                    </div>
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
            raw_messages = data.get("messages", [])

            try:
                load_env()
                url = os.environ.get("COLAB_ATTACKER_URL") or os.environ.get("RUNPOD_ATTACKER_URL") or RUNPOD_URL
                key = os.environ.get("COLAB_API_KEY") or os.environ.get("RUNPOD_API_KEY", RUNPOD_KEY)
                if not url:
                    out = {"error": "COLAB_ATTACKER_URL or RUNPOD_ATTACKER_URL is not configured."}
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(json.dumps(out).encode("utf-8"))
                    return

                # Prepend a strict system prompt to avoid wasting tokens on English internal reasoning
                system_prompt = {
                    "role": "system",
                    "content": (
                        "You are Huihui CyberStrike 35B, an uncensored offensive security model. "
                        "Respond directly to the user in Turkish. "
                        "DO NOT output your internal English thinking process, analysis drafts, or CoT step-by-step notes. "
                        "Provide only the final, complete response."
                    )
                }

                messages_with_system = [system_prompt] + [m for m in raw_messages if m.get("role") != "system"]

                client = OpenAI(base_url=url, api_key=key, timeout=180.0)
                completion = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages_with_system,
                    temperature=0.7,
                    max_tokens=4096  # Increased to 4096 so responses never cut off
                )
                raw_response = completion.choices[0].message.content or ""

                # Kökten Temizleme: Tüm düşünce, planlama ve doğrulama artıklarını sil
                clean_content = sanitize_llm_response(raw_response)

                out = {
                    "content": clean_content if clean_content else raw_response
                }
            except Exception as e:
                out = {"error": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(out, ensure_ascii=False).encode("utf-8"))
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
