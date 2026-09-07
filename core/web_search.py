"""
AutoRedTeam - Web Search Tool.

DeepSeek Orchestrator icin DuckDuckGo tabanli ucretsiz web aramasi.
"""

import logging
from typing import List

logger = logging.getLogger(__name__)


def web_search(query: str, max_results: int = 5) -> str:
    """
    DuckDuckGo uzerinden web aramasi yapar ve temiz metin ozeti dondurur.
    
    Args:
        query: Arama sorgusu (ornek: 'CVE-2024-1234 exploit details')
        max_results: Maksimum sonuc sayisi (varsayilan: 5)
    
    Returns:
        Temiz metin formatinda arama sonuclari ozeti.
    """
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        return (
            "[WEB_SEARCH ERROR]: 'duckduckgo-search' package not installed. "
            "Run: pip install duckduckgo-search"
        )

    try:
        results: List[dict] = []
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=max_results):
                results.append(r)

        if not results:
            return f"[WEB_SEARCH]: No results found for query: '{query}'"

        lines = [f"=== Web Search: '{query}' ===\n"]
        for i, r in enumerate(results, 1):
            title = r.get("title", "No title")
            body  = r.get("body", "")[:300]
            url   = r.get("href", "")
            lines.append(f"[{i}] {title}")
            lines.append(f"    {body}...")
            lines.append(f"    Source: {url}\n")

        return "\n".join(lines)

    except Exception as e:
        logger.error(f"Web search failed: {e}")
        return f"[WEB_SEARCH ERROR]: {e}"


# OpenAI-compatible tool schema (passed to DeepSeek as a tool)
WEB_SEARCH_TOOL_SCHEMA = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": (
            "Performs a real-time web search using DuckDuckGo to find fresh information "
            "about CVEs, exploits, vulnerabilities, software versions, and security advisories. "
            "Use this when you need up-to-date information beyond your training data cutoff."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "The search query. Be specific for better results. "
                        "Examples: 'CVE-2024-1234 PoC exploit', "
                        "'vsftpd 2.3.4 backdoor vulnerability', "
                        "'Apache 2.2.8 remote code execution 2024'"
                    )
                },
                "max_results": {
                    "type": "integer",
                    "description": "Number of results to return (1-10). Default is 5.",
                    "default": 5
                }
            },
            "required": ["query"]
        }
    }
}


def execute_tool_call(tool_name: str, arguments: dict) -> str:
    """Dispatches tool calls from the orchestrator."""
    if tool_name == "web_search":
        return web_search(
            query=arguments.get("query", ""),
            max_results=arguments.get("max_results", 5)
        )
    return f"[TOOL ERROR]: Unknown tool: {tool_name}"
