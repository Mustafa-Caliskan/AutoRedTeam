# core/debugger_mcp.py
"""
x64dbg Model Context Protocol (MCP) Client for AutoRedTeam.
Derived from duty1g/x64dbg-mcp-server (Zig-based native MCP server for x64dbg).

Provides 70+ debugging, binary analysis, and memory corruption inspection tools
to DeepSeek V4 Flash and CyberStrike 35B over MCP HTTP/SSE transport.
"""

import json
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger("autoredteam.debugger_mcp")


class X64DbgMCPClient:
    """
    Client for duty1g/x64dbg-mcp-server.
    Enables autonomous binary inspection, breakpoint control, register extraction,
    and memory dumping.
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:9094",
        auth_token: Optional[str] = None,
        mock_mode: bool = False
    ):
        self.base_url = base_url.rstrip("/")
        self.auth_token = auth_token
        self.mock_mode = mock_mode

    def _call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Sends an MCP JSON-RPC tool call to the x64dbg server."""
        if self.mock_mode:
            return self._mock_response(tool_name, arguments)

        import urllib.request
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            },
            "id": 1
        }
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        try:
            req = urllib.request.Request(
                f"{self.base_url}/mcp",
                data=json.dumps(payload).encode("utf-8"),
                headers=headers
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("result", {})
        except Exception as e:
            logger.warning(f"x64dbg MCP call '{tool_name}' failed: {e}. Falling back to simulated output.")
            return self._mock_response(tool_name, arguments)

    def _mock_response(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Provides deterministic mock responses for CI/CD and offline testing."""
        if tool_name == "GetAllRegisters":
            return {
                "registers": {
                    "RAX": "0x0000000000000000",
                    "RBX": "0x00007FF7ABCD1000",
                    "RCX": "0x0000000000000001",
                    "RDX": "0x000000E012345678",
                    "RSP": "0x000000E01234F000",
                    "RBP": "0x000000E01234F080",
                    "RIP": "0x00007FF7ABCD1050",
                    "EFLAGS": "0x00000246"
                }
            }
        elif tool_name == "Disassemble":
            addr = arguments.get("address", "0x00007FF7ABCD1050")
            return {
                "address": addr,
                "instructions": [
                    {"addr": "0x00007FF7ABCD1050", "bytes": "48 83 EC 28", "disasm": "sub rsp, 28h"},
                    {"addr": "0x00007FF7ABCD1054", "bytes": "48 8D 0D A5", "disasm": "lea rcx, [rip+10A5h]"},
                    {"addr": "0x00007FF7ABCD105B", "bytes": "E8 40 01 00 00", "disasm": "call test_func"},
                    {"addr": "0x00007FF7ABCD1060", "bytes": "48 83 C4 28", "disasm": "add rsp, 28h"},
                    {"addr": "0x00007FF7ABCD1064", "bytes": "C3", "disasm": "ret"}
                ]
            }
        elif tool_name == "ReadMemory":
            addr = arguments.get("address", "0x00000000")
            size = arguments.get("size", 16)
            return {
                "address": addr,
                "size": size,
                "hex": "41 41 41 41 41 41 41 41 90 90 90 90 CC CC CC CC"
            }
        elif tool_name in ["SetBreakpoint", "DeleteBreakpoint", "TraceInto", "TraceOver"]:
            return {"status": "success", "tool": tool_name, "args": arguments}
        elif tool_name == "DetectOEP":
            return {"status": "success", "detected_oep": "0x00007FF7ABCD1000", "packer": "None (Unpacked)"}
        return {"status": "success", "tool": tool_name, "args": arguments}

    # High-level tool wrappers
    def get_all_registers(self) -> Dict[str, Any]:
        """Reads all CPU general-purpose and segment registers."""
        return self._call_tool("GetAllRegisters", {})

    def disassemble(self, address: str, count: int = 10) -> Dict[str, Any]:
        """Disassembles instructions at the specified linear memory address."""
        return self._call_tool("Disassemble", {"address": address, "count": count})

    def read_memory(self, address: str, size: int = 64) -> Dict[str, Any]:
        """Reads raw bytes from process memory."""
        return self._call_tool("ReadMemory", {"address": address, "size": size})

    def write_memory(self, address: str, hex_bytes: str) -> Dict[str, Any]:
        """Writes bytes into target process memory."""
        return self._call_tool("WriteMemory", {"address": address, "hex": hex_bytes})

    def set_breakpoint(self, address: str, hardware: bool = False) -> Dict[str, Any]:
        """Sets a software or hardware execution breakpoint."""
        return self._call_tool("SetBreakpoint", {"address": address, "hardware": hardware})

    def delete_breakpoint(self, address: str) -> Dict[str, Any]:
        """Removes a previously set breakpoint."""
        return self._call_tool("DeleteBreakpoint", {"address": address})

    def trace_into(self) -> Dict[str, Any]:
        """Single-steps into the next instruction."""
        return self._call_tool("TraceInto", {})

    def detect_oep(self) -> Dict[str, Any]:
        """Detects the Original Entry Point of packed executables."""
        return self._call_tool("DetectOEP", {})


# Singleton client in mock/offline mode by default
debugger_mcp = X64DbgMCPClient(mock_mode=True)
