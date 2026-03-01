"""
Gideon MCP Security Tools Server

Provides security tools via Model Context Protocol (MCP) using SSE transport.
"""

import asyncio
import json
import subprocess
import shlex
from typing import Any
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel

app = FastAPI(title="Gideon MCP Security Tools")

# ============================================================================
# Tool Definitions
# ============================================================================

TOOLS = {
    "nmap": {
        "name": "nmap",
        "description": "Network exploration tool and security scanner. Discovers hosts, services, and vulnerabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP, hostname, or CIDR range"},
                "ports": {"type": "string", "description": "Port specification (e.g., '22,80,443' or '1-1000')"},
                "flags": {"type": "string", "description": "Additional nmap flags (e.g., '-sV -sC')"},
            },
            "required": ["target"],
        },
    },
    "nuclei": {
        "name": "nuclei",
        "description": "Fast vulnerability scanner with 8000+ templates for CVEs, misconfigurations, and exposures.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or file with URLs"},
                "templates": {"type": "string", "description": "Template tags to use (e.g., 'cves,misconfig')"},
                "severity": {"type": "string", "description": "Severity filter (critical,high,medium,low,info)"},
            },
            "required": ["target"],
        },
    },
    "httpx": {
        "name": "httpx",
        "description": "HTTP toolkit for probing, technology detection, and status checking.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or domain"},
                "flags": {"type": "string", "description": "Additional flags (e.g., '-tech-detect -status-code')"},
            },
            "required": ["target"],
        },
    },
    "katana": {
        "name": "katana",
        "description": "Web crawler for discovering endpoints, JavaScript files, and resources.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to crawl"},
                "depth": {"type": "integer", "description": "Crawl depth (default: 3)"},
                "flags": {"type": "string", "description": "Additional flags"},
            },
            "required": ["target"],
        },
    },
    "subfinder": {
        "name": "subfinder",
        "description": "Subdomain discovery tool using passive sources (certificate transparency, DNS, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain for subdomain enumeration"},
                "flags": {"type": "string", "description": "Additional flags"},
            },
            "required": ["domain"],
        },
    },
    "ffuf": {
        "name": "ffuf",
        "description": "Fast web fuzzer for directory and parameter discovery.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with FUZZ keyword"},
                "wordlist": {"type": "string", "description": "Wordlist path (default: common.txt)"},
                "flags": {"type": "string", "description": "Additional flags"},
            },
            "required": ["url"],
        },
    },
    "whois": {
        "name": "whois",
        "description": "Query WHOIS information for domains and IP addresses.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or IP to query"},
            },
            "required": ["target"],
        },
    },
    "dig": {
        "name": "dig",
        "description": "DNS lookup utility for querying DNS records.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to query"},
                "record_type": {"type": "string", "description": "Record type (A, AAAA, MX, NS, TXT, etc.)"},
            },
            "required": ["domain"],
        },
    },
}

# ============================================================================
# Tool Execution
# ============================================================================

async def execute_tool(name: str, arguments: dict) -> dict:
    """Execute a security tool and return the result."""

    if name not in TOOLS:
        return {"error": f"Unknown tool: {name}"}

    try:
        if name == "nmap":
            cmd = build_nmap_command(arguments)
        elif name == "nuclei":
            cmd = build_nuclei_command(arguments)
        elif name == "httpx":
            cmd = build_httpx_command(arguments)
        elif name == "katana":
            cmd = build_katana_command(arguments)
        elif name == "subfinder":
            cmd = build_subfinder_command(arguments)
        elif name == "ffuf":
            cmd = build_ffuf_command(arguments)
        elif name == "whois":
            cmd = ["whois", arguments.get("target", "")]
        elif name == "dig":
            record_type = arguments.get("record_type", "A")
            cmd = ["dig", "+short", arguments.get("domain", ""), record_type]
        else:
            return {"error": f"Tool not implemented: {name}"}

        # Execute command with timeout
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=300  # 5 minute timeout
        )

        return {
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "returncode": process.returncode,
        }

    except asyncio.TimeoutError:
        return {"error": "Command timed out after 5 minutes"}
    except Exception as e:
        return {"error": str(e)}


def build_nmap_command(args: dict) -> list:
    """Build nmap command from arguments."""
    cmd = ["nmap"]

    if args.get("ports"):
        cmd.extend(["-p", args["ports"]])

    if args.get("flags"):
        cmd.extend(shlex.split(args["flags"]))
    else:
        # Default: service version detection
        cmd.append("-sV")

    cmd.append(args["target"])
    return cmd


def build_nuclei_command(args: dict) -> list:
    """Build nuclei command from arguments."""
    cmd = ["nuclei", "-u", args["target"], "-json"]

    if args.get("templates"):
        cmd.extend(["-tags", args["templates"]])

    if args.get("severity"):
        cmd.extend(["-severity", args["severity"]])

    return cmd


def build_httpx_command(args: dict) -> list:
    """Build httpx command from arguments."""
    cmd = ["httpx", "-u", args["target"], "-json"]

    if args.get("flags"):
        cmd.extend(shlex.split(args["flags"]))
    else:
        cmd.extend(["-status-code", "-tech-detect", "-title"])

    return cmd


def build_katana_command(args: dict) -> list:
    """Build katana command from arguments."""
    cmd = ["katana", "-u", args["target"], "-json"]

    if args.get("depth"):
        cmd.extend(["-d", str(args["depth"])])

    if args.get("flags"):
        cmd.extend(shlex.split(args["flags"]))

    return cmd


def build_subfinder_command(args: dict) -> list:
    """Build subfinder command from arguments."""
    cmd = ["subfinder", "-d", args["domain"], "-json"]

    if args.get("flags"):
        cmd.extend(shlex.split(args["flags"]))

    return cmd


def build_ffuf_command(args: dict) -> list:
    """Build ffuf command from arguments."""
    wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    cmd = ["ffuf", "-u", args["url"], "-w", wordlist, "-json"]

    if args.get("flags"):
        cmd.extend(shlex.split(args["flags"]))

    return cmd


# ============================================================================
# MCP Protocol Handlers
# ============================================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/sse")
async def sse_endpoint(request: Request):
    """SSE endpoint for MCP communication."""

    async def event_generator():
        # Send server info
        yield {
            "event": "message",
            "data": json.dumps({
                "jsonrpc": "2.0",
                "method": "server/info",
                "params": {
                    "name": "gideon-mcp-security",
                    "version": "1.0.0",
                    "capabilities": {
                        "tools": True,
                        "resources": False,
                        "prompts": False,
                        "logging": True,
                    },
                },
            }),
        }

        # Keep connection alive
        while True:
            if await request.is_disconnected():
                break
            await asyncio.sleep(30)
            yield {"event": "ping", "data": ""}

    return EventSourceResponse(event_generator())


@app.post("/tools/list")
async def list_tools():
    """List available tools."""
    return {
        "jsonrpc": "2.0",
        "result": {
            "tools": list(TOOLS.values()),
        },
    }


class ToolCallRequest(BaseModel):
    name: str
    arguments: dict = {}


@app.post("/tools/call")
async def call_tool(request: ToolCallRequest):
    """Execute a tool."""
    result = await execute_tool(request.name, request.arguments)

    if "error" in result:
        return {
            "jsonrpc": "2.0",
            "result": {
                "content": [{"type": "text", "text": f"Error: {result['error']}"}],
                "isError": True,
            },
        }

    output = result.get("stdout", "")
    if result.get("stderr"):
        output += f"\n\nStderr:\n{result['stderr']}"

    return {
        "jsonrpc": "2.0",
        "result": {
            "content": [{"type": "text", "text": output}],
            "isError": result.get("returncode", 0) != 0,
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
