"""Minimal, dependency-free MCP clients: stdio and Streamable HTTP.

Both speak JSON-RPC 2.0 and expose the same surface (start / initialize /
list_tools / call_tool / close / result_text). MCPClient spawns a local server
and talks newline-delimited JSON over its stdin/stdout. MCPHTTPClient POSTs to a
Streamable-HTTP endpoint and reads either a JSON body or a text/event-stream (SSE)
reply, so hosted scanning can reach a remote MCP server with no local process.
"""
from __future__ import annotations

import json
import os
import select
import shlex
import subprocess
import time
import urllib.error
import urllib.request

PROTOCOL_VERSION = "2024-11-05"


class MCPError(RuntimeError):
    pass


class MCPClient:
    def __init__(self, command, env: dict | None = None, cwd: str | None = None,
                 timeout: float = 30.0, wall_clock: float = 120.0):
        self.command = shlex.split(command) if isinstance(command, str) else list(command)
        # Minimal environment: the server under test is untrusted and must never
        # receive REDLINE_AUDIT_KEY, cloud credentials, or the rest of os.environ.
        base = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR",
                                           "SystemRoot", "USERPROFILE") if k in os.environ}
        self.env = {**base, **(env or {})}
        self.cwd = cwd
        self.wall_clock = wall_clock
        self._deadline = None
        self._buf = b""
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self._id = 0
        self.server_info: dict = {}

    # -- lifecycle --
    def start(self):
        try:
            self.proc = subprocess.Popen(
                self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=0,
                env=self.env, cwd=self.cwd)
            self._deadline = time.time() + self.wall_clock
        except (FileNotFoundError, OSError) as e:
            raise MCPError(f"failed to launch MCP server: {e}") from e
        return self

    def close(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.close()
            except Exception:
                pass
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.close()

    # -- transport --
    def _write(self, obj: dict):
        if not self.proc or self.proc.poll() is not None:
            raise MCPError("MCP server process is not running")
        line = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
        try:
            self.proc.stdin.write(line)
            self.proc.stdin.flush()
        except (BrokenPipeError, ValueError, OSError) as e:
            raise MCPError(f"MCP server closed the connection: {e}") from e

    def _read_line(self, deadline: float) -> str:
        fd = self.proc.stdout.fileno()
        while True:
            # Serve a complete line already sitting in our buffer before blocking on select,
            # so a server that writes several messages in one syscall doesn't stall us.
            nl = self._buf.find(b"\n")
            if nl >= 0:
                line, self._buf = self._buf[:nl], self._buf[nl + 1:]
                if line.strip():
                    return line.decode("utf-8", "ignore")
                continue
            if len(self._buf) > 8 * 1024 * 1024:
                raise MCPError("MCP server line exceeded 8 MiB")
            remaining = min(deadline, self._deadline) - time.time()
            if remaining <= 0:
                raise MCPError("timed out waiting for MCP server response")
            r, _, _ = select.select([fd], [], [], remaining)
            if not r:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError as e:
                raise MCPError(f"MCP read failed: {e}") from e
            if chunk == b"":
                raise MCPError("MCP server closed stdout")
            self._buf += chunk

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        rid = self._id
        self._write({"jsonrpc": "2.0", "id": rid, "method": method,
                     "params": params or {}})
        deadline = time.time() + self.timeout
        while True:
            line = self._read_line(deadline)
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip non-JSON noise
            if msg.get("id") != rid:
                continue  # skip notifications / other ids
            if "error" in msg:
                raise MCPError(f"{method}: {msg['error'].get('message', msg['error'])}")
            return msg.get("result", {})

    def _notify(self, method: str, params: dict | None = None):
        self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    # -- MCP methods --
    def initialize(self) -> dict:
        res = self._rpc("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "redline", "version": "0.3"},
        })
        self.server_info = res.get("serverInfo", {})
        self._notify("notifications/initialized")
        return res

    def list_tools(self) -> list[dict]:
        return self._rpc("tools/list", {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> dict:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    @staticmethod
    def result_text(result: dict) -> str:
        return _result_text(result)


def _result_text(result: dict) -> str:
    """Flatten a tools/call result's content array to text."""
    parts = []
    for c in result.get("content", []) or []:
        if isinstance(c, dict):
            parts.append(c.get("text", "") or json.dumps(c))
        else:
            parts.append(str(c))
    if result.get("isError"):
        parts.append("[isError]")
    return "\n".join(parts)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):   # refuse redirects (SSRF safety)
        return None


class MCPHTTPClient:
    """MCP over Streamable HTTP. The endpoint receives JSON-RPC via POST and replies
    with application/json or text/event-stream. No process is spawned."""

    def __init__(self, url: str, headers: dict | None = None, timeout: float = 30.0):
        self.url = url
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.session_id: str | None = None
        self.server_info: dict = {}
        self._id = 0
        self._opener = urllib.request.build_opener(_NoRedirect)

    @property
    def name(self) -> str:
        return self.url

    def start(self):
        return self

    def close(self):
        return None

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.close()

    def _post(self, obj: dict, is_notification: bool = False):
        body = json.dumps(obj, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream", **self.headers}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            resp = self._opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            raise MCPError(f"MCP HTTP {e.code}: {e.reason}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise MCPError(f"MCP HTTP request failed: {type(e).__name__}: {e}") from e
        with resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid:
                self.session_id = sid
            if is_notification:
                return None
            ctype = (resp.headers.get("Content-Type") or "").lower()
            rid = obj.get("id")
            deadline = time.time() + self.timeout
            if "text/event-stream" in ctype:
                return self._read_sse(resp, rid, deadline)
            raw = resp.read(8 * 1024 * 1024)
            try:
                msg = json.loads(raw or b"{}")
            except json.JSONDecodeError as e:
                raise MCPError(f"invalid JSON from MCP endpoint: {e}") from e
            return self._unwrap(msg, rid)

    def _read_sse(self, resp, rid, deadline):
        data_lines: list[str] = []
        for raw in resp:
            if time.time() > deadline:
                raise MCPError("timed out reading MCP SSE stream")
            line = raw.decode("utf-8", "ignore").rstrip("\n").rstrip("\r")
            if line == "":
                if data_lines:
                    try:
                        msg = json.loads("\n".join(data_lines))
                    except json.JSONDecodeError:
                        data_lines = []
                        continue
                    data_lines = []
                    if isinstance(msg, dict) and msg.get("id") == rid:
                        return self._unwrap(msg, rid)
                continue
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        raise MCPError("MCP SSE stream ended without a response")

    @staticmethod
    def _unwrap(msg: dict, rid) -> dict:
        if "error" in msg:
            err = msg["error"]
            raise MCPError(f"{err.get('message', err)}")
        return msg.get("result", {})

    def initialize(self) -> dict:
        res = self._post({"jsonrpc": "2.0", "id": self._next(), "method": "initialize",
                          "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                     "clientInfo": {"name": "redline", "version": "0.6"}}})
        self.server_info = (res or {}).get("serverInfo", {})
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                   is_notification=True)
        return res

    def list_tools(self) -> list[dict]:
        return (self._post({"jsonrpc": "2.0", "id": self._next(), "method": "tools/list",
                            "params": {}}) or {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> dict:
        return self._post({"jsonrpc": "2.0", "id": self._next(), "method": "tools/call",
                          "params": {"name": name, "arguments": arguments}}) or {}

    def _next(self) -> int:
        self._id += 1
        return self._id

    @staticmethod
    def result_text(result: dict) -> str:
        return _result_text(result)
