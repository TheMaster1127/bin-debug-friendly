# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import os
import re
import select
import shlex
import socket
import subprocess
import time
from pathlib import Path

from src.config import GDB_CMD_TIMEOUT_S

MI_EMBEDDED_RE = re.compile(r"(\*(?:stopped|running)|=(?:thread-|library-|breakpoint-)|\^(?:done|running|error|exit))")


class MIParser:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.length = len(text)

    def skip_ws(self):
        while self.pos < self.length and self.text[self.pos] in " \t":
            self.pos += 1

    def parse_c_string(self) -> str:
        assert self.text[self.pos] == '"'
        self.pos += 1
        out = []
        while self.pos < self.length:
            ch = self.text[self.pos]
            self.pos += 1
            if ch == '"':
                return "".join(out)
            if ch == "\\" and self.pos < self.length:
                esc = self.text[self.pos]
                self.pos += 1
                if esc == "n":
                    out.append("\n")
                elif esc == "t":
                    out.append("\t")
                elif esc == "r":
                    out.append("\r")
                elif esc == "\\":
                    out.append("\\")
                elif esc == '"':
                    out.append('"')
                else:
                    out.append(esc)
            else:
                out.append(ch)
        return "".join(out)

    def parse_value(self):
        self.skip_ws()
        if self.pos >= self.length:
            return ""
        ch = self.text[self.pos]
        if ch == '"':
            return self.parse_c_string()
        if ch == "{":
            return self.parse_tuple()
        if ch == "[":
            return self.parse_list()
        start = self.pos
        while self.pos < self.length and self.text[self.pos] not in ",}]":
            self.pos += 1
        return self.text[start:self.pos].strip()

    def parse_tuple(self) -> dict:
        self.pos += 1
        res = {}
        while self.pos < self.length:
            self.skip_ws()
            if self.pos < self.length and self.text[self.pos] == "}":
                self.pos += 1
                return res
            k, v = self.parse_result()
            if k:
                res[k] = v
            self.skip_ws()
            if self.pos < self.length and self.text[self.pos] == ",":
                self.pos += 1
        return res

    def parse_list(self) -> list:
        self.pos += 1
        items = []
        while self.pos < self.length:
            self.skip_ws()
            if self.pos < self.length and self.text[self.pos] == "]":
                self.pos += 1
                return items
            eq_idx = self.text.find("=", self.pos)
            next_special = min(
                [i for i in (
                    self.text.find('"', self.pos),
                    self.text.find("{", self.pos),
                    self.text.find("[", self.pos),
                    self.text.find("]", self.pos),
                ) if i != -1]
                or [self.length]
            )
            if eq_idx != -1 and eq_idx < next_special:
                k, v = self.parse_result()
                items.append({k: v})
            else:
                items.append(self.parse_value())
            self.skip_ws()
            if self.pos < self.length and self.text[self.pos] == ",":
                self.pos += 1
        return items

    def parse_result(self) -> tuple[str, object]:
        self.skip_ws()
        start = self.pos
        while self.pos < self.length and self.text[self.pos] not in "=,}":
            self.pos += 1
        key = self.text[start:self.pos].strip()
        if self.pos < self.length and self.text[self.pos] == "=":
            self.pos += 1
            val = self.parse_value()
            return key, val
        return key, None

    def parse_record_body(self) -> dict:
        res = {}
        while self.pos < self.length:
            self.skip_ws()
            if self.text[self.pos] == ",":
                self.pos += 1
                continue
            k, v = self.parse_result()
            if k:
                res[k] = v
        return res


def parse_mi_lines(line: str) -> list[tuple[str, str, object]]:
    raw_line = line.rstrip("\r\n")
    if not raw_line:
        return []
    if raw_line == "(gdb)" or raw_line == "(gdb) ":
        return [("prompt", "", "")]

    prefix = raw_line[0]
    if prefix in ("~", "@", "&"):
        p = MIParser(raw_line[1:])
        try:
            return [(prefix, "", p.parse_c_string())]
        except Exception:
            return [(prefix, "", raw_line[1:])]
    if prefix in ("^", "*", "+", "="):
        rest = raw_line[1:]
        comma = rest.find(",")
        if comma == -1:
            return [(prefix, rest.strip(), {})]
        cls = rest[:comma].strip()
        body = rest[comma + 1:]
        try:
            return [(prefix, cls, MIParser(body).parse_record_body())]
        except Exception:
            return [(prefix, cls, {"raw": body})]

    m = MI_EMBEDDED_RE.search(raw_line)
    if m and m.start() > 0:
        out_part = raw_line[:m.start()]
        mi_part = raw_line[m.start():]
        return [("raw", "", out_part)] + parse_mi_lines(mi_part)

    return [("raw", "", line)]


class MIProtocol:
    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self._read_buf = bytearray()
        self.target_output_buffer: list[str] = []
        self.all_target_output: list[str] = []
        self._stdin_fifo_host: Path | None = None
        self._stdin_fifo_fd: int | None = None
        self.stdin_queued_lines = 0

    def _append_target_output(self, text: str) -> None:
        self.target_output_buffer.append(text)
        self.all_target_output.append(text)

    def clear_target_output_history(self) -> None:
        self.target_output_buffer.clear()
        self.all_target_output.clear()

    def get_all_target_stdout(self) -> str:
        return "".join(self.all_target_output)

    def setup_target_stdin_fifo(self, work_dir: Path, sandbox_enabled: bool) -> str:
        self._stdin_fifo_host = work_dir / "target_stdin"
        if not self._stdin_fifo_host.exists():
            os.mkfifo(self._stdin_fifo_host)
        self._stdin_fifo_fd = os.open(self._stdin_fifo_host, os.O_RDWR | os.O_NONBLOCK)
        return "/tmp/work/target_stdin" if sandbox_enabled else str(self._stdin_fifo_host)

    def write_target_stdin(self, text: str) -> None:
        if self._stdin_fifo_fd is None:
            return
        payload = text if text.endswith("\n") else (text + "\n")
        os.write(self._stdin_fifo_fd, payload.encode("utf-8", errors="replace"))
        self.stdin_queued_lines += 1

    def drain_target_stdin(self) -> None:
        if self._stdin_fifo_fd is None:
            return
        self.stdin_queued_lines = 0
        self.clear_target_output_history()
        while True:
            try:
                chunk = os.read(self._stdin_fifo_fd, 4096)
                if not chunk:
                    break
            except BlockingIOError:
                break
            except OSError:
                break

    def spawn_gdb_process(
        self,
        sandbox,
        work_dir: Path,
        gdb_bin: str,
        target_path_in_gdb: str,
        use_qemu: bool,
        qemu_bin: str | None,
        target_args: list[str],
    ) -> tuple[int | None, str]:
        stdin_path_in_gdb = self.setup_target_stdin_fifo(work_dir, sandbox.enabled)
        qemu_port: int | None = None
        if use_qemu:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                qemu_port = s.getsockname()[1]

            args_str = " ".join(shlex.quote(a) for a in target_args)
            wrapper = work_dir / "run_qemu_gdb.sh"
            wrapper_script = (
                "#!/bin/sh\n"
                f"{shlex.quote(qemu_bin)} -g {qemu_port} {shlex.quote(target_path_in_gdb)} {args_str} < {shlex.quote(stdin_path_in_gdb)} &\n"
                "sleep 0.2\n"
                f"exec {shlex.quote(gdb_bin)} --interpreter=mi2 -q {shlex.quote(target_path_in_gdb)}\n"
            )
            wrapper.write_text(wrapper_script, encoding="utf-8")
            os.chmod(wrapper, 0o755)
            inner_cmd = ["/tmp/work/run_qemu_gdb.sh" if sandbox.enabled else str(wrapper)]
        else:
            inner_cmd = [gdb_bin, "--interpreter=mi2", "-q", target_path_in_gdb]

        if sandbox.enabled:
            full_cmd = sandbox.build_bwrap_prefix(work_dir, allow_loopback=use_qemu) + inner_cmd
        else:
            full_cmd = inner_cmd

        self.proc = subprocess.Popen(
            full_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        self._read_buf.clear()
        self._read_until_prompt()
        return qemu_port, stdin_path_in_gdb

    def close_process(self) -> None:
        if self._stdin_fifo_fd is not None:
            try:
                os.close(self._stdin_fifo_fd)
            except OSError:
                pass
            self._stdin_fifo_fd = None
        if self.proc:
            if self.proc.poll() is None:
                try:
                    if self.proc.stdin:
                        self.proc.stdin.write(b"-gdb-exit\n")
                        self.proc.stdin.flush()
                    self.proc.wait(timeout=2)
                except Exception:
                    self.proc.kill()
                    self.proc.wait(timeout=2)
            for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                if stream:
                    try:
                        stream.close()
                    except Exception:
                        pass
            self.proc = None

    def pop_target_output(self) -> str:
        if not self.target_output_buffer:
            return ""
        out = "".join(self.target_output_buffer)
        self.target_output_buffer.clear()
        return out

    def _readline_timeout(self, timeout: float) -> str:
        if not self.proc or not self.proc.stdout:
            return ""
        fd = self.proc.stdout.fileno()
        deadline = time.time() + max(0.05, timeout)
        while True:
            nl_idx = self._read_buf.find(b"\n")
            if nl_idx != -1:
                line_bytes = bytes(self._read_buf[:nl_idx + 1])
                del self._read_buf[:nl_idx + 1]
                return line_bytes.decode("utf-8", errors="replace")

            remaining = deadline - time.time()
            if remaining <= 0:
                if self._read_buf:
                    line_bytes = bytes(self._read_buf)
                    self._read_buf.clear()
                    return line_bytes.decode("utf-8", errors="replace")
                return ""

            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                if self._read_buf:
                    line_bytes = bytes(self._read_buf)
                    self._read_buf.clear()
                    return line_bytes.decode("utf-8", errors="replace")
                return ""

            chunk = os.read(fd, 4096)
            if not chunk:
                if self._read_buf:
                    line_bytes = bytes(self._read_buf)
                    self._read_buf.clear()
                    return line_bytes.decode("utf-8", errors="replace")
                return ""
            self._read_buf.extend(chunk)

    def _read_until_prompt(self, timeout: float = GDB_CMD_TIMEOUT_S) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self._readline_timeout(deadline - time.time())
            if not line:
                break
            for kind, _cls, data in parse_mi_lines(line):
                if kind in ("@", "raw"):
                    self._append_target_output(str(data))
                elif kind == "prompt":
                    return

    def send(self, cmd: str, timeout: float = GDB_CMD_TIMEOUT_S) -> dict:
        if not self.proc or self.proc.poll() is not None:
            return {"status": "error", "payload": {"msg": "GDB process terminated"}, "console": "", "stopped": None}
        self.proc.stdin.write((cmd.strip() + "\n").encode("utf-8"))
        self.proc.stdin.flush()

        console_chunks = []
        status = "done"
        payload = {}
        stopped = None

        deadline = time.time() + timeout
        saw_result = False
        while time.time() < deadline:
            line = self._readline_timeout(deadline - time.time())
            if not line:
                break
            done_prompt = False
            for kind, cls, data in parse_mi_lines(line):
                if kind == "~":
                    console_chunks.append(str(data))
                elif kind in ("@", "raw"):
                    self._append_target_output(str(data))
                elif kind == "^":
                    status = cls
                    payload = data if isinstance(data, dict) else {}
                    saw_result = True
                elif kind == "*" and cls == "stopped":
                    stopped = data if isinstance(data, dict) else {}
                    self._on_stopped_record(stopped)
                elif kind == "prompt" and saw_result:
                    done_prompt = True
            if done_prompt:
                break
        return {
            "status": status,
            "payload": payload,
            "console": "".join(console_chunks),
            "stopped": stopped,
        }

    def wait_stopped(self, timeout: float = 30.0) -> dict | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self._readline_timeout(deadline - time.time())
            if not line:
                return None
            for kind, cls, data in parse_mi_lines(line):
                if kind in ("@", "raw"):
                    self._append_target_output(str(data))
                elif kind == "*" and cls == "stopped":
                    stopped = data if isinstance(data, dict) else {}
                    self._on_stopped_record(stopped)
                    return stopped
        return None

    def _on_stopped_record(self, stopped: dict) -> None:
        pass
