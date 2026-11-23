# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import atexit
import re
from datetime import datetime
from pathlib import Path

from src.config import EU_FOLDER_TS_FORMAT, EU_LOG_TS_FORMAT, RECORD_DISAS_CONTEXT


def _eu_ts() -> str:
    now = datetime.now()
    return now.strftime(EU_LOG_TS_FORMAT) + f".{now.microsecond:06d}"


def _safe_func_filename(func_name: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_.-]+", "_", func_name.strip()) or "unknown"
    return f"func_{clean}.txt"


class SessionRecorder:
    def __init__(self, binary_path: Path, arch: str, bits: int, is_pie: bool):
        ts = datetime.now().strftime(EU_FOLDER_TS_FORMAT)
        self.out_dir = Path.cwd() / f"record-{binary_path.name}_{ts}"
        self.func_dir = self.out_dir / "functions"
        self.out_path = self.out_dir / "full_recording.txt"

        self.main_buffer: list[str] = [
            "========================================================================\n",
            "BIN-DEBUG-FRIENDLY — SESSION RECORDING\n",
            "========================================================================\n",
            f"BINARY        : {binary_path}\n",
            f"ARCHITECTURE  : {arch} ({bits}-bit, PIE={is_pie})\n",
            f"STARTED_AT    : {_eu_ts()}\n",
            f"DISAS_CONTEXT : +/- {RECORD_DISAS_CONTEXT} instructions around PC\n",
            "========================================================================\n\n",
        ]
        self.func_buffers: dict[str, list[str]] = {}
        self._initialized_funcs: set[str] = set()
        self._seen_funcs: set[str] = set()
        self._last_stack_lines: list[str] = []
        self.step_seq = 0
        self.closed = False
        self._dir_created = False
        self._func_dir_created = False
        self._main_initialized = False
        atexit.register(self.close)

    def record_command_only(self, command: str, duration_ms: float = 0.0, note: str = "") -> None:
        self.step_seq += 1
        lines = [
            f"[EVENT #{self.step_seq:05d}] TIME={_eu_ts()} | CMD={command!r} | DURATION={duration_ms:.2f}ms\n",
        ]
        if note:
            lines.append(f"  NOTE     : {note}\n")
        lines.append("-" * 72 + "\n")
        self.main_buffer.append("".join(lines))

    def record_event(
        self,
        command: str,
        duration_ms: float,
        pc_disp: str,
        func_name: str,
        disas_lines: list[str],
        regs: dict[str, int],
        prev_regs: dict[str, int],
        stack_lines: list[str],
        stdout_text: str = "",
        note: str = "",
    ) -> None:
        self.step_seq += 1
        changed_regs = [
            f"{k.upper()}=0x{v:x}"
            for k, v in regs.items()
            if k in prev_regs and prev_regs[k] != v
        ]
        is_new_func = func_name not in self._seen_funcs
        self._seen_funcs.add(func_name)

        lines = [
            f"[EVENT #{self.step_seq:05d}] TIME={_eu_ts()} | CMD={command!r} | DURATION={duration_ms:.2f}ms\n",
            f"  LOCATION : {pc_disp} ({func_name})\n",
        ]
        if note:
            lines.append(f"  NOTE     : {note}\n")
        if stdout_text.strip():
            lines.append(f"  STDOUT   : {stdout_text.strip()!r}\n")
        if changed_regs:
            lines.append(f"  CHANGED  : {' '.join(changed_regs)}\n")

        if disas_lines:
            lines.append("  DISASSEMBLY:\n")
            for dl in disas_lines:
                lines.append(f"    {dl}\n")

        if regs:
            if is_new_func or self.step_seq == 1 or not prev_regs:
                regs_str = " ".join(f"{k.upper()}=0x{v:x}" for k, v in regs.items())
                lines.append(f"  REGISTERS:\n    {regs_str}\n")

        if stack_lines:
            if is_new_func or self.step_seq == 1 or func_name == "exited":
                lines.append(f"  FULL ACTIVE STACK ({len(stack_lines)} lines):\n")
                for sl in stack_lines:
                    lines.append(f"    {sl}\n")
            else:
                prev_set = set(self._last_stack_lines)
                diff_lines = [sl for sl in stack_lines if sl not in prev_set]
                if diff_lines:
                    lines.append(f"  STACK CHANGED ({len(diff_lines)} lines):\n")
                    for sl in diff_lines:
                        lines.append(f"    {sl}\n")
            self._last_stack_lines = list(stack_lines)

        lines.append("-" * 72 + "\n")
        entry_txt = "".join(lines)

        self.main_buffer.append(entry_txt)
        fn_key = _safe_func_filename(func_name)
        self.func_buffers.setdefault(fn_key, []).append(entry_txt)

    def flush_idle(self) -> None:
        if not self.main_buffer and not any(self.func_buffers.values()):
            return
        if not self._dir_created:
            self.out_dir.mkdir(parents=True, exist_ok=True)
            self._dir_created = True

        if self.main_buffer:
            mode = "a" if self._main_initialized else "w"
            with self.out_path.open(mode, encoding="utf-8") as fh:
                fh.writelines(self.main_buffer)
            self.main_buffer.clear()
            self._main_initialized = True

        for fname, buf in self.func_buffers.items():
            if not buf:
                continue
            if not self._func_dir_created:
                self.func_dir.mkdir(parents=True, exist_ok=True)
                self._func_dir_created = True
            fpath = self.func_dir / fname
            fmode = "a" if fname in self._initialized_funcs else "w"
            with fpath.open(fmode, encoding="utf-8") as fh:
                if fname not in self._initialized_funcs:
                    fh.write(f"=== RECORDED FUNCTION TRACE: {fname} ===\n\n")
                fh.writelines(buf)
            buf.clear()
            self._initialized_funcs.add(fname)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.main_buffer.append(
                f"\n=== RECORDING CLOSED AT {_eu_ts()} (total events: {self.step_seq}) ===\n"
            )
            self.flush_idle()
        except Exception:
            pass
