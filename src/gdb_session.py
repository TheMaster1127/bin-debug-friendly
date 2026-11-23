# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import os
import re
import shlex
import shutil
import tempfile
from pathlib import Path

from src.config import SKIP_EXTERNAL_FUNCTIONS
from src.elf_utils import ElfInfo, resolve_target_address
from src.gdb_inspector import GdbInspectorMixin
from src.mi_protocol import MIProtocol
from src.sandbox import (
    SandboxEnv,
    detect_host_arch,
    find_gdb_binary,
    find_qemu_binary,
    needs_qemu,
)

ARG0_REG = {"x86_64": "rdi", "aarch64": "x0", "arm": "r0"}
CALL_MNEMONICS = {"call", "callq", "bl", "blr", "blx"}
INPUT_FUNC_HINTS = (
    "fgets", "gets", "scanf", "__isoc99_scanf", "getchar",
    "getc", "fgetc", "getline", "getdelim", "read@plt",
)


def _pc_from_stopped(stopped: dict | None) -> int | None:
    if not stopped:
        return None
    frame = stopped.get("frame")
    if isinstance(frame, dict) and "addr" in frame:
        try:
            return int(str(frame["addr"]), 0)
        except Exception:
            return None
    return None


def _is_call_insn(insn_text: str) -> bool:
    parts = insn_text.strip().lower().split(None, 1)
    return bool(parts and parts[0] in CALL_MNEMONICS)


def _looks_like_stdin_call(insn_text: str) -> bool:
    low = insn_text.lower()
    return any(tok in low for tok in INPUT_FUNC_HINTS)


class IgnoreCallManager:
    def __init__(self):
        self.mode = "none"
        self.remaining = 0
        self.nest_base_depth = 0

    def clear(self) -> str:
        self.mode = "none"
        self.remaining = 0
        return "Call ignoring disabled (normal step)."

    def set_all(self) -> str:
        self.mode = "all"
        self.remaining = 0
        return "Ignoring ALL calls during step (`unignore call` to resume)."

    def set_count(self, n: int) -> str:
        self.mode = "count"
        self.remaining = max(1, n)
        label = "once" if self.remaining == 1 else f"{self.remaining} times"
        return f"Ignoring calls {label}."

    def set_nest(self, current_depth: int) -> str:
        self.mode = "nest"
        self.remaining = 0
        self.nest_base_depth = current_depth
        return f"Ignoring nested calls (allowing 1 level from depth {current_depth})."

    def status_label(self) -> str:
        if self.mode == "all":
            return "ignore=all"
        if self.mode == "count":
            return f"ignore={self.remaining}"
        if self.mode == "nest":
            return f"ignore=nest(d>{self.nest_base_depth})"
        return "ignore=off"

    def should_skip_call_at_pc(self, session: "GdbSession", pc: int | None) -> bool:
        if self.mode == "none" or pc is None:
            return False
        insns = session.disassemble_at(pc, count=1)
        if not insns or not _is_call_insn(insns[0][2]):
            return False
        if self.mode == "all":
            return True
        if self.mode == "count":
            if self.remaining > 0:
                self.remaining -= 1
                if self.remaining == 0:
                    self.mode = "none"
                return True
            self.mode = "none"
            return False
        if self.mode == "nest":
            cur_depth = len(session.get_binary_call_frames())
            if cur_depth < self.nest_base_depth:
                self.mode = "none"
                return False
            return cur_depth >= self.nest_base_depth + 1
        return False


class GdbSession(MIProtocol, GdbInspectorMixin):
    def __init__(
        self,
        binary_path: Path,
        elf_info: ElfInfo,
        sandbox: SandboxEnv,
        target_args: list[str] | None = None,
    ):
        super().__init__()
        self.host_binary_path = binary_path.resolve()
        self.elf = elf_info
        self.sandbox = sandbox
        self.target_args = target_args or []

        self.host_arch = detect_host_arch()
        self.use_qemu = needs_qemu(self.host_arch, self.elf.arch)
        self.gdb_bin = find_gdb_binary(self.use_qemu)
        self.qemu_bin = find_qemu_binary(self.elf.arch) if self.use_qemu else None

        if self.use_qemu and not self.qemu_bin:
            raise RuntimeError(
                f"Target architecture is '{self.elf.arch}' on host '{self.host_arch}', "
                f"but no qemu-{self.elf.arch} user emulator was found in PATH."
            )

        self._tmp_dir_obj = tempfile.TemporaryDirectory(prefix="bdf_work_")
        self.work_dir = Path(self._tmp_dir_obj.name)
        self.local_bin_host = self.work_dir / "target_bin"
        shutil.copy2(self.host_binary_path, self.local_bin_host)
        os.chmod(self.local_bin_host, 0o755)

        self.target_path_in_gdb = "/tmp/work/target_bin" if self.sandbox.enabled else str(self.local_bin_host)
        self.stdin_path_in_gdb: str = ""
        self.reg_names: list[str] = []
        self.reg_name_to_idx: dict[str, int] = {}
        self.core_reg_indices: list[int] = []
        self.core_reg_query: str = ""
        self.pc_reg_idx: int | None = None
        self.sp_reg_idx: int | None = None
        self._cached_stack_bounds: tuple[int, int, bool] | None = None
        self._cached_functions: list[str] | None = None

        self.ignore_mgr = IgnoreCallManager()
        self.stdin_prompt_handler = None

        self.runtime_base: int | None = None
        self.exec_ranges: list[tuple[int, int]] = []
        self.all_bin_ranges: list[tuple[int, int]] = []
        self.plt_runtime_ranges: list[tuple[int, int]] = []
        self.text_runtime_range: tuple[int, int] | None = None
        self.started = False
        self.exited = False
        self.exit_code: int | None = None
        self.qemu_port: int | None = None

    def start_gdb(self) -> None:
        self.qemu_port, self.stdin_path_in_gdb = self.spawn_gdb_process(
            sandbox=self.sandbox,
            work_dir=self.work_dir,
            gdb_bin=self.gdb_bin,
            target_path_in_gdb=self.target_path_in_gdb,
            use_qemu=self.use_qemu,
            qemu_bin=self.qemu_bin,
            target_args=self.target_args,
        )

        self.send("-gdb-set confirm off")
        self.send("-gdb-set pagination off")
        if self.elf.arch in ("x86_64", "i386"):
            self.send("-gdb-set disassembly-flavor intel")
            self.send(f"-gdb-set architecture {'i386' if self.elf.arch == 'i386' else 'i386:x86-64'}")
        elif self.elf.arch == "aarch64":
            self.send("-gdb-set architecture aarch64")
        elif self.elf.arch == "arm":
            self.send("-gdb-set architecture arm")

        if self.use_qemu:
            res = self.send(f"-target-select remote 127.0.0.1:{self.qemu_port}")
            if res["status"] == "error":
                raise RuntimeError(f"QEMU remote GDB connection failed: {res['payload'].get('msg')}")
            self.started = True
            self._discover_mappings()
        else:
            escaped_args = " ".join(shlex.quote(a) for a in self.target_args)
            redir = f"< {shlex.quote(self.stdin_path_in_gdb)}"
            full_args = f"{escaped_args} {redir}".strip()
            self.send(f"-exec-arguments {full_args}")

        self._load_register_names()

    def close(self) -> None:
        self.close_process()
        self._tmp_dir_obj.cleanup()

    def _on_stopped_record(self, stopped: dict) -> None:
        reason = stopped.get("reason", "")
        if reason in ("exited-normally", "exited", "exited-signalled"):
            self.exited = True
            try:
                self.exit_code = int(stopped.get("exit-code", "0"), 0)
            except Exception:
                self.exit_code = 0

    def ensure_started_paused(self) -> None:
        if self.started and not self.exited:
            return
        self.exited = False
        self.exit_code = None
        self._cached_stack_bounds = None
        self.drain_target_stdin()
        self.target_output_buffer.clear()
        res = self.send('-interpreter-exec console "starti"')
        stopped = res["stopped"]
        if res["status"] == "running" and stopped is None:
            stopped = self.wait_stopped()
        if stopped:
            self._on_stopped_record(stopped)
        self.started = True
        self._load_register_names()
        self._discover_mappings()

    def restart_to_entry(self) -> dict | None:
        if self.use_qemu:
            return {"reason": "error", "msg": "Restarting remote QEMU session is not supported; re-launch main.py."}
        self.started = False
        self.exited = False
        self.exit_code = None
        self._cached_stack_bounds = None
        return self.advance_to_entry_point()

    def advance_to_entry_point(self) -> dict | None:
        self.ensure_started_paused()
        if self.exited:
            return {"reason": "exited"}
        pc = self.get_pc()
        base = self.runtime_base if self.runtime_base is not None else self.elf.base_vaddr
        entry_runtime = base + (self.elf.e_entry - self.elf.base_vaddr)
        if pc is not None and pc != entry_runtime and not self.addr_in_main_binary(pc):
            self.send(f"-break-insert -t *0x{entry_runtime:x}")
            return self.run_or_continue()
        return {"reason": "entry-point"}

    def has_symbol(self, symbol: str) -> bool:
        res = self.send(f'-interpreter-exec console "info address {symbol}"')
        return res["status"] != "error" and "No symbol" not in res["console"]

    def stop_at_symbol(self, symbol: str) -> tuple[bool, str, dict | None]:
        if not self.has_symbol(symbol):
            return False, f"No '{symbol}' function found in this binary.", None
        if self.exited or not self.started:
            self.started = False
            self.ensure_started_paused()
        res = self.send(f"-break-insert -t {symbol}")
        if res["status"] == "error":
            return False, res["payload"].get("msg", f"Failed to break at {symbol}"), None
        stopped = self.run_or_continue()
        return True, f"Stopped at {symbol}", stopped

    def run_to_next_call(self, raw_args: str) -> tuple[bool, str, dict | None]:
        tokens = raw_args.strip().split()
        ignore_missing_in_view = False
        filtered: list[str] = []
        for tok in tokens:
            if tok == "--ignore":
                ignore_missing_in_view = True
            else:
                filtered.append(tok)

        if not filtered:
            return False, "Usage: call <function_name> [--ignore]", None

        target_name = filtered[0]

        if self.exited or not self.started:
            self.started = False
            self.advance_to_entry_point()

        pc = self.get_pc()
        if pc is None:
            return False, "Cannot determine current PC.", None

        match = self.find_upcoming_call(pc, target_name)
        if match is not None:
            call_addr, insn_text, is_plt = match
            disp_call = self.to_display_addr(call_addr)
            if call_addr != pc:
                res = self.send(f"-break-insert -t *0x{call_addr:x}")
                if res["status"] == "error":
                    return False, res["payload"].get("msg", "Failed to set breakpoint on call"), None
                stopped = self.run_or_continue()
                if self.exited or self.get_pc() != call_addr:
                    return True, f"Stopped before reaching call 0x{disp_call:x}", stopped
            if is_plt and SKIP_EXTERNAL_FUNCTIONS:
                return True, f"At external call 0x{disp_call:x} ({insn_text})", {"reason": "breakpoint-hit"}
            stopped = self.step_instruction(1, step_over=False, respect_ignore_calls=False)
            return True, f"Entered call `{target_name}` via 0x{disp_call:x}", stopped

        if not ignore_missing_in_view:
            return (
                False,
                f"Cannot see an upcoming call to '{target_name}' from here. Pass '--ignore' to search/run globally.",
                None,
            )

        bin_funcs = self.get_binary_functions()
        low = target_name.lower()
        sym_to_try = next((f for f in bin_funcs if f.lower() == low), None)
        if sym_to_try is None:
            sym_to_try = next((f for f in bin_funcs if f.lower().startswith(low)), None)
        if sym_to_try is None:
            sym_to_try = next((f for f in bin_funcs if low in f.lower()), None)

        if sym_to_try and self.has_symbol(sym_to_try):
            ok, msg, stopped = self.stop_at_symbol(sym_to_try)
            return ok, f"Entered `{sym_to_try}` via --ignore ({msg})", stopped

        return False, f"Function '{target_name}' does not exist in this binary.", None

    def goto_address(self, parsed_addr: int) -> tuple[bool, str, dict | None]:
        if self.exited or not self.started:
            self.started = False
            self.ensure_started_paused()
        base = self.runtime_base if self.runtime_base is not None else self.elf.base_vaddr
        runtime_addr, mode = resolve_target_address(parsed_addr, self.elf, base)
        res = self.send(f"-break-insert -t *0x{runtime_addr:x}")
        if res["status"] == "error":
            return False, res["payload"].get("msg", "Failed to set target breakpoint"), None
        stopped = self.run_or_continue()
        disp = self.to_display_addr(runtime_addr)
        return True, f"Ran to 0x{disp:x} ({mode})", stopped

    def jump_to_target(self, parsed_addr: int | None, raw_symbol: str) -> tuple[bool, str]:
        if self.exited or not self.started:
            self.started = False
            self.ensure_started_paused()

        if parsed_addr is not None:
            base = self.runtime_base if self.runtime_base is not None else self.elf.base_vaddr
            runtime_addr, mode = resolve_target_address(parsed_addr, self.elf, base)
        else:
            eval_res = self.send(f'-data-evaluate-expression "&{raw_symbol}"')
            if eval_res["status"] == "error":
                eval_res = self.send(f'-data-evaluate-expression "{raw_symbol}"')
            if eval_res["status"] != "done":
                return False, f"Cannot resolve jump target '{raw_symbol}'"
            m = re.search(r"0x[0-9a-fA-F]+", str(eval_res["payload"].get("value", "")))
            if not m:
                return False, f"Cannot parse address for '{raw_symbol}'"
            runtime_addr = int(m.group(0), 16)
            mode = raw_symbol

        res = self.send(f"-gdb-set $pc = 0x{runtime_addr:x}")
        if res["status"] == "error":
            return False, res["payload"].get("msg", "Failed to set PC")
        disp = self.to_display_addr(runtime_addr)
        return True, f"Jumped PC to 0x{disp:x} ({mode}) [note: stack/regs unchanged]"

    def _discover_mappings(self) -> None:
        self.exec_ranges.clear()
        self.all_bin_ranges.clear()
        self.plt_runtime_ranges.clear()
        self.text_runtime_range = None
        self._cached_stack_bounds = None

        mappings = self.get_proc_mappings()
        bin_matches = [
            m for m in mappings
            if "target_bin" in m["objfile"] or self.host_binary_path.name in m["objfile"]
        ]
        if bin_matches:
            self.runtime_base = min(m["start"] for m in bin_matches)
            for m in bin_matches:
                self.all_bin_ranges.append((m["start"], m["end"]))
                if "x" in m["perms"]:
                    self.exec_ranges.append((m["start"], m["end"]))
        else:
            res = self.send('-interpreter-exec console "info auxv"')
            at_entry = None
            at_phdr = None
            for line in res["console"].splitlines():
                if "AT_ENTRY" in line:
                    m = re.search(r"(0x[0-9a-fA-F]+)", line)
                    if m:
                        at_entry = int(m.group(1), 16)
                elif "AT_PHDR" in line:
                    m = re.search(r"(0x[0-9a-fA-F]+)", line)
                    if m:
                        at_phdr = int(m.group(1), 16)
            if at_phdr is not None and self.elf.e_phoff:
                self.runtime_base = at_phdr - self.elf.e_phoff
            elif at_entry is not None:
                self.runtime_base = at_entry - self.elf.e_entry
            else:
                self.runtime_base = self.elf.base_vaddr

            for seg in self.elf.segments:
                lo = self.runtime_base + (seg.vaddr - self.elf.base_vaddr)
                hi = lo + seg.memsz
                self.all_bin_ranges.append((lo, hi))
                if seg.is_executable:
                    self.exec_ranges.append((lo, hi))

        for m in mappings:
            if "[stack]" in m["objfile"]:
                self._cached_stack_bounds = (m["start"], m["end"], True)
                break

        base = self.runtime_base if self.runtime_base is not None else self.elf.base_vaddr
        if self.elf.text_range is not None:
            tlo, thi = self.elf.text_range
            self.text_runtime_range = (base + (tlo - self.elf.base_vaddr), base + (thi - self.elf.base_vaddr))
        for plo, phi in self.elf.plt_ranges:
            self.plt_runtime_ranges.append((base + (plo - self.elf.base_vaddr), base + (phi - self.elf.base_vaddr)))

    def addr_in_plt(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self.plt_runtime_ranges)

    def addr_in_main_binary(self, addr: int) -> bool:
        if self.addr_in_plt(addr):
            return False
        return any(lo <= addr < hi for lo, hi in self.exec_ranges)

    def addr_in_any_binary_segment(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self.all_bin_ranges)

    def set_breakpoint(self, parsed_addr: int | None, raw_symbol: str) -> tuple[bool, str]:
        if (not self.started or self.exited) and self.elf.is_pie and parsed_addr is not None:
            self.ensure_started_paused()

        if parsed_addr is not None:
            base = self.runtime_base if self.runtime_base is not None else self.elf.base_vaddr
            runtime_addr, mode = resolve_target_address(parsed_addr, self.elf, base)
            res = self.send(f"-break-insert *0x{runtime_addr:x}")
            if res["status"] == "error":
                return False, res["payload"].get("msg", "Failed to set breakpoint")
            bkpt = res["payload"].get("bkpt", {})
            num = bkpt.get("number", "?")
            disp = self.to_display_addr(runtime_addr)
            return True, f"Breakpoint #{num} set at 0x{disp:x} ({mode})"

        res = self.send(f"-break-insert {raw_symbol}")
        if res["status"] == "error":
            return False, res["payload"].get("msg", f"Failed to set breakpoint at '{raw_symbol}'")
        bkpt = res["payload"].get("bkpt", {})
        return True, f"Breakpoint #{bkpt.get('number', '?')} set at {raw_symbol} ({bkpt.get('addr', '?')})"

    def _interrupt_and_wait(self) -> dict | None:
        self.send("-exec-interrupt")
        stopped = self.wait_stopped(timeout=3.0)
        if stopped:
            self._on_stopped_record(stopped)
        return stopped or {"reason": "interrupted"}

    def _wait_stopped_interactive(self, initial_timeout: float = 0.7) -> dict | None:
        try:
            stopped = self.wait_stopped(timeout=initial_timeout)
        except KeyboardInterrupt:
            return self._interrupt_and_wait()

        while stopped is None and self.stdin_prompt_handler is not None and not self.exited:
            try:
                user_in = self.stdin_prompt_handler(proactive=False)
            except KeyboardInterrupt:
                return self._interrupt_and_wait()
            if user_in is None:
                return self._interrupt_and_wait()
            self.write_target_stdin(user_in)
            try:
                stopped = self.wait_stopped(timeout=2.5)
            except KeyboardInterrupt:
                return self._interrupt_and_wait()

        if stopped is None and self.stdin_prompt_handler is None:
            try:
                stopped = self.wait_stopped(timeout=30.0)
            except KeyboardInterrupt:
                return self._interrupt_and_wait()
        return stopped

    def run_or_continue(self, restart_if_exited: bool = False) -> dict | None:
        if self.exited:
            if not restart_if_exited:
                return {"reason": "exited", "exit-code": str(self.exit_code or 0)}
            self.started = False
            self.ensure_started_paused()
        elif not self.started:
            self.ensure_started_paused()

        res = self.send("-exec-continue")
        if res["status"] == "error":
            return {"reason": "error", "msg": res["payload"].get("msg", "")}
        stopped = res["stopped"] or self._wait_stopped_interactive(initial_timeout=0.7)
        if stopped:
            self._on_stopped_record(stopped)
        return stopped

    def _exec_single_step(self, step_over: bool) -> dict | None:
        cmd = "-exec-next-instruction" if step_over else "-exec-step-instruction"
        res = self.send(cmd)
        if res["status"] == "error":
            return {"reason": "error", "msg": res["payload"].get("msg", "")}
        stopped = res["stopped"] or self._wait_stopped_interactive(initial_timeout=0.7)
        if stopped:
            self._on_stopped_record(stopped)
        return stopped

    def _detect_callback_arg0(self) -> int | None:
        reg_name = ARG0_REG.get(self.elf.arch)
        if reg_name:
            res = self.get_single_register(reg_name)
            if res and self.addr_in_main_binary(res[1]):
                return res[1]
        elif self.elf.arch == "i386":
            sp = self.get_sp()
            if sp:
                arg0 = self.read_pointer(sp + 4)
                if arg0 and self.addr_in_main_binary(arg0):
                    return arg0
        return None

    def _maybe_proactive_stdin(self, call_pc: int | None) -> bool:
        if call_pc is None or self.stdin_prompt_handler is None or self.stdin_queued_lines > 0:
            return True
        insns = self.disassemble_at(call_pc, count=1)
        if insns and _is_call_insn(insns[0][2]) and _looks_like_stdin_call(insns[0][2]):
            try:
                txt = self.stdin_prompt_handler(proactive=True)
            except KeyboardInterrupt:
                return False
            if txt is None:
                return False
            self.write_target_stdin(txt)
        return True

    def step_instruction(
        self,
        count: int = 1,
        step_over: bool = False,
        respect_skip_external: bool = True,
        respect_ignore_calls: bool = True,
    ) -> dict | None:
        if self.exited:
            return {"reason": "exited", "exit-code": str(self.exit_code or 0)}
        if not self.started:
            self.ensure_started_paused()

        if step_over and count > 1:
            res = self.send(f'-interpreter-exec console "ni {count}"')
            stopped = res["stopped"] or self._wait_stopped_interactive(initial_timeout=0.8)
            if stopped:
                self._on_stopped_record(stopped)
            if not self.exited and respect_skip_external and SKIP_EXTERNAL_FUNCTIONS:
                pc = _pc_from_stopped(stopped) or self.get_pc()
                if pc is not None and not self.addr_in_main_binary(pc):
                    stopped = self.step_over_or_finish_external(current_pc=pc, allow_callback_trap=False)
            return stopped

        stopped = None
        last_pc = self.get_pc()
        for _ in range(count):
            prev_pc = last_pc
            effective_step_over = step_over
            if not effective_step_over and respect_ignore_calls and prev_pc is not None:
                if self.ignore_mgr.should_skip_call_at_pc(self, prev_pc):
                    effective_step_over = True

            if effective_step_over:
                if not self._maybe_proactive_stdin(prev_pc):
                    return {"reason": "interrupted"}

            stopped = self._exec_single_step(step_over=effective_step_over)
            if self.exited:
                break
            reason = stopped.get("reason", "") if stopped else ""
            if reason in ("breakpoint-hit", "signal-received", "syscall-entry", "syscall-return", "interrupted"):
                break
            pc = _pc_from_stopped(stopped) or self.get_pc()
            if respect_skip_external and SKIP_EXTERNAL_FUNCTIONS:
                if pc is not None and not self.addr_in_main_binary(pc):
                    stopped = self.step_over_or_finish_external(
                        current_pc=pc,
                        from_pc=prev_pc,
                        allow_callback_trap=(not effective_step_over),
                    )
                    if self.exited:
                        break
                    pc = _pc_from_stopped(stopped) or self.get_pc()
            last_pc = pc
        return stopped

    def skip_function(self) -> tuple[bool, dict | None, str]:
        if self.exited:
            return False, None, "Program has already exited."
        if not self.started:
            self.ensure_started_paused()
        res = self.send("-exec-finish")
        if res["status"] == "error":
            return False, None, res["payload"].get("msg", "Cannot finish current frame.")
        stopped = res["stopped"] or self._wait_stopped_interactive(initial_timeout=0.8)
        if stopped:
            self._on_stopped_record(stopped)
        if not self.exited and SKIP_EXTERNAL_FUNCTIONS:
            pc = _pc_from_stopped(stopped) or self.get_pc()
            if pc is not None and not self.addr_in_main_binary(pc):
                stopped = self.step_over_or_finish_external(current_pc=pc)
        return True, stopped, "Returned from function"

    def step_over_or_finish_external(
        self,
        current_pc: int | None = None,
        from_pc: int | None = None,
        allow_callback_trap: bool = False,
        on_syscall=None,
    ) -> dict | None:
        pc = current_pc if current_pc is not None else self.get_pc()
        callback_addr = self._detect_callback_arg0() if allow_callback_trap else None

        if callback_addr is not None and callback_addr != from_pc:
            self.send(f"-break-insert -t *0x{callback_addr:x}")

        used_plt_ret_bp = False
        if pc is not None and self.addr_in_plt(pc):
            if not self._maybe_proactive_stdin(from_pc):
                return {"reason": "interrupted"}

            ret_addr = None
            if self.elf.arch in ("x86_64", "i386"):
                sp = self.get_sp()
                if sp:
                    ret_addr = self.read_pointer(sp)
            else:
                lr_res = self.get_single_register("lr")
                if lr_res:
                    ret_addr = lr_res[1]
            if ret_addr and self.addr_in_main_binary(ret_addr):
                self.send(f"-break-insert -t *0x{ret_addr:x}")
                used_plt_ret_bp = True

        if used_plt_ret_bp:
            res = self.send("-exec-continue")
        else:
            res = self.send("-exec-finish")
            if res["status"] == "error":
                return self._exec_single_step(step_over=True)

        stopped = res["stopped"] or self._wait_stopped_interactive(initial_timeout=0.7)
        if stopped:
            self._on_stopped_record(stopped)

        safety = 0
        while (
            stopped
            and not self.exited
            and stopped.get("reason") in ("syscall-entry", "syscall-return")
            and safety < 2000
        ):
            safety += 1
            if on_syscall is not None:
                on_syscall(stopped)
            cur_pc = _pc_from_stopped(stopped) or self.get_pc()
            if cur_pc is not None and self.addr_in_main_binary(cur_pc):
                break
            res2 = self.send("-exec-continue")
            stopped = res2["stopped"] or self._wait_stopped_interactive(initial_timeout=0.7)
            if stopped:
                self._on_stopped_record(stopped)
        return stopped

    def enable_syscall_catch(self) -> bool:
        res = self.send('-interpreter-exec console "catch syscall"')
        return res["status"] != "error"
