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
        self.reg_names: list[str] = []
        self.reg_name_to_idx: dict[str, int] = {}
        self.core_reg_indices: list[int] = []
        self.core_reg_query: str = ""
        self.pc_reg_idx: int | None = None
        self.sp_reg_idx: int | None = None
        self._cached_stack_bounds: tuple[int, int, bool] | None = None

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
        self.qemu_port = self.spawn_gdb_process(
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
        elif self.target_args:
            escaped = " ".join(shlex.quote(a) for a in self.target_args)
            self.send(f"-exec-arguments {escaped}")

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
        stopped = res["stopped"] or self.wait_stopped(timeout=60.0)
        if stopped:
            self._on_stopped_record(stopped)
        return stopped

    def _exec_single_step(self, step_over: bool) -> dict | None:
        cmd = "-exec-next-instruction" if step_over else "-exec-step-instruction"
        res = self.send(cmd)
        if res["status"] == "error":
            return {"reason": "error", "msg": res["payload"].get("msg", "")}
        stopped = res["stopped"] or self.wait_stopped()
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

    def step_instruction(
        self,
        count: int = 1,
        step_over: bool = False,
        respect_skip_external: bool = True,
    ) -> dict | None:
        if self.exited:
            return {"reason": "exited", "exit-code": str(self.exit_code or 0)}
        if not self.started:
            self.ensure_started_paused()

        if step_over and count > 1:
            res = self.send(f'-interpreter-exec console "ni {count}"')
            stopped = res["stopped"] or self.wait_stopped(timeout=30.0)
            if stopped:
                self._on_stopped_record(stopped)
            if not self.exited and respect_skip_external and SKIP_EXTERNAL_FUNCTIONS:
                pc = _pc_from_stopped(stopped) or self.get_pc()
                if pc is not None and not self.addr_in_main_binary(pc):
                    stopped = self.step_over_or_finish_external(current_pc=pc, allow_callback_trap=False)
            return stopped

        stopped = None
        last_pc = self.get_pc() if (count == 1 or (respect_skip_external and SKIP_EXTERNAL_FUNCTIONS)) else None
        for _ in range(count):
            prev_pc = last_pc
            stopped = self._exec_single_step(step_over=step_over)
            if self.exited:
                break
            reason = stopped.get("reason", "") if stopped else ""
            if reason in ("breakpoint-hit", "signal-received", "syscall-entry", "syscall-return"):
                break
            pc = _pc_from_stopped(stopped) or self.get_pc()
            if respect_skip_external and SKIP_EXTERNAL_FUNCTIONS:
                if pc is not None and not self.addr_in_main_binary(pc):
                    stopped = self.step_over_or_finish_external(
                        current_pc=pc,
                        from_pc=prev_pc,
                        allow_callback_trap=(not step_over),
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
        stopped = res["stopped"] or self.wait_stopped(timeout=30.0)
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

        stopped = res["stopped"] or self.wait_stopped(timeout=10.0)
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
            stopped = res2["stopped"] or self.wait_stopped(timeout=10.0)
            if stopped:
                self._on_stopped_record(stopped)
        return stopped

    def enable_syscall_catch(self) -> bool:
        res = self.send('-interpreter-exec console "catch syscall"')
        return res["status"] != "error"
