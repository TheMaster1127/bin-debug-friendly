# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import time
from datetime import datetime
from pathlib import Path

from src.config import (
    EU_FOLDER_TS_FORMAT,
    EU_LOG_TS_FORMAT,
    MAX_MAP_FOLDER_MB,
    MAX_MAP_INSTRUCTIONS,
)
from src.elf_utils import parse_address_input, resolve_target_address
from src.formatters import format_xxd_lines, prompt_for_target_stdin
from src.gdb_session import GdbSession

MAX_MAP_FOLDER_BYTES = MAX_MAP_FOLDER_MB * 1024 * 1024

JUMP_MNEMONICS = {
    "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
    "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns", "jp", "jnp",
    "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne",
    "b", "beq", "bne", "bgt", "bge", "blt", "ble", "bhi", "bhs",
    "blo", "bls", "cbz", "cbnz", "tbz", "tbnz", "br",
}

CALL_MNEMONICS = {"call", "callq", "bl", "blr", "blx"}
RET_MNEMONICS = {"ret", "retq", "retn", "retf", "bx"}


def classify_instruction(insn_text: str) -> dict[str, bool]:
    low = insn_text.strip().lower()
    parts = low.split(None, 1)
    mnemonic = parts[0] if parts else ""
    operands = parts[1] if len(parts) > 1 else ""

    is_jump = mnemonic in JUMP_MNEMONICS or (mnemonic.startswith("b.") and len(mnemonic) <= 5)
    is_call = mnemonic in CALL_MNEMONICS
    is_ret = mnemonic in RET_MNEMONICS or (mnemonic == "bx" and "lr" in operands)
    is_mem = (
        ("[" in operands and "]" in operands and mnemonic not in ("lea", "leaq"))
        or mnemonic in ("push", "pushq", "pop", "popq")
        or mnemonic.startswith(("ldr", "str", "ldp", "stp"))
    )
    return {
        "jump": is_jump,
        "call": is_call,
        "ret": is_ret,
        "mem": is_mem,
    }


def eu_timestamp_now() -> str:
    now = datetime.now()
    return now.strftime(EU_LOG_TS_FORMAT) + f".{now.microsecond:06d}"


class FolderSizeGuard:
    def __init__(self, limit_bytes: int):
        self.limit_bytes = limit_bytes
        self.written_bytes = 0
        self.truncated = False

    def can_write(self, extra_bytes: int) -> bool:
        if self.truncated:
            return False
        if self.written_bytes + extra_bytes > self.limit_bytes:
            self.truncated = True
            return False
        return True

    def record(self, num_bytes: int) -> None:
        self.written_bytes += num_bytes


def _read_active_stack_lines(session: GdbSession) -> list[str]:
    lo, hi, sp, _ = session.get_stack_bounds()
    active_len = min(max(64, hi - sp), 64 * 1024)
    data = session.read_memory(sp, active_len) or b""
    if not data:
        return []
    return format_xxd_lines(data, sp, sp)


def _format_stack_section(
    stack_lines: list[str],
    last_stack_lines: list[str],
    is_func_entry: bool,
) -> str:
    if not stack_lines:
        return ""
    if is_func_entry or not last_stack_lines:
        out = [f"  FULL ACTIVE STACK ({len(stack_lines)} lines):"]
        out.extend(f"    {ln}" for ln in stack_lines)
        return "\n".join(out) + "\n"

    prev_set = set(last_stack_lines)
    diff_lines = [ln for ln in stack_lines if ln not in prev_set]
    if not diff_lines:
        return ""
    out = [f"  STACK CHANGED ({len(diff_lines)} lines):"]
    out.extend(f"    {ln}" for ln in diff_lines)
    return "\n".join(out) + "\n"


def run_execution_mapper(
    session: GdbSession,
    func_spec: str | None = None,
    dump_stack_syscalls: bool = False,
    start_at_main: bool = False,
) -> Path:
    if session.stdin_prompt_handler is None:
        session.stdin_prompt_handler = prompt_for_target_stdin

    now_dt = datetime.now()
    folder_name = f"{session.host_binary_path.name}-mapped_{now_dt.strftime(EU_FOLDER_TS_FORMAT)}"
    out_dir = Path.cwd() / folder_name
    func_dir = out_dir / "functions"
    out_dir.mkdir(parents=True, exist_ok=True)
    func_dir.mkdir(parents=True, exist_ok=True)

    guard = FolderSizeGuard(MAX_MAP_FOLDER_BYTES)

    session.ensure_started_paused()

    target_func_addr: int | None = None
    if func_spec:
        parsed, sym = parse_address_input(func_spec)
        if parsed is not None:
            base = session.runtime_base if session.runtime_base is not None else session.elf.base_vaddr
            target_func_addr, _mode = resolve_target_address(parsed, session.elf, base)
            ok, msg = session.set_breakpoint(parsed, sym)
        else:
            ok, msg = session.set_breakpoint(None, sym)
        if not ok:
            raise RuntimeError(f"Could not set function breakpoint for '{func_spec}': {msg}")
        print(f"[*] --func mode enabled: waiting to hit {func_spec} ({msg})")
        stopped = session.run_or_continue()
        if session.exited:
            print("[!] Program exited before reaching target function.")
        elif stopped and target_func_addr is None:
            target_func_addr = session.get_pc()
    elif start_at_main:
        ok, msg, _ = session.stop_at_symbol("main")
        if not ok:
            raise RuntimeError(msg)
    else:
        session.advance_to_entry_point()

    if not session.exited:
        session.enable_syscall_catch()

    full_trace_path = out_dir / "full_trace.txt"
    syscalls_path = out_dir / "syscalls_trace.txt"
    summary_path = out_dir / "summary.txt"

    total_insns = 0
    unique_addrs: set[int] = set()
    jump_count = 0
    call_count = 0
    ret_count = 0
    mem_count = 0
    syscall_count = 0
    syscall_hist: dict[str, int] = {}
    func_counts: dict[int, int] = {}
    peak_mem_kb = session.get_peak_memory_kb() or 0

    func_files: dict[int, object] = {}
    call_stack: list[int] = []
    if target_func_addr is not None:
        call_stack.append(target_func_addr)
        func_counts[target_func_addr] = 1
    else:
        pc0 = session.get_pc()
        if pc0 is not None:
            call_stack.append(pc0)
            func_counts[pc0] = 1

    print(f"[*] Mapping execution -> {out_dir}")

    t_start = time.time()
    pending_syscall_entry: dict | None = None
    last_main_pc: int = session.get_pc() or 0
    interrupted = False

    with (
        full_trace_path.open("w", encoding="utf-8") as f_trace,
        syscalls_path.open("w", encoding="utf-8") as f_sys,
    ):
        header = (
            f"=== BIN-DEBUG-FRIENDLY EXECUTION TRACE ===\n"
            f"BINARY        : {session.host_binary_path}\n"
            f"ARCH / BITS   : {session.elf.arch} ({session.elf.bits}-bit)\n"
            f"STARTED_AT    : {eu_timestamp_now()}\n"
            f"SIZE_CAP_MB   : {MAX_MAP_FOLDER_MB} MB\n"
            + (f"FUNCTION_ADDR : 0x{session.to_display_addr(target_func_addr):x}\n" if target_func_addr else "")
            + "=" * 72 + "\n\n"
        )
        f_trace.write(header)
        guard.record(len(header.encode("utf-8")))

        sys_header = (
            f"=== SYSTEM CALL TRACE ===\n"
            f"BINARY     : {session.host_binary_path}\n"
            f"STARTED_AT : {eu_timestamp_now()}\n"
            + "=" * 72 + "\n\n"
        )
        f_sys.write(sys_header)
        guard.record(len(sys_header.encode("utf-8")))

        def record_syscall_event(sc_stopped: dict) -> None:
            nonlocal syscall_count, pending_syscall_entry
            reason = sc_stopped.get("reason")
            if reason not in ("syscall-entry", "syscall-return"):
                return
            sc_num = sc_stopped.get("syscall-number", "?")
            sc_name = sc_stopped.get("syscall-name", f"syscall_{sc_num}")
            sc_regs = session.get_registers()
            sc_regs_str = " ".join(f"{k.upper()}=0x{v:x}" for k, v in sc_regs.items())
            caller_disp = session.to_display_addr(last_main_pc) if last_main_pc else 0
            if reason == "syscall-entry":
                syscall_count += 1
                syscall_hist[sc_name] = syscall_hist.get(sc_name, 0) + 1
                pending_syscall_entry = {
                    "num": sc_num,
                    "name": sc_name,
                    "time": eu_timestamp_now(),
                    "caller_pc": caller_disp,
                    "regs_in": sc_regs_str,
                }
                if dump_stack_syscalls:
                    sc_stack = out_dir / f"syscall_{syscall_count:04d}_{sc_name}.stack.bin"
                    session.dump_stack_to_file(sc_stack)
                    if sc_stack.exists():
                        guard.record(sc_stack.stat().st_size)
            elif reason == "syscall-return":
                ret_reg = (
                    "rax" if session.elf.arch == "x86_64"
                    else ("eax" if session.elf.arch == "i386"
                          else ("x0" if session.elf.arch == "aarch64" else "r0"))
                )
                ret_val = sc_regs.get(ret_reg, 0)
                entry = pending_syscall_entry or {
                    "num": sc_num,
                    "name": sc_name,
                    "time": eu_timestamp_now(),
                    "caller_pc": caller_disp,
                    "regs_in": sc_regs_str,
                }
                sc_line = (
                    f"[SYSCALL #{syscall_count:04d}] NAME={entry['name']} (num={entry['num']}) | "
                    f"CALLER=0x{entry['caller_pc']:x} | TIME_IN={entry['time']} | TIME_OUT={eu_timestamp_now()}\n"
                    f"  REGS_IN : {entry['regs_in']}\n"
                    f"  RET_OUT : 0x{ret_val:x} ({ret_val})\n"
                )
                sc_bytes = len(sc_line.encode("utf-8"))
                if guard.can_write(sc_bytes):
                    f_sys.write(sc_line)
                    guard.record(sc_bytes)
                pending_syscall_entry = None

        func_depth = 1 if target_func_addr is not None else None
        last_was_call = False
        returned_via_external = False
        seen_funcs: set[int] = set()
        last_stack_lines: list[str] = []

        try:
            while not session.exited and total_insns < MAX_MAP_INSTRUCTIONS:
                if guard.truncated:
                    print(f"[!] Map folder size limit ({MAX_MAP_FOLDER_MB} MB) reached; stopping trace cleanly.")
                    break

                pc = session.get_pc()
                if pc is None:
                    break

                if not session.addr_in_main_binary(pc):
                    returned_via_external = True
                    ext_stopped = session.step_over_or_finish_external(
                        current_pc=pc,
                        from_pc=last_main_pc,
                        allow_callback_trap=(func_spec is None),
                        on_syscall=record_syscall_event,
                    )
                    if ext_stopped and ext_stopped.get("reason") in ("syscall-entry", "syscall-return"):
                        record_syscall_event(ext_stopped)
                    if ext_stopped and ext_stopped.get("reason") == "interrupted":
                        interrupted = True
                        break
                    if session.exited:
                        break
                    continue

                if returned_via_external:
                    returned_via_external = False
                    if last_was_call:
                        if pc > last_main_pc + 16 or pc < last_main_pc:
                            call_stack.append(pc)
                            func_counts[pc] = func_counts.get(pc, 0) + 1
                        last_was_call = False
                elif last_was_call:
                    call_stack.append(pc)
                    func_counts[pc] = func_counts.get(pc, 0) + 1
                    last_was_call = False

                last_main_pc = pc
                cur_func = call_stack[-1] if call_stack else (session.runtime_base or 0)
                is_func_entry = cur_func not in seen_funcs
                seen_funcs.add(cur_func)

                insns = session.disassemble_at(pc, count=1)
                insn_text = insns[0][2] if insns else "<unknown>"
                regs = session.get_registers()
                stack_lines = _read_active_stack_lines(session)
                stack_block = _format_stack_section(stack_lines, last_stack_lines, is_func_entry)
                if stack_lines:
                    last_stack_lines = stack_lines

                total_insns += 1
                unique_addrs.add(pc)
                cls_info = classify_instruction(insn_text)
                if cls_info["jump"]:
                    jump_count += 1
                if cls_info["call"]:
                    call_count += 1
                if cls_info["ret"]:
                    ret_count += 1
                if cls_info["mem"]:
                    mem_count += 1

                disp_pc = session.to_display_addr(pc)
                disp_func = session.to_display_addr(cur_func)
                regs_str = " ".join(f"{k.upper()}=0x{v:x}" for k, v in regs.items())

                block = (
                    f"[STEP {total_insns:06d}] TIME={eu_timestamp_now()} | "
                    f"FUNC=0x{disp_func:x} | ADDR=0x{disp_pc:x} | INSN={insn_text}\n"
                    f"  REGS: {regs_str}\n"
                    f"{stack_block}"
                )
                block_bytes = len(block.encode("utf-8"))
                if not guard.can_write(block_bytes):
                    print(f"[!] Map folder size limit ({MAX_MAP_FOLDER_MB} MB) reached.")
                    break

                f_trace.write(block)
                guard.record(block_bytes)

                if cur_func not in func_files:
                    fpath = func_dir / f"func_0x{disp_func:x}.txt"
                    fh = fpath.open("w", encoding="utf-8")
                    f_hdr = f"=== FUNCTION 0x{disp_func:x} TRACE ===\n\n"
                    fh.write(f_hdr)
                    guard.record(len(f_hdr.encode("utf-8")))
                    func_files[cur_func] = fh
                if guard.can_write(block_bytes):
                    func_files[cur_func].write(block)
                    guard.record(block_bytes)

                if cls_info["call"]:
                    last_was_call = True
                    if func_depth is not None:
                        func_depth += 1
                elif cls_info["ret"]:
                    if len(call_stack) > 1:
                        call_stack.pop()
                    if func_depth is not None:
                        func_depth -= 1
                        if func_depth <= 0:
                            session.step_instruction(1, respect_skip_external=False)
                            break

                if total_insns % 250 == 1:
                    pm = session.get_peak_memory_kb()
                    if pm and pm > peak_mem_kb:
                        peak_mem_kb = pm

                stopped = session.step_instruction(1, respect_skip_external=False)
                while stopped and stopped.get("reason") in ("syscall-entry", "syscall-return"):
                    record_syscall_event(stopped)
                    stopped = session.step_instruction(1, respect_skip_external=False)
        except KeyboardInterrupt:
            interrupted = True
            print("\n[!] Mapping interrupted by user; finalizing partial trace...")

        if pending_syscall_entry is not None:
            entry = pending_syscall_entry
            sc_line = (
                f"[SYSCALL #{syscall_count:04d}] NAME={entry['name']} (num={entry['num']}) | "
                f"CALLER=0x{entry['caller_pc']:x} | TIME_IN={entry['time']} | TIME_OUT={eu_timestamp_now()}\n"
                f"  REGS_IN : {entry['regs_in']}\n"
                f"  RET_OUT : <no return — process exited/interrupted>\n"
            )
            sc_bytes = len(sc_line.encode("utf-8"))
            if guard.can_write(sc_bytes):
                f_sys.write(sc_line)
                guard.record(sc_bytes)
            pending_syscall_entry = None

    for fh in func_files.values():
        fh.close()

    elapsed = time.time() - t_start
    final_pm = session.get_peak_memory_kb()
    if final_pm and final_pm > peak_mem_kb:
        peak_mem_kb = final_pm

    func_lines = [
        f"  - 0x{session.to_display_addr(faddr):x} : {cnt} call(s)"
        for faddr, cnt in sorted(func_counts.items(), key=lambda x: (-x[1], x[0]))
    ]
    sc_lines = [
        f"  - {name:<20} : {cnt} time(s)"
        for name, cnt in sorted(syscall_hist.items(), key=lambda x: (-x[1], x[0]))
    ]

    summary_txt = (
        "========================================================================\n"
        "BIN-DEBUG-FRIENDLY — EXECUTION MAP SUMMARY\n"
        "========================================================================\n"
        f"Binary                : {session.host_binary_path}\n"
        f"Architecture          : {session.elf.arch} ({session.elf.bits}-bit, PIE={session.elf.is_pie})\n"
        f"Completed At          : {eu_timestamp_now()}\n"
        f"Elapsed Time          : {elapsed:.2f}s\n"
        f"Interrupted By User   : {'YES' if interrupted else 'NO'}\n"
        f"Folder Size Written   : {guard.written_bytes / (1024 * 1024):.2f} MB / "
        f"{MAX_MAP_FOLDER_MB} MB cap\n"
        f"Truncated By Size Cap : {'YES' if guard.truncated else 'NO'}\n\n"
        "--- INSTRUCTION & MEMORY STATISTICS ---\n"
        f"Total Instructions    : {total_insns}\n"
        f"Unique Addresses      : {len(unique_addrs)}\n"
        f"Jump Instructions     : {jump_count}\n"
        f"Call Instructions     : {call_count}\n"
        f"Return Instructions   : {ret_count}\n"
        f"Memory Access Insns   : {mem_count}\n"
        f"Peak Memory (VmHWM)   : {peak_mem_kb} kB\n"
        f"Total System Calls    : {syscall_count}\n\n"
        "--- FUNCTIONS EXECUTED ---\n"
        + ("\n".join(func_lines) if func_lines else "  [none]")
        + "\n\n--- SYSTEM CALLS BREAKDOWN ---\n"
        + ("\n".join(sc_lines) if sc_lines else "  [none recorded]")
        + "\n"
    )
    summary_path.write_text(summary_txt, encoding="utf-8")

    print(f"[+] Mapping complete: {total_insns} instructions, {syscall_count} syscalls -> {out_dir}")
    print(f"[+] Summary saved   : {summary_path}")
    return out_dir
