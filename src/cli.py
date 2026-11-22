# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

try:
    import readline
    readline.set_history_length(1000)
except ImportError:
    readline = None

import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from src.config import (
    DEFAULT_INFO_FORMAT,
    EU_FOLDER_TS_FORMAT,
    EU_LOG_TS_FORMAT,
    MAX_INTERACTIVE_STEPS,
    STACK_PREVIEW_LINES,
)
from src.elf_utils import parse_address_input
from src.formatters import (
    build_prompt,
    format_disas_line,
    format_reg_line,
    format_xxd_lines,
    parse_set_value,
    print_help,
    print_stop_banner,
)
from src.gdb_session import GdbSession
from src.live_view import run_live_view


def handle_ls_command(session: GdbSession, raw_cmd: str, rest: str) -> None:
    if session.exited:
        print("[!] Program has exited. Type 'start' or 'main' first.")
        return
    if not session.started:
        session.ensure_started_paused()

    before, after = 2, 2
    arg_str = raw_cmd[2:] if len(raw_cmd) > 2 else (rest.split()[0] if rest else "")
    if arg_str:
        try:
            n = int(arg_str, 10)
        except ValueError:
            print(f"[!] Usage: ls [N] or lsN (e.g. ls, ls1, ls10). Got '{arg_str}'")
            return
        if n < 0:
            print("[!] Range must be >= 0.")
            return
        if n > 100:
            try:
                ans = input(
                    f"[!] Warning: displaying {n} instructions before and after ({2 * n + 1} lines) will fill your screen. Continue? (y/N): "
                ).strip().lower()
                if ans not in ("y", "yes"):
                    return
            except (EOFError, KeyboardInterrupt):
                print()
                return
        before = after = n

    pc = session.get_pc()
    if pc is None:
        print("[!] Cannot determine current PC.")
        return

    insns, pc_idx, cut_top, cut_bottom = session.disassemble_context(pc, before, after)
    if cut_top:
        print("  [--- cut off at top: start of code/function reached ---]")
    for idx, (a, op, text) in enumerate(insns):
        print(format_disas_line(session, a, op, text, is_current=(idx == pc_idx)))
    if cut_bottom:
        print("  [--- cut off at bottom: end of .text/code section reached ---]")


def print_stack_preview(session: GdbSession) -> None:
    lo, hi, sp, _ = session.get_stack_bounds()
    used = max(0, hi - sp)
    top_len = min(STACK_PREVIEW_LINES * 16, max(64, used))
    top_data = session.read_memory(sp, top_len) or b""
    print(f"=== Active Stack Preview (SP=0x{sp:x}, Active={used} bytes) ===")
    if top_data:
        print("-- From SP upward --")
        for line in format_xxd_lines(top_data, sp, sp):
            print(line)
    if used > top_len + 16:
        bot_addr = max(sp, hi - 64)
        bot_data = session.read_memory(bot_addr, hi - bot_addr) or b""
        if bot_data:
            print("-- High end of stack --")
            for line in format_xxd_lines(bot_data, bot_addr, sp):
                print(line)
    print("Tip: `stack less` to scroll, `stack info` for size, `dump stack` for trimmed .stack.bin")


def handle_step_with_dump(session: GdbSession, step_over: bool, count: int, dump_stack_mode: str | None) -> None:
    if dump_stack_mode == "all" and count > 1:
        try:
            ans = input(f"[!] Are you sure? This will generate {count} stack dump files! (y/N): ").strip().lower()
            if ans not in ("y", "yes"):
                print("[*] Cancelled.")
                return
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Cancelled.")
            return

    ts = datetime.now().strftime(EU_FOLDER_TS_FORMAT)
    prog = session.host_binary_path.name
    if dump_stack_mode:
        out_dir = Path.cwd() / f"{prog}_stepdump_{ts}"
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path = out_dir / "steps_registers.txt"
    else:
        out_dir = None
        log_path = Path.cwd() / f"{prog}_steps_{ts}.txt"

    if dump_stack_mode == "ends":
        ok_s, msg_s = session.dump_stack_to_file(out_dir / "stack_start.stack.bin")
        if ok_s:
            print(f"[+] {msg_s}")

    stopped = None
    with log_path.open("w", encoding="utf-8") as fh:
        fh.write(f"=== STEP DUMP ({'next' if step_over else 'step'} x{count}) ===\n\n")
        for idx in range(1, count + 1):
            if session.exited:
                break
            pc = session.get_pc()
            regs = session.get_registers()
            fn = session.get_current_function() or "?"
            insn_text = ""
            if pc is not None:
                ins = session.disassemble_at(pc, count=1)
                if ins:
                    insn_text = f"{ins[0][1]}  {ins[0][2]}".strip()
                pc_str = f"0x{session.to_display_addr(pc):x}"
            else:
                pc_str = "?"

            fh.write(
                f"[STEP {idx:04d}] TIME={datetime.now().strftime(EU_LOG_TS_FORMAT)} | "
                f"ADDR={pc_str} ({fn}) | INSN={insn_text}\n"
            )
            for rname, val in regs.items():
                fh.write("  " + format_reg_line(session, rname, val, "all") + "\n")
            fh.write("\n")

            if dump_stack_mode == "all":
                session.dump_stack_to_file(out_dir / f"step_{idx:04d}.stack.bin")

            stopped = session.step_instruction(1, step_over=step_over)
            if session.exited:
                break

    if dump_stack_mode == "ends" and not session.exited:
        ok_e, msg_e = session.dump_stack_to_file(out_dir / "stack_end.stack.bin")
        if ok_e:
            print(f"[+] {msg_e}")

    print(f"[+] Step dump saved -> {out_dir or log_path}")
    print_stop_banner(session, stopped)


def run_interactive_cli(session: GdbSession) -> None:
    print(
        f"\n[+] Ready | {session.host_binary_path.name} "
        f"| {session.elf.arch} ({session.elf.bits}-bit) "
        f"| PIE={'yes' if session.elf.is_pie else 'no'}"
    )
    print_stop_banner(session, {"reason": "ready"})
    print("Type 'help' for commands (try 'view' for live window, or '0x...' to jump/run there).")

    while True:
        try:
            raw_line = input(build_prompt(session)).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting.")
            break

        if not raw_line:
            continue

        parts = raw_line.split(None, 1)
        cmd = parts[0].lower()
        rest = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            break

        if cmd in ("help", "?"):
            print_help()
            continue

        if cmd in ("view", "follow", "live"):
            run_live_view(session, rest.split())
            continue

        if cmd == "ls" or re.fullmatch(r"ls\d+", cmd):
            handle_ls_command(session, cmd, rest)
            continue

        if cmd in ("start", "restart"):
            stopped = session.restart_to_entry()
            print_stop_banner(session, stopped)
            continue

        if cmd == "main":
            ok, msg, stopped = session.stop_at_symbol("main")
            print(f"[{'+' if ok else '!'}] {msg}")
            if ok:
                print_stop_banner(session, stopped)
            continue

        if cmd in ("jump", "jmp"):
            if not rest:
                print("[!] Usage: jump <hex_address_or_symbol>")
                continue
            parsed_addr, sym = parse_address_input(rest)
            ok, msg = session.jump_to_target(parsed_addr, sym)
            print(f"[{'+' if ok else '!'}] {msg}")
            if ok:
                print_stop_banner(session, {"reason": "jumped"})
            continue

        if cmd in ("stop", "b", "break"):
            if not rest:
                print("[!] Usage: stop <hex_address_or_symbol> (or `stop main`)")
                continue
            if rest.lower() == "main":
                ok, msg, stopped = session.stop_at_symbol("main")
                print(f"[{'+' if ok else '!'}] {msg}")
                if ok:
                    print_stop_banner(session, stopped)
                continue
            parsed_addr, clean_sym = parse_address_input(rest)
            ok, msg = session.set_breakpoint(parsed_addr, clean_sym)
            print(f"[{'+' if ok else '!'}] {msg}")
            continue

        if cmd in ("run", "r"):
            stopped = session.run_or_continue(restart_if_exited=True)
            print_stop_banner(session, stopped)
            continue

        if cmd in ("continue", "c", "cont"):
            stopped = session.run_or_continue(restart_if_exited=False)
            print_stop_banner(session, stopped)
            continue

        if cmd == "skip":
            ok, stopped, msg = session.skip_function()
            if not ok:
                print(f"[!] {msg}")
            else:
                print_stop_banner(session, stopped)
            continue

        if cmd in ("next", "n", "ni", "step", "s", "si"):
            step_over = cmd in ("next", "n", "ni")
            tokens = rest.split()
            count = 1
            dump_idx = next((i for i, t in enumerate(tokens) if t.lower() == "dump"), None)
            if dump_idx is not None:
                if tokens[:dump_idx]:
                    try:
                        count = int(tokens[0], 0)
                    except ValueError:
                        print(f"[!] Invalid count: {tokens[0]}")
                        continue
                if count < 1 or count > MAX_INTERACTIVE_STEPS:
                    print(f"[!] Step count must be between 1 and {MAX_INTERACTIVE_STEPS}.")
                    continue
                dump_tokens = [t.lower() for t in tokens[dump_idx + 1:]]
                mode = ("all" if "all" in dump_tokens else "ends") if "stack" in dump_tokens else None
                handle_step_with_dump(session, step_over, count, mode)
                continue
            if tokens:
                try:
                    count = int(tokens[0], 0)
                    if count < 1 or count > MAX_INTERACTIVE_STEPS:
                        print(f"[!] Step count must be between 1 and {MAX_INTERACTIVE_STEPS}.")
                        continue
                except ValueError:
                    print(f"[!] Usage: {cmd} [count] [dump [stack [all]]]")
                    continue
            stopped = session.step_instruction(count, step_over=step_over)
            print_stop_banner(session, stopped)
            continue

        if cmd in ("info", "show"):
            if session.exited:
                print("[!] Program has exited. Type 'start' or 'main' first.")
                continue
            if not session.started:
                session.ensure_started_paused()

            low_rest = rest.lower()
            if low_rest in ("raw stack", "stack only"):
                print_stack_preview(session)
                continue
            if low_rest == "stack":
                for rname, val in session.get_registers().items():
                    print(format_reg_line(session, rname, val, DEFAULT_INFO_FORMAT))
                print()
                print_stack_preview(session)
                continue

            tokens = rest.split()
            fmt = DEFAULT_INFO_FORMAT
            target_reg = None
            fmt_flags = ("-h", "--hex", "hex", "-d", "--dec", "dec", "-c", "--char", "char", "-s", "--str", "str", "string", "all", "-a", "--all")
            for tok in tokens:
                low = tok.lower()
                if low in ("-h", "--hex", "hex"):
                    fmt = "hex"
                elif low in ("-d", "--dec", "dec"):
                    fmt = "dec"
                elif low in ("-c", "--char", "char"):
                    fmt = "char"
                elif low in ("-s", "--str", "str", "string"):
                    fmt = "str"
                elif low in ("all", "-a", "--all"):
                    fmt = "all"
                else:
                    target_reg = tok

            if target_reg:
                res = session.get_single_register(target_reg)
                if not res:
                    print(f"[!] Unknown register or flag: '{target_reg}'")
                    continue
                rname, val = res
                explicit_fmt = any(t.lower() in fmt_flags for t in tokens)
                print(format_reg_line(session, rname, val, fmt if explicit_fmt else "all"))
                continue

            for rname, val in session.get_registers().items():
                print(format_reg_line(session, rname, val, fmt))
            continue

        if cmd == "get":
            if not rest:
                print("[!] Usage: get <register>")
                continue
            if session.exited:
                print("[!] Program has exited. Type 'start' or 'main' first.")
                continue
            if not session.started:
                session.ensure_started_paused()
            res = session.get_single_register(rest)
            if not res:
                print(f"[!] Register '{rest}' not found.")
                continue
            print(format_reg_line(session, res[0], res[1], "all"))
            continue

        if cmd == "set":
            if session.exited:
                print("[!] Program has exited. Type 'start' or 'main' first.")
                continue
            if not session.started:
                session.ensure_started_paused()
            m = re.match(r"^(\S+)\s+(?:to\s+)?(.+)$", rest, re.IGNORECASE)
            if not m:
                print("[!] Usage: set <register> [to] <value>")
                continue
            try:
                val = parse_set_value(m.group(2), session.elf.endian)
            except ValueError:
                print(f"[!] Invalid value: {m.group(2)}")
                continue
            ok, msg = session.set_register(m.group(1), val)
            print(f"[{'+' if ok else '!'}] {msg}")
            continue

        if cmd == "dump" and rest.lower().startswith("stack"):
            cmd = "stack"
            rest = rest.lower().replace("stack", "dump", 1).strip()

        if cmd == "stack":
            if session.exited:
                print("[!] Program has exited. Type 'start' or 'main' first.")
                continue
            if not session.started:
                session.ensure_started_paused()
            sub = rest.lower()
            if sub == "info":
                lo, hi, sp, exact = session.get_stack_bounds()
                total, used, free = hi - lo, max(0, hi - sp), max(0, sp - lo)
                print(
                    f"=== Stack Info ({'[stack] mapping' if exact else 'estimated'}) ===\n"
                    f"  Region    : 0x{lo:x} - 0x{hi:x}\n"
                    f"  Total Size: {total} bytes ({total / 1024:.2f} KB)\n"
                    f"  Current SP: 0x{sp:x}\n"
                    f"  Active Use: {used} bytes (SP -> top)\n"
                    f"  Unused    : {free} bytes (below SP)"
                )
            elif sub in ("dump", "dump full"):
                out_name = f"{session.host_binary_path.name}.stack.bin"
                ok, msg = session.dump_stack_to_file(Path.cwd() / out_name, full=(sub == "dump full"))
                print(f"[{'+' if ok else '!'}] {msg}")
                if ok:
                    print(f"    Inspect with: xxd {out_name} | less")
            elif sub == "less":
                lo, hi, sp, _ = session.get_stack_bounds()
                data = session.read_memory(sp, min(max(256, hi - sp), 256 * 1024))
                if not data:
                    print("[!] Failed to read stack memory.")
                    continue
                text = "\n".join(format_xxd_lines(data, sp, sp)) + "\n"
                less_bin = shutil.which("less")
                if less_bin:
                    subprocess.run([less_bin, "-R"], input=text, text=True)
                else:
                    print(text)
            else:
                print_stack_preview(session)
            continue

        if cmd in ("disas", "disassemble", "d"):
            if session.exited:
                print("[!] Program has exited. Type 'start' or 'main' first.")
                continue
            if not session.started:
                session.ensure_started_paused()
            tokens = rest.split()
            count, target_addr = 10, session.get_pc()
            if tokens:
                if tokens[0].lower() in ("-m", "main"):
                    res = session.send('-data-evaluate-expression "main"')
                    if res["status"] == "done":
                        m_addr = re.search(r"0x[0-9a-fA-F]+", str(res["payload"].get("value", "")))
                        if m_addr:
                            target_addr = int(m_addr.group(0), 16)
                    if len(tokens) > 1 and tokens[1].isdigit():
                        count = max(1, int(tokens[1]))
                elif tokens[0].isdigit():
                    count = max(1, int(tokens[0]))
            if target_addr is None:
                print("[!] Cannot determine address to disassemble.")
                continue
            pc = session.get_pc()
            for a, op, insn in session.disassemble_at(target_addr, count):
                print(format_disas_line(session, a, op, insn, is_current=(a == pc)))
            continue

        if cmd == "maps":
            if session.exited:
                print("[!] Program has exited. Type 'start' or 'main' first.")
                continue
            if not session.started:
                session.ensure_started_paused()
            for m in session.get_proc_mappings():
                print(f"  0x{m['start']:016x}-0x{m['end']:016x} ({m['size']:>8} B) {m['perms']:<5} {m['objfile']}")
            continue

        # Direct `0x...` hex address shortcut: run/stop right at that address
        compact_raw = re.sub(r"\s+", "", raw_line.strip("\"'"))
        if compact_raw.lower().startswith("0x"):
            parsed_addr, _sym = parse_address_input(raw_line)
            if parsed_addr is not None:
                ok, msg, stopped = session.goto_address(parsed_addr)
                print(f"[{'+' if ok else '!'}] {msg}")
                if ok:
                    print_stop_banner(session, stopped)
                continue

        print(f"[!] Unknown command '{cmd}'. Type 'help' for available commands.")
