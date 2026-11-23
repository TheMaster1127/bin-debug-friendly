# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import sys

try:
    import readline
except ImportError:
    readline = None

try:
    import termios
except ImportError:
    termios = None

from src.colors import format_diff_xxd_line, highlight_char_diff
from src.config import (
    PROMPT_SHOW_ADDRESS,
    PROMPT_SHOW_FUNCTION,
    PROMPT_SHOW_TOOL_NAME,
    PROMPT_TOOL_NAME,
    SHOW_OPCODES_IN_DISAS,
)
from src.gdb_session import GdbSession

TOP_COMMANDS = [
    "call", "view", "ls", "main", "start", "restart", "stop", "break", "jump", "jmp",
    "run", "continue", "step", "next", "skip", "ignore", "unignore", "stdin",
    "info", "show", "get", "set", "stack", "dump", "disas", "maps", "help", "quit", "exit",
]


def setup_readline_completer(session: GdbSession) -> None:
    if readline is None:
        return
    readline.set_history_length(1000)
    readline.set_completer_delims(" \t\n")

    def completer(text: str, state: int):
        buf = readline.get_line_buffer().lstrip()
        parts = buf.split()
        if len(parts) >= 2 or (len(parts) == 1 and buf.endswith((" ", "\t"))):
            first = parts[0].lower()
            if first in ("call", "stop", "b", "break", "jump", "jmp"):
                funcs = session.get_binary_functions()
                matches = [f for f in funcs if f.lower().startswith(text.lower())]
                return matches[state] if state < len(matches) else None
            return None

        matches = [c for c in TOP_COMMANDS if c.startswith(text.lower())]
        return matches[state] if state < len(matches) else None

    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")


def format_reg_parts(session: GdbSession, val: int, bits: int) -> dict[str, str]:
    mask = (1 << bits) - 1
    uval = val & mask
    hex_width = bits // 4
    nbytes = bits // 8
    raw = uval.to_bytes(nbytes, "little" if session.elf.endian == "<" else "big")

    hex_s = f"0x{uval:0{hex_width}x}"

    sign_bit = 1 << (bits - 1)
    sval = uval - (1 << bits) if (uval & sign_bit) else uval
    dec_s = f"{uval} ({sval})" if sval != uval else str(uval)

    char_s = "'" + "".join(chr(b) if 32 <= b < 127 else "." for b in raw) + "'"

    deref = session.read_c_string(uval)
    if deref is not None:
        safe = deref.replace("\n", "\\n").replace("\r", "\\r")
        str_s = f'-> "{safe[:40]}"'
    else:
        printable = "".join(chr(b) for b in raw if 32 <= b < 127)
        str_s = f'"{printable}"' if printable else '""'

    return {"hex": hex_s, "dec": dec_s, "char": char_s, "str": str_s}


def format_reg_line(
    session: GdbSession,
    rname: str,
    val: int,
    fmt: str,
    prev_val: int | None = None,
) -> str:
    parts = format_reg_parts(session, val, session.elf.bits)
    old_parts = format_reg_parts(session, prev_val, session.elf.bits) if prev_val is not None else None
    label = f"{rname.upper():<7}"

    if fmt == "hex":
        body = highlight_char_diff(parts["hex"], old_parts["hex"] if old_parts else None)
    elif fmt == "dec":
        body = highlight_char_diff(parts["dec"], old_parts["dec"] if old_parts else None)
    elif fmt == "char":
        body = highlight_char_diff(parts["char"], old_parts["char"] if old_parts else None)
    elif fmt == "str":
        body = highlight_char_diff(parts["str"], old_parts["str"] if old_parts else None)
    elif fmt == "all":
        h = highlight_char_diff(parts["hex"], old_parts["hex"] if old_parts else None)
        d = highlight_char_diff(parts["dec"], old_parts["dec"] if old_parts else None)
        c = highlight_char_diff(parts["char"], old_parts["char"] if old_parts else None)
        s = highlight_char_diff(parts["str"], old_parts["str"] if old_parts else None)
        pad_h = " " * max(0, 18 - len(parts["hex"]))
        pad_d = " " * max(0, 28 - len(parts["dec"]))
        pad_c = " " * max(0, 10 - len(parts["char"]))
        body = f"{h}{pad_h} | dec={d}{pad_d} | char={c}{pad_c} | str={s}"
    else:
        body = parts["hex"]

    return f"{label}: {body}"


def parse_set_value(raw: str, endian: str) -> int:
    s = raw.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        inner = s[1:-1]
        if inner:
            data = inner.encode("latin-1", errors="replace")
            return int.from_bytes(data, "little" if endian == "<" else "big")
    return int(s, 0)


def format_xxd_lines(
    data: bytes,
    base_addr: int,
    sp: int,
    prev_bytes: dict[int, int] | None = None,
) -> list[str]:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        addr = base_addr + off
        line, _changed = format_diff_xxd_line(addr, chunk, prev_bytes, sp)
        lines.append(line)
    return lines


def format_disas_line(
    session: GdbSession,
    runtime_addr: int,
    opcodes: str,
    insn: str,
    is_current: bool = False,
    marker: str | None = None,
) -> str:
    arrow = marker if marker is not None else ("=>" if is_current else "  ")
    disp_addr = session.to_display_addr(runtime_addr)
    if SHOW_OPCODES_IN_DISAS and opcodes:
        return f"  {arrow} 0x{disp_addr:x}:  {opcodes:<24} {insn}"
    return f"  {arrow} 0x{disp_addr:x}:  {insn}"


def build_prompt(session: GdbSession) -> str:
    if session.exited:
        return "(exited)> "
    chunks = []
    if PROMPT_SHOW_TOOL_NAME:
        chunks.append(PROMPT_TOOL_NAME)
    if PROMPT_SHOW_ADDRESS:
        pc = session.get_pc()
        if pc is not None:
            disp = session.to_display_addr(pc)
            chunks.append(f"0x{disp:x}")
    if PROMPT_SHOW_FUNCTION:
        fn = session.get_current_function()
        if fn:
            chunks.append(f"({fn})")
    if not chunks:
        return f"{PROMPT_TOOL_NAME}> "
    return " ".join(chunks) + "> "


def flush_target_stdout(session: GdbSession) -> None:
    out = session.pop_target_output()
    if out:
        print(f"--- program stdout ---\n{out.rstrip()}\n----------------------")


def print_stop_banner(session: GdbSession, stopped: dict | None) -> None:
    flush_target_stdout(session)
    if not stopped:
        return
    reason = stopped.get("reason", "paused")
    if session.exited:
        print(f"[*] Program exited (code={session.exit_code}). Type 'start', 'main', or 'run' to restart.")
        return
    pc = session.get_pc()
    if pc is not None:
        disp = session.to_display_addr(pc)
        fn = session.get_current_function()
        fn_str = f" in {fn}" if fn else ""
        insns = session.disassemble_at(pc, count=3)
        print(f"[*] Stopped ({reason}) at 0x{disp:x}{fn_str}")
        for idx, (a, op, text) in enumerate(insns):
            print(format_disas_line(session, a, op, text, is_current=(idx == 0)))
    else:
        print(f"[*] Stopped ({reason})")


def _flush_host_tty_stdin() -> None:
    if termios is not None:
        try:
            if sys.stdin.isatty():
                termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
        except Exception:
            pass


def prompt_for_target_stdin(proactive: bool = False) -> str | None:
    _flush_host_tty_stdin()
    msg = (
        "\n[INPUT] Target is calling fgets/scanf/read.\n"
        "Type stdin line + Enter (empty Enter sends '\\n', Ctrl+C cancels): "
        if proactive
        else "\n[INPUT] Target is waiting on stdin.\n"
             "Type stdin line + Enter (empty Enter sends '\\n', Ctrl+C pauses): "
    )
    try:
        return input(msg)
    except EOFError:
        return None


def handle_ignore_command(session: GdbSession, raw_line: str) -> str | None:
    clean = raw_line.strip().lstrip("/").lower()
    tokens = clean.split()
    if not tokens:
        return None

    verb = tokens[0]
    rest = tokens[1:]

    if verb in ("unignore", "unskip"):
        return session.ignore_mgr.clear()

    if verb == "skip" and rest and rest[0] in ("call", "calls"):
        if len(rest) > 1 and rest[1] == "once":
            return session.ignore_mgr.set_count(1)
        if len(rest) > 1 and rest[1].isdigit():
            return session.ignore_mgr.set_count(int(rest[1]))
        return session.ignore_mgr.set_all()

    if verb == "ignore":
        if not rest or rest[0] in ("call", "calls"):
            tail = rest[1:] if rest else []
            if not tail:
                return session.ignore_mgr.set_all()
            if tail[0] == "once":
                return session.ignore_mgr.set_count(1)
            if tail[0].isdigit():
                return session.ignore_mgr.set_count(int(tail[0]))
            if tail[0] in ("nest", "nested"):
                depth = len(session.get_binary_call_frames())
                return session.ignore_mgr.set_nest(depth)
        elif rest[0] == "once":
            return session.ignore_mgr.set_count(1)
        elif rest[0].isdigit():
            return session.ignore_mgr.set_count(int(rest[0]))
        elif rest[0] in ("nest", "nested"):
            depth = len(session.get_binary_call_frames())
            return session.ignore_mgr.set_nest(depth)
        return "Usage: ignore call | ignore once | ignore call <N> | ignore nest | unignore call"

    return None


def print_help() -> None:
    print(
        "\n=== bin-debug-friendly Complete Command Reference ===\n"
        "\n[Breakpoints & Navigation]\n"
        "  0x<addr>                   Shortcut: run/restart directly to exact hex address and stop\n"
        "  call <func> [--ignore]     Run to upcoming `call <func>` & enter it (Tab autocompletes!)\n"
        "                             Pass `--ignore` if not visible in view to break/run globally\n"
        "  stop <addr|sym>            Set breakpoint at objdump/hex address or symbol (aliases: b, break)\n"
        "  main / stop main           Run (or restart) directly until main() is hit\n"
        "  start / restart            Restart program from beginning, paused at _start\n"
        "  run (r)                    Start/continue (automatically restarts if exited)\n"
        "  continue (c, cont)         Resume execution until next breakpoint/exit\n"
        "  jump <addr|sym>            Force PC/RIP to jump immediately (alias: jmp)\n"
        "\n[Stepping & Call Control]\n"
        "  step [N] (s, si)           Step 1 (or N) instruction(s) into calls\n"
        "  next [N] (n, ni)           Step 1 (or N) instruction(s) over calls\n"
        "  step/next [N] dump [stack [all]]\n"
        "                             Step N times & save registers/stack (`stack` = start+end, `all` = every step)\n"
        "  skip                       Finish rest of current function and return to caller\n"
        "  ignore call                Step skips ALL calls (aliases: /ignore call, ignore calls, skip call)\n"
        "  ignore once / ignore call N\n"
        "                             Ignore next 1 (or N) call(s) (aliases: ignore N, skip call N)\n"
        "  ignore nest                Allow 1 call deeper, then ignore nested calls (alias: ignore nested)\n"
        "  unignore call              Resume stepping into calls (aliases: unignore, unskip call)\n"
        "\n[Live View Mode]\n"
        "  view [opts]                Enter stationary live-arrow window (aliases: follow, live)\n"
        "                             Options: max | min | only | regs | stack | raw stack | stack only | all\n"
        "                                      <N> (page size) | nest | nest<N> (e.g. nest2, nest5, nest0)\n"
        "                                      -h | -d | -c | -s (register format)\n"
        "                             Inside view: Enter/s/step N, n/next N, k/skip, call <fn> [--ignore],\n"
        "                               r/run, c/continue, main, start, stop <addr>, jump/jmp <addr>,\n"
        "                               set <reg> <val>, stdin <text>, dump stack, info/info all, size <N>,\n"
        "                               nest<N>, max/min, 0x.., q\n"
        "\n[Inspection & Memory]\n"
        "  ls [N] / lsN               Show N instructions before & after PC (default 2, warns >100)\n"
        "  disas [N]                  Disassemble N forward in Intel syntax (aliases: disassemble, d, disas main [N])\n"
        "  info [reg] [flag]          Dump all or 1 register (alias: show): -h (hex), -d (dec), -c (char), -s (str), all/-a\n"
        "  info stack                 Show registers + active stack preview\n"
        "  info raw stack             Show active stack preview only (alias: info stack only)\n"
        "  get <reg>                  Show single register in all formats\n"
        "  set <reg> [to] <val>       Modify register (hex, decimal, or quoted ASCII e.g. \"ABCD\")\n"
        "  stack                      Preview active stack (SP -> top)\n"
        "  stack less                 Browse active stack interactively in `less`\n"
        "  stack info                 Show stack mapping bounds, active & unused bytes\n"
        "  dump stack [full]          Save active zero-trimmed stack (or full VMA) to <bin>.stack.bin (alias: stack dump)\n"
        "  maps                       Print /proc/<pid>/maps memory layout\n"
        "  stdin <text>               Pre-queue a line of input for target stdin (fgets/scanf)\n"
        "  help (?) / quit (exit, q)  Show this help or exit debugger\n"
    )
