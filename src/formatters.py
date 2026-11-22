# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

from src.config import (
    PROMPT_SHOW_ADDRESS,
    PROMPT_SHOW_FUNCTION,
    PROMPT_SHOW_TOOL_NAME,
    PROMPT_TOOL_NAME,
    SHOW_OPCODES_IN_DISAS,
)
from src.gdb_session import GdbSession


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


def format_reg_line(session: GdbSession, rname: str, val: int, fmt: str) -> str:
    parts = format_reg_parts(session, val, session.elf.bits)
    label = f"{rname.upper():<7}"
    if fmt == "hex":
        return f"{label}: {parts['hex']}"
    if fmt == "dec":
        return f"{label}: {parts['dec']}"
    if fmt == "char":
        return f"{label}: {parts['char']}"
    if fmt == "str":
        return f"{label}: {parts['str']}"
    if fmt == "all":
        return (
            f"{label}: {parts['hex']:<18} | "
            f"dec={parts['dec']:<28} | "
            f"char={parts['char']:<10} | "
            f"str={parts['str']}"
        )
    return f"{label}: {parts['hex']}"


def parse_set_value(raw: str, endian: str) -> int:
    s = raw.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        inner = s[1:-1]
        if inner:
            data = inner.encode("latin-1", errors="replace")
            return int.from_bytes(data, "little" if endian == "<" else "big")
    return int(s, 0)


def format_xxd_lines(data: bytes, base_addr: int, sp: int) -> list[str]:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        addr = base_addr + off
        hex_pairs = " ".join(
            "".join(f"{b:02x}" for b in chunk[i:i + 2])
            for i in range(0, len(chunk), 2)
        )
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        marker = "  <-- SP" if addr <= sp < addr + 16 else ""
        lines.append(f"0x{addr:016x}: {hex_pairs:<39}  {ascii_part}{marker}")
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


def print_help() -> None:
    print(
        "\n=== bin-debug-friendly Commands ===\n"
        "  0x<addr>             Shortcut: run directly to exact hex address and stop\n"
        "  view [opts]          Live fixed-window mode (`=>` arrow moves, panels live-update)\n"
        "                         view [N] | view only | view stack | view raw stack | view all\n"
        "                         view nest | view nest2 | view nest5 (extra nested call panes)\n"
        "  ls [N] / lsN         Show instructions around current PC (default 2 before & after)\n"
        "  main / stop main     Run (or restart) directly until main() is hit\n"
        "  start / restart      Restart program paused at the entry point (_start)\n"
        "  stop <addr>          Set breakpoint at exact objdump/hex address\n"
        "  jump <addr>          Force PC/RIP to jump immediately to <addr> (alias: jmp)\n"
        "  run / continue (c)   Run/continue (or restart if exited)\n"
        "  next [N]             Step over calls 1 (or N) instruction(s)\n"
        "  step [N]             Step into calls 1 (or N) instruction(s)\n"
        "  next/step [N] dump [stack [all]]\n"
        "                       Step N times and dump registers (and stack) to file(s)\n"
        "  skip                 Skip rest of current function (return to caller)\n"
        "  info [reg] [flag]    Dump registers (alias: show)\n"
        "                         -h (hex) | -d (dec) | -c (char) | -s (str) | all\n"
        "                         info stack (regs+stack) | info raw stack (stack only)\n"
        "  get <reg>            Show one register in all formats\n"
        "  set <reg> [to] <val> Modify a register (hex, decimal, or quoted ASCII)\n"
        "  stack / stack less   Preview stack or browse interactively in `less`\n"
        "  stack info           Show stack region boundaries & size\n"
        "  dump stack [full]    Dump active zero-trimmed stack (or full) to .stack.bin\n"
        "  disas [N]            Disassemble N instructions forward (objdump Intel style)\n"
        "  maps                 Show memory mappings of process\n"
        "  help                 Show this help menu\n"
        "  quit / exit          Exit debugger\n"
    )
