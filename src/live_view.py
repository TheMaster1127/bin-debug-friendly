# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import re
import shutil

from src.config import (
    DEFAULT_INFO_FORMAT,
    MAX_INTERACTIVE_STEPS,
    VIEW_DEFAULT_NEST,
    VIEW_DEFAULT_REGS,
    VIEW_DEFAULT_STACK,
    VIEW_HIGHLIGHT_CHANGES,
    VIEW_PAGE_SIZE,
    VIEW_SPLIT_MIN_COLS,
    VIEW_STACK_ROWS,
)
from src.elf_utils import parse_address_input
from src.formatters import (
    format_disas_line,
    format_reg_line,
    format_xxd_lines,
    parse_set_value,
)
from src.gdb_session import GdbSession

NEST_TOKEN_RE = re.compile(r"^nest(\d*)$")
STEP_CMD_RE = re.compile(r"^(s|step|si|n|next|ni)(?:\s+(\d+|0x[0-9a-fA-F]+))?$")


def parse_nest_token(tok: str) -> int | None:
    m = NEST_TOKEN_RE.fullmatch(tok.strip().lower())
    if not m:
        return None
    return 1 if m.group(1) == "" else int(m.group(1))


def parse_view_options(tokens: list[str]) -> tuple[int, bool, bool, str, int]:
    page_size = VIEW_PAGE_SIZE
    show_regs = VIEW_DEFAULT_REGS
    show_stack = VIEW_DEFAULT_STACK
    reg_fmt = DEFAULT_INFO_FORMAT
    nest_limit = VIEW_DEFAULT_NEST

    low_tokens = [t.lower() for t in tokens]
    low_joined = " ".join(low_tokens)
    if "raw stack" in low_joined or "stack only" in low_joined:
        show_regs = False
        show_stack = True
    elif "only" in low_tokens:
        show_regs = False
        show_stack = False
    elif "all" in low_tokens:
        show_regs = True
        show_stack = True
        reg_fmt = "all"
    elif "stack" in low_tokens:
        show_regs = True
        show_stack = True

    for tok in low_tokens:
        nval = parse_nest_token(tok)
        if nval is not None:
            nest_limit = max(0, min(10, nval))
            continue
        if tok.isdigit():
            page_size = max(3, min(200, int(tok)))
        elif tok in ("-h", "hex"):
            reg_fmt = "hex"
        elif tok in ("-d", "dec"):
            reg_fmt = "dec"
        elif tok in ("-c", "char"):
            reg_fmt = "char"
        elif tok in ("-s", "str"):
            reg_fmt = "str"

    return page_size, show_regs, show_stack, reg_fmt, nest_limit


def render_two_columns(left: list[str], right: list[str], left_width: int) -> list[str]:
    out = []
    total = max(len(left), len(right))
    for i in range(total):
        l_txt = left[i] if i < len(left) else ""
        r_txt = right[i] if i < len(right) else ""
        if len(l_txt) > left_width:
            l_txt = l_txt[:left_width - 1] + "~"
        out.append(f"{l_txt:<{left_width}} | {r_txt}")
    return out


def fetch_view_page(
    session: GdbSession,
    pc: int,
    page_size: int,
    func_name: str | None = None,
) -> list[tuple[int, str, str]]:
    before = min(3, max(1, page_size // 5))
    after = max(1, page_size - before - 1)
    fn = func_name or session.get_current_function()
    if fn and fn != "??":
        f_res = session.send(f'-data-evaluate-expression "{fn}"')
        if f_res["status"] == "done":
            m = re.search(r"0x[0-9a-fA-F]+", str(f_res["payload"].get("value", "")))
            if m:
                faddr = int(m.group(0), 16)
                if faddr <= pc and (pc - faddr) < page_size * 12:
                    fn_insns = session.disassemble_at(faddr, count=page_size)
                    if any(a == pc for a, _, _ in fn_insns):
                        return fn_insns

    insns, _idx, _ct, _cb = session.disassemble_context(pc, before, after, func_name=fn)
    return insns


def should_refresh_page(page_insns: list[tuple[int, str, str]], pc: int | None, force_refresh: bool) -> bool:
    if pc is None:
        return False
    if force_refresh or not page_insns:
        return True
    return not any(a == pc for a, _, _ in page_insns)


def select_visible_frames(frames: list[dict], nest_limit: int) -> list[dict]:
    if not frames:
        return []
    if nest_limit <= 0 or len(frames) == 1:
        return [frames[-1]]
    nested = frames[1:]
    if len(nested) > nest_limit:
        nested = nested[-nest_limit:]
    return [frames[0]] + nested


def build_code_panes(
    session: GdbSession,
    visible_frames: list[dict],
    frame_pages: dict[int, list[tuple[int, str, str]]],
    page_size: int,
    nest_limit: int,
    force_refresh: bool,
) -> list[str]:
    if session.exited:
        return [
            f"[CODE] page={page_size} | nest={nest_limit}",
            f"  [*] Program exited (code={session.exit_code}). Type 'main', 'start', or 'q'.",
        ]

    lines: list[str] = []
    per_pane_size = page_size if len(visible_frames) <= 1 else max(5, page_size // len(visible_frames))

    active_keys = {i for i in range(len(visible_frames))}
    for k in list(frame_pages.keys()):
        if k not in active_keys:
            del frame_pages[k]

    for idx, fr in enumerate(visible_frames):
        addr = fr["addr"]
        fn = fr["func"]
        is_innermost = (idx == len(visible_frames) - 1)

        cached = frame_pages.get(idx, [])
        if should_refresh_page(cached, addr, force_refresh):
            cached = fetch_view_page(session, addr, per_pane_size, func_name=fn)
            frame_pages[idx] = cached

        if idx == 0 and len(visible_frames) == 1:
            hdr = f"[CODE: {fn}] page={page_size} | nest={nest_limit} | step N | nest<N> | size <N> | only | regs | stack"
        elif idx == 0:
            hdr = f"[ROOT: {fn}] (caller paused at ->)"
        else:
            hdr = f"[NEST {idx}/{nest_limit}: {fn}]" + (" (active =>)" if is_innermost else " (caller ->)")
        lines.append(hdr)

        highlight_idx = next((i for i, (a, _, _) in enumerate(cached) if a == addr), -1)
        if not is_innermost and highlight_idx > 0:
            highlight_idx -= 1

        for i, (a, op, insn) in enumerate(cached):
            if i == highlight_idx:
                marker = "=>" if is_innermost else "->"
            else:
                marker = "  "
            lines.append(format_disas_line(session, a, op, insn, marker=marker))

        if idx < len(visible_frames) - 1:
            lines.append("")

    return lines


def build_reg_lines(
    session: GdbSession,
    regs: dict[str, int],
    prev_regs: dict[str, int],
    fmt: str,
    compact_side: bool,
) -> list[str]:
    lines = ["[REGISTERS] (* = changed)"]
    for rname, val in regs.items():
        changed = VIEW_HIGHLIGHT_CHANGES and rname in prev_regs and prev_regs[rname] != val
        mark = "*" if changed else " "
        if compact_side and fmt == "hex":
            hex_w = session.elf.bits // 4
            lines.append(f"{mark}{rname.upper():<6}: 0x{val:0{hex_w}x}")
        else:
            lines.append(mark + format_reg_line(session, rname, val, fmt))
    return lines


def build_stack_lines(
    session: GdbSession,
    rows: int,
    prev_stack_map: dict[int, bytes],
) -> tuple[list[str], dict[int, bytes]]:
    lo, hi, sp, _ = session.get_stack_bounds()
    used = max(0, hi - sp)
    read_len = min(max(64, rows * 16), max(64, used))
    data = session.read_memory(sp, read_len) or b""
    lines = [f"[STACK] SP=0x{sp:x} (Active={used} B, * = changed)"]
    cur_map: dict[int, bytes] = {}
    if data:
        xxd_lines = format_xxd_lines(data, sp, sp)
        for idx, line in enumerate(xxd_lines):
            row_addr = sp + idx * 16
            chunk = data[idx * 16:(idx + 1) * 16]
            cur_map[row_addr] = chunk
            changed = VIEW_HIGHLIGHT_CHANGES and row_addr in prev_stack_map and prev_stack_map[row_addr] != chunk
            mark = "*" if changed else " "
            lines.append(mark + line)
    else:
        lines.append("  [stack unreadable]")
    return lines, cur_map


def render_live_screen(
    session: GdbSession,
    code_lines: list[str],
    show_regs: bool,
    show_stack: bool,
    reg_fmt: str,
    prev_regs: dict[str, int],
    prev_stack_map: dict[int, bytes],
    extra_msg: str,
) -> tuple[dict[str, int], dict[int, bytes]]:
    term_cols, _ = shutil.get_terminal_size((100, 30))
    pc = session.get_pc() if not session.exited else None
    fn = (session.get_current_function() or "??") if not session.exited else "exited"

    regs = session.get_registers() if (not session.exited and show_regs) else {}
    reg_lines = (
        build_reg_lines(session, regs, prev_regs, reg_fmt, compact_side=(term_cols >= VIEW_SPLIT_MIN_COLS))
        if show_regs and regs
        else []
    )
    if not session.exited and show_stack:
        stack_lines, cur_stack_map = build_stack_lines(session, VIEW_STACK_ROWS, prev_stack_map)
    else:
        stack_lines, cur_stack_map = [], {}

    print("\033[2J\033[H", end="")
    disp_pc = session.to_display_addr(pc) if pc is not None else 0
    status_hdr = "EXITED" if session.exited else f"0x{disp_pc:x} ({fn})"
    print(f"=== LIVE VIEW | {session.host_binary_path.name} | {status_hdr} | term={term_cols} cols ===")
    print("=" * min(term_cols, 140))

    if term_cols >= VIEW_SPLIT_MIN_COLS and (reg_lines or stack_lines):
        left_pane = list(code_lines)
        right_pane: list[str] = []
        if reg_lines and stack_lines:
            left_pane.append("")
            left_pane.extend(reg_lines)
            right_pane = stack_lines
            left_w = max(62, term_cols // 2 - 2)
        else:
            right_pane = stack_lines if stack_lines else reg_lines
            left_w = max(58, int(term_cols * 0.52))
        for row in render_two_columns(left_pane, right_pane, left_w):
            print(row)
    else:
        for line in code_lines:
            print(line)
        if reg_lines:
            print("-" * min(term_cols, 100))
            if reg_fmt == "hex" and not show_stack:
                items = reg_lines[1:]
                print(reg_lines[0])
                for i in range(0, len(items), 3):
                    print("  " + " | ".join(f"{x:<28}" for x in items[i:i + 3]))
            else:
                for line in reg_lines:
                    print(line)
        if stack_lines:
            print("-" * min(term_cols, 100))
            for line in stack_lines:
                print(line)

    print("=" * min(term_cols, 140))
    if extra_msg:
        print(f"  [{extra_msg}]")
    return regs, cur_stack_map


def run_live_view(session: GdbSession, args_tokens: list[str] | None = None) -> None:
    if session.exited:
        print("[!] Program has exited. Type 'start' or 'main' first.")
        return
    if not session.started:
        session.ensure_started_paused()

    page_size, show_regs, show_stack, reg_fmt, nest_limit = parse_view_options(args_tokens or [])
    frame_pages: dict[int, list[tuple[int, str, str]]] = {}
    prev_regs: dict[str, int] = {}
    prev_stack_map: dict[int, bytes] = {}
    extra_msg = ""
    force_refresh = True

    while True:
        if not session.exited:
            all_frames = session.get_binary_call_frames()
            if not all_frames:
                pc = session.get_pc()
                fn = session.get_current_function() or "??"
                all_frames = [{"level": 0, "addr": pc, "func": fn}] if pc is not None else []
            visible_frames = select_visible_frames(all_frames, nest_limit)
        else:
            visible_frames = []

        code_lines = build_code_panes(
            session, visible_frames, frame_pages, page_size, nest_limit, force_refresh
        )
        force_refresh = False

        out = session.pop_target_output()
        if out:
            extra_msg = f"stdout: {out.strip()}"

        current_regs, current_stack_map = render_live_screen(
            session, code_lines, show_regs, show_stack, reg_fmt, prev_regs, prev_stack_map, extra_msg
        )
        extra_msg = ""

        try:
            raw = input("\nview [Enter/step N, next N, skip, run, nest[N], size N, only, regs, stack, 0x.., q]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        low = raw.lower()
        if low in ("q", "quit", "exit"):
            break

        # Empty Enter = step 1
        if low == "":
            if not session.exited:
                prev_regs = current_regs
                prev_stack_map = current_stack_map
                session.step_instruction(1, step_over=False)
            else:
                extra_msg = "Program exited (type 'start' or 'main')"
            continue

        # step / s / si / next / n / ni with optional count (e.g. `step 5`, `next 10`)
        m_step = STEP_CMD_RE.fullmatch(low)
        if m_step:
            if session.exited:
                extra_msg = "Program exited (type 'start' or 'main')"
                continue
            verb = m_step.group(1)
            cnt_str = m_step.group(2)
            count = int(cnt_str, 0) if cnt_str else 1
            if count < 1 or count > MAX_INTERACTIVE_STEPS:
                extra_msg = f"Step count must be 1..{MAX_INTERACTIVE_STEPS}"
                continue
            step_over = verb in ("n", "next", "ni")
            prev_regs = current_regs
            prev_stack_map = current_stack_map
            session.step_instruction(count, step_over=step_over)
            continue

        if low in ("k", "skip"):
            prev_regs = current_regs
            prev_stack_map = current_stack_map
            ok, _st, msg = session.skip_function()
            if not ok:
                extra_msg = msg
            continue

        if low in ("r", "run", "c", "continue"):
            prev_regs = current_regs
            prev_stack_map = current_stack_map
            session.run_or_continue(restart_if_exited=(low in ("r", "run")))
            continue

        if low == "main":
            prev_regs = {}
            prev_stack_map = {}
            ok, msg, _ = session.stop_at_symbol("main")
            extra_msg = msg
            force_refresh = True
            continue

        if low in ("start", "restart"):
            prev_regs = {}
            prev_stack_map = {}
            session.restart_to_entry()
            force_refresh = True
            continue

        nval = parse_nest_token(low)
        if nval is not None:
            nest_limit = max(0, min(10, nval))
            force_refresh = True
            extra_msg = f"Nesting depth set to {nest_limit}" if nest_limit > 0 else "Nesting disabled"
            continue

        if low == "only":
            show_regs, show_stack = False, False
            continue

        if low == "regs":
            show_regs = not show_regs
            continue

        if low == "stack":
            show_stack = not show_stack
            continue

        if low in ("raw stack", "info raw stack"):
            show_regs, show_stack = False, True
            continue

        if low in ("info stack", "all"):
            show_regs, show_stack = True, True
            continue

        m_sz = re.match(r"^(?:view|size)\s+(\d+)$", low)
        if m_sz:
            page_size = max(3, min(200, int(m_sz.group(1))))
            force_refresh = True
            continue

        if low.isdigit():
            page_size = max(3, min(200, int(low)))
            force_refresh = True
            continue

        if low.startswith(("jump ", "jmp ")):
            target_str = raw.split(None, 1)[1].strip()
            p_addr, sym = parse_address_input(target_str)
            _ok, msg = session.jump_to_target(p_addr, sym)
            extra_msg = msg
            force_refresh = True
            continue

        if low.startswith("stop "):
            target_str = raw.split(None, 1)[1].strip()
            p_addr, sym = parse_address_input(target_str)
            _ok, msg = session.set_breakpoint(p_addr, sym)
            extra_msg = msg
            continue

        if low.startswith("set "):
            m = re.match(r"^set\s+(\S+)\s+(?:to\s+)?(.+)$", raw, re.IGNORECASE)
            if m:
                try:
                    val = parse_set_value(m.group(2), session.elf.endian)
                    _ok, msg = session.set_register(m.group(1), val)
                    extra_msg = msg
                except ValueError:
                    extra_msg = f"Invalid value: {m.group(2)}"
            continue

        if low in ("dump stack", "stack dump"):
            out_path = session.host_binary_path.parent / f"{session.host_binary_path.name}.stack.bin"
            _ok, msg = session.dump_stack_to_file(out_path)
            extra_msg = msg
            continue

        if re.sub(r"\s+", "", low).strip("\"'").startswith("0x"):
            p_addr, _sym = parse_address_input(raw)
            if p_addr is not None:
                prev_regs = current_regs
                prev_stack_map = current_stack_map
                _ok, msg, _ = session.goto_address(p_addr)
                extra_msg = msg
                force_refresh = True
                continue

        extra_msg = f"Unknown view command '{raw}'"
