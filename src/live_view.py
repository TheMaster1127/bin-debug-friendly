# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import re
import shutil
import sys
import time

from src.colors import format_diff_xxd_line, green, highlight_char_diff, pad_visible, truncate_visible
from src.config import (
    COLLAPSE_STACK_ZEROS_IN_VIEW,
    MAX_INTERACTIVE_STEPS,
    RECORD_DISAS_CONTEXT,
    VIEW_DEFAULT_NEST,
    VIEW_DEFAULT_REG_FORMAT,
    VIEW_DEFAULT_REGS,
    VIEW_DEFAULT_STACK,
    VIEW_HIGHLIGHT_CHANGES,
    VIEW_PAGE_SIZE,
    VIEW_SPLIT_MIN_COLS,
    VIEW_STACK_ROWS,
)
from src.elf_utils import parse_address_input
from src.formatters import (
    build_prompt,
    format_disas_line,
    format_reg_line,
    format_xxd_lines,
    handle_ignore_command,
    parse_set_value,
    setup_readline_completer,
)
from src.gdb_session import GdbSession
from src.recorder import SessionRecorder

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
    reg_fmt = VIEW_DEFAULT_REG_FORMAT
    nest_limit = VIEW_DEFAULT_NEST

    low_tokens = [t.lower() for t in tokens]
    low_joined = " ".join(low_tokens)
    if "raw stack" in low_joined or "stack only" in low_joined:
        show_regs = False
        show_stack = True
    elif "only" in low_tokens or "min" in low_tokens:
        show_regs = False
        show_stack = False
    elif "max" in low_tokens:
        show_regs = True
        show_stack = True
        reg_fmt = "all"
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
        l_txt = truncate_visible(l_txt, left_width)
        l_txt = pad_visible(l_txt, left_width)
        out.append(f"{l_txt} | {r_txt}")
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
        lines = [
            f"[EXITED] exit_code={session.exit_code} | page={page_size} | nest={nest_limit}",
            "  --- Program Output (stdout) ---",
        ]
        all_out = session.get_all_target_stdout().strip()
        if all_out:
            for out_ln in all_out.splitlines():
                lines.append("  " + green(out_ln))
        else:
            lines.append("  [no stdout produced]")
        lines.append("  -------------------------------")
        lines.append("  Type 'main', 'start', or 'q' to leave view.")
        return lines

    lines = []
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
            hdr = (
                f"[CODE: {fn}] page={page_size} | nest={nest_limit} | "
                f"{session.ignore_mgr.status_label()} | info | info all | stack | min"
            )
        elif idx == 0:
            hdr = f"[ROOT: {fn}] (caller ->)"
        else:
            hdr = f"[NEST {idx}/{nest_limit}: {fn}]" + (" (active =>)" if is_innermost else " (caller ->)")
        lines.append(hdr)

        highlight_idx = next((i for i, (a, _, _) in enumerate(cached) if a == addr), -1)
        if not is_innermost and highlight_idx > 0:
            highlight_idx -= 1

        for i, (a, op, insn) in enumerate(cached):
            marker = ("=>" if is_innermost else "->") if i == highlight_idx else "  "
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
    lines = [f"[REGISTERS fmt={fmt}] (* / green = changed chars; `info` toggles, `info all` toggles hex/all)"]
    hex_w = session.elf.bits // 4
    for rname, val in regs.items():
        has_prev = VIEW_HIGHLIGHT_CHANGES and rname in prev_regs
        prev_val = prev_regs[rname] if has_prev else None
        changed = has_prev and prev_val != val
        mark = "*" if changed else " "
        if compact_side and fmt == "hex":
            val_str = f"0x{val:0{hex_w}x}"
            if changed and prev_val is not None:
                old_str = f"0x{prev_val:0{hex_w}x}"
                val_str = highlight_char_diff(val_str, old_str)
            lines.append(f"{mark}{rname.upper():<6}: {val_str}")
        else:
            lines.append(mark + format_reg_line(session, rname, val, fmt, prev_val=prev_val if changed else None))
    return lines


def build_stack_lines(
    session: GdbSession,
    max_display_rows: int,
    prev_stack_bytes: dict[int, int],
) -> tuple[list[str], dict[int, int]]:
    lo, hi, sp, _ = session.get_stack_bounds()
    used = max(0, hi - sp)
    read_len = min(max(256, used), 16 * 1024)
    data = session.read_memory(sp, read_len) or b""
    lines = [f"[STACK] SP=0x{sp:x} (Active={used} B, * / green = changed bytes)"]
    cur_bytes: dict[int, int] = {}
    if not data:
        lines.append("  [stack unreadable]")
        return lines, cur_bytes

    for i, b in enumerate(data):
        cur_bytes[sp + i] = b

    row_entries: list[tuple[str, bool, bool]] = []
    for off in range(0, len(data), 16):
        row_addr = sp + off
        chunk = data[off:off + 16]
        line, changed = format_diff_xxd_line(
            row_addr, chunk, prev_stack_bytes if VIEW_HIGHLIGHT_CHANGES else None, sp
        )
        mark = "*" if changed else " "
        is_all_zero = (not changed) and (row_addr > sp) and all(b == 0 for b in chunk)
        row_entries.append((mark + line, is_all_zero, changed))

    if COLLAPSE_STACK_ZEROS_IN_VIEW:
        collapsed: list[str] = []
        i = 0
        while i < len(row_entries):
            text, is_zero, _chg = row_entries[i]
            if is_zero:
                j = i
                while j < len(row_entries) and row_entries[j][1]:
                    j += 1
                run_len = j - i
                if run_len >= 3:
                    collapsed.append(row_entries[i][0])
                    collapsed.append(f"  ... ({run_len - 2} zero lines / {(run_len - 2) * 16} bytes skipped) ...")
                    collapsed.append(row_entries[j - 1][0])
                else:
                    for k in range(i, j):
                        collapsed.append(row_entries[k][0])
                i = j
            else:
                collapsed.append(text)
                i += 1
        body_lines = collapsed
    else:
        body_lines = [r[0] for r in row_entries]

    if len(body_lines) > max_display_rows:
        omitted = len(body_lines) - max_display_rows
        body_lines = body_lines[:max_display_rows - 1] + [f"  ... ({omitted + 1} more stack lines; use `stack less` or `dump stack`) ..."]

    lines.extend(body_lines)
    return lines, cur_bytes


def render_live_screen(
    session: GdbSession,
    code_lines: list[str],
    show_regs: bool,
    show_stack: bool,
    reg_fmt: str,
    prev_regs: dict[str, int],
    prev_stack_bytes: dict[int, int],
    extra_msg: str,
) -> tuple[dict[str, int], dict[int, int]]:
    term_cols, term_rows = shutil.get_terminal_size((100, 30))
    pc = session.get_pc() if not session.exited else None
    fn = (session.get_current_function() or "??") if not session.exited else "exited"

    regs = session.get_registers() if (not session.exited and show_regs) else {}
    reg_lines = (
        build_reg_lines(session, regs, prev_regs, reg_fmt, compact_side=(term_cols >= VIEW_SPLIT_MIN_COLS))
        if show_regs and regs
        else []
    )
    if term_cols >= VIEW_SPLIT_MIN_COLS:
        stack_rows = max(VIEW_STACK_ROWS, term_rows - 7)
    else:
        stack_rows = VIEW_STACK_ROWS

    if not session.exited and show_stack:
        stack_lines, cur_stack_bytes = build_stack_lines(session, stack_rows, prev_stack_bytes)
    else:
        stack_lines, cur_stack_bytes = [], {}

    disp_pc = session.to_display_addr(pc) if pc is not None else 0
    status_hdr = "EXITED" if session.exited else f"0x{disp_pc:x} ({fn})"

    out_lines: list[str] = [
        f"=== LIVE VIEW | {session.host_binary_path.name} | {status_hdr} | {session.ignore_mgr.status_label()} ===",
        "=" * min(term_cols, 140),
    ]

    if term_cols >= VIEW_SPLIT_MIN_COLS and (reg_lines or stack_lines):
        left_pane = list(code_lines)
        right_pane: list[str] = []
        if reg_lines and stack_lines:
            left_pane.append("")
            left_pane.extend(reg_lines)
            right_pane = stack_lines
            if reg_fmt == "all":
                left_w = max(105, min(term_cols - 92, int(term_cols * 0.60)))
            else:
                left_w = max(62, term_cols // 2 - 2)
        else:
            right_pane = stack_lines if stack_lines else reg_lines
            left_w = max(58, int(term_cols * 0.52))
        out_lines.extend(render_two_columns(left_pane, right_pane, left_w))
    else:
        out_lines.extend(code_lines)
        if reg_lines:
            out_lines.append("-" * min(term_cols, 100))
            if reg_fmt == "hex" and not show_stack:
                items = reg_lines[1:]
                out_lines.append(reg_lines[0])
                for i in range(0, len(items), 3):
                    out_lines.append("  " + " | ".join(pad_visible(x, 28) for x in items[i:i + 3]))
            else:
                out_lines.extend(reg_lines)
        if stack_lines:
            out_lines.append("-" * min(term_cols, 100))
            out_lines.extend(stack_lines)

    out_lines.append("=" * min(term_cols, 140))
    if extra_msg:
        out_lines.append(f"  [{extra_msg}]")

    frame = "\033[H" + "\n".join(f"{ln}\033[K" for ln in out_lines) + "\n\033[J"
    sys.stdout.write(frame)
    sys.stdout.flush()
    return regs, cur_stack_bytes


def _read_full_active_stack_lines(session: GdbSession) -> list[str]:
    lo, hi, sp, _ = session.get_stack_bounds()
    active_len = min(max(64, hi - sp), 64 * 1024)
    sdata = session.read_memory(sp, active_len) or b""
    if not sdata:
        return []
    return format_xxd_lines(sdata, sp, sp)


def _record_view_step(
    session: GdbSession,
    recorder: SessionRecorder | None,
    cmd_str: str,
    t0: float,
    prev_regs: dict[str, int],
    stdout_text: str,
    note: str = "",
) -> None:
    if recorder is None:
        return
    dur = (time.time() - t0) * 1000.0
    if session.exited:
        recorder.record_event(
            command=cmd_str,
            duration_ms=dur,
            pc_disp="EXITED",
            func_name="exited",
            disas_lines=[],
            regs={},
            prev_regs=prev_regs,
            stack_lines=[],
            stdout_text=stdout_text,
            note=f"exit_code={session.exit_code}" if not note else note,
            derefs=None,
        )
        return
    pc = session.get_pc()
    fn = session.get_current_function() or "??"
    pc_disp = f"0x{session.to_display_addr(pc):x}" if pc is not None else "?"
    ctx_insns, pc_idx, _, _ = (
        session.disassemble_context(pc, RECORD_DISAS_CONTEXT, RECORD_DISAS_CONTEXT, func_name=fn)
        if pc is not None
        else ([], -1, False, False)
    )
    disas_lines = [
        format_disas_line(session, a, op, insn, is_current=(idx == pc_idx))
        for idx, (a, op, insn) in enumerate(ctx_insns)
    ]
    regs = session.get_registers()
    derefs = session.get_registers_deref()
    slines = _read_full_active_stack_lines(session)
    recorder.record_event(
        command=cmd_str,
        duration_ms=dur,
        pc_disp=pc_disp,
        func_name=fn,
        disas_lines=disas_lines,
        regs=regs,
        prev_regs=prev_regs,
        stack_lines=slines,
        stdout_text=stdout_text,
        note=note,
        derefs=derefs,
    )


def run_live_view(
    session: GdbSession,
    args_tokens: list[str] | None = None,
    recorder: SessionRecorder | None = None,
) -> None:
    if session.exited:
        print("[!] Program has exited. Type 'start' or 'main' first.")
        return
    if not session.started:
        session.ensure_started_paused()

    setup_readline_completer(session)

    page_size, show_regs, show_stack, reg_fmt, nest_limit = parse_view_options(args_tokens or [])
    frame_pages: dict[int, list[tuple[int, str, str]]] = {}
    prev_regs: dict[str, int] = {}
    prev_stack_bytes: dict[int, int] = {}
    extra_msg = ""
    force_refresh = True

    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

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
        if out and not extra_msg:
            extra_msg = f"stdout: {out.strip()}"

        current_regs, current_stack_bytes = render_live_screen(
            session, code_lines, show_regs, show_stack, reg_fmt, prev_regs, prev_stack_bytes, extra_msg
        )

        if recorder is not None:
            recorder.flush_idle()

        extra_msg = ""
        loc_prompt = build_prompt(session)

        try:
            raw = input(
                f"\nview [Enter/step N, next N, call <fn>, skip, ignore.., info, stack, nest[N], 0x.., q] {loc_prompt}"
            ).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        low = raw.lower()
        t0 = time.time()

        if low in ("q", "quit", "exit"):
            break

        ign_msg = handle_ignore_command(session, raw)
        if ign_msg is not None:
            extra_msg = ign_msg
            if recorder is not None:
                recorder.record_command_only(raw, (time.time() - t0) * 1000.0, note=ign_msg)
            continue

        if low.startswith("stdin "):
            txt = raw.split(None, 1)[1]
            session.write_target_stdin(txt)
            extra_msg = f"Queued stdin line: {txt!r}"
            if recorder is not None:
                recorder.record_command_only(raw, (time.time() - t0) * 1000.0, note=extra_msg)
            continue

        if low == "" or STEP_CMD_RE.fullmatch(low):
            if session.exited:
                extra_msg = "Program exited (type 'start' or 'main')"
                continue
            if low == "":
                count, step_over, cmd_label = 1, False, "step"
            else:
                m_step = STEP_CMD_RE.fullmatch(low)
                verb = m_step.group(1)
                cnt_str = m_step.group(2)
                count = int(cnt_str, 0) if cnt_str else 1
                if count < 1 or count > MAX_INTERACTIVE_STEPS:
                    extra_msg = f"Step count must be 1..{MAX_INTERACTIVE_STEPS}"
                    continue
                step_over = verb in ("n", "next", "ni")
                cmd_label = raw

            prev_regs = current_regs
            prev_stack_bytes = current_stack_bytes
            session.step_instruction(count, step_over=step_over)
            step_out = session.pop_target_output()
            if step_out:
                extra_msg = f"stdout: {step_out.strip()}"
            _record_view_step(session, recorder, cmd_label, t0, prev_regs, step_out)
            continue

        if low in ("k", "skip"):
            prev_regs = current_regs
            prev_stack_bytes = current_stack_bytes
            ok, _st, msg = session.skip_function()
            if not ok:
                extra_msg = msg
            step_out = session.pop_target_output()
            if step_out and ok:
                extra_msg = f"stdout: {step_out.strip()}"
            _record_view_step(session, recorder, "skip", t0, prev_regs, step_out, note=msg)
            continue

        if low in ("r", "run", "c", "continue"):
            prev_regs = current_regs
            prev_stack_bytes = current_stack_bytes
            session.run_or_continue(restart_if_exited=(low in ("r", "run")))
            step_out = session.pop_target_output()
            if step_out:
                extra_msg = f"stdout: {step_out.strip()}"
            _record_view_step(session, recorder, raw, t0, prev_regs, step_out)
            continue

        if low == "main":
            prev_regs = {}
            prev_stack_bytes = {}
            ok, msg, _ = session.stop_at_symbol("main")
            extra_msg = msg
            force_refresh = True
            step_out = session.pop_target_output()
            _record_view_step(session, recorder, "main", t0, prev_regs, step_out, note=msg)
            continue

        if low in ("start", "restart"):
            prev_regs = {}
            prev_stack_bytes = {}
            session.restart_to_entry()
            force_refresh = True
            _record_view_step(session, recorder, raw, t0, prev_regs, session.pop_target_output())
            continue

        if low.startswith("call "):
            target_args = raw.split(None, 1)[1].strip()
            prev_regs = current_regs
            prev_stack_bytes = current_stack_bytes
            ok, msg, _ = session.run_to_next_call(target_args)
            extra_msg = msg
            if ok:
                force_refresh = True
                step_out = session.pop_target_output()
                if step_out:
                    extra_msg = f"{msg} | stdout: {step_out.strip()}"
                _record_view_step(session, recorder, raw, t0, prev_regs, step_out, note=msg)
            continue

        nval = parse_nest_token(low)
        if nval is not None:
            nest_limit = max(0, min(10, nval))
            force_refresh = True
            extra_msg = f"Nesting depth set to {nest_limit}" if nest_limit > 0 else "Nesting disabled"
            continue

        if low in ("only", "min", "view min"):
            show_regs, show_stack = False, False
            continue

        if low in ("max", "view max"):
            show_regs, show_stack, reg_fmt = True, True, "all"
            page_size = VIEW_PAGE_SIZE
            force_refresh = True
            continue

        if low in ("regs", "info", "show"):
            show_regs = not show_regs
            extra_msg = f"Registers {'shown' if show_regs else 'hidden'}"
            continue

        if low == "stack":
            show_stack = not show_stack
            extra_msg = f"Stack {'shown' if show_stack else 'hidden'}"
            continue

        if low in ("raw stack", "info raw stack", "stack only", "info stack only"):
            show_regs, show_stack = False, True
            continue

        if low == "info stack":
            show_regs, show_stack = True, True
            continue

        if low in ("info all", "regs all", "regs full", "full"):
            show_regs = True
            reg_fmt = "hex" if reg_fmt == "all" else "all"
            extra_msg = f"Register format -> {reg_fmt}"
            continue

        if low == "all":
            show_regs, show_stack, reg_fmt = True, True, "all"
            continue

        m_fmt = re.match(r"^(?:(?:info|show|regs)\s+)?(-h|-d|-c|-s|hex|dec|char|str)$", low)
        if m_fmt:
            f_tok = m_fmt.group(1)
            reg_fmt = {"-h": "hex", "-d": "dec", "-c": "char", "-s": "str"}.get(f_tok, f_tok)
            show_regs = True
            extra_msg = f"Register format -> {reg_fmt}"
            continue

        if low.startswith(("info ", "show ", "get ")):
            tok = raw.split(None, 1)[1].strip()
            res = session.get_single_register(tok)
            if res:
                extra_msg = format_reg_line(session, res[0], res[1], "all")
            else:
                extra_msg = f"Register '{tok}' not found"
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
            _record_view_step(session, recorder, raw, t0, prev_regs, "", note=msg)
            continue

        if low.startswith(("stop ", "b ", "break ")):
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
                    _record_view_step(session, recorder, raw, t0, prev_regs, "", note=msg)
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
                prev_stack_bytes = current_stack_bytes
                _ok, msg, _ = session.goto_address(p_addr)
                extra_msg = msg
                force_refresh = True
                step_out = session.pop_target_output()
                if step_out:
                    extra_msg = f"stdout: {step_out.strip()}"
                _record_view_step(session, recorder, raw, t0, prev_regs, step_out, note=msg)
                continue

        extra_msg = f"Unknown view command '{raw}'"
