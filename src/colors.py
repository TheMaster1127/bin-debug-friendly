# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import re
import sys

from src.config import ENABLE_COLORS

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

try:
    import colorama
    from colorama import Fore, Style
    _HAS_COLORAMA = True
except ImportError:
    colorama = None
    Fore = None
    Style = None
    _HAS_COLORAMA = False

_COLOR_INIT_DONE = False


def colors_active() -> bool:
    global _COLOR_INIT_DONE
    if not ENABLE_COLORS or not _HAS_COLORAMA:
        return False
    try:
        if not sys.stdout.isatty():
            return False
    except Exception:
        return False
    if not _COLOR_INIT_DONE:
        colorama.init(autoreset=False, strip=False)
        _COLOR_INIT_DONE = True
    return True


def green(text: str) -> str:
    if not colors_active():
        return text
    return f"{Style.BRIGHT}{Fore.GREEN}{text}{Style.RESET_ALL}"


def highlight_char_diff(new_str: str, old_str: str | None) -> str:
    """
    Colors ONLY the exact characters in `new_str` that differ from `old_str` in bright green.
    """
    if old_str is None or not colors_active() or new_str == old_str:
        return new_str

    # Align from right for hex/numeric strings of equal length, or index-by-index
    out: list[str] = []
    run: list[str] = []

    def flush_run():
        if run:
            out.append(green("".join(run)))
            run.clear()

    if new_str.startswith("0x") and old_str.startswith("0x") and len(new_str) == len(old_str):
        for nc, oc in zip(new_str, old_str):
            if nc != oc:
                run.append(nc)
            else:
                flush_run()
                out.append(nc)
        flush_run()
        return "".join(out)

    max_len = len(new_str)
    for idx in range(max_len):
        nc = new_str[idx]
        oc = old_str[idx] if idx < len(old_str) else None
        if nc != oc:
            run.append(nc)
        else:
            flush_run()
            out.append(nc)
    flush_run()
    return "".join(out)


def visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def pad_visible(text: str, width: int) -> str:
    vlen = visible_len(text)
    if vlen >= width:
        return text
    return text + (" " * (width - vlen))


def truncate_visible(text: str, max_width: int) -> str:
    if visible_len(text) <= max_width:
        return text
    plain = ANSI_RE.sub("", text)
    return plain[:max_width - 1] + "~"


def format_diff_xxd_line(
    addr: int,
    chunk: bytes,
    prev_bytes: dict[int, int] | None,
    sp: int,
) -> tuple[str, bool]:
    """
    Formats one 16-byte xxd stack row, highlighting ONLY the exact byte addresses
    whose value changed compared to `prev_bytes` in bright green (both hex and ASCII).
    """
    use_color = colors_active()
    changed_indices: set[int] = set()
    if prev_bytes:
        for i, b in enumerate(chunk):
            b_addr = addr + i
            if b_addr in prev_bytes and prev_bytes[b_addr] != b:
                changed_indices.add(i)

    hex_groups = []
    for i in range(0, len(chunk), 2):
        pair_str = ""
        for j in range(i, min(i + 2, len(chunk))):
            hx = f"{chunk[j]:02x}"
            if j in changed_indices and use_color:
                hx = green(hx)
            pair_str += hx
        hex_groups.append(pair_str)

    hex_col = pad_visible(" ".join(hex_groups), 39)

    ascii_chars = []
    for i, b in enumerate(chunk):
        ch = chr(b) if 32 <= b < 127 else "."
        if i in changed_indices and use_color:
            ch = green(ch)
        ascii_chars.append(ch)
    ascii_col = "".join(ascii_chars)

    marker = "  <-- SP" if addr <= sp < addr + 16 else ""
    line = f"0x{addr:016x}: {hex_col}  {ascii_col}{marker}"
    return line, bool(changed_indices)
