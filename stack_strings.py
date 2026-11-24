#!/usr/bin/env python3
# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)
"""
stack_strings.py — Extracts, reconstructs, and deduplicates all dynamic strings
that ever materialized on the stack or in dereferenced registers across a trace.
"""

import argparse
import ast
import re
import sys
from pathlib import Path

HEX_ROW_RE = re.compile(
    r"0x[0-9a-fA-F]+:\s+((?:[0-9a-fA-F]{4}\s*){1,8})"
)
EVENT_HEADER_RE = re.compile(
    r"^\[(EVENT\s+#\d+|STEP\s+\d+)\]\s+(?:TIME=([^\s|]+))?.*?(?:(?:FUNC|LOCATION)\s*[:=]\s*(\S+))?",
    re.IGNORECASE,
)
DEREF_LINE_RE = re.compile(r"DEREF\s*:\s*(.+)$", re.IGNORECASE)
DEREF_TOKEN_RE = re.compile(r"([A-Za-z0-9]+)\s*->\s*(['\"].*?['\"])")
ANSI_STRIP_RE = re.compile(r"\x1b\[[0-9;]*m")


def find_trace_file(target: Path) -> Path:
    if target.is_file():
        return target
    if target.is_dir():
        for candidate in ("full_recording.txt", "full_trace.txt"):
            p = target / candidate
            if p.is_file():
                return p
        txts = sorted(target.glob("*.txt"))
        if txts:
            return txts[0]
    sys.exit(f"[!] Error: cannot find trace file in '{target}'")


def parse_trace_data(file_path: Path) -> tuple[list[dict], dict[str, dict]]:
    snapshots: list[dict] = []
    current_meta = {"event": "INIT", "time": "", "loc": ""}
    current_bytes = bytearray()
    deref_strings: dict[str, dict] = {}
    in_stack_block = False

    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            plain = ANSI_STRIP_RE.sub("", line).strip()

            m_ev = EVENT_HEADER_RE.match(plain)
            if m_ev:
                if current_bytes:
                    snapshots.append({
                        "meta": dict(current_meta),
                        "data": bytes(current_bytes),
                    })
                    current_bytes = bytearray()
                current_meta["event"] = m_ev.group(1) or "?"
                current_meta["time"] = m_ev.group(2) or ""
                current_meta["loc"] = m_ev.group(3) or ""
                in_stack_block = False
                continue

            m_deref = DEREF_LINE_RE.search(plain)
            if m_deref:
                for reg_name, raw_repr in DEREF_TOKEN_RE.findall(m_deref.group(1)):
                    try:
                        val = ast.literal_eval(raw_repr)
                    except Exception:
                        val = raw_repr.strip("'\"")
                    if val and val not in deref_strings:
                        deref_strings[val] = {
                            "event": current_meta["event"],
                            "time": current_meta["time"],
                            "loc": f"{current_meta['loc']} ({reg_name.upper()} deref)",
                        }
                continue

            if (
                "STACK_ON_ENTRY" in plain
                or "FULL ACTIVE STACK" in plain
                or "STACK CHANGED" in plain
                or "STACK:" in plain
            ):
                in_stack_block = True
                continue

            if in_stack_block and plain.startswith(("-", "REGISTERS:", "[REGISTERS", "DISASSEMBLY:")):
                in_stack_block = False
                continue

            m_row = HEX_ROW_RE.search(plain)
            if m_row:
                hex_groups = m_row.group(1).replace(" ", "")
                try:
                    row_bytes = bytes.fromhex(hex_groups)
                    current_bytes.extend(row_bytes)
                except ValueError:
                    pass

    if current_bytes:
        snapshots.append({
            "meta": dict(current_meta),
            "data": bytes(current_bytes),
        })

    return snapshots, deref_strings


def extract_ascii_strings(data: bytes, min_len: int) -> list[str]:
    pattern = b"[\x20-\x7e]{" + str(min_len).encode() + b",}"
    matches = re.findall(pattern, data)
    return [m.decode("ascii", errors="replace") for m in matches]


def filter_redundant_prefixes(strings: list[str]) -> list[str]:
    if not strings:
        return []
    result: list[str] = []
    for i, s in enumerate(strings):
        is_sub = False
        for j, other in enumerate(strings):
            if i != j and s != other and s in other:
                is_sub = True
                break
        if not is_sub:
            result.append(s)
    return result or strings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stack_strings.py",
        description="Reconstruct dynamic stack binary & extract unique runtime strings across time.",
    )
    parser.add_argument(
        "target",
        help="Path to trace file (full_recording.txt / full_trace.txt) or folder (record-*/ / *-mapped_*/)",
    )
    parser.add_argument(
        "-n", "--min-len",
        type=int,
        default=4,
        help="Minimum string length to extract (default: 4)",
    )
    parser.add_argument(
        "-b", "--bin-out",
        default=None,
        help="Path to write concatenated binary stack file (default: <target>_all_stacks.bin)",
    )
    parser.add_argument(
        "-o", "--out",
        default=None,
        help="Path to write unique strings text file (default: <target>_stack_strings.txt)",
    )
    parser.add_argument(
        "-a", "--annotated",
        action="store_true",
        help="Show discovery timeline: [event @ location] for every first-seen string",
    )
    parser.add_argument(
        "-c", "--collapse",
        action="store_true",
        help="Collapse prefix build-ups (e.g. keep 'letmein123' and drop 'letm', 'letme')",
    )
    parser.add_argument(
        "-s", "--sort",
        action="store_true",
        help="Sort strings alphabetically instead of chronological discovery order",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode: print only unique strings to stdout",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    trace_file = find_trace_file(target_path)

    if not args.quiet:
        print(f"[*] Reading trace -> {trace_file}")

    snapshots, deref_strings = parse_trace_data(trace_file)
    if not snapshots and not deref_strings:
        sys.exit("[!] No stack data or register dereferences found in trace file.")

    combined_binary = bytearray()
    first_seen: dict[str, dict] = {}

    for snap in snapshots:
        chunk = snap["data"]
        combined_binary.extend(chunk)

        found_strings = extract_ascii_strings(chunk, args.min_len)
        for s in found_strings:
            if s not in first_seen:
                first_seen[s] = {
                    "event": snap["meta"]["event"],
                    "time": snap["meta"]["time"],
                    "loc": snap["meta"]["loc"],
                }

    # Merge strings pointed to by registers (even if on heap and never on stack!)
    deref_count = 0
    for s, meta in deref_strings.items():
        if len(s) >= args.min_len:
            # Also append to the raw binary file
            combined_binary.extend(s.encode("ascii", errors="replace") + b"\x00")
            deref_count += 1
            if s not in first_seen:
                first_seen[s] = meta

    raw_strings = list(first_seen.keys())
    final_strings = filter_redundant_prefixes(raw_strings) if args.collapse else raw_strings

    if args.sort:
        final_strings.sort()

    base_name = target_path.name if target_path.is_dir() else target_path.stem
    bin_out_path = Path(args.bin_out) if args.bin_out else Path.cwd() / f"{base_name}_all_stacks.bin"
    txt_out_path = Path(args.out) if args.out else Path.cwd() / f"{base_name}_stack_strings.txt"

    bin_out_path.write_bytes(combined_binary)

    with txt_out_path.open("w", encoding="utf-8") as fh:
        fh.write(f"=== STRINGS EXTRACTED FROM {trace_file.name} ===\n")
        fh.write(f"TOTAL_BINARY_BYTES: {len(combined_binary):,} bytes\n")
        fh.write(f"SNAPSHOTS_PARSED  : {len(snapshots)}\n")
        fh.write(f"REGISTER_DEREFS   : {len(deref_strings)} strings\n")
        fh.write(f"UNIQUE_STRINGS    : {len(final_strings)} (min_len={args.min_len})\n")
        fh.write("=" * 72 + "\n\n")

        for s in final_strings:
            meta = first_seen.get(s, {})
            if args.annotated:
                loc_str = f" @ {meta['loc']}" if meta.get("loc") else ""
                fh.write(f"[{meta.get('event', '?')}{loc_str}] {s}\n")
            else:
                fh.write(f"{s}\n")

    if args.quiet:
        for s in final_strings:
            if args.annotated:
                meta = first_seen.get(s, {})
                loc_str = f" @ {meta['loc']}" if meta.get("loc") else ""
                print(f"[{meta.get('event', '?')}{loc_str}] {s}")
            else:
                print(s)
    else:
        print(f"[+] Reconstructed binary saved : {bin_out_path} ({len(combined_binary):,} bytes)")
        print(f"[+] Unique strings saved       : {txt_out_path} ({len(final_strings)} strings, incl. {deref_count} register derefs)")
        print("-" * 72)
        print("=== UNIQUE STRINGS FOUND (STACK & DEREF REGISTERS) ===")
        for s in final_strings[:50]:
            meta = first_seen.get(s, {})
            loc_str = f" @ {meta['loc']}" if meta.get("loc") else ""
            if args.annotated:
                print(f"  [{meta.get('event', '?'):<12}{loc_str:<32}] {s}")
            else:
                print(f"  {s}")
        if len(final_strings) > 50:
            print(f"  ... ({len(final_strings) - 50} more in {txt_out_path.name}) ...")


if __name__ == "__main__":
    main()
