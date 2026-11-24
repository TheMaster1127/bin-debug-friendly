#!/usr/bin/env python3
# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)
"""
heap_dump.py — Lifecycle heap dumper companion for bin-debug-friendly.

Captures [heap] snapshots both:
  1. Right before stdin is read (sys_read fd == 0)
  2. After stdin, right before strcmp/memcmp/explicit_bzero/free/exit_group
     (defeating just-in-time heap decoding + immediate wipe before exit!)

Works on normal, stripped, and sstripped binaries inside Bubblewrap.

Usage:
    python3 heap_dump.py test4                     # interactive prompt
    python3 heap_dump.py test4 -A "-o flag arg2"   # pass binary arguments cleanly
    python3 heap_dump.py test4 --input letmein123  # automated input
    python3 heap_dump.py test4 --no-input          # send empty newline
"""

import argparse
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.elf_utils import parse_elf
from src.formatters import prompt_for_target_stdin
from src.gdb_session import GdbSession
from src.sandbox import SandboxEnv

WATCH_FUNCS = (
    ("strcmp", "strcmp"),
    ("strncmp", "strncmp"),
    ("memcmp", "memcmp"),
    ("explicit_bzero", "pre-bzero"),
    ("__explicit_bzero_chk", "pre-bzero"),
    ("free", "pre-free"),
)
MAX_HEAP_SNAPSHOTS = 16


def extract_target_args_flag(argv: list[str]) -> tuple[list[str], list[str]]:
    cleaned: list[str] = []
    extracted: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("-A", "-a", "--args"):
            if i + 1 >= len(argv):
                sys.exit(f"[!] Error: {tok} requires a quoted argument string.")
            raw_str = argv[i + 1]
            try:
                extracted.extend(shlex.split(raw_str))
            except ValueError as e:
                sys.exit(f"[!] Error parsing {tok} string ({e}): {raw_str}")
            i += 2
            continue
        if tok.startswith(("-A=", "-a=", "--args=")):
            raw_str = tok.split("=", 1)[1]
            try:
                extracted.extend(shlex.split(raw_str))
            except ValueError as e:
                sys.exit(f"[!] Error parsing {tok} string ({e}): {raw_str}")
            i += 1
            continue
        cleaned.append(tok)
        i += 1
    return cleaned, extracted


def extract_strings(data: bytes, base: int, min_len: int) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    cur = bytearray()
    cur_addr = 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                cur_addr = base + i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append((cur_addr, cur.decode("ascii", errors="replace")))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append((cur_addr, cur.decode("ascii", errors="replace")))
    return out


def find_heap_mapping(session: GdbSession) -> dict | None:
    mappings = session.get_proc_mappings()
    heap = next((m for m in mappings if "[heap]" in m["objfile"]), None)
    if heap:
        return heap
    bin_end = max((m["end"] for m in mappings if "target_bin" in m["objfile"]), default=0)
    return next(
        (m for m in mappings if m["start"] >= bin_end and "rw" in m["perms"] and not m["objfile"].startswith("/")),
        None,
    )


def snapshot_heap(session: GdbSession, tag: str, seen_strings: dict[str, tuple[int, str]], min_len: int) -> bytes | None:
    heap = find_heap_mapping(session)
    if not heap:
        return None
    gdb_out = "/tmp/work/heap.bin" if session.sandbox.enabled else str(session.work_dir / "heap.bin")
    tmp_host = session.work_dir / "heap.bin"
    if tmp_host.exists():
        tmp_host.unlink()

    res = session.send(
        f'-interpreter-exec console "dump binary memory {gdb_out} 0x{heap["start"]:x} 0x{heap["end"]:x}"'
    )
    if res["status"] == "error" or not tmp_host.exists():
        return None

    data = tmp_host.read_bytes()
    for addr, s in extract_strings(data, heap["start"], min_len):
        if s not in seen_strings:
            seen_strings[s] = (addr, tag)

    for _rname, val in session.get_registers().items():
        s = session.read_c_string(val)
        if s and len(s) >= min_len and s not in seen_strings:
            seen_strings[s] = (val, f"{tag}/reg")

    return data


def _caller_is_main_binary(session: GdbSession) -> bool:
    if session.elf.arch in ("x86_64", "i386"):
        sp = session.get_sp()
        if sp:
            ra = session.read_pointer(sp)
            if ra and session.addr_in_main_binary(ra):
                return True
    else:
        lr = session.get_single_register("lr")
        if lr and session.addr_in_main_binary(lr[1]):
            return True
    return bool(session.get_binary_call_frames())


def run_until_stdin_read(session: GdbSession) -> bool:
    session.enable_syscall_catch()
    safety = 0
    while not session.exited and safety < 10000:
        safety += 1
        stopped = session.run_or_continue(restart_if_exited=False)
        if session.exited or not stopped:
            break
        if stopped.get("reason") == "syscall-entry":
            sc_name = stopped.get("syscall-name", "")
            sc_num = stopped.get("syscall-number", "")
            if sc_name == "read" or sc_num in ("0", "3", "63"):
                regs = session.get_registers()
                fd_reg = "rdi" if session.elf.arch == "x86_64" else ("ebx" if session.elf.arch == "i386" else "x0")
                if regs.get(fd_reg, 0) == 0:
                    return True
    return False


def install_post_stdin_traps(session: GdbSession) -> dict[str, str]:
    session.send("-break-delete")
    session.send('-interpreter-exec console "catch syscall exit_group"')
    session.send('-interpreter-exec console "catch syscall exit"')

    bp_tags: dict[str, str] = {}
    for sym, tag in WATCH_FUNCS:
        res = session.send(f"-break-insert {sym}")
        if res["status"] == "done":
            bkpt = res["payload"].get("bkpt", {})
            num = str(bkpt.get("number", ""))
            if num:
                bp_tags[num] = tag
    return bp_tags


def main() -> int:
    cleaned_argv, flagged_target_args = extract_target_args_flag(sys.argv[1:])

    ap = argparse.ArgumentParser(
        prog="bin-debug-friendly-heap",
        description="Lifecycle heap dumper (catches pre-stdin AND post-stdin/pre-wipe secrets).",
    )
    ap.add_argument("binary", help="Path to ELF binary")
    ap.add_argument("target_args", nargs="*", help="Optional arguments for target binary (or use -A \"...\")")
    ap.add_argument("-A", "-a", "--args", dest="target_args_str", default=None,
                    help="Quoted target argument string (supports escaped quotes \\\" and target flags)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("-i", "--input", default=None, help="Pre-feed this string to stdin")
    g.add_argument("--no-input", action="store_true", help="Send empty newline (short for --input '')")
    ap.add_argument("--min-len", type=int, default=4, help="Minimum string length (default: 4)")
    ap.add_argument("--top", type=int, default=25, help="Number of strings to display (default: 25)")
    ap.add_argument("-o", "--output", default=None, help="Output folder")
    args = ap.parse_args(cleaned_argv)

    all_target_args = flagged_target_args + list(args.target_args)

    bin_path = Path(args.binary).resolve()
    if not bin_path.is_file():
        print(f"[!] Binary not found: {bin_path}")
        return 1

    try:
        elf = parse_elf(bin_path)
    except ValueError as e:
        print(f"[!] ELF error: {e}")
        return 1

    print(f"[*] {bin_path.name} ({elf.arch}, {'PIE' if elf.is_pie else 'no-PIE'}, sstrip={'yes' if elf.is_sstripped else 'no'})")

    sandbox = SandboxEnv(enabled=True)
    session = GdbSession(bin_path, elf, sandbox, target_args=all_target_args)

    out_dir = (
        Path(args.output).resolve()
        if args.output
        else Path.cwd() / f"{bin_path.name}_heapdump"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        session.start_gdb()
        session.advance_to_entry_point()

        print("[*] Running to first stdin read...")
        hit_stdin = run_until_stdin_read(session)
        if not hit_stdin or session.exited:
            print("[!] Target exited or did not call stdin read.")
            return 1

        seen_strings: dict[str, tuple[int, str]] = {}
        heap_chunks: list[bytes] = []
        last_chunk: bytes | None = None

        snap0 = snapshot_heap(session, "pre-stdin", seen_strings, args.min_len)
        if snap0 is not None:
            heap_chunks.append(snap0)
            last_chunk = snap0
            print(f"[+] Pre-stdin [heap] snapshot: {len(snap0):,} bytes")
        else:
            print("[*] [heap] not mapped yet at stdin (will watch post-stdin allocations)...")

        if args.no_input:
            session.write_target_stdin("")
        elif args.input is not None:
            session.write_target_stdin(args.input)
        else:
            txt = prompt_for_target_stdin(proactive=False)
            if txt is not None:
                session.write_target_stdin(txt)

        bp_tags = install_post_stdin_traps(session)

        safety = 0
        while not session.exited and len(heap_chunks) < MAX_HEAP_SNAPSHOTS and safety < 200:
            safety += 1
            stopped = session.run_or_continue(restart_if_exited=False)
            if session.exited or not stopped:
                break
            reason = stopped.get("reason", "")
            if reason == "syscall-entry":
                sc_name = stopped.get("syscall-name", "")
                if sc_name in ("exit", "exit_group") or stopped.get("syscall-number") in ("60", "231", "252", "93", "94"):
                    snap = snapshot_heap(session, "pre-exit", seen_strings, args.min_len)
                    if snap is not None and snap != last_chunk:
                        heap_chunks.append(snap)
                        last_chunk = snap
                    session.send("-break-delete")
                    session.run_or_continue(restart_if_exited=False)
                    break
            elif reason == "breakpoint-hit":
                bkptno = str(stopped.get("bkptno", ""))
                tag = bp_tags.get(bkptno, "post-stdin")
                if _caller_is_main_binary(session):
                    snap = snapshot_heap(session, tag, seen_strings, args.min_len)
                    if snap is not None and snap != last_chunk:
                        heap_chunks.append(snap)
                        last_chunk = snap

        if not session.exited:
            session.send("-break-delete")
            session.run_or_continue(restart_if_exited=False)

        if not heap_chunks and not seen_strings:
            print("[!] Target never allocated a [heap] mapping.")
            return 1

        combined_heap = b"".join(heap_chunks)
        (out_dir / "heap.bin").write_bytes(combined_heap)

        sorted_strings = sorted(seen_strings.items(), key=lambda kv: (-len(kv[0]), kv[1][0]))
        (out_dir / "heap.strings.txt").write_text(
            "".join(f"0x{addr:016x}  [{tag}]  {s}\n" for s, (addr, tag) in sorted_strings),
            encoding="utf-8",
        )

        print(f"[+] Captured {len(heap_chunks)} distinct heap state(s) ({len(combined_heap):,} bytes total)")
        print(f"[+] Unique heap/pointer strings: {len(sorted_strings)}")
        shown = min(args.top, len(sorted_strings))
        for s, (addr, tag) in sorted_strings[:shown]:
            disp = s if len(s) <= 60 else s[:57] + "..."
            print(f"  0x{addr:016x}  [{tag:<12}]  {disp!r}")

        session.pop_target_output()
        stdout = session.get_all_target_stdout() or ""
        (out_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
        if stdout.strip():
            print(f"[*] Target output: {stdout.strip()!r}")

        print(f"[+] Saved artifacts -> {out_dir}/")
        return 0

    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
