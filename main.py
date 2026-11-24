#!/usr/bin/env python3
# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)
"""
bin-debug-friendly — Friendly, Bubblewrap-sandboxed Linux debugger & execution mapper.
"""

import argparse
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.cli import run_interactive_cli
from src.elf_utils import parse_elf
from src.gdb_session import GdbSession
from src.mapper import run_execution_mapper
from src.recorder import SessionRecorder
from src.sandbox import SandboxEnv, confirm_disable_sandbox


def extract_target_args_flag(argv: list[str]) -> tuple[list[str], list[str]]:
    """
    Safely extracts `-A "..."` / `-a "..."` / `--args "..."` before argparse runs
    so values starting with '-' (like `-A "-h -m -o foo"`) are never misread as
    debugger options. Supports shell quoting and backslash-escaped quotes (`\"`).
    """
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bin-debug-friendly",
        description="Friendly Linux ELF debugger & execution mapper (GPLv3).",
    )
    parser.add_argument("binary", help="Path to target ELF binary")
    parser.add_argument(
        "target_args",
        nargs="*",
        help="Optional arguments to pass to the target binary (or use -A \"...\")",
    )
    parser.add_argument(
        "-A", "-a", "--args",
        dest="target_args_str",
        default=None,
        help="Quoted target argument string (supports escaped quotes \\\" and target flags like -o/-m)",
    )
    parser.add_argument(
        "-m", "-main", "--main",
        dest="start_at_main",
        action="store_true",
        help="Start and stop at main()",
    )
    parser.add_argument(
        "-record", "--record",
        dest="record_session",
        action="store_true",
        help="Record interactive session into record-<bin>_<date>/ folder",
    )
    parser.add_argument(
        "-map", "--map",
        dest="map_exec",
        action="store_true",
        help="Map execution: trace instructions, registers, syscalls, and stats into a timestamped folder",
    )
    parser.add_argument(
        "-func", "--func", "--function",
        dest="func_addr",
        default=None,
        help="With --map: trace only the specified function address/symbol (auto-detects return)",
    )
    parser.add_argument(
        "--dump-stack-syscalls",
        action="store_true",
        help="With --map: also dump stack binary snapshots on each syscall",
    )
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Disable Bubblewrap sandbox (dangerous! requires multi-step confirmation)",
    )
    return parser


def main() -> None:
    if sys.platform != "linux":
        sys.exit("[!] FATAL: bin-debug-friendly is Linux-only.")

    cleaned_argv, flagged_target_args = extract_target_args_flag(sys.argv[1:])
    parser = build_parser()
    args = parser.parse_args(cleaned_argv)

    all_target_args = flagged_target_args + list(args.target_args)

    bin_path = Path(args.binary).resolve()
    if not bin_path.is_file():
        sys.exit(f"[!] Error: binary not found: {bin_path}")

    try:
        elf = parse_elf(bin_path)
    except ValueError as e:
        sys.exit(f"[!] Error parsing ELF binary: {e}")

    sandbox_enabled = True
    if args.no_sandbox:
        if not confirm_disable_sandbox():
            sys.exit(1)
        sandbox_enabled = False

    sandbox = SandboxEnv(enabled=sandbox_enabled)

    session = GdbSession(
        binary_path=bin_path,
        elf_info=elf,
        sandbox=sandbox,
        target_args=all_target_args,
    )

    recorder = (
        SessionRecorder(bin_path, elf.arch, elf.bits, elf.is_pie)
        if args.record_session and not args.map_exec
        else None
    )

    try:
        session.start_gdb()
        if args.map_exec:
            run_execution_mapper(
                session,
                func_spec=args.func_addr,
                dump_stack_syscalls=args.dump_stack_syscalls,
                start_at_main=args.start_at_main,
            )
        else:
            if args.start_at_main:
                ok, msg, _stopped = session.stop_at_symbol("main")
                if not ok:
                    sys.exit(
                        f"[!] Error: {msg} Run without -m/--main to start at the entry point."
                    )
            else:
                session.advance_to_entry_point()
            run_interactive_cli(session, recorder=recorder)
    finally:
        if recorder is not None:
            recorder.close()
            print(f"[+] Recording saved -> {recorder.out_dir}/")
        session.close()


if __name__ == "__main__":
    main()
