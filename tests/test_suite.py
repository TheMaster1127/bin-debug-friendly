# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from src.colors import ANSI_RE, colors_active, format_diff_xxd_line, highlight_char_diff, visible_len
from src.elf_utils import parse_address_input, parse_elf
from src.formatters import format_reg_line, handle_ignore_command, parse_set_value
from src.gdb_inspector import trim_zero_stack
from src.gdb_session import GdbSession, IgnoreCallManager
from src.live_view import (
    fetch_view_page,
    parse_nest_token,
    parse_view_options,
    render_two_columns,
    select_visible_frames,
    should_refresh_page,
)
from src.mapper import classify_instruction, run_execution_mapper
from src.recorder import SessionRecorder
from src.sandbox import SandboxEnv

TEST_C_SOURCE = r"""
#include <stdio.h>
#include <unistd.h>

__attribute__((noinline))
int secret_calc(int a, int b) {
    int c = a * 2 + b;
    return c;
}

int main(void) {
    int res = secret_calc(10, 5);
    printf("result=%d\n", res);
    fflush(stdout);
    return 0;
}
"""

TEST_FGETS_SOURCE = r"""
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[32] = {0};
    if (fgets(buf, sizeof(buf), stdin) != NULL) {
        printf("got=%s", buf);
        fflush(stdout);
    }
    return 0;
}
"""


class TestUnitHelpers(unittest.TestCase):
    def test_flexible_address_parsing(self):
        cases = [
            ("0x1149", 0x1149),
            ("1149", 0x1149),
            ("0X401149", 0x401149),
            ('"0x1149"', 0x1149),
            ('" 0x 40 11 49 "', 0x401149),
            ('"11 49"', 0x1149),
            ("  0x 12 ab ", 0x12AB),
        ]
        for raw, expected in cases:
            val, _ = parse_address_input(raw)
            self.assertEqual(val, expected)

    def test_view_option_parser_max_min_nest_and_split(self):
        sz, regs, stk, _, nest = parse_view_options(["only", "20", "nest5"])
        self.assertEqual((sz, regs, stk, nest), (20, False, False, 5))

        _, regs_min, stk_min, _, _ = parse_view_options(["min"])
        self.assertEqual((regs_min, stk_min), (False, False))

        _, regs_max, stk_max, _, _ = parse_view_options(["max"])
        self.assertEqual((regs_max, stk_max), (True, True))

        self.assertEqual(parse_nest_token("nest"), 1)
        self.assertEqual(parse_nest_token("nest1"), 1)
        self.assertEqual(parse_nest_token("nest2"), 2)
        self.assertEqual(parse_nest_token("nest0"), 0)

        frames = [{"func": "_start"}, {"func": "main"}, {"func": "secret_calc"}, {"func": "leaf"}]
        self.assertEqual([f["func"] for f in select_visible_frames(frames, 0)], ["leaf"])
        self.assertEqual([f["func"] for f in select_visible_frames(frames, 1)], ["_start", "leaf"])
        self.assertEqual([f["func"] for f in select_visible_frames(frames, 2)], ["_start", "secret_calc", "leaf"])

        cols = render_two_columns(["left1"], ["right1", "right2"], 10)
        self.assertEqual(cols[0], "left1      | right1")
        self.assertEqual(cols[1], "           | right2")

        small_page = [(0x1000, "55", "push rbp"), (0x1001, "48", "mov rbp,rsp")]
        self.assertFalse(should_refresh_page(small_page, 0x1001, False))
        self.assertTrue(should_refresh_page(small_page, 0x2000, False))
        self.assertTrue(should_refresh_page(small_page, 0x1001, True))

    def test_colors_char_diff_and_byte_addr_xxd(self):
        prev_bytes = {0x7000 + i: b for i, b in enumerate(b"ABCDXXXX12345678")}
        line, changed = format_diff_xxd_line(0x7000, b"ABCDEFGH12345678", prev_bytes, 0x7000)
        self.assertTrue(changed)
        self.assertIn("ABCDEFGH", ANSI_RE.sub("", line))
        self.assertEqual(visible_len("\x1b[32mhello\x1b[0m"), 5)

        diff_hex = highlight_char_diff("0x000000000000128d", "0x0000000000001288")
        self.assertEqual(ANSI_RE.sub("", diff_hex), "0x000000000000128d")

        orig_stdout = sys.stdout
        try:
            sys.stdout = io.StringIO()
            self.assertFalse(colors_active())
            plain_line, plain_changed = format_diff_xxd_line(0x7000, b"ABCDEFGH12345678", prev_bytes, 0x7000)
            self.assertTrue(plain_changed)
            self.assertNotIn("\x1b[", plain_line)
            self.assertIn("ABCDEFGH", plain_line)
        finally:
            sys.stdout = orig_stdout

    def test_ignore_call_manager(self):
        mgr = IgnoreCallManager()
        self.assertEqual(mgr.mode, "none")
        mgr.set_count(2)
        self.assertEqual((mgr.mode, mgr.remaining), ("count", 2))
        mgr.set_all()
        self.assertEqual(mgr.mode, "all")
        mgr.set_nest(1)
        self.assertEqual((mgr.mode, mgr.nest_base_depth), ("nest", 1))
        mgr.clear()
        self.assertEqual(mgr.mode, "none")

    def test_recorder_folder_idle_flush_and_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                rec = SessionRecorder(Path("/tmp/dummy"), "x86_64", 64, True)
                rec.record_event(
                    command="step",
                    duration_ms=1.2,
                    pc_disp="0x1140",
                    func_name="main",
                    disas_lines=["  => 0x1140:  55  push rbp"],
                    regs={"rax": 1, "rsp": 0x7000},
                    prev_regs={"rax": 0, "rsp": 0x7000},
                    stack_lines=["0x0000000000007000: 0100 ..."],
                )
                self.assertFalse(rec.out_dir.exists())
                rec.flush_idle()
                self.assertTrue(rec.out_path.exists())
                self.assertTrue((rec.func_dir / "func_main.txt").exists())
                rec.close()
                txt = rec.out_path.read_text(encoding="utf-8")
                self.assertIn("CMD='step'", txt)
                self.assertIn("CHANGED  : RAX=0x1", txt)
                self.assertIn("FULL ACTIVE STACK", txt)
                self.assertIn("RECORDING CLOSED", txt)
            finally:
                os.chdir(old_cwd)

    def test_trim_zero_stack(self):
        raw = (b"\x00" * 32) + b"ABCD1234EFGH5678" + (b"\x00" * 48)
        trimmed, new_base = trim_zero_stack(raw, 0x7000)
        self.assertEqual(trimmed, b"ABCD1234EFGH5678")
        self.assertEqual(new_base, 0x7020)

    def test_instruction_classifier(self):
        self.assertTrue(classify_instruction("jne 0x1170")["jump"])
        self.assertTrue(classify_instruction("call 0x1040")["call"])
        self.assertTrue(classify_instruction("ret")["ret"])
        self.assertTrue(classify_instruction("mov eax, DWORD PTR [rbp-0x4]")["mem"])
        self.assertFalse(classify_instruction("lea rax, [rbp-0x10]")["mem"])

    def test_parse_set_value(self):
        self.assertEqual(parse_set_value("0x2a", "<"), 42)
        self.assertEqual(parse_set_value('"AB"', "<"), 0x4241)


class TestEndToEndDebugger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="bdf_test_")
        cls.tmp_path = Path(cls.tmp.name)
        src = cls.tmp_path / "sample.c"
        src.write_text(TEST_C_SOURCE, encoding="utf-8")

        fgets_src = cls.tmp_path / "fgets_sample.c"
        fgets_src.write_text(TEST_FGETS_SOURCE, encoding="utf-8")

        cls.bin_pie = cls.tmp_path / "sample_pie"
        cls.bin_stripped = cls.tmp_path / "sample_stripped"
        cls.bin_fgets = cls.tmp_path / "fgets_pie"
        subprocess.run(["gcc", "-O0", "-fPIE", "-pie", str(src), "-o", str(cls.bin_pie)], check=True)
        subprocess.run(["gcc", "-O0", "-fPIE", "-pie", str(fgets_src), "-o", str(cls.bin_fgets)], check=True)
        shutil.copy2(cls.bin_pie, cls.bin_stripped)
        subprocess.run(["strip", "--strip-all", str(cls.bin_stripped)], check=True)

        cls.pie_secret_off = cls._find_symbol_addr(cls.bin_pie, "secret_calc")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @staticmethod
    def _find_symbol_addr(bin_path: Path, symbol: str) -> int:
        out = subprocess.check_output(["nm", str(bin_path)], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == symbol:
                return int(parts[0], 16)
        raise RuntimeError(f"Symbol {symbol} not found in {bin_path}")

    def test_call_command_and_no_libc_pollution(self):
        if not shutil.which("bwrap") or not shutil.which("gdb"):
            self.skipTest("bwrap or gdb not installed")

        elf = parse_elf(self.bin_pie)
        # Verify pure-Python .symtab extraction has binary funcs and zero libc funcs
        self.assertIn("secret_calc", elf.functions)
        self.assertNotIn("clock_adjtime", elf.functions)

        sandbox = SandboxEnv(enabled=True)
        session = GdbSession(self.bin_pie, elf, sandbox)
        try:
            session.start_gdb()
            session.stop_at_symbol("main")
            funcs = session.get_binary_functions()
            self.assertIn("secret_calc", funcs)
            self.assertNotIn("clock_adjtime", funcs)
            self.assertNotIn("c16rtomb", funcs)

            # Non-visible / nonexistent call without --ignore must fail immediately without running
            ok_bad, msg_bad, _ = session.run_to_next_call("nonexistent_fn_xyz")
            self.assertFalse(ok_bad)
            self.assertIn("--ignore", msg_bad)
            self.assertFalse(session.exited)

            # Nonexistent call WITH --ignore must fail immediately too
            ok_bad2, msg_bad2, _ = session.run_to_next_call("nonexistent_fn_xyz --ignore")
            self.assertFalse(ok_bad2)
            self.assertIn("does not exist", msg_bad2)

            # Valid upcoming call enters secret_calc
            ok, msg, _ = session.run_to_next_call("secret_calc")
            self.assertTrue(ok, msg)
            self.assertEqual(session.get_current_function(), "secret_calc")
        finally:
            session.close()

    def test_fgets_interactive_stdin_and_ignore_calls(self):
        if not shutil.which("bwrap") or not shutil.which("gdb"):
            self.skipTest("bwrap or gdb not installed")

        elf_fg = parse_elf(self.bin_fgets)
        sandbox = SandboxEnv(enabled=True)
        s_fg = GdbSession(self.bin_fgets, elf_fg, sandbox)
        try:
            s_fg.start_gdb()
            s_fg.stdin_prompt_handler = lambda proactive=False: "crackme_pass"
            s_fg.stop_at_symbol("main")
            s_fg.run_or_continue()
            self.assertTrue(s_fg.exited)
            self.assertIn("got=crackme_pass", s_fg.pop_target_output())
        finally:
            s_fg.close()

        elf = parse_elf(self.bin_pie)
        s_ign = GdbSession(self.bin_pie, elf, sandbox)
        try:
            s_ign.start_gdb()
            s_ign.stop_at_symbol("main")
            msg = handle_ignore_command(s_ign, "ignore once")
            self.assertIn("once", msg)
            for _ in range(15):
                s_ign.step_instruction(1, step_over=False)
                if s_ign.ignore_mgr.mode == "none":
                    break
            self.assertEqual(s_ign.get_current_function(), "main")
            self.assertEqual(s_ign.ignore_mgr.mode, "none")
        finally:
            s_ign.close()

    def test_start_steps_into_main_nested_frames_and_stationary_view(self):
        if not shutil.which("bwrap") or not shutil.which("gdb"):
            self.skipTest("bwrap or gdb not installed")

        elf = parse_elf(self.bin_pie)
        sandbox = SandboxEnv(enabled=True)
        session = GdbSession(self.bin_pie, elf, sandbox)
        try:
            session.start_gdb()
            session.advance_to_entry_point()
            for _ in range(30):
                if session.get_current_function() == "main":
                    break
                session.step_instruction(1, step_over=False)
            self.assertEqual(session.get_current_function(), "main")
            self.assertFalse(session.exited)

            page = fetch_view_page(session, session.get_pc(), 41)
            session.step_instruction(1, step_over=False)
            self.assertFalse(should_refresh_page(page, session.get_pc(), False))

            session.goto_address(self.pie_secret_off)
            frames = session.get_binary_call_frames()
            func_names = [f["func"] for f in frames]
            self.assertIn("main", func_names)
            self.assertEqual(func_names[-1], "secret_calc")
        finally:
            session.close()

    def test_entry_main_goto_jump_skip_stack(self):
        if not shutil.which("bwrap") or not shutil.which("gdb"):
            self.skipTest("bwrap or gdb not installed")

        elf = parse_elf(self.bin_pie)
        self.assertIsNotNone(elf.text_range)
        sandbox = SandboxEnv(enabled=True)
        session = GdbSession(self.bin_pie, elf, sandbox)
        try:
            session.start_gdb()
            session.advance_to_entry_point()
            self.assertEqual(session.to_display_addr(session.get_pc()), elf.e_entry)

            ok_go, msg_go, _ = session.goto_address(self.pie_secret_off)
            self.assertTrue(ok_go, msg_go)
            self.assertEqual(session.get_current_function(), "secret_calc")
            self.assertEqual(session.to_display_addr(session.get_pc()), self.pie_secret_off)

            ok_skip, _, _ = session.skip_function()
            self.assertTrue(ok_skip)
            self.assertEqual(session.get_current_function(), "main")

            session.run_or_continue()
            self.assertTrue(session.exited)
            self.assertIn("result=25", session.pop_target_output())

            session.restart_to_entry()
            self.assertFalse(session.exited)
            ok_jmp, msg_jmp = session.jump_to_target(self.pie_secret_off, hex(self.pie_secret_off))
            self.assertTrue(ok_jmp, msg_jmp)
            self.assertEqual(session.to_display_addr(session.get_pc()), self.pie_secret_off)

            line = format_reg_line(session, "rax", 0x41424344, "all")
            self.assertIn("RAX    :", line)
            self.assertIn("DCBA", line)

            stack_out = self.tmp_path / "active.stack.bin"
            ok_dump, dump_msg = session.dump_stack_to_file(stack_out)
            self.assertTrue(ok_dump, dump_msg)
            self.assertLess(stack_out.stat().st_size, 32 * 1024)
        finally:
            session.close()

    def test_stripped_main_missing(self):
        if not shutil.which("bwrap") or not shutil.which("gdb"):
            self.skipTest("bwrap or gdb not installed")

        elf = parse_elf(self.bin_stripped)
        sandbox = SandboxEnv(enabled=True)
        session = GdbSession(self.bin_stripped, elf, sandbox)
        try:
            session.start_gdb()
            ok, _msg, _ = session.stop_at_symbol("main")
            self.assertFalse(ok)
        finally:
            session.close()

    def test_mapper_mode(self):
        if not shutil.which("bwrap") or not shutil.which("gdb"):
            self.skipTest("bwrap or gdb not installed")

        elf = parse_elf(self.bin_pie)
        sandbox = SandboxEnv(enabled=True)
        old_cwd = os.getcwd()
        os.chdir(self.tmp_path)
        try:
            s_full = GdbSession(self.bin_pie, elf, sandbox)
            try:
                s_full.start_gdb()
                full_dir = run_execution_mapper(s_full)
                summary = (full_dir / "summary.txt").read_text(encoding="utf-8")
                syscalls = (full_dir / "syscalls_trace.txt").read_text(encoding="utf-8")
                self.assertIn("Total System Calls", summary)
                self.assertNotIn("Total System Calls    : 0", summary)
                self.assertIn("SYSCALL #0001", syscalls)
                self.assertGreater(len(list((full_dir / "functions").glob("func_*.txt"))), 1)
            finally:
                s_full.close()

            s_func = GdbSession(self.bin_pie, elf, sandbox)
            try:
                s_func.start_gdb()
                out_dir = run_execution_mapper(s_func, func_spec=f"0x{self.pie_secret_off:x}")
                self.assertTrue(out_dir.is_dir())
                self.assertRegex(out_dir.name, r"^sample_pie-mapped_\d{2}-\d{2}-\d{4}_\d{2}-\d{2}-\d{2}$")
                self.assertTrue((out_dir / "summary.txt").is_file())
            finally:
                s_func.close()
        finally:
            os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
