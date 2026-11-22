# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import re
from pathlib import Path

from src.config import (
    FALLBACK_STACK_DOWN_BYTES,
    FALLBACK_STACK_UP_BYTES,
    TRIM_STACK_DUMP_ZEROS,
    USE_OBJDUMP_ADDR,
)

CORE_REGS = {
    "x86_64": [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "rip", "eflags",
    ],
    "i386": [
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "eip", "eflags",
    ],
    "aarch64": [f"x{i}" for i in range(31)] + ["sp", "pc", "cpsr"],
    "arm": [f"r{i}" for i in range(13)] + ["sp", "lr", "pc", "cpsr"],
}

SP_REG = {"x86_64": "rsp", "i386": "esp", "aarch64": "sp", "arm": "sp"}
PC_REG = {"x86_64": "rip", "i386": "eip", "aarch64": "pc", "arm": "pc"}


def trim_zero_stack(data: bytes, base_addr: int) -> tuple[bytes, int]:
    if not data:
        return data, base_addr
    row_size = 16
    num_rows = (len(data) + row_size - 1) // row_size
    first_nz = None
    last_nz = None
    for idx in range(num_rows):
        chunk = data[idx * row_size:(idx + 1) * row_size]
        if any(b != 0 for b in chunk):
            if first_nz is None:
                first_nz = idx
            last_nz = idx
    if first_nz is None:
        return data[:min(len(data), 64)], base_addr
    start_off = first_nz * row_size
    end_off = min(len(data), (last_nz + 1) * row_size)
    return data[start_off:end_off], base_addr + start_off


class GdbInspectorMixin:
    def _load_register_names(self) -> None:
        res = self.send("-data-list-register-names")
        names = res["payload"].get("register-names", [])
        if isinstance(names, list):
            self.reg_names = [str(n).lower() for n in names]
            self.reg_name_to_idx = {n: i for i, n in enumerate(self.reg_names) if n}
            preferred = CORE_REGS.get(self.elf.arch, [])
            self.core_reg_indices = [
                self.reg_name_to_idx[r] for r in preferred if r in self.reg_name_to_idx
            ]
            self.core_reg_query = " ".join(str(i) for i in self.core_reg_indices)
            self.pc_reg_idx = self.reg_name_to_idx.get(PC_REG.get(self.elf.arch, "rip"))
            self.sp_reg_idx = self.reg_name_to_idx.get(SP_REG.get(self.elf.arch, "rsp"))

    def get_registers(self) -> dict[str, int]:
        if not self.reg_names:
            self._load_register_names()
        cmd = (
            f"-data-list-register-values x {self.core_reg_query}"
            if getattr(self, "core_reg_query", "")
            else "-data-list-register-values x"
        )
        res = self.send(cmd)
        vals = {}
        for item in res["payload"].get("register-values", []):
            if not isinstance(item, dict):
                continue
            try:
                idx = int(item["number"])
                name = self.reg_names[idx] if idx < len(self.reg_names) else ""
                if not name:
                    continue
                val_str = item["value"]
                if isinstance(val_str, str) and val_str.startswith("{"):
                    continue
                vals[name] = int(str(val_str), 0)
            except Exception:
                continue

        ordered = {}
        for rname in CORE_REGS.get(self.elf.arch, []):
            if rname in vals:
                ordered[rname] = vals[rname]
        return ordered or vals

    def get_single_register(self, reg_name: str) -> tuple[str, int] | None:
        if not self.reg_names:
            self._load_register_names()
        key = reg_name.strip().lower()
        idx = getattr(self, "reg_name_to_idx", {}).get(key)
        if idx is not None:
            res = self.send(f"-data-list-register-values x {idx}")
            items = res["payload"].get("register-values", [])
            if items and isinstance(items[0], dict):
                try:
                    return key, int(str(items[0]["value"]), 0)
                except Exception:
                    pass
        res = self.send(f'-data-evaluate-expression "${key}"')
        if res["status"] == "done":
            val_str = res["payload"].get("value", "")
            try:
                return key, int(str(val_str).split()[0], 0)
            except Exception:
                pass
        return None

    def set_register(self, reg_name: str, value: int) -> tuple[bool, str]:
        key = reg_name.strip().lower()
        res = self.send(f'-gdb-set ${key} = 0x{value:x}')
        if res["status"] == "error":
            return False, res["payload"].get("msg", f"Failed to set ${key}")
        return True, f"{key.upper()} set to 0x{value:x} ({value})"

    def get_pc(self) -> int | None:
        if not self.reg_names:
            self._load_register_names()
        pc_idx = getattr(self, "pc_reg_idx", None)
        if pc_idx is not None:
            res = self.send(f"-data-list-register-values x {pc_idx}")
            items = res["payload"].get("register-values", [])
            if items and isinstance(items[0], dict):
                try:
                    return int(str(items[0]["value"]), 0)
                except Exception:
                    pass
        return self.get_registers().get(PC_REG.get(self.elf.arch, "rip"))

    def get_sp(self) -> int | None:
        if not self.reg_names:
            self._load_register_names()
        sp_idx = getattr(self, "sp_reg_idx", None)
        if sp_idx is not None:
            res = self.send(f"-data-list-register-values x {sp_idx}")
            items = res["payload"].get("register-values", [])
            if items and isinstance(items[0], dict):
                try:
                    return int(str(items[0]["value"]), 0)
                except Exception:
                    pass
        return self.get_registers().get(SP_REG.get(self.elf.arch, "rsp"))

    def read_memory(self, addr: int, size: int) -> bytes | None:
        if addr <= 0 or size <= 0:
            return None
        res = self.send(f"-data-read-memory-bytes 0x{addr:x} {size}")
        if res["status"] != "done":
            return None
        mem = res["payload"].get("memory", [])
        if not mem or not isinstance(mem[0], dict):
            return None
        try:
            return bytes.fromhex(mem[0].get("contents", ""))
        except Exception:
            return None

    def read_pointer(self, addr: int) -> int | None:
        ptr_bytes = self.elf.bits // 8
        raw = self.read_memory(addr, ptr_bytes)
        if not raw or len(raw) < ptr_bytes:
            return None
        return int.from_bytes(raw, "little" if self.elf.endian == "<" else "big")

    def read_c_string(self, addr: int, max_len: int = 64) -> str | None:
        if addr < 0x1000:
            return None
        raw = self.read_memory(addr, max_len)
        if not raw:
            return None
        nul = raw.find(b"\x00")
        chunk = raw[:nul] if nul != -1 else raw
        if not chunk:
            return None
        printable = sum(1 for b in chunk if 32 <= b < 127 or b in (9, 10, 13))
        if printable / len(chunk) >= 0.85:
            return chunk.decode("ascii", errors="replace")
        return None

    def to_display_addr(self, runtime_addr: int) -> int:
        if (
            USE_OBJDUMP_ADDR
            and self.elf.is_pie
            and self.runtime_base is not None
            and self.addr_in_any_binary_segment(runtime_addr)
        ):
            return self.elf.base_vaddr + (runtime_addr - self.runtime_base)
        return runtime_addr

    def rebase_disas_text(self, insn_text: str) -> str:
        if not (USE_OBJDUMP_ADDR and self.elf.is_pie and self.runtime_base is not None):
            return insn_text

        def _repl(m: re.Match) -> str:
            val = int(m.group(0), 16)
            if self.addr_in_any_binary_segment(val):
                return f"0x{self.to_display_addr(val):x}"
            return m.group(0)

        return re.sub(r"0x[0-9a-fA-F]{6,16}", _repl, insn_text)

    def get_current_function(self) -> str | None:
        res = self.send("-stack-info-frame")
        if res["status"] != "done":
            return None
        frame = res["payload"].get("frame", {})
        if isinstance(frame, dict):
            func = frame.get("func")
            if func and func != "??":
                return str(func)
        return None

    def get_binary_call_frames(self) -> list[dict]:
        res = self.send("-stack-list-frames")
        if res["status"] != "done":
            return []
        raw_stack = res["payload"].get("stack", [])
        frames = []
        for entry in raw_stack:
            fr = entry.get("frame") if isinstance(entry, dict) else None
            if not isinstance(fr, dict):
                continue
            try:
                addr = int(str(fr.get("addr", "0")), 0)
                lvl = int(str(fr.get("level", "0")))
            except Exception:
                continue
            if self.addr_in_main_binary(addr):
                func = str(fr.get("func", "??"))
                frames.append({"level": lvl, "addr": addr, "func": func})
        frames.reverse()
        return frames

    def get_current_exec_bounds(self, addr: int) -> tuple[int, int] | None:
        if self.text_runtime_range is not None:
            tlo, thi = self.text_runtime_range
            if tlo <= addr < thi:
                return tlo, thi
        for lo, hi in self.exec_ranges:
            if lo <= addr < hi:
                return lo, hi
        for m in self.get_proc_mappings():
            if m["start"] <= addr < m["end"]:
                return m["start"], m["end"]
        return None

    def disassemble_range(self, start_addr: int, end_addr: int) -> list[tuple[int, str, str]]:
        if end_addr <= start_addr:
            return []
        res = self.send(f"-data-disassemble -s 0x{start_addr:x} -e 0x{end_addr:x} -- 2")
        insns = res["payload"].get("asm_insns", [])
        if not insns:
            res = self.send(f"-data-disassemble -s 0x{start_addr:x} -e 0x{end_addr:x} -- 0")
            insns = res["payload"].get("asm_insns", [])

        out = []
        for item in insns:
            if isinstance(item, dict):
                try:
                    a = int(item.get("address", "0"), 0)
                    opcodes = str(item.get("opcodes", "")).strip()
                    inst = self.rebase_disas_text(str(item.get("inst", "")).strip())
                    out.append((a, opcodes, inst))
                except Exception:
                    continue
        return out

    def disassemble_at(self, addr: int, count: int = 5) -> list[tuple[int, str, str]]:
        bounds = self.get_current_exec_bounds(addr)
        end_addr = addr + count * 16
        if bounds:
            end_addr = min(end_addr, bounds[1])
        return self.disassemble_range(addr, end_addr)[:count]

    def disassemble_context(self, pc: int, before: int, after: int, func_name: str | None = None) -> tuple[list[tuple[int, str, str]], int, bool, bool]:
        bounds = self.get_current_exec_bounds(pc)
        seg_lo, seg_hi = bounds if bounds else (max(0, pc - before * 16), pc + after * 16)

        start_anchor = max(seg_lo, pc - max(64, before * 12))
        fn = func_name or self.get_current_function()
        if fn and fn != "??":
            faddr_res = self.send(f'-data-evaluate-expression "{fn}"')
            if faddr_res["status"] == "done":
                m = re.search(r"0x[0-9a-fA-F]+", str(faddr_res["payload"].get("value", "")))
                if m:
                    faddr = int(m.group(0), 16)
                    if seg_lo <= faddr <= pc and (pc - faddr) <= 4096:
                        start_anchor = faddr

        if self.runtime_base is not None:
            entry_rt = self.runtime_base + (self.elf.e_entry - self.elf.base_vaddr)
            if seg_lo <= entry_rt <= pc and (pc - entry_rt) <= 4096 and entry_rt > start_anchor:
                start_anchor = entry_rt

        end_anchor = min(seg_hi, pc + max(32, (after + 2) * 16))
        insns = self.disassemble_range(start_anchor, end_anchor)

        pc_idx = next((idx for idx, (a, _, _) in enumerate(insns) if a == pc), None)
        if pc_idx is None:
            fwd = self.disassemble_at(pc, after + 1)
            return fwd, 0, before > 0, len(fwd) <= after

        lo_idx = max(0, pc_idx - before)
        hi_idx = min(len(insns), pc_idx + after + 1)
        cut_top = (pc_idx - before) < 0
        cut_bottom = (pc_idx + after + 1) > len(insns)
        return insns[lo_idx:hi_idx], pc_idx - lo_idx, cut_top, cut_bottom

    def get_proc_mappings(self) -> list[dict]:
        res = self.send('-interpreter-exec console "info proc mappings"')
        rows = []
        pat = re.compile(
            r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S+)(?:\s+(.*))?$"
        )
        pat_old = re.compile(
            r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)(?:\s+(.*))?$"
        )
        for line in res["console"].splitlines():
            m = pat.match(line)
            if m:
                rows.append({
                    "start": int(m.group(1), 16),
                    "end": int(m.group(2), 16),
                    "size": int(m.group(3), 16),
                    "offset": int(m.group(4), 16),
                    "perms": m.group(5),
                    "objfile": (m.group(6) or "").strip(),
                })
                continue
            m2 = pat_old.match(line)
            if m2:
                rows.append({
                    "start": int(m2.group(1), 16),
                    "end": int(m2.group(2), 16),
                    "size": int(m2.group(3), 16),
                    "offset": int(m2.group(4), 16),
                    "perms": "r-xp",
                    "objfile": (m2.group(5) or "").strip(),
                })
        return rows

    def get_stack_bounds(self) -> tuple[int, int, int, bool]:
        sp = self.get_sp() or 0
        cached = getattr(self, "_cached_stack_bounds", None)
        if cached is not None:
            c_lo, c_hi, c_exact = cached
            if c_lo <= sp < c_hi:
                return c_lo, c_hi, sp, c_exact
        for m in self.get_proc_mappings():
            if "[stack]" in m["objfile"] or (m["start"] <= sp < m["end"]):
                self._cached_stack_bounds = (m["start"], m["end"], True)
                return m["start"], m["end"], sp, True
        lo = max(0, sp - FALLBACK_STACK_DOWN_BYTES)
        hi = sp + FALLBACK_STACK_UP_BYTES
        return lo, hi, sp, False

    def dump_stack_to_file(self, host_dest_path: Path, full: bool = False) -> tuple[bool, str]:
        lo, hi, sp, exact = self.get_stack_bounds()
        dump_start = lo if full else sp
        if hi <= dump_start:
            dump_start = lo
        if hi <= dump_start:
            return False, "Invalid stack range."

        gdb_out = "/tmp/work/stack_dump.bin" if self.sandbox.enabled else str(self.work_dir / "stack_dump.bin")
        res = self.send(
            f'-interpreter-exec console "dump binary memory {gdb_out} 0x{dump_start:x} 0x{hi:x}"'
        )
        if res["status"] == "error":
            return False, res["payload"].get("msg", "Failed to dump stack memory")
        src_file = self.work_dir / "stack_dump.bin"
        if not src_file.exists():
            return False, "GDB did not produce stack dump file."

        raw_bytes = src_file.read_bytes()
        trimmed_start = dump_start
        if not full and TRIM_STACK_DUMP_ZEROS:
            raw_bytes, trimmed_start = trim_zero_stack(raw_bytes, dump_start)

        host_dest_path.write_bytes(raw_bytes)
        note = "full [stack]" if full else ("active SP trimmed" if TRIM_STACK_DUMP_ZEROS else "active SP..top")
        if not exact:
            note += ", est"
        return (
            True,
            f"Dumped {len(raw_bytes)} bytes (0x{trimmed_start:x}-0x{trimmed_start + len(raw_bytes):x}, {note}) -> {host_dest_path}",
        )

    def get_peak_memory_kb(self) -> int | None:
        res = self.send('-interpreter-exec console "info proc status"')
        for line in res["console"].splitlines():
            if "VmHWM" in line or "VmRSS" in line:
                m = re.search(r"(\d+)\s*kB", line)
                if m:
                    return int(m.group(1))
        return None
