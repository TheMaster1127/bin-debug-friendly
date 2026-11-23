# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

EI_CLASS = 4
EI_DATA = 5

ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATA2LSB = 1
ELFDATA2MSB = 2

ET_EXEC = 2
ET_DYN = 3

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

PT_LOAD = 1
PF_X = 1

SHT_SYMTAB = 2
STT_FUNC = 2

MACHINE_MAP = {
    EM_386: ("i386", 32),
    EM_ARM: ("arm", 32),
    EM_X86_64: ("x86_64", 64),
    EM_AARCH64: ("aarch64", 64),
}


@dataclass
class LoadSegment:
    vaddr: int
    memsz: int
    offset: int
    filesz: int
    flags: int

    @property
    def is_executable(self) -> bool:
        return bool(self.flags & PF_X)


@dataclass
class ElfInfo:
    path: Path
    arch: str
    bits: int
    endian: str  # "<" or ">"
    e_type: int
    is_pie: bool
    e_entry: int
    e_phoff: int
    base_vaddr: int
    segments: list[LoadSegment]
    text_range: tuple[int, int] | None = None
    plt_ranges: list[tuple[int, int]] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)

    def contains_vaddr(self, addr: int) -> bool:
        for seg in self.segments:
            if seg.vaddr <= addr < seg.vaddr + seg.memsz:
                return True
        return False

    def file_offset_to_vaddr(self, offset: int) -> int | None:
        for seg in self.segments:
            if seg.offset <= offset < seg.offset + seg.filesz:
                return seg.vaddr + (offset - seg.offset)
        return None


def _read_cstr(buf: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(buf):
        return ""
    end = buf.find(b"\x00", offset)
    if end == -1:
        end = len(buf)
    return buf[offset:end].decode("ascii", errors="replace")


def parse_elf(path: Path) -> ElfInfo:
    data = path.read_bytes()
    if len(data) < 52 or data[:4] != ELF_MAGIC:
        raise ValueError(f"Not a valid ELF binary: {path}")

    ei_class = data[EI_CLASS]
    ei_data = data[EI_DATA]

    if ei_class == ELFCLASS32:
        bits = 32
    elif ei_class == ELFCLASS64:
        bits = 64
    else:
        raise ValueError(f"Unsupported ELF class: {ei_class}")

    if ei_data == ELFDATA2LSB:
        endian = "<"
    elif ei_data == ELFDATA2MSB:
        endian = ">"
    else:
        raise ValueError(f"Unsupported ELF endianness: {ei_data}")

    if bits == 64:
        if len(data) < 64:
            raise ValueError("Truncated ELF64 header")
        (
            e_type, e_machine, _e_ver, e_entry, e_phoff, e_shoff,
            _e_flags, _e_ehsize, e_phentsize, e_phnum,
            e_shentsize, e_shnum, e_shstrndx,
        ) = struct.unpack(endian + "HHIQQQIHHHHHH", data[16:64])
    else:
        (
            e_type, e_machine, _e_ver, e_entry, e_phoff, e_shoff,
            _e_flags, _e_ehsize, e_phentsize, e_phnum,
            e_shentsize, e_shnum, e_shstrndx,
        ) = struct.unpack(endian + "HHIIIIIHHHHHH", data[16:52])

    arch, arch_bits = MACHINE_MAP.get(e_machine, (f"unknown({e_machine})", bits))
    is_pie = (e_type == ET_DYN)

    segments: list[LoadSegment] = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        if bits == 64:
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack(
                endian + "IIQQQQQQ", data[off:off + 56]
            )
        else:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, _p_align = struct.unpack(
                endian + "IIIIIIII", data[off:off + 32]
            )
        if p_type == PT_LOAD:
            segments.append(
                LoadSegment(
                    vaddr=p_vaddr,
                    memsz=p_memsz,
                    offset=p_offset,
                    filesz=p_filesz,
                    flags=p_flags,
                )
            )

    text_range: tuple[int, int] | None = None
    plt_ranges: list[tuple[int, int]] = []
    section_headers: list[tuple[int, int, int, int, int, int, int]] = []

    if e_shoff and e_shnum:
        for i in range(e_shnum):
            soff = e_shoff + i * e_shentsize
            if soff + (64 if bits == 64 else 40) > len(data):
                break
            if bits == 64:
                sh_name, sh_type, _sh_flags, sh_addr, sh_off, sh_size, sh_link, _sh_info, _sh_aa, sh_entsize = struct.unpack(
                    endian + "IIQQQQIIQQ", data[soff:soff + 64]
                )
            else:
                sh_name, sh_type, _sh_flags, sh_addr, sh_off, sh_size, sh_link, _sh_info, _sh_aa, sh_entsize = struct.unpack(
                    endian + "IIIIIIIIII", data[soff:soff + 40]
                )
            section_headers.append((sh_name, sh_type, sh_addr, sh_off, sh_size, sh_link, sh_entsize))

    shstrtab = b""
    if 0 <= e_shstrndx < len(section_headers):
        _sn, _st, _sa, s_off, s_sz, _sl, _se = section_headers[e_shstrndx]
        shstrtab = data[s_off:s_off + s_sz]

    functions_set: set[str] = set()
    for sh_name, sh_type, sh_addr, sh_off, sh_size, sh_link, sh_entsize in section_headers:
        name = _read_cstr(shstrtab, sh_name)
        if name == ".text" and sh_size > 0:
            text_range = (sh_addr, sh_addr + sh_size)
        elif name.startswith(".plt") and sh_size > 0:
            plt_ranges.append((sh_addr, sh_addr + sh_size))
        elif sh_type == SHT_SYMTAB and sh_entsize > 0 and 0 <= sh_link < len(section_headers):
            _ln, _lt, _la, str_off, str_sz, _ll, _le = section_headers[sh_link]
            strtab = data[str_off:str_off + str_sz]
            sym_end = min(len(data), sh_off + sh_size)
            pos = sh_off
            while pos + sh_entsize <= sym_end:
                if bits == 64:
                    st_name, st_info, _st_other, _st_shndx, st_value, _st_size = struct.unpack(
                        endian + "IBBHQQ", data[pos:pos + 24]
                    )
                else:
                    st_name, st_value, _st_size, st_info, _st_other, _st_shndx = struct.unpack(
                        endian + "IIIBBH", data[pos:pos + 16]
                    )
                if (st_info & 0xF) == STT_FUNC and st_value != 0:
                    fn_name = _read_cstr(strtab, st_name)
                    if fn_name:
                        functions_set.add(fn_name)
                pos += sh_entsize

    user_fns = sorted(f for f in functions_set if not f.startswith("_"))
    internal_fns = sorted(f for f in functions_set if f.startswith("_"))

    base_vaddr = min((s.vaddr for s in segments), default=0)
    return ElfInfo(
        path=path,
        arch=arch,
        bits=arch_bits,
        endian=endian,
        e_type=e_type,
        is_pie=is_pie,
        e_entry=e_entry,
        e_phoff=e_phoff,
        base_vaddr=base_vaddr,
        segments=segments,
        text_range=text_range,
        plt_ranges=plt_ranges,
        functions=user_fns + internal_fns,
    )


def parse_address_input(raw: str) -> tuple[int | None, str]:
    s = raw.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()

    compact = re.sub(r"\s+", "", s)
    if not compact:
        return None, ""

    if compact.lower().startswith("0x"):
        hex_body = compact[2:]
        if hex_body and re.fullmatch(r"[0-9a-fA-F]+", hex_body):
            return int(hex_body, 16), "0x" + hex_body.lower()
        return None, s

    if re.fullmatch(r"[0-9a-fA-F]+", compact):
        return int(compact, 16), "0x" + compact.lower()

    return None, s


def resolve_target_address(addr: int, elf: ElfInfo, runtime_base: int) -> tuple[int, str]:
    if elf.is_pie:
        if runtime_base and addr >= runtime_base:
            for seg in elf.segments:
                lo = runtime_base + (seg.vaddr - elf.base_vaddr)
                hi = lo + seg.memsz
                if lo <= addr < hi:
                    return addr, "runtime_vaddr"
            if addr < runtime_base + 0x10000000:
                return addr, "runtime_vaddr"

        if elf.contains_vaddr(addr):
            resolved = runtime_base + (addr - elf.base_vaddr)
            return resolved, f"pie_vaddr(objdump=0x{addr:x})"

        vaddr = elf.file_offset_to_vaddr(addr)
        if vaddr is not None:
            resolved = runtime_base + (vaddr - elf.base_vaddr)
            return resolved, f"pie_file_off(objdump=0x{vaddr:x})"

        return runtime_base + addr, "pie_offset"

    if elf.contains_vaddr(addr):
        return addr, "exec_vaddr"

    vaddr = elf.file_offset_to_vaddr(addr)
    if vaddr is not None and addr < elf.base_vaddr:
        return vaddr, f"exec_file_off(vaddr=0x{vaddr:x})"

    return addr, "direct_addr"
