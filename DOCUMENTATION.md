# `bin-debug-friendly` — Technical Documentation & Design Specification

> **Document Scope:** Complete architectural specification, design rationale, module-by-module internals, pure-Python ELF32/ELF64 parsing, `sstrip` synthetic section reconstruction, stripped-`main` recovery, GDB/MI2 pipe & FIFO isolation, indexed register caching, external call skipping & `IgnoreCallManager`, stationary ANSI live-view rendering, session recording (`DEREF`), autonomous execution mapping, lifecycle heap dumping (`heap_dump.py`), dynamic stack/register string extraction (`stack_strings.py`), safety limits, and Bubblewrap/QEMU sandboxing.

---

## Table of Contents

1. [Design Philosophy: Why `bin-debug-friendly` Exists](#1-design-philosophy-why-bin-debug-friendly-exists)
2. [System Architecture & Module Dependency Graph](#2-system-architecture--module-dependency-graph)
3. [Module-by-Module Technical Reference](#3-module-by-module-technical-reference)
4. [ELF32/ELF64 Parsing, `sstrip` Recovery & PIE Resolution (`src/elf_utils.py`)](#4-elf32elf64-parsing-sstrip-recovery--pie-resolution-srcelf_utilspy)
5. [Unbuffered GDB/MI2 Transport & Isolated `stdin`/`stdout` (`src/mi_protocol.py`)](#5-unbuffered-gdbmi2-transport--isolated-stdinstdout-srcmi_protocolpy)
6. [High-Speed Register, Memory & Disassembly Engine (`src/gdb_inspector.py`)](#6-high-speed-register-memory--disassembly-engine-srcgdb_inspectorpy)
7. [Execution Control, External Skipping, `call` & `ignore` (`src/gdb_session.py`)](#7-execution-control-external-skipping-call--ignore-srcgdb_sessionpy)
8. [Stationary Live View, Split Layout, `nestN` & Color Diffs (`src/live_view.py`, `src/colors.py`)](#8-stationary-live-view-split-layout-nestn--color-diffs-srclive_viewpy-srccolorspy)
9. [Zero-Trimmed Stack Inspection & Binary Dumping](#9-zero-trimmed-stack-inspection--binary-dumping)
10. [Session Recording Specification (`src/recorder.py`)](#10-session-recording-specification-srcrecorderpy)
11. [Autonomous Execution Mapping & Syscall Tracing (`src/mapper.py`)](#11-autonomous-execution-mapping--syscall-tracing-srcmapperpy)
12. [Lifecycle Heap Dumper Architecture (`heap_dump.py`)](#12-lifecycle-heap-dumper-architecture-heap_dumppy)
13. [Dynamic Stack & Register String Extractor (`stack_strings.py`)](#13-dynamic-stack--register-string-extractor-stack_stringspy)
14. [Safety Limits, Timeouts & Graceful Interrupts](#14-safety-limits-timeouts--graceful-interrupts)
15. [Bubblewrap Sandbox & Cross-Architecture QEMU Design (`src/sandbox.py`)](#15-bubblewrap-sandbox--cross-architecture-qemu-design-srcsandboxpy)
16. [Configuration Reference (`src/config.py`)](#16-configuration-reference-srcconfigpy)

---

## 1. Design Philosophy: Why `bin-debug-friendly` Exists

Raw GDB is designed for source-level debugging with DWARF debug info. Reverse-engineering stripped binaries, crackmes, packed payloads, or custom tiny ELFs exposes severe gaps in standard tools:

1. **Address Disconnect:** Disassemblers (`objdump`, `binpatch`, `readelf`) show static offsets (`0x1149`), whereas PIE binaries relocate at runtime (`0x555555555149`). Address translation should be invisible.
2. **Anti-Analysis (`strip` & `sstrip`):** Removing `.symtab` or wiping the entire ELF section header table (`e_shoff = 0`) breaks standard disassemblers and crashes GDB's BFD loader—even though the Linux kernel runs the binary cleanly via `PT_LOAD` program headers.
3. **Loader & Shared Library Noise:** Single-stepping casually pulls analysts into `ld-linux.so`, `.plt` trampolines, and `libc` internals instead of staying focused on target logic.
4. **Transient Secrets (Stack, Heap & Registers):** Modern crackmes and malware decrypt secrets only in temporary stack buffers, heap chunks (`malloc` + `explicit_bzero` + `free`), or pointer registers—leaving zero plaintext in static `.rodata`.
5. **Unsafe Execution:** Running untrusted ELFs directly on a workstation exposes `/home`, SSH keys, and the network stack. Air-gapped Linux namespaces should be the default.

`bin-debug-friendly` solves all five using **Python 3 standard library modules only** (zero mandatory `pip` packages), GNU `gdb --interpreter=mi2`, `bubblewrap`, and optional `qemu-user` / `colorama`.

---

## 2. System Architecture & Module Dependency Graph

```text
                        ┌───────────────────────────────────────┐
                        │   Entry Points & Companion Tools      │
                        │ • main.py (-m, -record, -map, -func)  │
                        │ • heap_dump.py (Lifecycle Heap Trap)  │
                        │ • stack_strings.py (Trace Extractor)  │
                        └───────────────────┬───────────────────┘
                                            │
                 ┌──────────────────────────┴──────────────────────────┐
                 ▼                                                     ▼
┌─────────────────────────────────┐                   ┌─────────────────────────────────┐
│     Interactive Frontend        │                   │     Execution Mapper Mode       │
│  • src/cli.py (REPL, ls, dump)  │                   │  • src/mapper.py                │
│  • src/live_view.py (TUI/nestN) │                   │    - Instruction & Reg Trace    │
│  • src/formatters.py (Intel/hex)│                   │    - DEREF Register Strings     │
│  • src/colors.py (TTY green)    │                   │    - Active Stack & Stack Diffs │
│  • src/recorder.py (--record)   │                   │    - Syscall Catch & Stats      │
└────────────────┬────────────────┘                   │    - 250 MB Size Guard          │
                 │                                    └────────────────┬────────────────┘
                 └──────────────────────────┬──────────────────────────┘
                                            ▼
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                              GDB Session Layer (3 Modules)                            │
│  • src/gdb_session.py   — Breakpoints, sstrip recovery, PIE/PLT skip, call, ignore    │
│  • src/gdb_inspector.py — Indexed GPRs, .text disas, call frames, stack dumps         │
│  • src/mi_protocol.py   — Unbuffered binary pipe I/O, FIFO stdin, MI2 parser          │
└────────────────┬───────────────────────────────────────────┬──────────────────────────┘
                 ▼                                           ▼
┌─────────────────────────────────────────┐ ┌───────────────────────────────────────────┐
│            src/elf_utils.py             │ │              src/sandbox.py               │
│  • ELF32/ELF64 Header & PT_LOAD         │ │  • Bubblewrap (--unshare-all)             │
│  • .text, .plt*, .symtab Bounds         │ │  • QEMU user-mode (-g <port>) + GDB       │
│  • sstrip Synthetic Section Repair      │ │  • 3-Step --no-sandbox Gate               │
│  • x86_64/i386 _start -> main() Recovery│ └───────────────────────────────────────────┘
└─────────────────────────────────────────┘
```

---

## 3. Module-by-Module Technical Reference

| Component | Primary Role | Key Exports |
|-----------|--------------|-------------|
| `main.py` | CLI entry point, ELF validation, `--no-sandbox` gate, session/recorder lifecycle, `--map` / `-m` dispatch. | `build_parser()`, `main()` |
| `heap_dump.py` | Standalone lifecycle `[heap]` dumper trapping `sys_read`, `strcmp`/`memcmp`/`explicit_bzero`/`free`, and `exit_group`. | `run_until_stdin_read()`, `snapshot_heap()`, `install_post_stdin_traps()` |
| `stack_strings.py` | Standalone dynamic string extractor reconstructing concatenated stack & `DEREF` binaries across time. | `parse_trace_data()`, `extract_ascii_strings()`, `filter_redundant_prefixes()` |
| `src/config.py` | Central configuration constants for display, view layout, recording, external skipping, stack trimming, and caps. | `VIEW_PAGE_SIZE`, `MAX_MAP_FOLDER_MB`, etc. |
| `src/elf_utils.py` | Pure-Python ELF32/ELF64 parser, `sstrip` section synthesizer, `_start`-to-`main` resolver (`x86_64`/`i386`), and PIE math. | `ElfInfo`, `parse_elf()`, `reconstruct_sstripped_sections()`, `resolve_entry_main_address()` |
| `src/sandbox.py` | Host/target architecture matching, `bwrap` container builder, QEMU detection, `--no-sandbox` gate. | `SandboxEnv`, `confirm_disable_sandbox()`, `detect_host_arch()`, `needs_qemu()` |
| `src/mi_protocol.py` | Raw `bufsize=0` GDB/MI2 pipe driver, recursive MI2 parser, target `stdin` FIFO, accumulated `stdout` store. | `MIProtocol`, `MIParser`, `parse_mi_lines()` |
| `src/gdb_inspector.py` | Indexed GPR retrieval, memory/C-string reads, Intel opcode disassembly, `ls` slicing, binary-only function listing, stack dumps. | `GdbInspectorMixin`, `trim_zero_stack()`, `CORE_REGS` |
| `src/gdb_session.py` | Process lifecycle (`_start` vs `main`), PIE base discovery, `goto_address`, `jump_to_target`, `run_to_next_call`, `IgnoreCallManager`, `get_registers_deref`. | `GdbSession`, `IgnoreCallManager` |
| `src/formatters.py` | Character-level register diff formatting, `xxd`-style stack lines, `readline` Tab completer, prompt builder, `help`. | `format_reg_line()`, `setup_readline_completer()`, `handle_ignore_command()` |
| `src/colors.py` | Optional `colorama` wrapper restricted to interactive TTYs (`sys.stdout.isatty()`), ANSI-aware padding, byte-level `xxd` diffs. | `colors_active()`, `highlight_char_diff()`, `format_diff_xxd_line()`, `visible_len()` |
| `src/live_view.py` | Flicker-free single-flush ANSI dashboard with wide-screen split layout, `max`/`min`/`only`/`raw stack`, zero-collapsed stack, and `nestN` panes. | `run_live_view()`, `parse_view_options()`, `select_visible_frames()` |
| `src/cli.py` | Interactive command REPL supporting navigation, stepping, batch-dumping, register editing, stack inspection, and recording. | `run_interactive_cli()`, `handle_ls_command()`, `handle_step_with_dump()` |
| `src/recorder.py` | Idle-flushed session recorder writing `record-<bin>_<date>/full_recording.txt` and `functions/func_*.txt` with `DEREF` strings. | `SessionRecorder` |
| `src/mapper.py` | Autonomous execution mapper generating `<bin>-mapped_<date>/` with instruction traces, `DEREF`, stack diffs, syscalls, and stats. | `run_execution_mapper()`, `classify_instruction()`, `FolderSizeGuard` |

> **Note (`main.py` & `heap_dump.py`):** Both entry-point scripts pre-extract `-A`/`-a`/`--args` via `shlex.split()` before `argparse` runs so target flags (`-h`, `-m`, `-o`) and escaped quotes (`\"`) pass through cleanly, and resolve `Path(__file__).resolve().parent` so global wrapper/symlink installs always locate `src/` while writing output artifacts to `Path.cwd()`.

---

## 4. ELF32/ELF64 Parsing, `sstrip` Recovery & PIE Resolution (`src/elf_utils.py`)

`parse_elf()` parses binaries natively using `struct.unpack` without spawning external tools:

1. **Header & Segment Inspection:** Extracts bitness (`32`/`64`), endianness (`<`/`>`), architecture (`x86_64`, `i386`, `aarch64`, `arm`), PIE status (`ET_DYN` vs `ET_EXEC`), `e_entry`, and all `PT_LOAD` segments (`vaddr`, `memsz`, `offset`, `filesz`, `PF_X`, `PF_W`).
2. **Section Extraction (`.text`, `.plt*`, `.symtab`):** Extracts `.text` bounds (clamping `ls`/`disas` from trailing zero padding), `.plt*` ranges, and `STT_FUNC` symbol names belonging strictly to the target binary (`functions`).
3. **`sstrip` Synthetic Section Reconstruction (`reconstruct_sstripped_sections`):**
   - Binaries processed with `sstrip` have `e_shoff == 0` and `e_shnum == 0`, which causes GDB's BFD loader to crash or fail disassembly (`find_pc_section == NULL`).
   - When `GdbSession` copies an `sstrip`ped binary into its temporary sandbox (`/tmp/work/target_bin`), it aligns and appends `.shstrtab` plus 4 synthetic section headers (`NULL`, `.text`, `.data`, `.shstrtab`) **at the very end of the file past the last `PT_LOAD` segment**—so zero runtime `p_offset` or `p_vaddr` values shift—and patches `e_shoff`, `e_shentsize`, `e_shnum = 4`, and `e_shstrndx = 3` in the sandbox copy's ELF header. The original host binary is never modified, while GDB gains full disassembly, breakpoint, and register support.
4. **Stripped `main()` Recovery (`resolve_entry_main_address`):**
   - On `x86_64` (`lea rdi, [rip + disp32]`) and `i386` (`push imm32` before `call`), inspects machine code at `e_entry` (`_start`) to locate `main()` statically even when all symbols are stripped. (On `aarch64`/`arm`, static `-m` requires symbols, while stepping through `_start` dynamically traps `main()` via `X0`/`R0` using `_detect_callback_arg0()`.)
5. **PIE Rebasing (`resolve_target_address` & `to_display_addr`):**
   - Translates static `objdump` offsets and raw file offsets to live runtime addresses via `runtime_base`, and translates runtime addresses inside binary segments back to `objdump` offsets when `USE_OBJDUMP_ADDR = True`.

---

## 5. Unbuffered GDB/MI2 Transport & Isolated `stdin`/`stdout` (`src/mi_protocol.py`)

- **Unbuffered Binary Pipe I/O:** Runs GDB with `bufsize=0` and an explicit `bytearray` line buffer (`_read_buf`). `_readline_timeout()` drains buffered newlines before polling `select.select()`, preventing buffering deadlocks.
- **Recursive-Descent MI2 Parser (`MIParser`):** Parses GDB/MI2 async records, result tuples, lists, console streams (`~`), and target streams (`@`).
- **Isolated Target `stdin` FIFO:** Creates `/tmp/work/target_stdin` (`O_RDWR | O_NONBLOCK` on host) wired to the inferior via `-exec-arguments ... < /tmp/work/target_stdin`, keeping target input (`fgets`, `scanf`, `read(0)`) completely separate from GDB's MI2 pipe.
- **Accumulated `stdout` Retention:** Captures inferior output into both `target_output_buffer` (per-step banner) and `all_target_output` (retained across the run so `[EXITED]` views and `heap_dump.py` always display complete program output).

---

## 6. High-Speed Register, Memory & Disassembly Engine (`src/gdb_inspector.py`)

- **Indexed Register Queries:** Caches the integer indices of `CORE_REGS` (`~18` GPRs/IP/Flags) at startup, skipping 150+ AVX-512/FPU registers on every step. `get_pc()` and `get_sp()` query 1 register index; `step_instruction()` extracts `PC` directly from `*stopped["frame"]["addr"]`.
- **Cached Stack Mapping Bounds:** `get_stack_bounds()` caches `[stack]` bounds from `info proc mappings` until `SP` moves outside the cached window.
- **Intel Opcode Disassembly:** Uses MI mode `2` (`-- 2`) to fetch raw machine-code bytes alongside Intel mnemonics, anchored to function start or `e_entry` in `disassemble_context()` to preserve x86 variable-length alignment.

---

## 7. Execution Control, External Skipping, `call` & `ignore` (`src/gdb_session.py`)

- **Entry & Restart Lifecycle:** `advance_to_entry_point()` uses `starti` to map memory, resolves `runtime_base`, and runs past `ld.so` to `_start`. `stop_at_symbol("main")` falls back automatically to `resolve_entry_main_address()` on stripped `x86_64`/`i386` binaries.
- **External Skipping & Callback Traps:** When `SKIP_EXTERNAL_FUNCTIONS = True`, `.plt*` calls fast-return via `[SP]`/`LR` breakpoints, while `_detect_callback_arg0()` inspects ABI argument 0 (`RDI`/`X0`/`R0`/`[ESP+4]`) to trap `.text` callbacks (such as `main` passed to `__libc_start_main`).
- **`IgnoreCallManager`:** Supports `none`, `all` (`ignore call`), `count` (`ignore once` / `ignore call N`, decrementing only on `call` opcodes), and `nest` (`ignore nest`, allowing 1 call deeper while ignoring deeper sub-calls).
- **`call <target> [--ignore]`:** Scans forward in `.text` for the first matching `call`; refuses to hang if not visible ahead unless exact `--ignore` is passed, in which case it breaks globally against the binary's own function list.
- **`get_registers_deref()`:** Evaluates all core registers (`>= 0x1000`) and returns printable C-strings (`read_c_string()`) for pointer tracking across `--record` and `--map`.

---

## 8. Stationary Live View, Split Layout, `nestN` & Color Diffs (`src/live_view.py`, `src/colors.py`)

- **Single-Flush Flicker-Free Rendering:** Writes `\033[H` + `\033[K`-terminated lines + `\033[J` in one atomic `sys.stdout.write()`.
- **Stationary Page Cache & `nestN`:** Maintains per-frame instruction windows in `frame_pages[idx]` (refreshing only when `PC` leaves the cached window), displaying root + up to `N` deepest active call frames (`->` caller call site, `=>` active `PC`).
- **Wide-Screen Split & Exact Diffs:** Switches to side-by-side panes at `VIEW_SPLIT_MIN_COLS` (`125`), aligns using ANSI-stripped `visible_len()`, highlights exact changed register characters via `highlight_char_diff()`, highlights exact changed stack byte addresses via `format_diff_xxd_line()`, and collapses 3+ unchanged zero rows (`COLLAPSE_STACK_ZEROS_IN_VIEW`). `colors_active()` enforces `sys.stdout.isatty()`.

---

## 9. Zero-Trimmed Stack Inspection & Binary Dumping

- `dump_stack_to_file(full=False)` dumps `[SP .. stack_end]` rather than the entire `135 KB` `[stack]` mapping, and `trim_zero_stack()` strips leading/trailing 16-byte all-zero rows when `TRIM_STACK_DUMP_ZEROS = True`.

---

## 10. Session Recording Specification (`src/recorder.py`)

Outputs into `record-<binary>_<DD-MM-YYYY_HH-MM-SS>/` (`full_recording.txt` and `functions/func_*.txt`):
- Logs event sequence, 24h European timestamp, command, duration (`ms`), `+/- RECORD_DISAS_CONTEXT` disassembly, `CHANGED` registers, **`DEREF` register strings**, `STDOUT`, `FULL ACTIVE STACK` on entry/function switch/exit, and `STACK CHANGED` rows on modifying steps.
- Accumulates in memory during execution and flushes exclusively during idle prompt waits (`flush_idle()`) and `atexit`/`finally` hooks.

---

## 11. Autonomous Execution Mapping & Syscall Tracing (`src/mapper.py`)

Outputs into `<binary>-mapped_<DD-MM-YYYY_HH-MM-SS>/` (`full_trace.txt`, `syscalls_trace.txt`, `summary.txt`, `functions/`, and optional `syscall_NNNN_<name>.stack.bin` files):
1. Advances to `--func`, `main` (`-m`), or `_start` *before* enabling `catch syscall`.
2. Records instructions, all GPRs, **`DEREF` register strings**, `FULL ACTIVE STACK` on function entries, and `STACK CHANGED` rows on modifying steps.
3. Forwards `syscall-entry`/`syscall-return` events inside external `libc` calls via `on_syscall`, flushing non-returning exit syscalls (`exit_group`) cleanly.
4. Supports interactive `stdin` prompting (`prompt_for_target_stdin`) and tracks `VmHWM` peak memory and instruction classifications (`jump`, `call`, `ret`, `mem`).

---

## 12. Lifecycle Heap Dumper Architecture (`heap_dump.py`)

`heap_dump.py` uses a two-phase kernel + dynamic-symbol lifecycle strategy so secrets cannot hide in `[heap]`:

1. **Phase 1 — Pre-Input Trap (`sys_read` on `fd == 0`):**
   - Runs under `catch syscall` until kernel `read` (`syscall 0` on `x86_64`, `3` on `i386`, `63` on `aarch64`) executes with `fd == 0`.
   - Captures the `pre-stdin` `[heap]` snapshot (plus GPR C-string dereferences) before input is provided.
   - If the binary has not called `malloc` yet before `stdin`, proceeds cleanly to Phase 2.
2. **Phase 2 — Post-Input Anti-Wipe Traps (`install_post_stdin_traps`):**
   - Feeds user input (`--input`, `--no-input`, or interactive prompt) into `/tmp/work/target_stdin`.
   - Sets watch breakpoints on `libc`'s exported `.dynsym` functions (`strcmp`, `strncmp`, `memcmp`, `explicit_bzero`, `__explicit_bzero_chk`, `free`) plus `catch syscall exit_group`/`exit`—working even when the target binary itself is `sstrip`ped.
   - Whenever any of these traps fires with a return address inside the main binary (`_caller_is_main_binary()`), snapshots `[heap]` **before** `explicit_bzero` or `free` can zero/reclaim the memory, deduplicating distinct heap states across time (capped at `MAX_HEAP_SNAPSHOTS = 16` and `200` trap stops).
3. **Output Artifacts:**
   - `heap.bin`: Concatenated raw bytes of all distinct heap states observed.
   - `heap.strings.txt`: Longest-first unique printable strings tagged with discovery phase (`[pre-stdin]`, `[strcmp]`, `[pre-bzero]`, `[pre-free]`, `[pre-exit]`, or `[<phase>/reg]` for GPR dereferences such as `[strcmp/reg]` and `[pre-free/reg]`).
   - `stdout.txt`: Complete target output.

---

## 13. Dynamic Stack & Register String Extractor (`stack_strings.py`)

`stack_strings.py` unifies transient stack and register string recovery across `--record` and `--map` traces:
1. **Ingests** `full_recording.txt`, `full_trace.txt`, or any run directory.
2. **Reconstructs Raw Binary:** Decodes all stack `xxd` hex rows and appends `DEREF:` register strings into `<target>_all_stacks.bin`.
3. **Extracts & Annotates:** Pulls printable ASCII sequences (`>= --min-len`, default `4`) with exact first-seen `[EVENT/STEP @ location]` metadata (`-a`).
4. **Prefix Collapsing (`--collapse`):** Collapses progressive byte-by-byte construction loops (`crac` $\rightarrow$ `crack` $\rightarrow$ `crackme123`) into the final surviving string.

---

## 14. Safety Limits, Timeouts & Graceful Interrupts

1. **Interactive Batch Step Cap (`MAX_INTERACTIVE_STEPS = 100_000`):** Bounds single `step <N>` / `next <N>` invocations.
2. **Mapper Instruction Cap (`MAX_MAP_INSTRUCTIONS = 2_000_000`):** Halts runaway/infinite loops cleanly during `--map` and writes `summary.txt`.
3. **Mapper Disk Size Cap (`MAX_MAP_FOLDER_MB = 250`):** `FolderSizeGuard` caps total `--map` directory output at 250 MB (`Truncated By Size Cap : YES`).
4. **Heap Snapshot Cap (`MAX_HEAP_SNAPSHOTS = 16`):** Bounds post-input heap snapshots in `heap_dump.py` (with `200` max trap stops).
5. **Non-Interactive Wait Timeout (`30.0` seconds) & Command Timeout (`GDB_CMD_TIMEOUT_S = 15.0`):** When `stdin_prompt_handler` is `None` (automated waits or `heap_dump.py --input` if a target loops onto another blocking read), `wait_stopped(timeout=30.0)` returns `None` after 30s so `heap_dump.py` can release/close cleanly via `finally: session.close()`.
6. **Graceful `Ctrl+C` Behavior:**
   - `--map`: Pauses execution, flushes pending syscalls, and writes `summary.txt` with `Interrupted By User : YES`.
   - `--record`: Flushes all buffered events and writes `=== RECORDING CLOSED AT ... ===`.
   - Interactive CLI / `view`: Cancels proactive stdin prompts or sends `-exec-interrupt` to pause running targets.
   - `heap_dump.py`: Cleans up and closes the Bubblewrap sandbox via `finally: session.close()`.

---

## 15. Bubblewrap Sandbox & Cross-Architecture QEMU Design (`src/sandbox.py`)

```text
Host Filesystem                       Bubblewrap Sandbox (/tmp/work)
┌────────────────────────┐            ┌──────────────────────────────────────┐
│ /home/<user>/...       │ ──[NONE]──►│ Completely hidden & unmounted        │
│ Host Network Stack     │ ──[NONE]──►│ --unshare-all (no internet sockets)  │
│ /usr, /bin, /lib*      │ ──[RO]────►│ Read-only system runtime & QEMU bins │
│ Sanitized Target & FIFO│ ──[RW]────►│ /tmp/work/target_bin & target_stdin  │
└────────────────────────┘            └──────────────────────────────────────┘
```

- **Native Targets:** `bwrap --unshare-all --cap-drop ALL --new-session --die-with-parent --clearenv` spawns `gdb --interpreter=mi2` directly inside the sandbox.
- **Cross-Arch Targets:** When `needs_qemu(host_arch, elf.arch)` is `True`, launches `qemu-<arch> -g <port>` alongside `gdb-multiarch` inside the sandbox.
- **`--no-sandbox` Gate:** Requires a 3-step confirmation (two explicit yes/no prompts followed by matching `"iknow"`, case- and whitespace-insensitive, when prompted for `"I know"`) before executing directly on the host.

---

## 16. Configuration Reference (`src/config.py`)

| Constant | Default | Purpose |
|----------|---------|---------|
| `DEFAULT_INFO_FORMAT` | `"hex"` | Default format for CLI `info`/`show` (`"hex"`, `"dec"`, `"char"`, `"str"`, `"all"`). |
| `ENABLE_COLORS` | `True` | Enable TTY-only green diff highlights via optional `colorama`. |
| `PROMPT_SHOW_ADDRESS` | `True` | Display current `objdump`-style `PC` in prompts. |
| `PROMPT_SHOW_FUNCTION` | `True` | Display current function name in prompts. |
| `PROMPT_SHOW_TOOL_NAME` | `False` | Prefix prompt with `PROMPT_TOOL_NAME`. |
| `PROMPT_TOOL_NAME` | `"bdf"` | Fallback/prefix tool label in prompts. |
| `USE_OBJDUMP_ADDR` | `True` | Rebase PIE addresses inside the binary to `objdump` offsets. |
| `SHOW_OPCODES_IN_DISAS` | `True` | Show raw hex opcodes alongside Intel assembly. |
| `VIEW_PAGE_SIZE` | `41` | Default instruction window size in `view`. |
| `VIEW_DEFAULT_REGS` | `True` | Show `[REGISTERS]` panel by default when opening `view`. |
| `VIEW_DEFAULT_STACK` | `True` | Show `[STACK]` panel by default when opening `view`. |
| `VIEW_DEFAULT_REG_FORMAT` | `"all"` | Default register display format inside `view`. |
| `VIEW_DEFAULT_NEST` | `0` | Default nested call pane count (`0` = active function only). |
| `VIEW_HIGHLIGHT_CHANGES` | `True` | Mark changed registers & stack bytes with `*` and green diffs. |
| `VIEW_SPLIT_MIN_COLS` | `125` | Terminal column threshold for side-by-side split layout. |
| `VIEW_STACK_ROWS` | `14` | Fallback stack rows on narrow terminals. |
| `COLLAPSE_STACK_ZEROS_IN_VIEW` | `True` | Collapse runs of 3+ unchanged zero stack lines in `view`. |
| `RECORD_DISAS_CONTEXT` | `4` | Instructions recorded before & after `PC` per `--record` event. |
| `SKIP_EXTERNAL_FUNCTIONS` | `True` | Auto-skip `.plt` stubs, `ld.so`, and `libc` internals during `step`. |
| `TRIM_STACK_DUMP_ZEROS` | `True` | Trim leading/trailing pure-zero rows in `dump stack`. |
| `MAX_MAP_FOLDER_MB` | `250` | Maximum output size (MB) for `--map` folders. |
| `MAX_MAP_INSTRUCTIONS` | `2_000_000` | Safety instruction cap for `--map` against infinite loops. |
| `MAX_INTERACTIVE_STEPS` | `100_000` | Maximum step/next count per single interactive command. |
| `STACK_PREVIEW_LINES` | `16` | Stack preview line count for `stack` / `info stack`. |
| `FALLBACK_STACK_DOWN_BYTES` | `4096` | Fallback stack read window below `SP` if `/proc` mapping is unavailable. |
| `FALLBACK_STACK_UP_BYTES` | `65536` | Fallback stack read window above `SP` if `/proc` mapping is unavailable. |
| `GDB_CMD_TIMEOUT_S` | `15.0` | Timeout (seconds) for individual GDB/MI commands. |
| `SANDBOX_SELFTEST_TIMEOUT_S` | `5.0` | Timeout (seconds) for Bubblewrap startup self-test. |
| `EU_FOLDER_TS_FORMAT` | `"%d-%m-%Y_%H-%M-%S"` | European 24-hour folder timestamp format. |
| `EU_LOG_TS_FORMAT` | `"%d-%m-%Y %H:%M:%S"` | European 24-hour log timestamp format. |
