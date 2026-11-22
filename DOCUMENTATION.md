# bin-debug-friendly — Technical Documentation & Architecture Specification

> **Scope:** Complete internal design, module breakdown, unbuffered GDB/MI2 protocol engine, pure-Python ELF32/ELF64 & PIE address resolver, external-library skipping mechanics, stationary live-view renderer, execution mapper, and Bubblewrap sandbox isolation.

---

## Table of Contents
1. [Architectural Overview & Module Map](#1-architectural-overview--module-map)
2. [Pure-Python ELF Parser & Exact Address Resolution](#2-pure-python-elf-parser--exact-address-resolution)
3. [Unbuffered GDB/MI2 Protocol Engine (`src/mi_protocol.py`)](#3-unbuffered-gdbmi2-protocol-engine-srcmi_protocolpy)
4. [High-Speed Register, Memory & Disassembly Inspection (`src/gdb_inspector.py`)](#4-high-speed-register-memory--disassembly-inspection-srcgdb_inspectorspy)
5. [Execution Control, PLT Skipping & Callback Trapping (`src/gdb_session.py`)](#5-execution-control-plt-skipping--callback-trapping-srcgdb_sessionpy)
6. [Stationary Live View, Split Layout & Call Nesting (`src/live_view.py`)](#6-stationary-live-view-split-layout--call-nesting-srclive_viewpy)
7. [Zero-Trimmed Stack Inspection & Binary Dumping](#7-zero-trimmed-stack-inspection--binary-dumping)
8. [Execution Mapping & Syscall Tracing (`src/mapper.py`)](#8-execution-mapping--syscall-tracing-srcmapperpy)
9. [Bubblewrap Sandboxing & QEMU Cross-Arch Architecture (`src/sandbox.py`)](#9-bubblewrap-sandboxing--qemu-cross-arch-architecture-srcsandboxpy)
10. [Engineering Post-Mortem: Bugs Solved & Performance Optimizations](#10-engineering-post-mortem-bugs-solved--performance-optimizations)

---

## 1. Architectural Overview & Module Map

```text
                        ┌───────────────────────────────┐
                        │            main.py            │
                        │  CLI Flags (-m, -map, -func)  │
                        └───────────────┬───────────────┘
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼                                             ▼
┌─────────────────────────────────┐           ┌─────────────────────────────────┐
│     Interactive Frontend        │           │     Execution Mapper Mode       │
│  • src/cli.py (REPL & ls/dump)  │           │  • src/mapper.py                │
│  • src/live_view.py (TUI/nestN) │           │    - Instruction & Reg Trace    │
│  • src/formatters.py (Intel/hex)│           │    - Syscall Catch & Stats      │
└────────────────┬────────────────┘           │    - 250 MB Size Guard          │
                 │                            └────────────────┬────────────────┘
                 └──────────────────────┬──────────────────────┘
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         GDB Session Layer (3 Modules)                        │
│  • src/gdb_session.py   — Breakpoints, PIE/PLT skip, callback traps, jump   │
│  • src/gdb_inspector.py — Indexed GPRs, .text disas, call frames, stack dump│
│  • src/mi_protocol.py   — Unbuffered binary pipe I/O + MI2 recursive parser  │
└────────────────┬─────────────────────────────────────┬───────────────────────┘
                 ▼                                     ▼
┌─────────────────────────────────┐   ┌────────────────────────────────────────┐
│       src/elf_utils.py          │   │           src/sandbox.py               │
│  • ELF32/ELF64 Header & PT_LOAD │   │  • Bubblewrap (--unshare-all)          │
│  • .text & .plt* Section Bounds │   │  • QEMU user-mode (-g <port>) + GDB    │
│  • Flexible Hex & PIE Resolver  │   │  • Multi-step --no-sandbox Gate        │
└─────────────────────────────────┘   └────────────────────────────────────────┘
```

### Source Files Summary
| File | Responsibility |
| :--- | :--- |
| `main.py` | Argument parsing, ELF verification, sandbox confirmation, mode dispatch (`_start` vs `-m` vs `--map`). |
| `src/config.py` | Centralized user configuration (formats, prompt flags, `VIEW_PAGE_SIZE`, `SKIP_EXTERNAL_FUNCTIONS`, `MAX_MAP_FOLDER_MB`). |
| `src/elf_utils.py` | Pure-Python ELF32/ELF64 parser, section extractor (`.text`, `.plt*`), flexible address parser, PIE rebase logic. |
| `src/sandbox.py` | Host/target architecture detection, `bwrap` command builder, startup self-test, `--no-sandbox` multi-step gate. |
| `src/mi_protocol.py` | Recursive-descent GDB/MI2 parser, `select()` + `os.read()` unbuffered pipe I/O, raw target stdout splitting. |
| `src/gdb_inspector.py` | Fast indexed register queries, memory/C-string reading, Intel opcode disassembly, `ls` context, stack bounds & zero trimming. |
| `src/gdb_session.py` | Process start/restart, PIE runtime base discovery, `goto_address`, `jump_to_target`, `skip_function`, PLT/external skipping. |
| `src/formatters.py` | Aligned register formatting, `xxd`-style stack formatter, prompt builder, `objdump`-style disassembly lines. |
| `src/live_view.py` | Stationary ANSI live view, dynamic `nestN` caller/callee windows, wide-screen split columns, `*` change highlights. |
| `src/cli.py` | Interactive REPL (`ls`, `0x...`, `jump`, `step/next N dump`, `info stack`, `stack less`, `dump stack`, `maps`). |
| `src/mapper.py` | Non-interactive execution tracer producing European-dated folders (`full_trace.txt`, `syscalls_trace.txt`, `summary.txt`, `functions/`). |

---

## 2. Pure-Python ELF Parser & Exact Address Resolution

### Header, Segment & Section Extraction (`src/elf_utils.py`)
`parse_elf()` parses raw bytes directly with `struct.unpack` (no `readelf` or `objdump` subprocess calls):
1. Validates `\x7fELF`, extracts `EI_CLASS` (32/64-bit) and `EI_DATA` (`<` little / `>` big endian).
2. Identifies `e_machine` (`x86_64`, `i386`, `aarch64`, `arm`) and `e_type` (`ET_EXEC` = fixed address, `ET_DYN` = PIE).
3. Parses all `PT_LOAD` program headers (`LoadSegment`) to compute `base_vaddr` and file-offset-to-vaddr mappings.
4. Parses `.shstrtab` and all section headers to extract exact runtime-rebasable bounds for:
   - **`.text`** (`text_range`): ensures `ls` and `disas` stop at the true end of code instead of disassembling trailing page `0x00` padding as `add BYTE PTR [rax], al`.
   - **`.plt*`** (`.plt`, `.plt.sec`, `.plt.got`): distinguishes external dynamic-linker trampolines inside the binary from actual user `.text` code.

### Flexible Address Parsing & PIE Rebasing
`parse_address_input()` strips surrounding quotes and all internal/external whitespace, accepting `0x1149`, `1149`, `" 0x 40 11 49 "`, and `0X1149` identically.

When debugging a PIE binary (`ET_DYN`):
1. `ensure_started_paused()` executes `starti`, at which point the Linux kernel has already mapped both `ld.so` and the main executable into virtual memory.
2. `_discover_mappings()` inspects `info proc mappings` (falling back to `info auxv` `AT_PHDR - e_phoff` or `AT_ENTRY - e_entry` when under QEMU user-mode) to obtain the exact `runtime_base` (e.g., `0x555555554000`).
3. `resolve_target_address()` converts any user address:
   - Already in runtime range (`>= runtime_base`) $\rightarrow$ used directly.
   - An ELF virtual address (`elf.contains_vaddr(addr)`) $\rightarrow$ `runtime_base + (addr - elf.base_vaddr)`.
   - A raw file offset (`elf.file_offset_to_vaddr(addr)`) $\rightarrow$ `runtime_base + (vaddr - elf.base_vaddr)`.
4. `to_display_addr()` and `rebase_disas_text()` perform the inverse conversion when `USE_OBJDUMP_ADDR = True`, displaying `0x1149` and `# 0x2004` / `call 0x1030 <puts@plt>` exactly like `objdump`.

---

## 3. Unbuffered GDB/MI2 Protocol Engine (`src/mi_protocol.py`)

### Why Unbuffered Binary Pipes (`bufsize=0`)?
Python's `TextIOWrapper` (`text=True, bufsize=1`) reads ahead into an internal user-space buffer. Calling `select.select([fd])` before `readline()` deadlocks whenever `(gdb) ` is already buffered inside `TextIOWrapper` while the kernel pipe is empty.

`MIProtocol` avoids this permanently:
* Spawns GDB with `bufsize=0` (raw unbuffered `FileIO`).
* Maintains an explicit `self._read_buf = bytearray()`.
* `_readline_timeout()` checks `self._read_buf.find(b"\n")` **first**, and only calls `select.select([fd])` + `os.read(fd, 4096)` when no complete line is buffered.

### Capturing Target Stdout Without a PTY
When GDB runs without a dedicated PTY (`--tty`), the target writes directly to the shared stdout pipe as raw lines rather than `@"..."` MI async packets. `parse_mi_lines()` captures all `raw` lines into `target_output_buffer` and uses `MI_EMBEDDED_RE` to cleanly split target output that lacks a trailing `\n` when followed immediately by `*stopped`, `^done`, or `=thread-*`.

---

## 4. High-Speed Register, Memory & Disassembly Inspection (`src/gdb_inspector.py`)

### Indexed Register Queries (Avoiding 150-Register AVX-512 Overhead)
On modern x86-64 CPUs, `-data-list-register-values x` dumps 150+ registers (`zmm0..zmm31`, `ymm`, `xmm`, `st0..st7`, `mxcsr`) totaling ~10 KB per call.

During `_load_register_names()`:
* `GdbInspectorMixin` maps the 18 core architecture registers (`CORE_REGS`) to their integer GDB register indices (`core_reg_query = "0 1 2 ... 17"`), plus `pc_reg_idx` and `sp_reg_idx`.
* `get_registers()` queries **only those 18 indices**.
* `get_pc()` and `get_sp()` query **only 1 register index** (and `step_instruction()` extracts `PC` directly from `*stopped["frame"]["addr"]` at **0 extra GDB calls**).

### Disassembly & `ls` Synchronization
`disassemble_range()` requests MI mode `2` (`-- 2`) to fetch raw hex `opcodes` alongside Intel `inst` mnemonics.  
For `ls [N]` / `lsN`, `disassemble_context()` anchors at the current function's start address (or `_start` if near entry) before slicing `[pc_idx - before : pc_idx + after + 1]` within `.text` bounds, avoiding x86 variable-length byte desynchronization and preventing trailing zero-page disassembly.

---

## 5. Execution Control, PLT Skipping & Callback Trapping (`src/gdb_session.py`)

### Startup Entry vs `-m` / `--main`
* **Default:** `advance_to_entry_point()` stops at `starti`, computes `runtime_entry = runtime_base + (e_entry - base_vaddr)`, and skips `ld.so` initialization straight to `_start`.
* **`-m` / `--main`:** Checks `has_symbol("main")`. If missing (e.g., stripped binary), aborts cleanly without starting; otherwise sets a temporary breakpoint at `main` and runs there.

### External Library & `.plt` Skipping + Callback Trapping
When `SKIP_EXTERNAL_FUNCTIONS = True`:
1. **`next [N]`:** Batches `N > 1` natively via a single `-interpreter-exec console "ni {count}"` command.
2. **`step [N]`:** If `PC` enters a `.plt*` stub (`addr_in_plt(pc) == True`) or external shared library (`addr_in_main_binary(pc) == False`):
   - **Callback Trap:** `_detect_callback_arg0()` inspects the first ABI argument (`RDI` on x86-64, `X0` on AArch64, `R0` on ARM32, `[ESP+4]` on i386). If it points inside `.text` (e.g., `main` passed from `_start` into `__libc_start_main`, or a callback passed to `qsort`), a one-shot temporary breakpoint is placed at that `.text` target so `step` lands inside `main()` instead of exiting!
   - **Fast PLT Return:** For standard external calls like `printf@plt` / `puts@plt`, reads the return address directly from `[SP]` (or `LR` on ARM), sets a one-shot temporary breakpoint there, and continues straight back to the caller instruction.
   - **Fallback:** Executes `-exec-finish` (looping cleanly past any `syscall-entry`/`syscall-return` events if active).

### Restartability & Direct Control
- `restart_to_entry()` resets `started`, `exited`, `exit_code`, and cached stack bounds cleanly so `start`, `main`, `run` (after exit), and `0x...` all work seamlessly even after program termination.
- `jump_to_target()` resolves any hex address or symbol and updates `$pc` directly via `-gdb-set $pc = 0x...`.

---

## 6. Stationary Live View, Split Layout & Call Nesting (`src/live_view.py`)

### Stationary Page Caching
Each visible call frame maintains its own cached instruction list (`frame_pages[idx]`). A page is only re-fetched when:
1. `force_refresh` is `True` (user changed `size N`, `nestN`, `main`, `start`, `jump`, or `0x...`), or
2. `PC` steps or jumps outside the cached page (`not any(a == pc for a, _, _ in cached)`).

When `PC` walks within the page, ANSI `\033[2J\033[H` redraws the exact same instructions in place and moves only the `=>` arrow.

### Nested Call Windows (`nest` / `nestN`)
`get_binary_call_frames()` parses `-stack-list-frames`, filters out intermediate external library frames (`libc`/`ld.so`), and reverses them into `outermost -> innermost` order.
* `nest0` (default): shows only the active innermost frame.
* `nest` / `nest1` .. `nestN`: keeps the root frame (`frames[0]`) plus up to `N` deepest nested frames (`frames[1:][-N:]`).
* Parent frames mark their call instruction with `->`; the active innermost frame marks `PC` with `=>`. Returned frames are evicted automatically.

### Wide-Screen Layout & Change Highlighting
* Queries `shutil.get_terminal_size()`. When `term_cols >= VIEW_SPLIT_MIN_COLS` (`125`), `render_two_columns()` places Code (+ Registers if Stack is also active) on the left pane and Stack/Registers on the right pane separated by `|`.
* Compares `regs` against `prev_regs` and 16-byte stack rows against `prev_stack_map`, prefixing changed entries with `*`.

---

## 7. Zero-Trimmed Stack Inspection & Binary Dumping

Linux allocates a ~135 KB `[stack]` VMA where low addresses below `SP` are unallocated zero pages.
1. `get_stack_bounds()` caches `[stack]` `(start, end)` from `info proc mappings` (re-querying only if `SP` leaves the cached range).
2. `dump_stack_to_file(full=False)` dumps `[SP .. stack_end]` instead of `[stack_start .. stack_end]`, then `trim_zero_stack()` removes leading and trailing 16-byte all-zero rows (`TRIM_STACK_DUMP_ZEROS = True`) so `xxd <binary>.stack.bin` shows only active stack data.
3. Passing `dump stack full` bypasses trimming and dumps the entire `[stack]` mapping.

---

## 8. Execution Mapping & Syscall Tracing (`src/mapper.py`)

1. Advances to `--func <addr>` (if specified) or `_start` *before* enabling `catch syscall` (preventing `ld.so` startup syscalls from interrupting initial breakpoint arrival).
2. Tracks call depth (`func_depth`) on `call`/`bl` and `ret`/`bx lr` instructions when `--func` is active, automatically stopping once the traced function returns.
3. Skips external library execution automatically via `step_over_or_finish_external()`.
4. Classifies every instruction (`jump`, `call`, `ret`, `mem`) and samples `VmHWM` peak memory from `info proc status`.
5. Enforces `MAX_MAP_FOLDER_MB` (`250` MB) via `FolderSizeGuard` across `full_trace.txt`, `syscalls_trace.txt`, and `functions/func_0x*.txt`, finalizing `summary.txt` cleanly with European 24-hour timestamps (`DD-MM-YYYY HH:MM:SS`).

---

## 9. Bubblewrap Sandboxing & QEMU Cross-Arch Architecture (`src/sandbox.py`)

```text
Host Filesystem                       Bubblewrap Sandbox (/tmp/work)
┌────────────────────────┐            ┌──────────────────────────────────────┐
│ /home/<user>/...       │ ──[NONE]──►│ Completely hidden & unmounted        │
│ Host Network Stack     │ ──[NONE]──►│ --unshare-all (no internet sockets)  │
│ /usr, /bin, /lib*      │ ──[RO]────►│ Read-only system runtime & QEMU bins │
│ Target Binary Copy     │ ──[RW]────►│ /tmp/work/target_bin                 │
└────────────────────────┘            └──────────────────────────────────────┘
```

* **Native Execution:** `bwrap` runs `gdb --interpreter=mi2 -q /tmp/work/target_bin` directly inside the sandbox (`gdb` is parent of `target_bin`, so `ptrace` works even under `yama.ptrace_scope=1` and `--cap-drop ALL`).
* **Cross-Architecture Emulation:** When `needs_qemu(host_arch, target_arch)` is `True`, a sandboxed wrapper script launches `qemu-<arch> -g <ephemeral_port> /tmp/work/target_bin` in the background and connects `gdb-multiarch` via `-target-select remote 127.0.0.1:<port>`.
* **`--no-sandbox` Gate:** Requires two explicit confirmations followed by matching `"iknow"` (whitespace- and case-insensitive) in the final prompt.

---

## 10. Engineering Post-Mortem: Bugs Solved & Performance Optimizations

| # | Issue Discovered | Root Cause | Permanent Fix |
| :--- | :--- | :--- | :--- |
| **1** | `select.select()` deadlock on GDB startup | Python `TextIOWrapper` (`bufsize=1`) buffered `(gdb) ` in user space while `select` blocked on an empty kernel FD. | Switched to unbuffered `bufsize=0` binary pipe + `bytearray` line buffer (`_readline_timeout`). |
| **2** | `--map -func` hung in `ld.so` | `catch syscall` was enabled before `run_or_continue()` reached `--func`, stopping inside `ld.so` startup syscalls. | Enabled `catch syscall` only *after* hitting `--func` or `_start`. |
| **3** | `result=25` / target stdout missing | Without a PTY, GDB emits inferior stdout as `raw` lines rather than `@"..."` MI records. | Captured `raw` lines in `MIProtocol` and split glued MI records via `MI_EMBEDDED_RE`. |
| **4** | `step` walked through `puts@plt` | `.plt*` sections reside inside the main binary's executable `PT_LOAD` segment. | Parsed ELF section headers for `.plt*` and added fast `[SP]`/`LR` return-address trapping. |
| **5** | `step` through `_start` exited without entering `main` | `_start` passes `main` in `RDI` to `__libc_start_main`; `-exec-finish` ran past `main` to exit. | Added `_detect_callback_arg0()` to trap `.text` callbacks passed to external calls. |
| **6** | `ls 21` disassembled trailing `0x00` bytes | Execution bounds clamped to 4 KB `PT_LOAD` page end instead of `.text` section size. | Parsed `.text` (`sh_addr`, `sh_size`) in `elf_utils.py` and clamped disassembly bounds. |
| **7** | Previous lines vanished on every step in `view` | `len(page_insns) != page_size` re-anchored the page top to `PC` near the end of `.text`. | Replaced with `should_refresh_page()` using explicit `force_refresh` and `pc not in page`. |
| **8** | `step 9` took ~6–8 seconds | Unindexed `-data-list-register-values x` serialized 150+ AVX-512/FPU registers multiple times per step + repeated `info proc mappings`. | Indexed only the 18 core registers, used `*stopped` frame addresses for `PC`, cached `[stack]` bounds, and batched `next N` via `ni N`. |
