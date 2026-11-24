# `bin-debug-friendly` — Technical Documentation & Design Specification

> **Document Scope:** Complete architectural specification, design rationale, module-by-module internals, pure-Python ELF32/ELF64 & PIE address resolution, GDB/MI2 pipe & FIFO isolation, indexed register caching, external call skipping & `IgnoreCallManager`, stationary ANSI live-view rendering, session recording format, autonomous execution mapping, dynamic stack string extraction, safety limits & timeouts, and Bubblewrap/QEMU sandboxing.

---

## Table of Contents

1. [Design Philosophy: Why `bin-debug-friendly` Exists](#1-design-philosophy-why-bin-debug-friendly-exists)
2. [System Architecture & Module Dependency Graph](#2-system-architecture--module-dependency-graph)
3. [Module-by-Module Technical Reference](#3-module-by-module-technical-reference)
4. [Pure-Python ELF32/ELF64 Parser & PIE Address Translation (`src/elf_utils.py`)](#4-pure-python-elf32elf64-parser--pie-address-translation-srcelf_utilspy)
5. [Unbuffered GDB/MI2 Transport & Isolated `stdin`/`stdout` (`src/mi_protocol.py`)](#5-unbuffered-gdbmi2-transport--isolated-stdinstdout-srcmi_protocolpy)
6. [High-Speed Register, Memory & Disassembly Engine (`src/gdb_inspector.py`)](#6-high-speed-register-memory--disassembly-engine-srcgdb_inspectorpy)
7. [Execution Control, External Skipping, `call` & `ignore` (`src/gdb_session.py`)](#7-execution-control-external-skipping-call--ignore-srcgdb_sessionpy)
8. [Stationary Live View, Split Layout, `nestN` & Color Diffs (`src/live_view.py`, `src/colors.py`)](#8-stationary-live-view-split-layout-nestn--color-diffs-srclive_viewpy-srccolorspy)
9. [Zero-Trimmed Stack Inspection & Binary Dumping](#9-zero-trimmed-stack-inspection--binary-dumping)
10. [Session Recording Specification (`src/recorder.py`)](#10-session-recording-specification-srcrecorderpy)
11. [Autonomous Execution Mapping & Syscall Tracing (`src/mapper.py`)](#11-autonomous-execution-mapping--syscall-tracing-srcmapperpy)
12. [Dynamic Stack-String Extractor (`stack_strings.py`)](#12-dynamic-stack-string-extractor-stack_stringspy)
13. [Safety Limits, Timeouts & Graceful Interrupts](#13-safety-limits-timeouts--graceful-interrupts)
14. [Bubblewrap Sandbox & Cross-Architecture QEMU Design (`src/sandbox.py`)](#14-bubblewrap-sandbox--cross-architecture-qemu-design-srcsandboxpy)
15. [Configuration Reference (`src/config.py`)](#15-configuration-reference-srcconfigpy)

---

## 1. Design Philosophy: Why `bin-debug-friendly` Exists

Raw GDB is built for source-level C/C++ debugging with full DWARF symbols. When reverse-engineering stripped binaries, crackmes, or compiled C/Rust targets without source code, standard GDB introduces constant friction:

1. **Address Disconnect:** Disassemblers (`objdump`, `binpatch`, `readelf`) show static offsets (`0x1149`) or fixed VMAs (`0x401149`), whereas PIE binaries relocate at runtime (`0x555555555149`). Translating between static offsets and live runtime addresses should be automatic, never manual.
2. **Loader & Shared Library Noise:** Single-stepping through `_start` or `call printf@plt` normally pulls the analyst into `ld-linux.so`, GOT/PLT resolution trampolines, and `libc` internals—while still needing to stop cleanly at `main()` or user callbacks invoked from `libc`.
3. **Scroll Blindness:** Traditional CLI debuggers scroll past previous disassembly, register values, and stack bytes on every step, hiding *what changed* between instruction $i$ and instruction $i+1$.
4. **Unsafe Execution:** Running untrusted or unknown ELF binaries directly on a developer workstation exposes `/home`, SSH keys, and the network stack. Debugging should be air-gapped inside Linux namespaces by default.
5. **Transient Secret Loss:** Many binaries unpack, decrypt, or XOR-construct strings only on the stack in temporary memory. Static `strings` cannot find them. Tracking stack changes across time and extracting them automatically turns transient memory secrets into permanent artifacts.

`bin-debug-friendly` achieves all of this using **Python 3 standard library modules only** (zero mandatory `pip` packages), GNU `gdb --interpreter=mi2`, `bubblewrap`, and optional `qemu-user` / `colorama`.

---

## 2. System Architecture & Module Dependency Graph

```text
                        ┌─────────────────────────────────┐
                        │             main.py             │
                        │ CLI Entry (-m, -record, -map)   │
                        └────────────────┬────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
┌─────────────────────────────────┐             ┌─────────────────────────────────┐
│     Interactive Frontend        │             │     Execution Mapper Mode       │
│  • src/cli.py (REPL, ls, dump)  │             │  • src/mapper.py                │
│  • src/live_view.py (TUI/nestN) │             │    - Instruction & Reg Trace    │
│  • src/formatters.py (Intel/hex)│             │    - Active Stack Snapshots &   │
│  • src/colors.py (TTY green)    │             │      Stack Diff Logging         │
│  • src/recorder.py (--record)   │             │    - Syscall Catch & Stats      │
└────────────────┬────────────────┘             │    - 250 MB Size Guard          │
                 │                              └────────────────┬────────────────┘
                 └───────────────────────┬───────────────────────┘
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          GDB Session Layer (3 Modules)                          │
│  • src/gdb_session.py   — Breakpoints, PIE/PLT skip, IgnoreCallMgr, call <fn>   │
│  • src/gdb_inspector.py — Indexed GPRs, .text disas, call frames, stack dumps   │
│  • src/mi_protocol.py   — Unbuffered binary pipe I/O, FIFO stdin, MI2 parser    │
└────────────────┬───────────────────────────────────────┬────────────────────────┘
                 ▼                                       ▼
┌─────────────────────────────────┐     ┌─────────────────────────────────────────┐
│       src/elf_utils.py          │     │            src/sandbox.py               │
│  • ELF32/ELF64 Header & PT_LOAD │     │  • Bubblewrap (--unshare-all)           │
│  • .text, .plt*, .symtab Bounds │     │  • QEMU user-mode (-g <port>) + GDB     │
│  • Flexible Hex & PIE Resolver  │     │  • Multi-step --no-sandbox Gate         │
└─────────────────────────────────┘     └─────────────────────────────────────────┘
```

---

## 3. Module-by-Module Technical Reference

| Module | Primary Role | Key Exports |
|--------|--------------|-------------|
| `main.py` | CLI entry point, ELF validation, `--no-sandbox` gate, session/recorder lifecycle, `--map` / `-m` dispatch. | `build_parser()`, `main()` |
| `src/config.py` | Central configuration constants for register formats, prompt components, live view defaults, record context, external call skipping, stack trimming, and mapper caps. | `VIEW_PAGE_SIZE`, `MAX_MAP_FOLDER_MB`, etc. |
| `src/elf_utils.py` | Zero-dependency ELF32/ELF64 binary & symbol parser and address translator. | `ElfInfo`, `parse_elf()`, `parse_address_input()`, `resolve_target_address()` |
| `src/sandbox.py` | Architecture matching, `bwrap` container builder, QEMU detection, host confirmation. | `SandboxEnv`, `confirm_disable_sandbox()`, `detect_host_arch()`, `needs_qemu()` |
| `src/mi_protocol.py` | Raw `bufsize=0` GDB/MI2 pipe driver, recursive MI2 parser, target `stdin` FIFO, accumulated `stdout` storage. | `MIProtocol`, `MIParser`, `parse_mi_lines()` |
| `src/gdb_inspector.py` | Fast indexed register queries, memory/C-string inspection, Intel opcode disassembly, `ls` context slicing, binary-only function listing, and zero-trimmed stack dumps. | `GdbInspectorMixin`, `trim_zero_stack()`, `CORE_REGS` |
| `src/gdb_session.py` | Process lifecycle (`_start` vs `main`), PIE runtime base discovery, `goto_address`, `jump_to_target`, `run_to_next_call`, `IgnoreCallManager`, proactive/stalled `stdin` prompting, and `.plt`/external skipping. | `GdbSession`, `IgnoreCallManager` |
| `src/formatters.py` | Character-level register diff formatting, `xxd`-style stack lines, `readline` Tab autocompleter, prompt builder, `ignore` command parser, and complete `help` reference. | `format_reg_line()`, `setup_readline_completer()`, `handle_ignore_command()`, `print_help()` |
| `src/colors.py` | Optional `colorama` wrapper constrained strictly to interactive TTYs (`sys.stdout.isatty()`), providing ANSI-aware width alignment (`visible_len`) and byte-level `xxd` diffs. | `colors_active()`, `highlight_char_diff()`, `format_diff_xxd_line()`, `visible_len()` |
| `src/live_view.py` | Flicker-free single-flush ANSI dashboard with wide-screen split layout, `max`/`min`/`only`/`raw stack` modes, zero-collapsed active stack, live format toggles, and `nestN` caller/callee panes. | `run_live_view()`, `parse_view_options()`, `select_visible_frames()` |
| `src/cli.py` | Interactive command REPL supporting all navigation, stepping, batch-dumping, inspection, stack, and recording hooks. | `run_interactive_cli()`, `handle_ls_command()`, `handle_step_with_dump()` |
| `src/recorder.py` | Idle-flushed session recorder writing `record-<bin>_<date>/full_recording.txt` and `functions/func_*.txt` strictly during idle prompt waits. | `SessionRecorder` |
| `src/mapper.py` | Autonomous execution mapper generating `<bin>-mapped_<date>/` with instruction traces, active stack snapshots & diffs, syscall logs, and aggregate statistics under a hard `250 MB` limit. | `run_execution_mapper()`, `classify_instruction()`, `FolderSizeGuard` |
| `stack_strings.py` | Standalone CLI extractor reconstructing concatenated stack binaries and extracting unique runtime strings across time. | `parse_stack_snapshots()`, `extract_ascii_strings()`, `filter_redundant_prefixes()` |

---

## 4. Pure-Python ELF32/ELF64 Parser & PIE Address Translation (`src/elf_utils.py`)

`parse_elf()` parses binary headers directly via `struct.unpack` without spawning `readelf` or `objdump`:

1. **Header & Architecture Detection:**
   - Verifies `\x7fELF`, reads `EI_CLASS` (`ELFCLASS32` / `ELFCLASS64`), `EI_DATA` (`<` little-endian / `>` big-endian), `e_machine` (`EM_X86_64`, `EM_386`, `EM_AARCH64`, `EM_ARM`), and `e_type` (`ET_EXEC` vs `ET_DYN`).
2. **Segment Mapping (`PT_LOAD`):**
   - Stores all `LoadSegment` entries (`vaddr`, `memsz`, `offset`, `filesz`, `flags`) and computes `base_vaddr = min(seg.vaddr)`.
   - Provides `contains_vaddr()` and `file_offset_to_vaddr()` so raw file offsets copied from `xxd` or a hex editor map directly to their virtual address.
3. **Section Extraction (`.text`, `.plt*`, `.symtab`):**
   - **`.text` (`text_range`):** Clamps `ls` and `disas` forward disassembly to the actual end of executable code, avoiding trailing page `0x00` padding.
   - **`.plt*` (`plt_ranges`):** Identifies `.plt`, `.plt.sec`, and `.plt.got` stubs inside the executable so stepping treats them as external library trampolines rather than user code.
   - **`.symtab` / `.strtab` (`functions`):** Extracts `STT_FUNC` symbols belonging strictly to the target binary (`user_fns` sorted first, internal `_` symbols second), keeping `Tab` autocompletion fast and free of `libc` symbols.
4. **PIE Runtime Rebasing (`resolve_target_address`):**
   - If `elf.is_pie` is `True`:
     - Addresses `>= runtime_base` inside mapped segments are used directly as live runtime addresses.
     - Addresses inside `elf.segments` (`objdump` offsets) resolve to `runtime_base + (addr - elf.base_vaddr)`.
     - Raw file offsets resolve via `file_offset_to_vaddr(addr)` then rebase from `runtime_base`.
   - When displaying addresses (`to_display_addr` and `rebase_disas_text`), live addresses inside the binary convert back to `objdump`-style offsets whenever `USE_OBJDUMP_ADDR = True`.

---

## 5. Unbuffered GDB/MI2 Transport & Isolated `stdin`/`stdout` (`src/mi_protocol.py`)

### Unbuffered Binary Pipe I/O
`MIProtocol` launches GDB with `bufsize=0` (raw unbuffered OS pipes) and manages its own `self._read_buf = bytearray()`. `_readline_timeout()` always checks `self._read_buf.find(b"\n")` before calling `select.select([fd])` and `os.read(fd, 4096)`, guaranteeing non-blocking timeouts with zero buffering deadlocks.

### Recursive-Descent MI2 Parser (`MIParser`)
Handles GDB/MI2 async records (`*stopped`, `=thread-*`), result records (`^done`, `^running`, `^error`), console streams (`~"..."`), target streams (`@"..."`), nested tuples (`{...}`), lists (`[...]`), and escaped C-strings.

### Target `stdout` & `stdin` Isolation
- **Target `stdout`:** In pipe mode without a PTY, GDB passes inferior `stdout` directly through the pipe. `parse_mi_lines()` captures both `@"..."` and `raw` lines into `target_output_buffer` (for per-step display) and `all_target_output` (retained across the full run for `EXITED` screens), splitting any target text lacking a trailing newline via `MI_EMBEDDED_RE`.
- **Target `stdin` FIFO:** `setup_target_stdin_fifo()` creates a named pipe in `work_dir` (`/tmp/work/target_stdin` inside Bubblewrap), opened `O_RDWR | O_NONBLOCK` on the host so Python keeps a writer open without blocking and feeds lines cleanly to `fgets`/`scanf`/`read(0)` via `-exec-arguments ... < /tmp/work/target_stdin`. Target input calls block cleanly on the FIFO without colliding with GDB's MI2 command stream.

---

## 6. High-Speed Register, Memory & Disassembly Engine (`src/gdb_inspector.py`)

### Indexed Core Register Queries
On modern x86-64 hardware, an unfiltered `-data-list-register-values x` returns 150+ registers (including AVX-512 `zmm0..zmm31`, `ymm`, `xmm`, and FPU stacks). During `_load_register_names()`:
- `CORE_REGS` indices are cached as a space-separated query (`core_reg_query`) covering only the 18 core GPRs/IP/Flags (or 10 on `i386`, 34 on `aarch64`, 17 on `arm`).
- `get_pc()` and `get_sp()` query **1 single register index** (`pc_reg_idx` / `sp_reg_idx`), while `step_instruction()` reads `PC` directly from `*stopped["frame"]["addr"]` at zero extra MI cost.

### Disassembly & `ls` Alignment
- `disassemble_range()` uses MI mode `2` (`-- 2`) to obtain raw instruction opcodes alongside Intel mnemonics, rebasing embedded PIE targets via `rebase_disas_text()`.
- `disassemble_context(pc, before, after)` anchors disassembly at the enclosing function's start address (or `e_entry`) before slicing `[pc_idx - before : pc_idx + after + 1]` inside `.text`, ensuring synchronized x86 variable-length decoding and reporting `cut_top` / `cut_bottom` flags.

---

## 7. Execution Control, External Skipping, `call` & `ignore` (`src/gdb_session.py`)

### Entry & Restart Semantics
- `advance_to_entry_point()` uses `starti` to map the process, discovers `runtime_base` from `info proc mappings` (or `info auxv` `AT_PHDR`/`AT_ENTRY`), and advances past `ld.so` to `_start`.
- `restart_to_entry()` resets `started`, `exited`, `exit_code`, `target_output_buffer`, `all_target_output`, and `_cached_stack_bounds`, allowing `start`, `main`, `run`, `call`, and `0x...` to restart seamlessly after exit.

### External Library & Callback Handling
When `SKIP_EXTERNAL_FUNCTIONS = True`:
1. **`next N`:** Runs `-interpreter-exec console "ni {N}"` natively in a single MI call.
2. **PLT Fast Return:** When `PC` enters a `.plt*` section (`addr_in_plt`), `step_over_or_finish_external()` reads the caller return address from `[SP]` (`x86_64`/`i386`) or `LR` (`aarch64`/`arm`), inserts a one-shot temporary breakpoint inside `.text`, and continues straight back to the caller instruction.
3. **Callback Trapping (`_detect_callback_arg0`):** Inspects ABI argument 0 (`RDI`, `X0`, `R0`, or `[ESP+4]`) before leaving `_start` or callback-taking libc calls; if it points into `.text` (e.g., `main` passed from `_start` to `__libc_start_main`), a one-shot breakpoint traps entry into `main()`—working even on stripped binaries.

### `IgnoreCallManager`
Supports four modes with immediate override priority:
- `none`: normal stepping into user functions.
- `all` (`ignore call`): all `call` instructions step over.
- `count` (`ignore once` / `ignore call N`): checks `_is_call_insn()` at `PC` before stepping and decrements `remaining` only when a `call` is skipped.
- `nest` (`ignore nest`): snapshots `nest_base_depth` and permits stepping 1 call level deeper (`<= nest_base_depth + 1`) while skipping deeper nested calls.

### `call <target> [--ignore]`
- Scans forward from `PC` in `.text` (`find_upcoming_call`) for exact `<name>` / `<name@plt>` matches first, then substring matches.
- Runs to the call instruction and steps 1 instruction into user callees (or stops on the `call` if it is an external `@plt` stub when `SKIP_EXTERNAL_FUNCTIONS = True`).
- If not visible ahead of `PC`, fails immediately unless exact `--ignore` is supplied—in which case it resolves against `get_binary_functions()` (never `libc`) and breaks globally until hit.

### Interactive `stdin` & Interrupt Handling
- `_maybe_proactive_stdin()` inspects the `call` target before stepping over `fgets`, `gets`, `scanf`, `getchar`, `getline`, or `read@plt`, flushes buffered TTY newlines via `termios.tcflush`, and writes user input to the FIFO.
- `_wait_stopped_interactive()` polls running waits (`0.7s`) and converts `KeyboardInterrupt` (`Ctrl+C`) into `-exec-interrupt` so the target pauses cleanly without terminating the debugger.

---

## 8. Stationary Live View, Split Layout, `nestN` & Color Diffs (`src/live_view.py`, `src/colors.py`)

### Flicker-Free Single-Flush Rendering
`render_live_screen()` builds the complete screen in memory and writes it in one syscall:
```text
\033[H + (line + \033[K + \n)... + \033[J
```
Avoiding `\033[2J` on redraws eliminates blank-frame flicker even while holding `Enter`.

### Stationary Frame & Nested Call Panes (`nestN`)
- `get_binary_call_frames()` parses `-stack-list-frames`, filters out external shared-library frames (`libc`/`ld.so`), and reverses into `outermost -> innermost`.
- `select_visible_frames(frames, nest_limit)` retains the root frame plus up to `nest_limit` deepest active callees (`nest` = `nest1`, `nest2`..`nestN`).
- Each frame caches its instruction window in `frame_pages[idx]` and refreshes only when `PC` exits the cached page or when `force_refresh` is triggered (`size`, `nest`, `jump`, `main`, `start`, `call`, `0x...`).

### Wide-Screen Layout & Byte/Char Diffs
- When `term_cols >= VIEW_SPLIT_MIN_COLS` (`125`), `render_two_columns()` places Code (+ Registers if Stack is also active) on the left pane and Stack/Registers on the right pane separated by `|`.
- `highlight_char_diff()` colors only changed characters in `[REGISTERS]`.
- `format_diff_xxd_line()` compares each byte address against `prev_stack_bytes: dict[int, int]` (surviving 8-byte `SP` shifts intact) and colors only changed bytes in both the hex and ASCII columns.
- `colors_active()` enforces `ENABLE_COLORS and _HAS_COLORAMA and sys.stdout.isatty()`, guaranteeing zero ANSI escape leakage when piped to files or clipboards.

---

## 9. Zero-Trimmed Stack Inspection & Binary Dumping

- `dump_stack_to_file(full=False)` dumps `[SP .. stack_end]` rather than the entire `135 KB` `[stack]` VMA.
- `trim_zero_stack()` strips leading and trailing 16-byte all-zero rows when `TRIM_STACK_DUMP_ZEROS = True` and reports the exact trimmed `[start - end]` memory range and byte count.
- Inside `view`, `COLLAPSE_STACK_ZEROS_IN_VIEW = True` collapses runs of 3+ unchanged all-zero 16-byte rows into a compact summary line (`... (N zero lines / B bytes skipped) ...`) while tracking every underlying byte address in `cur_bytes`.

---

## 10. Session Recording Specification (`src/recorder.py`)

`SessionRecorder` writes deterministic, non-JSON records into `record-<binary>_<DD-MM-YYYY_HH-MM-SS>/`:
- `full_recording.txt`: Complete chronological event stream (`[EVENT #00001]`, European 24h timestamp, `CMD`, `DURATION` in ms, `LOCATION`, `NOTE`, `STDOUT`, `CHANGED` registers, `+/- RECORD_DISAS_CONTEXT` disassembly, and stack).
- `functions/func_<name>.txt`: Per-function event logs (directory created lazily only when function events exist).
- **Stack Size Discipline:** Logs `FULL ACTIVE STACK` on event #1, whenever entering a new function, and on exit; logs only `STACK CHANGED` rows on intermediate steps within the same function.
- **Idle-Only Disk I/O:** Events accumulate in memory buffers during command execution and flush exclusively at prompt wait boundaries (`flush_idle()`) and `atexit`/`finally` hooks.

---

## 11. Autonomous Execution Mapping & Syscall Tracing (`src/mapper.py`)

`run_execution_mapper()` records an autonomous execution profile under `<binary>-mapped_<DD-MM-YYYY_HH-MM-SS>/`:
1. Advances to `--func`, `main` (`-m`), or `_start` *before* enabling `catch syscall`.
2. When `--func` is specified, tracks call depth (`func_depth`) across `call` and `ret` instructions and halts cleanly when the target invocation returns.
3. **Active Stack Snapshots & Diffs:** Unlike raw instruction tracers, `full_trace.txt` logs `FULL ACTIVE STACK` on function entries and `STACK CHANGED` rows on modifying steps, matching the structured format of `--record`.
4. **Interactive Target `stdin`:** If the binary calls `fgets`/`scanf`/`read` during `--map`, `mapper.py` routes through `prompt_for_target_stdin()` and feeds lines cleanly via the FIFO without hanging.
5. **Syscall Interception:** Steps through main-binary code while forwarding `syscall-entry`/`syscall-return` events inside `libc` via `on_syscall`, flushing any final non-returning syscall (`exit_group`) on process exit.
6. **Size Cap Enforcement:** Classifies instructions (`jump`, `call`, `ret`, `mem`) via `classify_instruction()`, samples `VmHWM` peak memory from `info proc status`, and enforces `MAX_MAP_FOLDER_MB` (`250` MB) via `FolderSizeGuard`.

---

## 12. Dynamic Stack-String Extractor (`stack_strings.py`)

Static analysis on an ELF binary (`strings bin`) only surfaces strings located in read-only data sections (`.rodata`, `.data`). Binaries that construct passwords at runtime, decrypt strings via XOR/RC4 loops, or write user inputs into stack buffers leave zero traces in static tools.

`stack_strings.py` bridges execution tracing and string recovery:
1. **Trace Ingestion:** Accepts a path to `full_recording.txt`, `full_trace.txt`, or an entire run folder (`record-.../` or `...-mapped_.../`).
2. **Binary Stack Stream Reconstruction:** Parses all hex byte rows across `FULL ACTIVE STACK`, `STACK_ON_ENTRY`, and `STACK CHANGED` blocks, decoding them via `bytes.fromhex()` into a concatenated binary file (`<target>_all_stacks.bin`).
3. **ASCII Extraction & Discovery Timeline:** Uses regex pattern `[\x20-\x7e]{min_len,}` to extract all printable strings, recording the exact event/step ID, timestamp, and function location where each unique string first appeared.
4. **Incremental Prefix Collapsing (`--collapse`):** Collapses progressive stack-construction iterations (`['crac', 'crack', 'crackm', 'crackme', 'crackme1', 'crackme12', 'crackme123']`) into the single longest surviving secret (`'crackme123'`).

---

## 13. Safety Limits, Timeouts & Graceful Interrupts

`bin-debug-friendly` implements four layers of protection against infinite loops, frozen I/O, or disk exhaustion:

1. **Instruction Execution Cap (`MAX_MAP_INSTRUCTIONS = 2_000_000`):**  
   Guards against runaway or infinite loops during `--map`. If 2 million instructions execute without program termination or function return, the tracer halts cleanly and writes `summary.txt`.
2. **Disk Storage Cap (`MAX_MAP_FOLDER_MB = 250`):**  
   `FolderSizeGuard` monitors bytes written across `full_trace.txt`, `syscalls_trace.txt`, and `functions/`. If the total directory size reaches 250 MB, writing stops immediately and `summary.txt` records `Truncated By Size Cap : YES`.
3. **Stall & Blocking Syscall Timeout (30 seconds):**  
   If an external call freezes on a blocking socket, unmocked device read, or sleep, GDB's `wait_stopped()` times out after 30 seconds.
4. **Graceful User Interruption (`Ctrl+C`):**  
   Pressing `Ctrl+C` during `--map` or interactive stepping raises a managed `KeyboardInterrupt`. The runner halts the inferior via `-exec-interrupt`, flushes any pending system call record, closes open file handles, and writes `summary.txt` with `Interrupted By User : YES`.

---

## 14. Bubblewrap Sandbox & Cross-Architecture QEMU Design (`src/sandbox.py`)

```text
Host Filesystem                       Bubblewrap Sandbox (/tmp/work)
┌────────────────────────┐            ┌──────────────────────────────────────┐
│ /home/<user>/...       │ ──[NONE]──►│ Completely hidden & unmounted        │
│ Host Network Stack     │ ──[NONE]──►│ --unshare-all (no internet sockets)  │
│ /usr, /bin, /lib*      │ ──[RO]────►│ Read-only system runtime & QEMU bins │
│ Target Binary & FIFOs  │ ──[RW]────►│ /tmp/work/target_bin & target_stdin  │
└────────────────────────┘            └──────────────────────────────────────┘
```

- **Native Debugging:** Runs `gdb --interpreter=mi2` directly inside `bwrap --unshare-all --cap-drop ALL --new-session --die-with-parent --clearenv`, keeping `gdb` as the direct parent of the inferior so `ptrace` operates cleanly under `yama.ptrace_scope=1`.
- **Cross-Architecture Emulation:** When `needs_qemu(host_arch, elf.arch)` is `True` (e.g., `aarch64`/`arm` on `x86_64`), a sandboxed shell wrapper spawns `qemu-<arch> -g <port> target_bin < target_stdin` and connects `gdb-multiarch` to `127.0.0.1:<port>` inside the sandbox.
- **`--no-sandbox` Safety Gate:** `confirm_disable_sandbox()` displays a prominent warning and requires two confirmations followed by matching `"iknow"` (case- and whitespace-insensitive) before executing directly on the host.

---

## 15. Configuration Reference (`src/config.py`)

| Constant | Default | Purpose |
|----------|---------|---------|
| `DEFAULT_INFO_FORMAT` | `"hex"` | Default format for CLI `info`/`show` (`"hex"`, `"dec"`, `"char"`, `"str"`, `"all"`). |
| `ENABLE_COLORS` | `True` | Enable TTY-only green diff highlights via optional `colorama`. |
| `PROMPT_SHOW_ADDRESS` | `True` | Display current `objdump`-style `PC` in prompts. |
| `PROMPT_SHOW_FUNCTION` | `True` | Display current function name in prompts. |
| `PROMPT_SHOW_TOOL_NAME` | `False` | Prefix prompt with `PROMPT_TOOL_NAME` (`"bdf"`). |
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
| `MAX_MAP_FOLDER_MB` | `250` | Maximum output size (MB) for `--map` trace folders. |
| `MAX_MAP_INSTRUCTIONS` | `2_000_000` | Safety instruction cap for `--map` against infinite loops. |
| `MAX_INTERACTIVE_STEPS` | `100_000` | Maximum step/next count per single interactive command. |
| `EU_FOLDER_TS_FORMAT` | `"%d-%m-%Y_%H-%M-%S"` | European 24-hour folder timestamp format. |
| `EU_LOG_TS_FORMAT` | `"%d-%m-%Y %H:%M:%S"` | European 24-hour log timestamp format. |

