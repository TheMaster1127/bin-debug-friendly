# bin-debug-friendly

> **A fast, Bubblewrap-sandboxed Linux ELF debugger and execution mapper with exact `objdump`-style hex addressing (zero `main+offset` math), a stationary live-arrow TUI (`view`), nested call windows (`nestN`), smart zero-trimmed stack dumps, and cross-architecture QEMU support.**

**PLATFORM SUPPORT: LINUX ONLY.**  
*`bin-debug-friendly` relies on Linux kernel namespaces (`bubblewrap`), `/proc/<pid>/maps`, ELF32/ELF64 parsing, GNU `gdb`, and optional `qemu-user` emulation.*  
**ZERO `pip` DEPENDENCIES:** Built strictly using the Python 3 standard library.

---

## Table of Contents
1. [Why `bin-debug-friendly`?](#1-why-bin-debug-friendly)
2. [Key Features](#2-key-features)
3. [Prerequisites & Installation (Artix / Arch / Debian)](#3-prerequisites--installation-artix--arch--debian)
4. [Quick Start & Launch Flags](#4-quick-start--launch-flags)
5. [Interactive Debugger Command Reference](#5-interactive-debugger-command-reference)
6. [Live View (`view`) & Nested Call Windows (`nestN`)](#6-live-view-view--nested-call-windows-nestn)
7. [Execution Mapping (`--map` & `--func`)](#7-execution-mapping---map--func)
8. [Configuration (`src/config.py`)](#8-configuration-srcconfigpy)
9. [Security Model (Bubblewrap Sandbox & `--no-sandbox` Gate)](#9-security-model-bubblewrap-sandbox--no-sandbox-gate)
10. [Running the Test Suite](#10-running-the-test-suite)

---

## 1. Why `bin-debug-friendly`?

Debugging stripped or PIE-enabled binaries in raw GDB is tedious:
- You copy `0x1149` from `objdump` or a hex dump, and GDB forces you to manually compute `runtime_base + 0x1149` or `b *main+0x12`.
- Stepping casually drops you inside `.plt` trampolines, `_dl_runtime_resolve`, and hundreds of lines of `libc` assembly.
- Inspecting registers means squinting at a single format (`hex`), and dumping `[stack]` writes 135 KB of mostly `0x00` guard space.
- Seeing your code, changed registers, changed stack bytes, and caller functions at the same time requires juggling fragile GDB TUI layouts.

**`bin-debug-friendly`** wraps GDB's Machine Interface (`--interpreter=mi2`) inside an air-gapped Bubblewrap sandbox and fixes all of it out of the box.

---

## 2. Key Features

* **Exact `objdump`-Style Addressing (Zero `main+offset` Math):**
  * Pure-Python ELF32/ELF64 header, `PT_LOAD`, and section parser (`.text`, `.plt*`).
  * Automatically detects PIE (`ET_DYN`) vs fixed (`ET_EXEC`) binaries and resolves runtime base addresses dynamically via `/proc/<pid>/maps` (with `info auxv` fallback for QEMU).
  * Accepts `0x1149`, `1149`, `"0x 11 49"`, uppercase/lowercase, with or without quotes—or type `0x1149` *alone* at the prompt to run directly there and stop!
* **Stationary Live `view` Mode + Nested Call Panes (`nestN`):**
  * Keeps your disassembly stationary while only the `=>` arrow walks down line-by-line (automatically advancing pages at the bottom).
  * Automatically splits into a **two-column side-by-side layout** on wide monitors (`>= 125` columns), showing Code + Registers + Active Stack simultaneously.
  * Highlights changed registers and changed 16-byte stack rows with `*` after every step.
  * **`nest` / `nest1` / `nest2` / `nest5`:** Opens up to `N` nested caller/callee assembly windows (`->` marks caller call sites, `=>` tracks the active instruction) and closes them automatically on return.
* **Intel Syntax Always + Clean `ls` Context:**
  * Enforces Intel syntax (`-gdb-set disassembly-flavor intel`) with raw opcodes and rebased `objdump` target addresses.
  * `ls` / `lsN` shows `N` instructions before and after `PC`, clamped cleanly to `.text` (with top/bottom cutoff notices and a screen-flood warning when `N > 100`).
* **Automatic External Library Skipping:**
  * Automatically skips `.plt` stubs, `ld.so`, and `libc` internals during `step`, while still trapping `.text` callbacks (like `main` passed via `RDI`/`X0`/`R0` to `__libc_start_main`).
* **Multi-Format Registers & Live Editing:**
  * `info` / `show` supports `-h` (hex), `-d` (decimal + signed), `-c` (ASCII chars), `-s` (C-string dereference / inline ASCII), and `all` with vertically aligned columns.
  * `set <reg> [to] <val>` modifies registers mid-run using hex, decimal, or quoted ASCII (`"ABCD"`).
* **Smart Zero-Trimmed Stack Dumps:**
  * `dump stack` dumps from `SP` upward and strips empty leading/trailing zero blocks into `<binary>.stack.bin` ready for `xxd`.
  * `stack less` opens the active stack directly inside `less`; `stack info` prints exact mapping bounds and used/free byte counts.
* **Execution Mapping (`-map` / `--map` & `-func` / `--func`):**
  * Traces every executed instruction inside the main binary, recording European 24-hour timestamps (`DD-MM-YYYY HH:MM:SS`), disassembly, registers, system calls (`catch syscall`), jump/call/ret/memory counts, peak memory (`VmHWM`), and per-function call counts.
  * Enforces a hard **250 MB** cap (`MAX_MAP_FOLDER_MB` in `src/config.py`) so tight loops never exhaust disk space.
* **Multi-Architecture Support (`x86_64`, `i386`, `aarch64`, `arm`):**
  * Runs native binaries directly in Bubblewrap and automatically pairs cross-arch ELF binaries with `qemu-<arch> -g <port>` + `gdb-multiarch` inside the sandbox.

---

## 3. Prerequisites & Installation (Artix / Arch / Debian)

### Artix / Arch Linux
```bash
sudo pacman -S --needed python gdb bubblewrap
# Optional for ARM / AArch64 cross-architecture debugging:
sudo pacman -S --needed qemu-user gdb-multiarch
```

### Debian / Ubuntu
```bash
sudo apt update && sudo apt install -y python3 gdb bubblewrap
# Optional for ARM / AArch64 cross-architecture debugging:
sudo apt install -y qemu-user gdb-multiarch
```

Make `main.py` executable:
```bash
chmod +x main.py
```

---

## 4. Quick Start & Launch Flags

### Launch Modes
```bash
# 1. Start paused at the binary's real entry point (_start)
python3 main.py ./my_binary

# 2. Pass arguments to the target binary
python3 main.py ./my_binary arg1 --flag arg2

# 3. Start paused directly at main() (errors cleanly without running if stripped / no main)
python3 main.py ./my_binary -m
python3 main.py ./my_binary --main

# 4. Execution mapping mode (traces full main-binary execution + syscalls + stats)
python3 main.py ./my_binary --map
python3 main.py ./my_binary -map -func 0x1139

# 5. Map execution + dump binary stack snapshot on every syscall
python3 main.py ./my_binary --map --dump-stack-syscalls

# 6. Disable Bubblewrap sandbox (triggers multi-step security confirmation!)
python3 main.py ./my_binary --no-sandbox
```

---

## 5. Interactive Debugger Command Reference

Command history (`Up` / `Down` arrows, `Ctrl+R`, `Left`/`Right`) is enabled automatically via Python `readline`.

| Command | Aliases / Forms | Description |
| :--- | :--- | :--- |
| **`0x<addr>`** | `0x1149`, `"0x 11 49"` | Shortcut: restarts if exited, sets a one-shot breakpoint at exact address, and runs there. |
| **`view [opts]`** | `follow`, `live` | Opens stationary live-arrow window (see [Section 6](#6-live-view-view--nested-call-windows-nestn)). |
| **`ls [N]`** | `ls`, `ls1`, `ls10`, `ls 20` | Shows `N` instructions before & after `PC` (default 2), clamped to `.text` (warns if `N > 100`). |
| **`main`** | `stop main` | Runs (or restarts if exited) directly until `main()` is hit. |
| **`start`** | `restart` | Restarts the program cleanly from the beginning, paused at `_start`. |
| **`stop <addr>`** | `b`, `break` | Sets a breakpoint at exact `objdump`/hex address (0x/spaces/quotes flexible) or symbol. |
| **`jump <addr>`** | `jmp <addr>` | Forces `PC` (`RIP`/`EIP`/`PC`) straight to `<addr>` or symbol without changing stack/regs. |
| **`run`** | `r` | Continues execution, or restarts from the beginning if already exited. |
| **`continue`** | `c`, `cont` | Resumes execution until the next breakpoint or exit. |
| **`step [N]`** | `s`, `si` | Steps 1 (or `N`) instruction(s) into calls (skipping `.plt`/external libs if enabled). |
| **`next [N]`** | `n`, `ni` | Steps 1 (or `N`) instruction(s) over calls (batched natively via `ni N` for speed). |
| **`step/next N dump`** | `... dump [stack [all]]` | Steps `N` times and logs all instructions & registers; `stack` dumps start/end `.stack.bin`, `stack all` warns then dumps every step. |
| **`skip`** | — | Finishes the rest of the current function and stops in the caller. |
| **`info [reg] [flag]`** | `show` | Dumps all registers (or one register). Flags: `-h` (hex), `-d` (dec), `-c` (char), `-s` (string), `all`. |
| **`info stack`** | `info raw stack` | `info stack` prints registers + stack preview; `info raw stack` prints stack only. |
| **`get <reg>`** | — | Displays a single register in all formats (`hex`, `dec`, `char`, `str`). |
| **`set <reg> [to] <val>`** | — | Sets a register using hex (`0x2a`), decimal (`42`), or ASCII (`"ABCD"`). |
| **`stack`** | `stack less`, `stack info` | Previews active stack, browses it inside `less`, or prints stack region bounds & size. |
| **`dump stack`** | `stack dump [full]` | Saves active zero-trimmed stack (or `full` VMA) to `<binary>.stack.bin` for `xxd`. |
| **`disas [N]`** | `d`, `disas main [N]` | Disassembles `N` instructions forward in `objdump` Intel style with opcodes. |
| **`maps`** | — | Prints `/proc/<pid>/maps` memory layout of the debugged process. |
| **`help`** / **`quit`** | `?`, `exit`, `q` | Shows command summary or exits cleanly. |

---

## 6. Live View (`view`) & Nested Call Windows (`nestN`)

Launch `view` with any combination of options in any order:

```text
0x113d (main)> view                    # Code + live Registers
0x113d (main)> view only               # Code only (minimal)
0x113d (main)> view stack              # Code + live Registers + live Stack
0x113d (main)> view raw stack          # Code + live Stack only (no Registers)
0x113d (main)> view all 30             # 30-line page + all-format Registers + Stack
0x113d (main)> view nest2 stack 35     # Up to 2 nested call panes + Stack + 35-line window
```

### Example Wide-Screen Layout (`view stack 40`)
```text
=== LIVE VIEW | main | 0x1159 (main) | term=279 cols ===
============================================================================================================================================
[CODE: main] page=40 | nest=0 | step N | nest<N> | size <N> | only | regs | stack  | [STACK] SP=0x7fffffffec50 (Active=944 B, * = changed)
     0x1139:  55                       push   rbp                                  |  0x00007fffffffec50: 0000 0000 0000 0000 80ed ffff 0100 0000  ................  <-- SP
     0x113a:  48 89 e5                 mov    rbp,rsp                              | *0x00007fffffffec60: 88ed ffff ff7f 0000 7e79 c2f7 ff7f 0000  ........~y......
  => 0x1159:  b8 00 00 00 00           mov    eax,0x0                              |  0x00007fffffffec70: 00e0 fbf7 ff7f 0000 3951 5555 5555 0000  ........9QUUUU..
...
[REGISTERS] (* = changed)                                                          |
 RAX   : 0x0000000000000001                                                        |
*RDI   : 0x0000555555556004                                                        |
*RIP   : 0x0000555555555159                                                        |
```

### Controls Inside `view`
* **`Enter`** / **`s`** / **`step`** / **`step N`**: Step `1` or `N` instructions forward (moving `=>` down without scrolling).
* **`n`** / **`next`** / **`next N`**: Step over calls `1` or `N` instructions.
* **`k`** / **`skip`**: Return out of the current function.
* **`r`** / **`run`** / **`c`**: Continue (or restart if exited).
* **`nest`** (`= nest1`), **`nest2`**, **`nest5`**, **`nest0`**: Change call-window nesting depth on the fly.
* **`size <N>`** / **`view <N>`** / **`<N>`**: Resize code page on the fly.
* **`only`** / **`regs`** / **`stack`** / **`raw stack`** / **`all`**: Toggle panes dynamically.
* **`main`**, **`start`**, **`0x<addr>`**, **`jump <addr>`**, **`stop <addr>`**, **`set <reg> <val>`**, **`dump stack`**, **`q`**: All work directly inside `view`.

---

## 7. Execution Mapping (`--map` & `--func`)

Run in non-interactive trace mode:
```bash
python3 main.py ./my_binary --map
python3 main.py ./my_binary -map -func 0x1139
```

Creates a European-dated output directory (24-hour clock):
```text
my_binary-mapped_22-11-2026_20-50-02/
├── full_trace.txt        # Chronological instructions, EU timestamps, func addr, all GPRs
├── syscalls_trace.txt    # Every syscall: number/name, caller PC, time in/out, regs in, return val
├── summary.txt           # Instruction totals, jumps/calls/rets/mem accesses, VmHWM, func counts
└── functions/
    └── func_0x1139.txt   # Per-function filtered instruction trace
```

* **Only main binary code is traced** (external `libc` / `ld.so` internals are skipped automatically).
* **Hard 250 MB Cap:** Logging automatically halts cleanly if folder output reaches `MAX_MAP_FOLDER_MB` (`250` MB).

---

## 8. Configuration (`src/config.py`)

| Setting | Default | Purpose |
| :--- | :--- | :--- |
| `DEFAULT_INFO_FORMAT` | `"hex"` | Default format for `info` (`"hex"`, `"dec"`, `"char"`, `"str"`, `"all"`). |
| `PROMPT_SHOW_ADDRESS` | `True` | Show current `objdump`-style PC in the CLI prompt (`0x113d`). |
| `PROMPT_SHOW_FUNCTION` | `True` | Show current function name in the CLI prompt (`(main)`). |
| `PROMPT_SHOW_TOOL_NAME` | `False` | Prefix prompt with `PROMPT_TOOL_NAME` (`"bdf"`). |
| `USE_OBJDUMP_ADDR` | `True` | Rebase PIE addresses inside the main binary to `objdump` offsets. |
| `SHOW_OPCODES_IN_DISAS` | `True` | Display raw hex opcodes alongside Intel disassembly. |
| `VIEW_PAGE_SIZE` | `10` | Default instruction count per `view` page. |
| `VIEW_DEFAULT_REGS` / `STACK` / `NEST` | `True` / `False` / `0` | Default panels & nesting depth when opening `view`. |
| `VIEW_HIGHLIGHT_CHANGES` | `True` | Mark changed registers & stack rows with `*`. |
| `VIEW_SPLIT_MIN_COLS` | `125` | Terminal column threshold for side-by-side layout. |
| `SKIP_EXTERNAL_FUNCTIONS` | `True` | Auto-skip `.plt` stubs, `ld.so`, and `libc` internals on `step`. |
| `TRIM_STACK_DUMP_ZEROS` | `True` | Trim leading/trailing all-zero rows in `dump stack`. |
| `MAX_MAP_FOLDER_MB` | `250` | Maximum disk size (MB) for `--map` output folders. |
| `MAX_MAP_INSTRUCTIONS` | `2_000_000` | Safety instruction cap for `--map` against infinite loops. |

---

## 9. Security Model (Bubblewrap Sandbox & `--no-sandbox` Gate)

By default, every target binary and GDB process runs inside an air-gapped Bubblewrap container:
```bash
bwrap --unshare-all --cap-drop ALL --new-session --die-with-parent --clearenv ...
```
- **`/home` is completely unmounted and invisible** to the target binary.
- **Zero network / internet access** (`--unshare-all`).
- **Only `/tmp/work` is writable** (a disposable temporary directory managed per session).
- **`--no-sandbox` Safety Gate:** Disabling the sandbox prints a massive security warning and requires a 3-step confirmation ending with typing `I know` explicitly.

---

## 10. Running the Test Suite

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## License

This project is licensed under the [GNU General Public License v3.0 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.html).
