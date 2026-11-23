# `bin-debug-friendly`

> **A fast, Bubblewrap-sandboxed Linux ELF debugger, stationary live-arrow TUI, and execution mapper with exact `objdump`-style hex addressing, byte-level green memory/register diffs, nested call windows, smart stack dumps, and cross-architecture QEMU support.**

**⚠️ PLATFORM SUPPORT: LINUX ONLY.**  
*`bin-debug-friendly` relies on Linux kernel namespaces (`bubblewrap`), `/proc/<pid>/maps` memory introspection, named FIFOs, ELF32/ELF64 binary parsing, GNU `gdb`, and optional `qemu-user` emulation.*  

**ZERO MANDATORY `pip` DEPENDENCIES:** Built 100% on the Python 3 standard library (`colorama` is purely optional for terminal diff colors and never required).

---

## Table of Contents

1. [Why `bin-debug-friendly`?](#1-why-bin-debug-friendly)
2. [Key Features at a Glance](#2-key-features-at-a-glance)
3. [Synopsis & Launch Flags](#3-synopsis--launch-flags)
4. [Quick Start & Prerequisites](#4-quick-start--prerequisites)
5. [Direct Exact-Address Debugging (No `main+offset` Math)](#5-direct-exact-address-debugging-no-mainoffset-math)
6. [Complete Interactive Command Reference](#6-complete-interactive-command-reference)
7. [Live View (`view`) & Nested Call Windows (`nestN`)](#7-live-view-view--nested-call-windows-nestn)
8. [Call Navigation (`call <func>`) & Call Ignoring (`ignore`)](#8-call-navigation-call-func--call-ignoring-ignore)
9. [Interactive `stdin` (`fgets` / `scanf` / `read`)](#9-interactive-stdin-fgets--scanf--read)
10. [Smart Zero-Trimmed Stack Inspection & Dumping](#10-smart-zero-trimmed-stack-inspection--dumping)
11. [Session Recording (`--record`)](#11-session-recording---record)
12. [Autonomous Execution Mapping (`--map` & `--func`)](#12-autonomous-execution-mapping---map--func)
13. [Configuration (`src/config.py`)](#13-configuration-srcconfigpy)
14. [Security Model (Bubblewrap Sandbox & `--no-sandbox`)](#14-security-model-bubblewrap-sandbox----no-sandbox)
15. [Cross-Architecture Debugging (QEMU + ARM / AArch64 / x86)](#15-cross-architecture-debugging-qemu--arm--aarch64--x86)
16. [Real-World Reverse Engineering Walkthroughs](#16-real-world-reverse-engineering-walkthroughs)
17. [Running the Test Suite](#17-running-the-test-suite)
18. [License](#license)

---

## 1. Why `bin-debug-friendly`?

Have you ever copied an address like `0x1149` straight out of `objdump`, `binpatch`, `readelf`, or a hex dump—and then watched raw GDB fight you every step of the way?

In plain GDB:
- Setting a breakpoint on a PIE binary means manually calculating `runtime_base + 0x1149` or typing annoying `b *main+0x12` expressions.
- Stepping casually drops you straight into `puts@plt`, `_dl_runtime_resolve`, and hundreds of lines of `ld-linux.so` and `libc` internals.
- Register dumps show only raw hex unless you manually cast and print memory strings one register at a time.
- Dumping `[stack]` writes out `135 KB` of mostly `0x00` guard space instead of your actual active stack frames.
- Watching a crackme decode a password or fill a stack buffer requires constantly re-typing `x/32bx $rsp`, `i r`, and `disas` over and over as your terminal scrolls away.

**`bin-debug-friendly`** solves all of this out of the box:
- **Exact `objdump` addresses everywhere:** Copy `0x12c4` (or `12c4`, or `" 0x 12 c4 "`) straight from disassembly and type `0x12c4` or `stop 0x12c4`—PIE rebasing happens automatically.
- **Intel syntax locked in:** Clean `objdump`-style Intel disassembly with raw hex opcodes and rebased target comments (`# 0x2004`, `call 0x1030 <puts@plt>`).
- **Stationary Live `view`:** A flicker-free dashboard where your code stays locked in place while only the `=>` arrow walks down, your registers update live in all formats (`hex | dec | char | str`), and changed characters & stack bytes light up **bright green** right beside the code.
- **Built-in execution mapper & session recorder:** Trace every main-binary instruction, active stack diff, and system call into clean, structured text folders (`--map`), or record your interactive debugging steps for later human or AI analysis (`--record`).
- **Sandboxed by default:** Every target binary executes inside an air-gapped **Bubblewrap (`bwrap`)** container with `/home` hidden and zero internet access.

---

## 2. Key Features at a Glance

* **Pure-Python ELF32 & ELF64 Engine:** Detects architecture (`x86_64`, `i386`, `aarch64`, `arm`), endianness, bitness, PIE (`ET_DYN`) vs fixed (`ET_EXEC`), `.text` bounds, `.plt*` trampoline ranges, and `.symtab` binary function names with zero external tools.
* **Sub-Millisecond Stepping:** Indexed register queries pull only the 18 core architecture registers (skipping 150+ AVX-512/FPU vectors), while `PC` is extracted directly from GDB stop frames and `[stack]` bounds are cached.
* **Stationary Wide-Screen `view` + `nestN`:** Displays 41 lines of code, `all`-format registers, and a zero-collapsed active `[STACK]` side-by-side on wide monitors (`>= 125` cols), plus `nest1`..`nestN` stacked caller/callee code windows.
* **Exact Green Diffs (`src/colors.py`):** Highlights only the exact changed hex/decimal/ASCII characters in `[REGISTERS]` and only the exact changed bytes in `[STACK]` (auto-disabled cleanly when `colorama` is absent or stdout is piped to a file/clipboard).
* **Smart `call <func> [--ignore]` + Tab Autocomplete:** Autocompletes strictly from your binary's `.symtab` and `.text`/`.plt` calls (never polluted with `libc` symbols), runs to the upcoming call site, and steps straight inside.
* **Granular Call Ignoring:** `ignore call`, `ignore once`, `ignore call N`, `ignore nest`, and `unignore call`.
* **Non-Colliding Target `stdin`:** Dedicated sandboxed FIFO handles `fgets`, `scanf`, `getchar`, `getline`, and `read` cleanly—flushing held Enter keys and prompting you seamlessly without corrupting GDB's control pipe (works in interactive CLI, `view`, and `--map`!).
* **Zero-Trimmed `.stack.bin` Dumps:** Dumps only the active stack (`SP` upward) stripped of empty guard zeros, ready immediately for `xxd`.
* **Session Recording (`--record`) & Execution Mapping (`--map`):** Clean, structured, predictable non-JSON output folders with European 24-hour timestamps (`DD-MM-YYYY HH:MM:SS`).

---

## 3. Synopsis & Launch Flags

```bash
python3 main.py <binary> [target_args...] [OPTIONS]
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-m`, `-main`, `--main` | *(none)* | Start and automatically pause at `main()`. Also pairs with `--map` to map from `main()` forward! Errors out cleanly without starting if the binary is stripped or has no `main` symbol. |
| `-record`, `--record` | *(none)* | Record every interactive command, timing, disassembly context, register diff, full active stack, and `stdout` into `record-<bin>_<DD-MM-YYYY_HH-MM-SS>/`. |
| `-map`, `--map` | *(none)* | Run autonomous execution mapper: traces instructions, register states, active stack snapshots & diffs, system calls, and stats into `<bin>-mapped_<DD-MM-YYYY_HH-MM-SS>/`. |
| `-func`, `--func`, `--function` | `ADDR\|SYM` | With `--map`: start tracing when `ADDR` or `SYM` is entered and automatically stop when it returns. |
| `--dump-stack-syscalls` | *(none)* | With `--map`: save binary `.stack.bin` snapshots on every system call entry. |
| `--no-sandbox` | *(none)* | Disable Bubblewrap isolation and debug directly on the host (triggers a full-screen warning and 3-step confirmation requiring `"I know"`). |

### Default Entry Behavior
- Running `python3 main.py ./binary` (without `-m`) automatically skips dynamic linker (`ld-linux.so`) startup and pauses cleanly at the binary's real entry point (`_start`), ready for inspection even on stripped binaries.
- Running `python3 main.py ./binary -m` verifies that `main` exists and pauses directly on `main()`.

---

## 4. Quick Start & Prerequisites

### System Requirements (Linux Only)
* **Python 3.10+** (standard library only—no `pip` packages required)
* **GNU `gdb`**
* **`bubblewrap` (`bwrap`)** — mandatory for sandboxed execution
* **Optional:**
  * `colorama` — enables bright-green byte/character change highlights in interactive terminals
  * `qemu-user` + `gdb-multiarch` — enables debugging ARM / AArch64 / 32-bit x86 binaries across architectures
  * `xxd` and `less` — for inspecting `.stack.bin` dumps and `stack less`

### Install Dependencies

```bash
# Artix / Arch Linux
sudo pacman -S --needed python gdb bubblewrap
# Optional colors & cross-arch support:
sudo pacman -S --needed python-colorama qemu-user gdb-multiarch

# Debian / Ubuntu
sudo apt update && sudo apt install -y python3 gdb bubblewrap
# Optional colors & cross-arch support:
sudo apt install -y python3-colorama qemu-user gdb-multiarch
```

### First Run
```bash
chmod +x main.py
python3 main.py ./your_binary
```

---

## 5. Direct Exact-Address Debugging (No `main+offset` Math)

Whether your binary is compiled with **PIE (`-fPIE -pie`, the modern GCC default)** or **`-no-pie`**, `bin-debug-friendly` lets you use the exact addresses printed by `objdump`, `binpatch`, `readelf`, or `xxd`.

### Accepted Hex Formats
Every address command (`stop`, `0x...`, `jump`, `--func`) normalizes whitespace, quotes, case, and `0x` prefixes automatically:
- `0x1149`
- `1149`
- `0X401149`
- `"0x1149"`
- `" 0x 40 11 49 "`
- `"11 49"`

### Instant Run-To Shortcut (`0x...`)
Type any `0x`-prefixed hex address by itself at the prompt (either in the main CLI or inside `view`):
```text
0x1040 (_start)> 0x12c4
[+] Ran to 0x12c4 (pie_vaddr(objdump=0x12c4))
[*] Stopped (breakpoint-hit) at 0x12c4 in main
  => 0x12c4:  e8 23 ff ff ff           call   0x11ec <check_password>
```
If the program has already exited, typing `0x12c4` restarts it cleanly and runs straight to `0x12c4`.

---

## 6. Complete Interactive Command Reference

Full `readline` history (`Up` / `Down` arrows, `Ctrl+R`, `Left`/`Right` line editing) and `Tab` autocompletion are active in both the main REPL and `view`.

### Navigation, Breakpoints & Execution
| Command | Aliases | Usage & Behavior |
|---------|---------|------------------|
| **`0x<addr>`** | `"0x 11 49"` | Immediately runs (or restarts if exited) to `<addr>` and stops. |
| **`call <func> [--ignore]`** | *(Tab completes)* | Runs to the next upcoming `call <func>` ahead of `PC` and steps straight inside. Pass `--ignore` to break globally if the call isn't linearly ahead. |
| **`stop <addr\|sym>`** | `b`, `break` | Sets a persistent breakpoint at an `objdump`/hex address or symbol. |
| **`main`** | `stop main` | Runs (or restarts if exited) directly to `main()`. |
| **`start`** | `restart` | Restarts the program from the beginning and pauses at `_start`. |
| **`run`** | `r` | Resumes execution, or restarts from the beginning if already exited. |
| **`continue`** | `c`, `cont` | Resumes execution until the next breakpoint or exit. |
| **`jump <addr\|sym>`** | `jmp` | Forces `PC`/`RIP` immediately to `<addr>` or symbol (leaves stack and registers untouched). |

### Stepping & Batch Dumping
| Command | Aliases | Usage & Behavior |
|---------|---------|------------------|
| **`step [N]`** | `s`, `si` | Steps `1` (or `N`) instruction(s) into calls (skipping `.plt`/`libc` when `SKIP_EXTERNAL_FUNCTIONS = True`). |
| **`next [N]`** | `n`, `ni` | Steps `1` (or `N`) instruction(s) over calls (batched natively via `ni N` for instant execution). |
| **`step [N] dump`** | `next [N] dump` | Steps `N` times and writes every instruction, disassembly, and all register formats to `<bin>_steps_<date>.txt`. |
| **`step [N] dump stack`** | `next [N] dump stack` | Same as above, plus dumps `stack_start.stack.bin` and `stack_end.stack.bin` inside `<bin>_stepdump_<date>/`. |
| **`step [N] dump stack all`** | `next [N] dump stack all` | Prompts `"Are you sure? This will generate N stack dump files!"` and dumps a `.stack.bin` at every single step. |
| **`skip`** | — | Finishes the rest of the current function and stops back in the caller. |

### Call Ignoring & Target Stdin
| Command | Aliases | Usage & Behavior |
|---------|---------|------------------|
| **`ignore call`** | `/ignore call`, `ignore calls`, `skip call` | Makes `step` skip over all `call` instructions until disabled. |
| **`ignore once`** | `ignore call 1`, `ignore 1` | Ignores the next `1` call instruction encountered. |
| **`ignore call <N>`** | `ignore <N>`, `skip call <N>` | Ignores the next `N` call instructions encountered, decrementing only on actual `call` opcodes. |
| **`ignore nest`** | `ignore nested` | Allows stepping 1 call level deeper, then skips any deeper nested calls inside it. |
| **`unignore call`** | `unignore`, `unskip call` | Restores normal stepping into calls. |
| **`stdin <text>`** | — | Pre-queues an input line into the target's `stdin` FIFO before stepping past `fgets`/`scanf`/`read`. |

### Disassembly, Registers & Memory
| Command | Aliases | Usage & Behavior |
|---------|---------|------------------|
| **`view [opts]`** | `follow`, `live` | Launches stationary live-arrow TUI dashboard (see [Section 7](#7-live-view-view--nested-call-windows-nestn)). |
| **`ls [N]`** | `ls`, `ls1`, `ls10`, `ls 20` | Shows `N` instructions before & after `PC` (default `2`), clamped to `.text` with top/bottom cutoff notices. Warns if `N > 100`. |
| **`disas [N]`** | `disassemble`, `d` | Disassembles `N` instructions forward in `objdump` Intel style (`disas main [N]` supported). |
| **`info [reg] [flag]`** | `show` | Dumps all registers (or one register) formatted as `REG: value`. Flags: `-h` (hex), `-d` (dec), `-c` (char), `-s` (string/C-string deref), `all` / `-a`. |
| **`info stack`** | — | Prints all registers followed by the active stack preview. |
| **`info raw stack`** | `info stack only` | Prints only the active stack preview (no registers). |
| **`get <reg>`** | — | Case-insensitive single-register inspection in all formats (`hex \| dec \| char \| str`). |
| **`set <reg> [to] <val>`** | — | Sets a register using hex (`0x2a`), decimal (`42`), or ASCII (`"ABCD"`). |
| **`stack`** | — | Previews the top and bottom of the active stack around `SP`. |
| **`stack less`** | — | Pipes the active stack directly into `less` for interactive scrolling. |
| **`stack info`** | — | Prints `[stack]` region bounds, total mapped size, active bytes (`SP` to top), and unused bytes. |
| **`dump stack [full]`** | `stack dump` | Saves active zero-trimmed stack (or full `[stack]` VMA with `full`) to `<binary>.stack.bin` for `xxd`. |
| **`maps`** | — | Prints `/proc/<pid>/maps` memory regions of the process. |
| **`help`** / **`quit`** | `?`, `exit`, `q` | Displays command summary or exits cleanly. |

---

## 7. Live View (`view`) & Nested Call Windows (`nestN`)

Entering `view` switches into a **flicker-free, stationary dashboard** (updating in place via single-buffer ANSI writes—no scrolling spam and no blank-screen flashes).

### What You See by Default
With the defaults in `src/config.py` (`VIEW_PAGE_SIZE = 41`, `VIEW_DEFAULT_REGS = True`, `VIEW_DEFAULT_STACK = True`, `VIEW_DEFAULT_REG_FORMAT = "all"`):
- **Left Pane:** Up to 41 Intel instructions of your current function/page (`=>` walks down without the instructions moving) + **all core registers** in `hex | dec | char | str` format.
- **Right Pane** *(on terminals `>= 125` cols wide)*: **Active `[STACK]`** starting at `SP`, automatically collapsing runs of 3+ unchanged zero lines (`... (N zero lines skipped) ...`) so you see both local variables/buffers AND saved frames/`argv`/`env` at once.
- **Green Byte & Char Diffs:** Every register character and every individual stack byte (both hex pair and ASCII character) that changed on your last step is marked with `*` and highlighted **bright green**.
- **Prompt Location:** Your live address & function (`0x126d (main)> `) sit right at the end of the `view` input line.
- **Exit Output Persistence:** When the program terminates inside `view`, the `[EXITED]` screen prints the full accumulated `Program Output (stdout)` right inside the main panel.

### Launch Options & In-View Controls

Launch `view` with any combination of flags in any order:
```text
0x124f (main)> view                    # Default: 41 lines + info all + live stack
0x124f (main)> view min                # Minimal: disassembly code only (alias: view only)
0x124f (main)> view raw stack          # Code + live stack only (no registers)
0x124f (main)> view nest2 30           # Root + up to 2 nested call panes, 30-line budget
0x124f (main)> view max                # Full dashboard (Code + info all + Stack)
```

Everything is controllable **live inside `view`**:
- **`Enter`** / **`s`** / **`step [N]`**: Step `1` or `N` instructions forward.
- **`n`** / **`next [N]`**: Step over calls `1` or `N` instructions.
- **`k`** / **`skip`**: Finish current function and return to caller.
- **`call <func> [--ignore]`**: Jump to upcoming call (with `Tab` autocomplete) and enter it.
- **`info`** / **`regs`**: Toggle `[REGISTERS]` panel on/off.
- **`stack`**: Toggle `[STACK]` panel on/off.
- **`info all`**: Toggle register format between `all` (`hex | dec | char | str`) and compact `hex` (or type `-h`, `-d`, `-c`, `-s`).
- **`info <reg>`** / **`get <reg>`**: Inspect one register in all formats right in the status bar.
- **`min`** / **`only`** / **`max`** / **`raw stack`** / **`all`**: Switch layouts instantaneously.
- **`size <N>`** / **`<N>`**: Change code page size on the fly.
- **`nest`** (`= nest1`), **`nest2`**, **`nest5`**, **`nest0`**: Change call-pane nesting depth on the fly. Parent caller windows stay pinned with `->` on their call site while the active callee shows `=>`, closing automatically when returning.
- **`main`**, **`start`**, **`run`**, **`continue`**, **`jump <addr>`**, **`stop <addr>`**, **`set <reg> <val>`**, **`stdin <text>`**, **`dump stack`**, **`ignore ...`**, **`0x<addr>`**, **`q`**: All work directly inside `view`.

---

## 8. Call Navigation (`call <func>`) & Call Ignoring (`ignore`)

### Targeted `call <func>`
When staring at a 40-line function like `main()` in a crackme, you often want to skip boilerplate `printf`/`strlen` setup and jump straight into `check_password`:
```text
view [...] 0x124f (main)> call ch<Tab>
view [...] 0x124f (main)> call check_password
```
1. Pressing `Tab` completes **only functions that actually exist in your binary** (`.symtab` + `.text`/`.plt` calls)—never flooding you with 2,000 unrelated `libc` symbols.
2. `bin-debug-friendly` scans ahead of `PC` for the first `call` matching `check_password`, runs right up to that `call` site, and steps 1 instruction inside `check_password` (`0x11ec`).
3. If no call to `<target>` is visible ahead of `PC`, it warns you immediately instead of hanging in the background. Pass `--ignore` (`call secret_fn --ignore`) to break globally anywhere in the binary until `secret_fn` executes.

### Call Ignoring (`ignore`)
- **`ignore call`**: Steps over every `call` until you run `unignore call`.
- **`ignore once` / `ignore call 3`**: Steps over the next `1` (or `3`) `call` instructions, then automatically resumes stepping into calls.
- **`ignore nest`**: Lets you enter one function call, then skips any deeper helper calls inside it while letting you inspect every instruction of that function.

---

## 9. Interactive `stdin` (`fgets` / `scanf` / `read`)

When debugging crackmes or CLI tools that read user input (`fgets`, `scanf`, `gets`, `getchar`, `getline`, `read`):
- The target binary's `fd 0` is wired to a dedicated sandboxed FIFO (`/tmp/work/target_stdin`), completely separate from GDB's MI2 pipe.
- Whenever you step over or run into an input call (or whenever a running target waits for input in interactive mode or `--map`), `bin-debug-friendly`:
  1. Flushes any accidental held-down `Enter` keystrokes from your terminal (`termios.tcflush`) so spamming `Enter` while stepping never skips the prompt.
  2. Prompts cleanly:
     ```text
     [INPUT] Target is calling fgets/scanf/read.
     Type stdin line + Enter (empty Enter sends '\n', Ctrl+C cancels): crackme123
     ```
  3. Feeds `"crackme123\n"` into the target and pauses cleanly right after `fgets` returns—where you immediately see `"crackme123"` light up **green** in `[STACK]`!
- You can also pre-queue input lines anytime before stepping using `stdin <text>`.

---

## 10. Smart Zero-Trimmed Stack Inspection & Dumping

Linux maps `135 KB` (`0x21000` bytes) for `[stack]`, almost all of which below `SP` is unused `0x00` guard memory.

- **`dump stack`** dumps **only the active stack (`SP` up to stack top)** and strips leading/trailing pure-zero 16-byte rows (`TRIM_STACK_DUMP_ZEROS = True`), saving `<binary>.stack.bin` (typically ~900 bytes–2 KB instead of 135 KB):
  ```text
  0x124f (main)> dump stack
  [+] Dumped 928 bytes (0x7fffffffec60-0x7ffffffff000, active SP trimmed) -> ./main.stack.bin
      Inspect with: xxd main.stack.bin | less
  ```
- **`dump stack full`** dumps the entire raw `[stack]` VMA if needed.
- **`stack less`** opens the active stack directly inside `less`.
- **`stack info`** prints exact `[stack]` start/end addresses, total mapped size, active bytes, and unused bytes.

---

## 11. Session Recording (`--record`)

Launch with `-record` or `--record`:
```bash
python3 main.py ./crackme -m --record
```

Every action is recorded into a timestamped folder:
```text
record-crackme_23-11-2026_14-04-27/
├── full_recording.txt          # Chronological session events
└── functions/                  # Created when function events occur
    ├── func_main.txt
    ├── func_check_password.txt
    └── func_build_password.txt
```

### What Gets Recorded
- **Per-Event Header:** Event number, European 24h timestamp (`DD-MM-YYYY HH:MM:SS.uuuuuu`), exact command typed, execution duration (`ms`), current `objdump`-style address, and function name.
- **Disassembly Context:** `+/- RECORD_DISAS_CONTEXT` instructions (`4` behind, `=>` current, `4` ahead).
- **Exact Diffs:** `CHANGED` register summary, `STDOUT` output, and `STACK CHANGED` rows on every step—plus **full register state & full active stack** at event #1, whenever entering a new function, and on program exit.
- **Zero Stepping Overhead:** Buffers strictly in memory during active commands and flushes to disk only while idle waiting for your next command (with `atexit`/`finally` hooks guaranteeing `Ctrl+C` never loses data).

---

## 12. Autonomous Execution Mapping (`--map` & `--func`)

Run non-interactive execution tracing across the whole binary or a single function:
```bash
# Map entire main-binary execution + stack + syscalls (starts from _start)
python3 main.py ./my_program --map

# Map from main() forward
python3 main.py ./my_program --map -m

# Map only a specific function (auto-detects return via call depth)
python3 main.py ./my_program -map -func 0x1189

# Also capture .stack.bin snapshots on every syscall
python3 main.py ./my_program --map --dump-stack-syscalls
```

Creates `<program>-mapped_<DD-MM-YYYY_HH-MM-SS>/` (non-JSON, human-readable & grep-friendly, hard-capped at `MAX_MAP_FOLDER_MB = 250` MB):
```text
my_program-mapped_23-11-2026_12-29-58/
├── full_trace.txt        # Chronological instruction trace, EU timestamps, func addr, all GPRs,
│                         # FULL ACTIVE STACK on function entry & STACK CHANGED rows on modifying steps
├── syscalls_trace.txt    # Every syscall: name, number, caller PC, time in/out, regs in, ret out
├── summary.txt           # Instruction totals, jumps/calls/rets/mem accesses, VmHWM peak memory, func & syscall tables
└── functions/
    ├── func_0x1040.txt
    ├── func_0x1139.txt
    └── func_0x1189.txt
```
- **Active Stack Tracking:** Unlike raw GDB instruction tracers, `full_trace.txt` logs `FULL ACTIVE STACK` on each function entry and `STACK CHANGED` rows on steps where the stack is modified.
- **Interactive `stdin` Support:** If the binary calls `fgets`/`scanf`/`read` during `--map`, it cleanly asks for input via `[INPUT]` without hanging in the background.
- **Clean Interrupts:** Pressing `Ctrl+C` cleanly finalizes the partial trace and records `Interrupted By User : YES` in `summary.txt`.
- **Skips `libc` / `ld.so` Clutter:** Automatically skips external shared-library instructions while still trapping callbacks back into your binary (such as `main()` from `__libc_start_main`) and logging every syscall invoked inside external calls (`write`, `newfstatat`, `brk`, `exit_group`, etc.).

---

## 13. Configuration (`src/config.py`)

Customize defaults cleanly in `src/config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `DEFAULT_INFO_FORMAT` | `"hex"` | Default format for CLI `info`/`show` (`"hex"`, `"dec"`, `"char"`, `"str"`, `"all"`). |
| `ENABLE_COLORS` | `True` | Enable green diff highlights via `colorama` when stdout is a TTY. |
| `PROMPT_SHOW_ADDRESS` | `True` | Show `objdump`-style PC in prompts (`0x126d`). |
| `PROMPT_SHOW_FUNCTION` | `True` | Show enclosing function name in prompts (`(main)`). |
| `PROMPT_SHOW_TOOL_NAME` | `False` | Prefix prompt with `PROMPT_TOOL_NAME` (`"bdf"`). |
| `USE_OBJDUMP_ADDR` | `True` | Rebase PIE addresses inside the binary to `objdump` offsets. |
| `SHOW_OPCODES_IN_DISAS` | `True` | Show raw instruction hex opcodes alongside Intel mnemonics. |
| `VIEW_PAGE_SIZE` | `41` | Default instruction page size in `view`. |
| `VIEW_DEFAULT_REGS` | `True` | Show `[REGISTERS]` panel on entering `view`. |
| `VIEW_DEFAULT_STACK` | `True` | Show `[STACK]` panel on entering `view`. |
| `VIEW_DEFAULT_REG_FORMAT` | `"all"` | Default register format in `view` (`"hex"`, `"dec"`, `"char"`, `"str"`, `"all"`). |
| `VIEW_DEFAULT_NEST` | `0` | Default nested call pane depth (`0` = active frame only). |
| `VIEW_HIGHLIGHT_CHANGES` | `True` | Mark changed registers & stack bytes with `*` and green diffs. |
| `VIEW_SPLIT_MIN_COLS` | `125` | Terminal column threshold for side-by-side split layout. |
| `COLLAPSE_STACK_ZEROS_IN_VIEW` | `True` | Collapse runs of 3+ unchanged all-zero stack rows in `view`. |
| `RECORD_DISAS_CONTEXT` | `4` | Instructions captured before & after `PC` per `--record` event. |
| `SKIP_EXTERNAL_FUNCTIONS` | `True` | Auto-skip `.plt` stubs, `ld.so`, and `libc` internals on `step`. |
| `TRIM_STACK_DUMP_ZEROS` | `True` | Trim leading/trailing zero rows in `dump stack`. |
| `MAX_MAP_FOLDER_MB` | `250` | Maximum output size (MB) for `--map` folders. |
| `MAX_MAP_INSTRUCTIONS` | `2_000_000` | Safety instruction cap for `--map` against infinite loops. |

---

## 14. Security Model (Bubblewrap Sandbox & `--no-sandbox`)

Every debugged binary and GDB session runs inside an isolated Bubblewrap container by default:
```bash
bwrap --unshare-all --cap-drop ALL --new-session --die-with-parent --clearenv ...
```
- **`/home` is completely hidden and unmounted.**
- **Zero network / internet access** (`--unshare-all`).
- **System paths (`/usr`, `/bin`, `/lib*`) are read-only.**
- **Only a disposable `/tmp/work` sandbox directory is writable.**
- **Explicit `--no-sandbox` Gate:** Disabling the sandbox displays a full-screen security warning and requires two confirmations plus typing `"I know"` explicitly before touching the host.

---

## 15. Cross-Architecture Debugging (QEMU + ARM / AArch64 / x86)

`bin-debug-friendly` inspects `e_machine` in the ELF header automatically:
- **Native (`x86_64` on `x86_64`, `i386` on `x86_64`, `aarch64` on `aarch64`):** Debugs natively inside Bubblewrap.
- **Cross-Arch (`aarch64` or `arm` on `x86_64`, etc.):** Automatically launches `qemu-<arch> -g <port>` inside the Bubblewrap sandbox and connects `gdb-multiarch` over localhost inside the isolated container—giving you exact `objdump` addressing, live `view`, register diffs, and stack inspection across architectures.

---

## 16. Real-World Reverse Engineering Walkthroughs

### Walkthrough 1: Cracking a Password-Checking Binary (`fgets` + XOR Loop)
```bash
python3 main.py ./crackme -m --record
```
1. You land paused directly at `main()`. Type `view` to open the 41-line split dashboard with `all` registers and live `[STACK]`.
2. Notice `call check_password` ahead at `0x12c4`, preceded by `call fgets@plt` at `0x1288`.
3. Type `call check<Tab>` -> `call check_password`.
4. Before `fgets@plt` executes, `bin-debug-friendly` flushes buffered keys and asks `[INPUT] Target is calling fgets/scanf/read`. Type `test123` + Enter.
5. Execution stops right at `0x11ec (check_password)` and `"test123"` appears in `[STACK]`.
6. Type `call build_password`, then `step 19` a few times—watching the XOR loop decode `"crackme123"` byte-by-byte in bright green on the stack right before `call strcmp@plt`!
7. Quit with `q` -> `q`; your complete session is saved under `record-crackme_.../full_recording.txt` and `functions/func_build_password.txt`.

### Walkthrough 2: Pairing with `binpatch` + `xxd`
1. Find an interesting offset or branch with `binpatch` (`binpatch ./app -m -d -r`).
2. Jump straight there without manual PIE math:
   ```bash
   python3 main.py ./app
   0x1040 (_start)> 0x11cd
   ```
3. Inspect registers in ASCII/string mode (`info -s` or `get rdi`), test forcing a branch via `set rax 1` or `jump 0x11e2`, or dump the active stack (`dump stack`) and inspect with `xxd app.stack.bin`.

---

## 17. Running the Test Suite

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## License

This project is licensed under the [GNU General Public License v3.0 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.html).
