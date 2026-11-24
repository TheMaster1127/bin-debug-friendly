# `bin-debug-friendly`

> **A fast, Bubblewrap-sandboxed Linux ELF debugger, stationary live-arrow TUI, execution mapper, lifecycle heap dumper, and dynamic stack/register string extractor—built to shred any runnable ELF binary (even stripped & `sstrip`ped) into clean, human-readable intelligence.**

**⚠️ PLATFORM SUPPORT: LINUX ONLY.**  
*`bin-debug-friendly` relies on Linux kernel namespaces (`bubblewrap`), `/proc/<pid>/maps` memory introspection, named FIFOs, ELF32/ELF64 binary parsing, GNU `gdb`, and optional `qemu-user` emulation.*  

**ZERO MANDATORY `pip` DEPENDENCIES:** Built 100% on the Python 3 standard library (`colorama` is purely optional for terminal diff colors and never required).

---

## Table of Contents

1. [Why `bin-debug-friendly`?](#1-why-bin-debug-friendly)
2. [You Can't Hide From This Suite](#2-you-cant-hide-from-this-suite)
3. [The Three-Tool Arsenal](#3-the-three-tool-arsenal)
4. [Quick Start & Prerequisites](#4-quick-start--prerequisites)
5. [Synopsis & Launch Flags (`main.py`)](#5-synopsis--launch-flags-mainpy)
6. [Direct Exact-Address Debugging (Zero `main+offset` Math)](#6-direct-exact-address-debugging-zero-mainoffset-math)
7. [Complete Interactive Command Reference](#7-complete-interactive-command-reference)
8. [Live View (`view`) & Nested Call Windows (`nestN`)](#8-live-view-view--nested-call-windows-nestn)
9. [Call Navigation (`call <func>`) & Call Ignoring (`ignore`)](#9-call-navigation-call-func--call-ignoring-ignore)
10. [Interactive `stdin` (`fgets` / `scanf` / `read`)](#10-interactive-stdin-fgets--scanf--read)
11. [Smart Zero-Trimmed Stack Inspection & Dumping](#11-smart-zero-trimmed-stack-inspection--dumping)
12. [Session Recording (`--record`) & Register Dereferencing (`DEREF`)](#12-session-recording---record--register-dereferencing-deref)
13. [Autonomous Execution Mapping (`--map` & `--func`)](#13-autonomous-execution-mapping---map--func)
14. [Lifecycle Heap Dumper (`heap_dump.py`)](#14-lifecycle-heap-dumper-heap_dumppy)
15. [Dynamic Stack & Register String Extractor (`stack_strings.py`)](#15-dynamic-stack--register-string-extractor-stack_stringspy)
16. [Safety Limits, Timeouts & Graceful Interrupts](#16-safety-limits-timeouts--graceful-interrupts)
17. [Configuration Reference (`src/config.py`)](#17-configuration-reference-srcconfigpy)
18. [Security Model (Bubblewrap Sandbox & `--no-sandbox`)](#18-security-model-bubblewrap-sandbox----no-sandbox)
19. [Cross-Architecture Debugging (QEMU + ARM / AArch64 / x86)](#19-cross-architecture-debugging-qemu--arm--aarch64--x86)
20. [Real-World Reverse Engineering Walkthroughs](#20-real-world-reverse-engineering-walkthroughs)
21. [Running the Test Suite](#21-running-the-test-suite)
22. [License](#license)

---

## 1. Why `bin-debug-friendly`?

Have you ever copied an address like `0x1149` straight out of `objdump`, `binpatch`, `readelf`, or a hex dump—only to watch raw GDB fight you every single step of the way?

In plain GDB:
- Debugging a PIE binary means manually calculating `runtime_base + 0x1149` or typing `b *main+0x12`.
- Stepping casually drops you inside `puts@plt`, `_dl_runtime_resolve`, and hundreds of lines of `ld-linux.so` and `libc` internals.
- Register dumps show raw hex without showing whether `RDI` or `RDX` points to `"letmein123"` or `"Wrong."`.
- Dumping `[stack]` writes `135 KB` of empty `0x00` guard memory instead of your active stack frames.
- Feeding `fgets` / `scanf` inside a debugger turns into messy TTY collisions.
- Static `strings binary` finds **nothing** when a binary decrypts its secrets onto the stack or heap at runtime.
- Feeding an **`sstrip`ped** binary (where all section headers are deleted) makes standard disassemblers and debuggers crash or refuse to work.

**`bin-debug-friendly` replaces all of that pain with a fast, unified, human-friendly reverse-engineering workflow.**  
If an ELF binary is valid and can run on Linux, you can debug it, record it, map it, dump its stack, snapshot its heap, extract its runtime strings, and tear it apart—even if it was stripped down to the bone with `strip --strip-all` or `sstrip`, or compiled into a sub-1 KB custom syscall ELF binary.

---

## 2. You Can't Hide From This Suite

Crackmes, CTFs, obfuscated tools, and malware try every trick in the book to hide secrets from static analysis. Here is how **`bin-debug-friendly`** defeats each layer automatically:

| Anti-Analysis / Hiding Trick | How `bin-debug-friendly` Defeats It |
| :--- | :--- |
| **PIE / ASLR randomization** | Automatically discovers runtime base via `/proc/<pid>/maps` / `auxv` and translates `objdump` offsets back and forth transparently. |
| **Stack-constructed / XOR-decoded secrets** | `view` lights up changed stack bytes **green** in real time; `--record` and `--map` log stack diffs; `stack_strings.py` catches secrets materializing byte-by-byte (`crac` $\rightarrow$ `crackme123`). |
| **Heap-only allocation (`malloc`, never touches stack)** | `heap_dump.py` freezes execution at `sys_read` (`fd == 0`) and dumps `[heap]` immediately, revealing heap-only buffers like `letmein123`. |
| **Just-in-time decode *after* `fgets` + `explicit_bzero` / `free` wipe** | `heap_dump.py` installs post-`stdin` traps on `strcmp`, `strncmp`, `memcmp`, `explicit_bzero`, `free`, and `exit_group`—snapshotting `[heap]` *before* the wipe (up to `16` distinct states). |
| **Register-only pointer passing** | `--map` and `--record` automatically check every GPR (`>= 0x1000`) for printable C-strings and log `DEREF: RDI->'letmein123'`; `stack_strings.py` sweeps them all up *(note: coincidental short ASCII runs inside GOT/libc pointers like `@QUUUU` also appear alongside real strings)*. |
| **`strip --strip-all` & `sstrip` (zero section headers)** | Reconstructs synthetic `.text`, `.data`, and `.shstrtab` sections past the last `PT_LOAD` segment in the sandboxed copy so GDB never crashes; recovers `main()` statically from `_start` on `x86_64` (`lea rdi, [rip+disp32]`) and `i386` (`push imm32` before `call`), and traps `main` dynamically via `X0`/`R0` when stepping `_start` on `aarch64`/`arm`. |

---

## 3. The Three-Tool Arsenal

1. **`main.py`** — The core Bubblewrap-sandboxed ELF debugger, stationary live-arrow `view` dashboard, session recorder (`--record`), and autonomous execution/syscall mapper (`--map`).
2. **`heap_dump.py`** — Standalone lifecycle heap dumper that catches `[heap]` snapshots before `stdin` reads and right before `strcmp`/`explicit_bzero`/`free`/`exit_group` wipes—working even on `sstrip`ped binaries.
3. **`stack_strings.py`** — Standalone string extractor that reconstructs all chronological stack states and `DEREF:` register targets from any `--record` or `--map` folder into a unified binary stream and deduplicated timeline.

---

## 4. Quick Start & Prerequisites

### System Requirements (Linux Only)
* **Python 3.10+** (standard library only—zero mandatory `pip` packages)
* **GNU `gdb`**
* **`bubblewrap` (`bwrap`)** — mandatory for sandboxed execution
* **Optional:**
  * `colorama` — enables bright-green byte/character change highlights in interactive TTYs
  * `qemu-user` + `gdb-multiarch` — enables cross-architecture debugging (`aarch64`, `arm`, `i386`)
  * `xxd` and `less` — for inspecting `.stack.bin` / `heap.bin` dumps and `stack less`

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

### Make Scripts Executable
```bash
chmod +x main.py heap_dump.py stack_strings.py
```

For system-wide installation (`bin-debug-friendly`, `bin-debug-friendly-heap`, `bin-debug-friendly-strings`), see [`INSTALLATION.md`](INSTALLATION.md).

---

## 5. Synopsis & Launch Flags (`main.py`)

```bash
python3 main.py <binary> [target_args...] [OPTIONS]
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-m`, `-main`, `--main` | *(none)* | Start and automatically pause at `main()`. Supports symbol-rich binaries across all architectures, plus stripped/`sstrip`ped binaries on `x86_64` and `i386` (via `_start` recovery). Also pairs with `--map` to map from `main()` forward. |
| `-A`, `-a`, `--args` | `"ARGS"` | Pass arguments to the target binary safely (supports quoted strings and escaped `\"`, e.g. `-A "-o out.txt \"hello \\\"world\\\"\""`). |
| `-record`, `--record` | *(none)* | Record every interactive command, timing, disassembly context, register diff, register dereferences (`DEREF`), full active stack, and `stdout` into `record-<bin>_<DD-MM-YYYY_HH-MM-SS>/`. |
| `-map`, `--map` | *(none)* | Run autonomous execution mapper: traces instructions, GPRs, `DEREF:` strings, active stack snapshots & diffs, system calls, and stats into `<bin>-mapped_<DD-MM-YYYY_HH-MM-SS>/`. |
| `-func`, `--func`, `--function` | `ADDR\|SYM` | With `--map`: start tracing when `ADDR` or `SYM` is entered and automatically stop when it returns. |
| `--dump-stack-syscalls` | *(none)* | With `--map`: save binary `.stack.bin` snapshots (`syscall_NNNN_<name>.stack.bin`) on every system call entry. |
| `--no-sandbox` | *(none)* | Disable Bubblewrap isolation and debug directly on the host (triggers a full-screen warning and 3-step confirmation: two yes/no prompts followed by typing `"I know"`). |

### Default Entry Behavior
- Running `python3 main.py ./binary` (without `-m`) automatically skips `ld-linux.so` loader noise and pauses cleanly at the binary's real entry point (`_start`), ready for inspection even on stripped, `sstrip`ped, or raw custom-syscall binaries.

---

## 6. Direct Exact-Address Debugging (Zero `main+offset` Math)

Whether your binary is compiled with **PIE (`-fPIE -pie`)**, **`-no-pie`**, or stripped with **`sstrip`**, you can paste addresses directly from `objdump`, `binpatch`, `readelf`, or `xxd`.

### Accepted Hex Formats
Every address command (`stop`, `0x...`, `jump`, `--func`) normalizes whitespace, quotes, case, and `0x` prefixes automatically:
- `0x1149`
- `1149`
- `0X401149`
- `"0x1149"`
- `" 0x 40 11 49 "`
- `"11 49"`

### Instant Run-To Shortcut (`0x...`)
Type any `0x`-prefixed hex address alone at the prompt (in either the main CLI or `view`):
```text
0x10a0 (_start)> 0x12c4
[+] Ran to 0x12c4 (pie_vaddr(objdump=0x12c4))
[*] Stopped (breakpoint-hit) at 0x12c4 in main
  => 0x12c4:  e8 23 ff ff ff           call   0x11ec <check_password>
```
If the program has already exited, typing `0x12c4` restarts it cleanly and runs straight there.

---

## 7. Complete Interactive Command Reference

Full `readline` history (`Up` / `Down` arrows, `Ctrl+R`, `Left`/`Right` editing) and `Tab` autocompletion are active in both the main CLI and `view`.

### Navigation, Breakpoints & Execution
| Command | Aliases | Usage & Behavior |
|---------|---------|------------------|
| **`0x<addr>`** | `"0x 11 49"` | Immediately runs (or restarts if exited) to `<addr>` and stops. |
| **`call <func> [--ignore]`** | *(Tab completes)* | Runs to the next upcoming `call <func>` ahead of `PC` and steps straight inside. Pass `--ignore` to break globally if the call isn't linearly ahead. |
| **`stop <addr\|sym>`** | `b`, `break` | Sets a persistent breakpoint at an `objdump`/hex address or symbol. |
| **`main`** | `stop main` | Runs (or restarts if exited) directly to `main()` (works on stripped/`sstrip` `x86_64`/`i386` binaries too). |
| **`start`** | `restart` | Restarts the program cleanly from the beginning and pauses at `_start`. |
| **`run`** | `r` | Resumes execution, or restarts automatically if already exited. |
| **`continue`** | `c`, `cont` | Resumes execution until the next breakpoint or exit. |
| **`jump <addr\|sym>`** | `jmp` | Forces `PC`/`RIP` immediately to `<addr>` or symbol (leaves stack and registers untouched). |

### Stepping & Batch Dumping
| Command | Aliases | Usage & Behavior |
|---------|---------|------------------|
| **`step [N]`** | `s`, `si` | Steps `1` (or `N`) instruction(s) into calls (skipping `.plt`/`libc` when `SKIP_EXTERNAL_FUNCTIONS = True`). |
| **`next [N]`** | `n`, `ni` | Steps `1` (or `N`) instruction(s) over calls (batched natively via `ni N` for instant execution). |
| **`step/next [N] dump`** | — | Steps `N` times and writes every instruction, disassembly, and all register formats to `<bin>_steps_<date>.txt`. |
| **`step/next [N] dump stack`** | — | Same as above, plus dumps `stack_start.stack.bin` and `stack_end.stack.bin` inside `<bin>_stepdump_<date>/`. |
| **`step/next [N] dump stack all`** | — | Prompts `"Are you sure? This will generate N stack dump files!"` and dumps a `.stack.bin` at every single step. |
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
| **`view [opts]`** | `follow`, `live` | Launches stationary live-arrow dashboard (see [Section 8](#8-live-view-view--nested-call-windows-nestn)). |
| **`ls [N]`** | `ls`, `ls1`, `ls10`, `ls 20` | Shows `N` instructions before & after `PC` (default `2`), clamped to `.text` with top/bottom cutoff notices. Warns if `N > 100`. |
| **`disas [N]`** | `disassemble`, `d` | Disassembles `N` instructions forward in `objdump` Intel style (`disas main [N]` supported). |
| **`info [reg] [flag]`** | `show` | Dumps all registers (or one register) formatted as `REG: value`. Flags: `-h` (hex), `-d` (dec), `-c` (char), `-s` (string/C-string deref), `all` / `-a`. |
| **`info stack`** | — | Prints all registers followed by the active stack preview. |
| **`info raw stack`** | `info stack only` | Prints only the active stack preview (no registers). |
| **`get <reg>`** | — | Case-insensitive single-register inspection in all formats (`hex \| dec \| char \| str`). |
| **`set <reg> [to] <val>`** | — | Modifies a register using hex (`0x2a`), decimal (`42`), or quoted ASCII (`"ABCD"`). |
| **`stack`** | — | Previews the top and bottom of the active stack around `SP`. |
| **`stack less`** | — | Pipes the active stack directly into `less` for interactive scrolling. |
| **`stack info`** | — | Prints `[stack]` region bounds, total mapped size, active bytes (`SP` to top), and unused bytes. |
| **`dump stack [full]`** | `stack dump` | Saves active zero-trimmed stack (or full `[stack]` VMA with `full`) to `<binary>.stack.bin` for `xxd`. |
| **`maps`** | — | Prints `/proc/<pid>/maps` memory regions of the process. |
| **`help`** / **`quit`** | `?`, `exit`, `q` | Displays command summary or exits cleanly. |

---

## 8. Live View (`view`) & Nested Call Windows (`nestN`)

Entering `view` switches into a **flicker-free, stationary dashboard** rendered in a single buffered terminal flush—no scrolling spam and no blank-screen flashes.

### What You See by Default
With the defaults in `src/config.py` (`VIEW_PAGE_SIZE = 41`, `VIEW_DEFAULT_REGS = True`, `VIEW_DEFAULT_STACK = True`, `VIEW_DEFAULT_REG_FORMAT = "all"`):
- **Left Pane:** Up to 41 Intel instructions of your current function/page (`=>` walks down without scrolling the code) + **all core registers** in `hex | dec | char | str` (automatically dereferencing pointers like `str=-> "letmein123"`).
- **Right Pane** *(on terminals `>= 125` cols wide)*: **Active `[STACK]`** starting at `SP`, automatically collapsing runs of 3+ unchanged zero lines (`... (N zero lines skipped) ...`) so you see both local variables AND `argv`/`env` together.
- **Exact Green Diffs:** Every changed register character and every individual changed stack byte (both hex pair and ASCII character) is marked with `*` and highlighted **bright green**.
- **Live Prompt Location:** Your current address and function (`0x121f (main)> `) sit right at the end of the `view` prompt.
- **Exit Output Box:** When the target terminates inside `view`, the `[EXITED]` view panel displays the full accumulated `Program Output (stdout)`.

### Launch Options & In-View Controls

```text
0x121f (main)> view                    # Default: 41 lines + info all + live stack
0x121f (main)> view min                # Minimal: disassembly code only (alias: view only)
0x121f (main)> view raw stack          # Code + live stack only (no registers)
0x121f (main)> view nest2 30           # Root + up to 2 nested call panes, 30-line budget
0x121f (main)> view max                # Full dashboard (Code + info all + Stack)
```

Everything is controllable **live inside `view`**:
- **`Enter`** / **`s`** / **`step [N]`**: Step `1` or `N` instructions forward.
- **`n`** / **`next [N]`**: Step over calls `1` or `N` instructions.
- **`k`** / **`skip`**: Finish current function and return to caller.
- **`call <func> [--ignore]`**: Jump to upcoming call (with `Tab` autocomplete) and enter it.
- **`info`** / **`regs`**: Toggle `[REGISTERS]` panel on/off.
- **`stack`**: Toggle `[STACK]` panel on/off.
- **`info all`**: Toggle register format between `all` (`hex | dec | char | str`) and compact `hex` (or use `-h`, `-d`, `-c`, `-s`).
- **`info <reg>`** / **`get <reg>`**: Inspect one register in all formats right in the status bar.
- **`min`** / **`only`** / **`max`** / **`raw stack`** / **`all`**: Switch layouts instantaneously.
- **`size <N>`** / **`<N>`**: Resize code page on the fly.
- **`nest`** (`= nest1`), **`nest2`**, **`nest5`**, **`nest0`**: Open up to `N` nested caller/callee assembly panes simultaneously (`->` marks caller call sites; `=>` tracks live `PC`).
- **`main`**, **`start`**, **`run`**, **`continue`**, **`jump <addr>`**, **`stop <addr>`**, **`set <reg> <val>`**, **`stdin <text>`**, **`dump stack`**, **`ignore ...`**, **`0x<addr>`**, **`q`**: All work directly inside `view`.

---

## 9. Call Navigation (`call <func>`) & Call Ignoring (`ignore`)

### Targeted `call <func>`
Type `call ` and press **`Tab`** to autocomplete **only functions inside your binary** (`.symtab` + `.text`/`.plt` calls—never cluttered with 2,000 unrelated `libc` functions):
```text
view [...] 0x121f (main)> call ch<Tab>
view [...] 0x121f (main)> call check_password
```
- If the call appears ahead of `PC`, `call` runs right to that call site and steps 1 instruction straight into the callee.
- If no call to `<target>` is visible ahead of `PC`, it warns you immediately instead of running away in the background. Pass `--ignore` (`call secret_fn --ignore`) to break globally anywhere in the binary until `secret_fn` executes.

### Call Ignoring (`ignore`)
- **`ignore call`** *(or `/ignore call`, `skip call`)*: Every `step` automatically steps *over* all `call` instructions until disabled.
- **`ignore once`** / **`ignore call <N>`**: Ignores the next `1` (or `N`) `call` instructions encountered, then returns to normal stepping.
- **`ignore nest`**: Allows entering 1 call deeper, then skips deeper nested helper calls inside it.
- **`unignore call`** *(or `unignore`, `unskip call`)*: Resumes stepping into calls normally.

---

## 10. Interactive `stdin` (`fgets` / `scanf` / `read`)

The target binary's `fd 0` is wired to a dedicated sandboxed FIFO (`/tmp/work/target_stdin`), completely isolated from GDB's MI2 control pipe:
- Whenever the target reads input (`fgets`, `scanf`, `gets`, `getchar`, `getline`, `read`) in interactive CLI, `view`, `--map`, or `heap_dump.py`:
  1. Flushes any accidental held-down `Enter` keys from your TTY (`termios.tcflush`) so spamming `Enter` never skips your input prompt.
  2. Prompts cleanly:
     - **Proactive prompt** *(caught before stepping over `fgets`/`scanf`/`read`)*:
       ```text
       [INPUT] Target is calling fgets/scanf/read.
       Type stdin line + Enter (empty Enter sends '\n', Ctrl+C cancels):
       ```
       Pressing **`Ctrl+C` cancels** that step without feeding stdin and keeps the target paused before the call.
     - **Running-target prompt** *(when `run`/`continue`/`--map` blocks on `stdin`)*:
       ```text
       [INPUT] Target is waiting on stdin.
       Type stdin line + Enter (empty Enter sends '\n', Ctrl+C pauses):
       ```
       Pressing **`Ctrl+C` pauses** the running inferior via `-exec-interrupt` and returns control to you.
  3. Otherwise feeds `<your_text>\n` into the target FIFO and lets execution continue past the read.
- You can also pre-queue input anytime before stepping with `stdin <text>`.

---

## 11. Smart Zero-Trimmed Stack Inspection & Dumping

Linux maps `135 KB` (`0x21000` bytes) for `[stack]`, most of which below `SP` is empty `0x00` guard memory.
- **`dump stack`** dumps **only the active stack (`SP` up to stack top)** and strips leading/trailing pure-zero 16-byte rows (`TRIM_STACK_DUMP_ZEROS = True`) into `<binary>.stack.bin` ready for `xxd`.
- **`dump stack full`** dumps the entire raw `[stack]` VMA.
- **`stack less`** opens the active stack directly inside `less`.
- **`stack info`** prints exact mapping bounds, active stack bytes, and unused space.

---

## 12. Session Recording (`--record`) & Register Dereferencing (`DEREF`)

Launch with `-record` or `--record`:
```bash
python3 main.py ./test4 --record
```

Creates `record-<binary>_<DD-MM-YYYY_HH-MM-SS>/`:
```text
record-test4_24-11-2026_12-08-18/
├── full_recording.txt          # Chronological events, disas context, stack, & DEREF strings
└── functions/                  # Per-function filtered logs (created when function events exist)
    ├── func_main.txt
    └── func_exited.txt
```

### Register Dereferencing (`DEREF`)
Even when a binary stores secrets **exclusively on the heap** (`malloc(64)`), whenever any GPR (`RAX`, `RDI`, `RSI`, `RDX`, etc.) points to a printable C-string (`>= 0x1000`), `--record` logs it automatically:
```text
[EVENT #00190] TIME=24-11-2026 12:09:12.114201 | CMD='step' | DURATION=0.49ms
  LOCATION : 0x11fe (??)
  CHANGED  : RDI=0x5555555590a0 RIP=0x5555555551fe
  DEREF    : RDI->'letmein123' | R15->'@QUUUU'
```
*(Coincidental short ASCII runs inside GOT/libc pointers like `@QUUUU` can appear alongside real strings like `letmein123`.)*

Events buffer in memory and flush to disk **only while idle at the prompt** (plus `atexit`/`finally` hooks so `Ctrl+C` never loses data).

---

## 13. Autonomous Execution Mapping (`--map` & `--func`)

Run non-interactive execution tracing across the whole binary or a single function:
```bash
# Map entire main-binary execution + stack + derefs + syscalls (from _start)
python3 main.py ./my_program --map

# Map from main() forward
python3 main.py ./my_program --map -m

# Map only a specific function (auto-detects return via call depth)
python3 main.py ./my_program -map -func 0x1199

# Also capture binary .stack.bin snapshots on every syscall
python3 main.py ./my_program --map --dump-stack-syscalls
```

Creates `<program>-mapped_<DD-MM-YYYY_HH-MM-SS>/`:
```text
my_program-mapped_24-11-2026_12-10-41/
├── full_trace.txt                  # Chronological instruction trace, EU 24h timestamps, func addr, all GPRs,
│                                   # DEREF register strings, FULL ACTIVE STACK on entry, & STACK CHANGED rows
├── syscalls_trace.txt              # Every syscall: name, number, caller PC, time in/out, regs in, ret out
├── summary.txt                     # Instruction totals, jumps/calls/rets/mem accesses, VmHWM peak memory, func & syscall tables
├── syscall_0001_write.stack.bin    # (Only created when --dump-stack-syscalls is passed)
└── functions/
    └── func_0x...txt
```

---

## 14. Lifecycle Heap Dumper (`heap_dump.py`)

**Stop guessing what's on the heap. See it.**

A companion script to `bin-debug-friendly` that captures `[heap]` across the binary's lifecycle—working on normal, stripped, and `sstrip`ped binaries inside Bubblewrap (up to `MAX_HEAP_SNAPSHOTS = 16` distinct snapshots per run).

### Three Modes
| Mode | Command | Behavior |
|---|---|---|
| **Interactive** | `python3 heap_dump.py test4` | Prompts you for stdin at `sys_read`. |
| **Scripted** | `python3 heap_dump.py test4 --input "letmein123"` | Feeds `"letmein123\n"` non-interactively. |
| **Empty** | `python3 heap_dump.py test4 --no-input` | Sends an empty `\n`. |

### How It Works
1. **Pre-Stdin Trap:** Traps kernel `sys_read` (`fd == 0`) right before stdin is read and takes a **`pre-stdin`** `[heap]` snapshot (catching secrets planted before `fgets`, and proceeding cleanly if `malloc` isn't called until after `fgets`).
2. **Post-Stdin Anti-Wipe Traps:** Feeds your input, then installs watchpoints on `libc` `.dynsym` functions (`strcmp`, `strncmp`, `memcmp`, `explicit_bzero`, `__explicit_bzero_chk`, `free`) plus `catch syscall exit_group`/`exit` (so even on `sstrip`ped targets, `[heap]` is snapshotted *before* `explicit_bzero` or `free` erases secrets written after `fgets`).
3. **Artifacts Saved to `<binary>_heapdump/`:**
   ```text
   test4_heapdump/
   ├── heap.bin            # Raw concatenated heap snapshots across the lifecycle (up to 16 states)
   ├── heap.strings.txt    # Every unique string with [phase] tags ("0xADDR  [phase]  string")
   └── stdout.txt          # Target's stdout output
   ```

### Options
| Flag | Default | Controls |
|------|---------|----------|
| `-i`, `--input` | *(none)* | Pre-feed a line of stdin (non-interactive). |
| `--no-input` | `False` | Send an empty newline `\n`. |
| `--min-len N` | `4` | Minimum string length to include. |
| `--top N` | `25` | Number of strings to print to terminal (all strings are saved to file). |
| `-A`, `-a`, `--args` | *(none)* | Pass arguments to the target binary (supports quotes and escaped `\"`). |
| `-o`, `--output` | `./<bin>_heapdump` | Custom output directory. |

### Real Observed Run on `sstrip`ped `test4`
In `test4`, `build_password(pw)` decodes `letmein123` before `fgets`, so `letmein123` is caught at `[pre-stdin]`, while post-input heap writes (`fghj`, `Password: Wrong.`) are caught at `[strcmp]` and `[pre-free]` (whereas a binary that decodes `pw` *after* `fgets` and calls `explicit_bzero`/`free` sees `pw` at `[strcmp]` / `[pre-bzero]` / `[pre-free]`):
```text
$ python3 heap_dump.py test4
[*] test4 (x86_64, PIE, sstrip=yes)
[*] Bubblewrap Sandbox active: /home hidden, --unshare-all, --cap-drop ALL, no internet
[*] Running to first stdin read...
[+] Pre-stdin [heap] snapshot: 135,168 bytes

[INPUT] Target is waiting on stdin.
Type stdin line + Enter (empty Enter sends '\n', Ctrl+C pauses): fghj
[+] Captured 6 distinct heap state(s) (811,008 bytes total)
[+] Unique heap/pointer strings: 10
  0x00005555555590f0  [pre-free    ]  'Password: Wrong.'
  0x00005555555590a0  [pre-stdin   ]  'letmein123'
  0x00005555555590f0  [pre-stdin   ]  'Password: '
  0x0000555555557dd8  [strcmp/reg  ]  '@QUUUU'
  0x00007fffffffec38  [pre-free/reg]  'ASUUUU'
  0x00007fffffffec38  [pre-free/reg]  'MSUUUU'
  0x0000555555559010  [strcmp      ]  'fghj'
  0x0000555555559010  [pre-free    ]  'YUUU'
  0x000055555555901c  [pre-free    ]  'tw4<'
  0x000055555555b1e2  [pre-free    ]  'UUUU'
[*] Target output: 'Password: Wrong.'
[+] Saved artifacts -> /home/themaster1127/GitHub_Projects/bin-debug-friendly/test4_heapdump/
```

---

## 15. Dynamic Stack & Register String Extractor (`stack_strings.py`)

Static `strings binary` only sees `.rodata`. `stack_strings.py` parses any `record-.../` folder, `...-mapped_.../` folder, or `.txt` trace, **concatenates every stack snapshot and every `DEREF:` register string across time into a raw binary file**, and extracts every unique string chronologically.

```bash
# Extract with discovery timeline and collapse partial build-up prefixes
python3 stack_strings.py ./record-test4_24-11-2026_12-08-18 -a -c
```

### Options
| Flag | Description |
|------|-------------|
| `-n`, `--min-len` | Minimum string length (default: `4`). Use `-n 1` to see 1-char build-ups. |
| `-c`, `--collapse` | Collapse incremental prefixes (e.g. keep `crackme123` and drop `crac`, `crack`, `crackme`). |
| `-a`, `--annotated` | Print `[EVENT/STEP @ location]` discovery timeline for every string. |
| `-s`, `--sort` | Sort alphabetically instead of chronological discovery order. |
| `-q`, `--quiet` | Print only unique strings to stdout (great for piping to `grep`). |
| `-b`, `--bin-out` | Custom path for concatenated binary output (`<target>_all_stacks.bin`). |
| `-o`, `--out` | Custom path for extracted strings file (`<target>_stack_strings.txt`). |

### Real Output on `sstrip`ped `test4`
```text
=== UNIQUE STRINGS FOUND (STACK & DEREF REGISTERS) ===
  [EVENT #00001                                ] /tmp/work/target_bin
  [EVENT #00001                                ] PATH=/usr/bin:/bin:/usr/sbin:/sbin
  [EVENT #00045 @  (RDX deref)                 ] 6?.7?34khi
  [EVENT #00190 @  (RDI deref)                 ] letmein123
  [EVENT #00202 @  (RAX deref)                 ] Password:
  [EVENT #00220 @  (RAX deref)                 ] ghjyk
  [EVENT #00264 @  (RAX deref)                 ] Wrong.
```
Notice it captured **both** the raw encrypted XOR bytes (`6?.7?34khi`) *and* the final decrypted password (`letmein123`)—straight from an `sstrip`ped binary!

---

## 16. Safety Limits, Timeouts & Graceful Interrupts

To prevent runaway loops, frozen sockets, or disk exhaustion:

1. **Interactive Batch Step Cap (`MAX_INTERACTIVE_STEPS = 100_000`):**  
   Bounds single `step <N>` / `next <N>` commands to `1..100,000` instructions.
2. **Mapper Instruction Cap (`MAX_MAP_INSTRUCTIONS = 2_000_000`):**  
   If a target enters an infinite or runaway loop during `--map`, tracing halts cleanly after **2,000,000 instructions** and writes `summary.txt`.
3. **Mapper Disk Size Cap (`MAX_MAP_FOLDER_MB = 250`):**  
   If `--map` output reaches **250 MB**, writing halts cleanly and `summary.txt` records `Truncated By Size Cap : YES`.
4. **Heap Snapshot Cap (`MAX_HEAP_SNAPSHOTS = 16`):**  
   `heap_dump.py` captures up to **16** distinct `[heap]` states per run (and up to `200` trap stops) before releasing the target to exit.
5. **Non-Interactive Wait Timeout (`30.0` seconds):**  
   When no `stdin` prompt handler is attached (e.g., `heap_dump.py --input` if a target loops onto a second blocking `fgets`, or automated waits), `wait_stopped(timeout=30.0)` returns `None` after **30 seconds**; `heap_dump.py` then detaches traps or lets `finally: session.close()` tear down the sandbox cleanly and return to your shell. (Single MI commands also enforce `GDB_CMD_TIMEOUT_S = 15.0`.)
6. **Graceful `Ctrl+C` Behavior:**
   - **`--map`:** Halts tracing, flushes any open syscall/stack record, and writes `summary.txt` with `Interrupted By User : YES`.
   - **`--record`:** Flushes all buffered events and closes `full_recording.txt` with `=== RECORDING CLOSED AT ... ===`.
   - **Interactive CLI / `view`:** Pauses the running inferior via `-exec-interrupt` (or cancels a proactive stdin prompt).
   - **`heap_dump.py`:** Aborts cleanly and tears down the Bubblewrap sandbox via `finally: session.close()`.

---

## 17. Configuration Reference (`src/config.py`)

| Setting | Default | Description |
|---------|---------|-------------|
| `DEFAULT_INFO_FORMAT` | `"hex"` | Default format for CLI `info`/`show` (`"hex"`, `"dec"`, `"char"`, `"str"`, `"all"`). |
| `ENABLE_COLORS` | `True` | Enable TTY-only green diff highlights via optional `colorama`. |
| `PROMPT_SHOW_ADDRESS` | `True` | Show `objdump`-style PC in prompts (`0x121f`). |
| `PROMPT_SHOW_FUNCTION` | `True` | Show enclosing function name in prompts (`(main)`). |
| `PROMPT_SHOW_TOOL_NAME` | `False` | Prefix prompt with `PROMPT_TOOL_NAME` (`"bdf"`). |
| `PROMPT_TOOL_NAME` | `"bdf"` | Fallback/prefix tool label in prompts. |
| `USE_OBJDUMP_ADDR` | `True` | Rebase PIE addresses inside the binary to `objdump` offsets. |
| `SHOW_OPCODES_IN_DISAS` | `True` | Show raw instruction hex opcodes alongside Intel mnemonics. |
| `VIEW_PAGE_SIZE` | `41` | Default instruction page size in `view`. |
| `VIEW_DEFAULT_REGS` | `True` | Show `[REGISTERS]` panel on entering `view`. |
| `VIEW_DEFAULT_STACK` | `True` | Show `[STACK]` panel on entering `view`. |
| `VIEW_DEFAULT_REG_FORMAT` | `"all"` | Default register format in `view` (`"hex"`, `"dec"`, `"char"`, `"str"`, `"all"`). |
| `VIEW_DEFAULT_NEST` | `0` | Default nested call pane depth (`0` = active frame only). |
| `VIEW_HIGHLIGHT_CHANGES` | `True` | Mark changed registers & stack bytes with `*` and green diffs. |
| `VIEW_SPLIT_MIN_COLS` | `125` | Terminal column threshold for side-by-side split layout. |
| `VIEW_STACK_ROWS` | `14` | Fallback stack rows on narrow terminals. |
| `COLLAPSE_STACK_ZEROS_IN_VIEW` | `True` | Collapse runs of 3+ unchanged all-zero stack lines in `view`. |
| `RECORD_DISAS_CONTEXT` | `4` | Instructions captured before & after `PC` per `--record` event. |
| `SKIP_EXTERNAL_FUNCTIONS` | `True` | Auto-skip `.plt` stubs, `ld.so`, and `libc` internals on `step`. |
| `TRIM_STACK_DUMP_ZEROS` | `True` | Trim leading/trailing zero rows in `dump stack`. |
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

---

## 18. Security Model (Bubblewrap Sandbox & `--no-sandbox`)

Every debugged binary, GDB instance, and `heap_dump.py` run executes inside an air-gapped Bubblewrap container by default:
```bash
bwrap --unshare-all --cap-drop ALL --new-session --die-with-parent --clearenv ...
```
- **`/home` is completely unmounted and invisible.**
- **Zero network / internet access** (`--unshare-all`).
- **System paths (`/usr`, `/bin`, `/lib*`) are read-only.**
- **Only a disposable `/tmp/work` directory is writable.**
- **Explicit `--no-sandbox` Gate:** Disabling the sandbox displays a full-screen warning and requires a 3-step confirmation (two yes/no prompts followed by typing `"I know"`) before touching the host.

---

## 19. Cross-Architecture Debugging (QEMU + ARM / AArch64 / x86)

`bin-debug-friendly` inspects `e_machine` in the ELF header automatically:
- **Native (`x86_64` on `x86_64`, `i386` on `x86_64`, `aarch64` on `aarch64`):** Debugs natively inside Bubblewrap.
- **Cross-Arch (`aarch64` or `arm` on `x86_64`, etc.):** Automatically launches `qemu-<arch> -g <port>` inside the Bubblewrap sandbox and connects `gdb-multiarch` over localhost inside the isolated container—giving you exact `objdump` addressing, live `view`, register diffs, and stack inspection across architectures.

---

## 20. Real-World Reverse Engineering Walkthroughs

### Walkthrough 1: Shredding a Completely `sstrip`ped Heap Crackme (`test4`)
```bash
# 1. Dump the heap right before stdin AND before free/bzero wipes
python3 heap_dump.py ./test4 --input test

# 2. Or record interactively with DEREF register tracking, then extract all secrets
python3 main.py ./test4 --record
python3 stack_strings.py ./record-test4_... -a -c
```
Both routes uncover `letmein123` immediately—even with zero symbols and zero section headers!

### Walkthrough 2: Cracking a Stack XOR Loop in Live `view`
```bash
python3 main.py ./crackme -m --record
```
1. Type `view` to open the 41-line split dashboard (`all` registers + live `[STACK]`).
2. Type `call check<Tab>` $\rightarrow$ `call check_password`, and feed `fgets` when prompted so execution enters `check_password`.
3. Because execution is now paused inside `check_password`, typing `call build_password` scans forward from `check_password`'s body and steps straight into the XOR loop.
4. Hold `Enter` or type `step 19` to watch the XOR loop decode `"crackme123"` byte-by-byte in bright green on the stack.
5. Run `python3 stack_strings.py ./record-crackme_... -c -a` to extract the full timeline.

### Walkthrough 3: Debugging Sub-1 KB Custom-Syscall ELF Binaries
```bash
python3 main.py ./tiny_syscall_bin
0x4001dd> ignore call
0x4001dd> view
```
Even on minimal hand-assembled or debloated custom-syscall ELF binaries with no `libc` and 1 single `PT_LOAD` segment, `bin-debug-friendly` steps cleanly through loops, tracks registers/stack, and shows all `stdout` output on exit.

---

## 21. Running the Test Suite

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## License

This project is licensed under the [GNU General Public License v3.0 (GPLv3)](https://www.gnu.org/licenses/gpl-3.0.html).
