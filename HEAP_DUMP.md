# heap_dump.py

**Stop guessing what's on the heap. See it.**

A tiny companion to `bin-debug-friendly` that freezes your target right before
it reads input, snapshots the `[heap]`, and shows you the strings — then lets
the program finish so you see its real output. All inside the same bwrap
sandbox. No `ptrace` tricks, no root, no `/proc/PID/mem` surgery.

Built for anything from serious reverse engineering work to crackmes and CTFs.
---

## Get started in 10 seconds

    $ python heap_dump.py test3
    [*] test3 (x86_64, PIE)
    [INPUT] Target is calling fgets/scanf/read.
    Type stdin line + Enter: hjkl
    [*] heap: 135168 bytes
    [*] strings (4/4):
      0x555555559010  'hjkl'
      0x5555555590a0  'crackme123'
      0x5555555590f0  'Password: '
      0x55555555a100  'hjkl'
    [*] stdout: Password: Wrong.
    [*] saved: ./test3_heapdump/

You typed garbage. The program said `Wrong.` But the heap dump shows you
`crackme123` anyway — that's the decoded password, sitting in `pw[]`,
planted by `build_password()` before the program ever asked you anything.

Run it again with `--input crackme123` and the program says
`Access granted.` Same heap, same strings. That's the loop.

---

## Three modes. That's the whole surface.

| Mode | Command | Use when |
|---|---|---|
| **Interactive** | `python heap_dump.py test3` | You want to be prompted. Normal case. |
| **Scripted** | `python heap_dump.py test3 --input "hjkl"` | Same input every time. Repeatable. |
| **Empty** | `python heap_dump.py test3 --no-input` | Send just `\n` — see what happens with no input. |

Every mode does the same thing: stops at the first stdin call, feeds input,
dumps `[heap]`, runs the target to exit, writes three files, prints a
one-screen summary.

---

## Two knobs, if you want them

| Flag | Default | Controls |
|---|---|---|
| `--min-len N` | `4` | Minimum **length** of a string to include. Shorter strings dropped. |
| `--top N` | `20` | How many strings to **print**. All strings always saved to file. |
| `-o DIR` | `./<binary>_heapdump` | Where to write output. |

`--min-len` and `--top` are different things. `--min-len 4 --top 20` means
"include strings of 4+ chars, print the 20 longest." That's the default.

**Warning:** don't set `--min-len` above 10 or `crackme123` (10 chars)
disappears. Default is 4 for a reason.

---

## Three files, every run

    <binary>_heapdump/
    ├── heap.bin            raw bytes — feed to xxd, strings, a chunk walker
    ├── heap.strings.txt    every string, longest first, "0xADDR  'string'"
    └── stdout.txt          what the target printed

---

## Reading the string list

In the example above, `hjkl` appears twice and `crackme123` appears once:

| Address | String | What it is |
|---|---|---|
| `0x...010` | `hjkl` | Your `input[128]` buffer — what you typed |
| `0x...0a0` | `crackme123` | The `pw[64]` buffer — decoded by `build_password` **before** you typed anything |
| `0x...0f0` | `Password: ` | libc's stdout buffer, from the earlier `printf` |
| `0x...a100` | `hjkl` | libc's stdin buffer — libc keeps its own copy of your input |

The one you care about is `pw[]`. `hjkl` being there twice is normal —
it's in your `input[]` chunk and in libc's stdin buffer. Not a bug.

---

## When input doesn't satisfy the target

Some crackmes loop until input passes validation:

    do { fgets(buf, ...); } while (strlen(buf) < 8);

| Mode | Behavior |
|---|---|
| **Interactive** | Re-prompts you on every loop iteration. Type until it's happy, or Ctrl+C. |
| **`--input` / `--no-input`** | Feeds your string **once**. The next `fgets` blocks on an empty FIFO. After **30 seconds** with no progress, the tool **exits cleanly** — writes the partial stdout, kills the target, returns to your shell. |

**This is not a hang.** It's a bounded 30-second timeout followed by a clean
shutdown. Ctrl+C during those 30 seconds exits immediately.

---

## If something feels wrong

**"It printed `[+] Stopped at main` at the start."** That's the old version.
The current one prints `[*] test3 (x86_64, PIE)`. Re-save the file.

**"It hangs for hours."** Check you saved the current version:

    grep -c "for _ in range(20)" heap_dump.py   # must print 0

That line existed in a broken old build and caused a two-hour block. Current
version has zero occurrences.

**"It exits before I can type."** You're in `--input` or `--no-input` mode.
Drop those flags for interactive prompting.

---

## What's inside

- Runs the target under `bwrap --unshare-all --cap-drop ALL` — same sandbox
  `main.py` uses. No host network, no `/home`, no root.
- Uses GDB's `dump binary memory` (same mechanism as `dump_stack_to_file`).
  No `ptrace`, no `/proc/PID/mem`, no kernel modules.
- `session.close()` in `finally:` always runs. Every code path ends with a
  clean exit.

Requires Python 3.10+, `gdb`, `bubblewrap`. Must run from the project root.
