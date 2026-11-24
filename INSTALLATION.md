# Installing `bin-debug-friendly`

You can install `bin-debug-friendly` **system-wide** (available to any user from any directory, surviving reboots) or **user-only**—either automatically via `install.sh` or manually without running any script.

Once installed, three extensionless commands are placed on your `PATH` so typing **`bin-debug-friendly`** + **`Tab`** completes all three:

| Installed Command | Source Script | Purpose |
|---|---|---|
| `bin-debug-friendly` | `main.py` | Main sandboxed debugger, live `view`, `--record`, `--map` |
| `bin-debug-friendly-heap` | `heap_dump.py` | Lifecycle `[heap]` dumper |
| `bin-debug-friendly-strings` | `stack_strings.py` | Dynamic stack & register `DEREF` string extractor |

All artifacts (`.stack.bin`, `*_heapdump/`, `record-*/`, `*-mapped_*/`) are always saved into **your current working directory**, regardless of where the scripts are installed.

---

## Prerequisites

Install required dependencies before installing the tool:

```bash
# Artix / Arch Linux
sudo pacman -S --needed python gdb bubblewrap
# Optional (green terminal diffs & cross-arch QEMU):
sudo pacman -S --needed python-colorama qemu-user gdb-multiarch

# Debian / Ubuntu
sudo apt update && sudo apt install -y python3 gdb bubblewrap
# Optional:
sudo apt install -y python3-colorama qemu-user gdb-multiarch
```

---

## Option 1: Automatic Installation (`install.sh`)

Make the installer executable:
```bash
chmod +x install.sh
```

### System-Wide Install (Default — Recommended)
Installs the library modules to `/opt/bin-debug-friendly` and creates the commands in `/usr/local/bin` (accessible by all users from anywhere, persists across reboots):
```bash
./install.sh
```

### User-Only Install (No `sudo`)
Installs to `~/.local/share/bin-debug-friendly` and `~/.local/bin`:
```bash
./install.sh --user
```
*(If `~/.local/bin` is not in your `PATH`, add `export PATH="$HOME/.local/bin:$PATH"` to `~/.bashrc` or `~/.zshrc`.)*

### Uninstall
```bash
./install.sh --uninstall
# Or for --user installs:
./install.sh --user --uninstall
```

---

## Option 2: Manual Installation (Without Running `install.sh`)

> **Important:** Do **not** copy `main.py` or `heap_dump.py` alone into `/usr/local/bin` without `src/`, because they import modules from `src/`. Either install the folder to `/opt/bin-debug-friendly` with symlinks/wrappers, or symlink straight to your cloned repo.

### Method A: Manual System-Wide Install (`/opt` + `/usr/local/bin`)
```bash
# 1. Copy the application files into /opt/bin-debug-friendly
sudo mkdir -p /opt/bin-debug-friendly
sudo cp -r src main.py heap_dump.py stack_strings.py /opt/bin-debug-friendly/
sudo chmod 755 /opt/bin-debug-friendly/main.py \
               /opt/bin-debug-friendly/heap_dump.py \
               /opt/bin-debug-friendly/stack_strings.py

# 2. Symlink extensionless commands into /usr/local/bin
sudo ln -sf /opt/bin-debug-friendly/main.py /usr/local/bin/bin-debug-friendly
sudo ln -sf /opt/bin-debug-friendly/heap_dump.py /usr/local/bin/bin-debug-friendly-heap
sudo ln -sf /opt/bin-debug-friendly/stack_strings.py /usr/local/bin/bin-debug-friendly-strings
```
*(Because `main.py` and `heap_dump.py` use `Path(__file__).resolve().parent`, symlinks in `/usr/local/bin` resolve straight back to `/opt/bin-debug-friendly` to load `src/`.)*

### Method B: Symlink Directly From Your Git Clone (`~/.local/bin`)
Great if you `git pull` updates frequently—zero re-copying required:
```bash
mkdir -p ~/.local/bin
chmod +x main.py heap_dump.py stack_strings.py

ln -sf "$(pwd)/main.py" ~/.local/bin/bin-debug-friendly
ln -sf "$(pwd)/heap_dump.py" ~/.local/bin/bin-debug-friendly-heap
ln -sf "$(pwd)/stack_strings.py" ~/.local/bin/bin-debug-friendly-strings
```

Make sure `~/.local/bin` is in your shell `PATH` across reboots:
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Manual Uninstall
```bash
sudo rm -f /usr/local/bin/bin-debug-friendly \
           /usr/local/bin/bin-debug-friendly-heap \
           /usr/local/bin/bin-debug-friendly-strings
sudo rm -rf /opt/bin-debug-friendly
```

---

## Verify Installation & `-A` Target Arguments

Open a new terminal in any directory (e.g., `/tmp`) and test:
```bash
which bin-debug-friendly
bin-debug-friendly --help

# Pass flags & escaped quotes straight to the target binary with -A:
bin-debug-friendly ./my_app -A '-o output.txt "hello \"world\"" -m'
bin-debug-friendly-heap ./my_app -A '-o output.txt' --input secret
```
