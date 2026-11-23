# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.resolve()

# Default output format for CLI `info` / `show`:
# Options: "hex", "dec", "char", "str", "all"
DEFAULT_INFO_FORMAT = "hex"

# Enable ANSI green highlights via optional `colorama` (auto-disabled if not a TTY)
ENABLE_COLORS = True

# Prompt customization
PROMPT_SHOW_ADDRESS = True
PROMPT_SHOW_FUNCTION = True
PROMPT_SHOW_TOOL_NAME = False
PROMPT_TOOL_NAME = "bdf"

# Address & Disassembly display
USE_OBJDUMP_ADDR = True
SHOW_OPCODES_IN_DISAS = True

# Live `view` defaults
VIEW_PAGE_SIZE = 41
VIEW_DEFAULT_REGS = True
VIEW_DEFAULT_STACK = True
VIEW_DEFAULT_REG_FORMAT = "all"
VIEW_DEFAULT_NEST = 0
VIEW_HIGHLIGHT_CHANGES = True
VIEW_SPLIT_MIN_COLS = 125
VIEW_STACK_ROWS = 14
COLLAPSE_STACK_ZEROS_IN_VIEW = True

# `--record` disassembly context (instructions before and after PC)
RECORD_DISAS_CONTEXT = 4

# Automatically skip stepping inside PLT stubs & external libraries (libc, ld.so, etc.)
SKIP_EXTERNAL_FUNCTIONS = True

# Trim leading/trailing all-zero 16-byte rows when dumping the active stack (from SP upward)
TRIM_STACK_DUMP_ZEROS = True

# Maximum size of any `--map` output folder in megabytes
MAX_MAP_FOLDER_MB = 250

# Safety instruction limit for `--map` to guard against infinite loops
MAX_MAP_INSTRUCTIONS = 2_000_000

# Maximum single step/next batch count in interactive mode
MAX_INTERACTIVE_STEPS = 100_000

# Stack preview lines when running `stack` without `less`
STACK_PREVIEW_LINES = 16

# Fallback stack window (bytes) if /proc mappings are unavailable
FALLBACK_STACK_DOWN_BYTES = 4096
FALLBACK_STACK_UP_BYTES = 65536

# GDB / Sandbox timeouts (seconds)
GDB_CMD_TIMEOUT_S = 15.0
SANDBOX_SELFTEST_TIMEOUT_S = 5.0

# European timestamp formats (24-hour clock)
EU_FOLDER_TS_FORMAT = "%d-%m-%Y_%H-%M-%S"
EU_LOG_TS_FORMAT = "%d-%m-%Y %H:%M:%S"
