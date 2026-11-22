# Copyright (C) 2026 bin-debug-friendly contributors
# License: GNU GPLv3 (https://www.gnu.org/licenses/gpl-3.0.html)

import os
import re
import sys
import shutil
import platform
import subprocess
import tempfile
from pathlib import Path
from src.config import SANDBOX_SELFTEST_TIMEOUT_S


def detect_host_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("i386", "i686", "x86"):
        return "i386"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    if machine.startswith("arm"):
        return "arm"
    return machine


def needs_qemu(host_arch: str, target_arch: str) -> bool:
    if host_arch == target_arch:
        return False
    if host_arch == "x86_64" and target_arch == "i386":
        return False
    return True


def find_qemu_binary(target_arch: str) -> str | None:
    candidates = {
        "aarch64": ["qemu-aarch64", "qemu-aarch64-static"],
        "arm": ["qemu-arm", "qemu-arm-static"],
        "i386": ["qemu-i386", "qemu-i386-static"],
        "x86_64": ["qemu-x86_64", "qemu-x86_64-static"],
    }.get(target_arch, [])
    for name in candidates:
        p = shutil.which(name)
        if p:
            return p
    return None


def find_gdb_binary(cross_arch: bool) -> str:
    if cross_arch:
        for name in ("gdb-multiarch", "aarch64-linux-gnu-gdb", "arm-none-eabi-gdb", "gdb"):
            p = shutil.which(name)
            if p:
                return p
    p = shutil.which("gdb") or shutil.which("gdb-multiarch")
    if not p:
        sys.exit("[!] FATAL: 'gdb' is required. Install it with: sudo pacman -S gdb")
    return p


def confirm_disable_sandbox() -> bool:
    banner = (
        "\n"
        "========================================================================\n"
        "  [!!!] MASSIVE SECURITY WARNING: SANDBOX DISABLED (--no-sandbox) [!!!]\n"
        "========================================================================\n"
        "  You are about to run and debug this binary WITHOUT Bubblewrap.\n"
        "  The target program will have FULL ACCESS to:\n"
        "    - Your /home directory, SSH keys, API keys, and personal files\n"
        "    - Your network / internet connection\n"
        "    - Your system processes and devices\n\n"
        "  THIS CAN PERMANENTLY DAMAGE YOUR COMPUTER OR STEAL DATA IF THIS\n"
        "  BINARY IS NOT YOURS AND YOU DO NOT KNOW EXACTLY WHAT IS HAPPENING.\n"
        "========================================================================\n"
    )
    print(banner, file=sys.stderr)

    try:
        ans1 = input("Are you sure you want to continue? (yes / press Enter): ").strip().lower()
        if ans1 not in ("", "y", "yes"):
            print("[*] Aborted safely.")
            return False

        ans2 = input("Are you REALLY sure? This runs unsandboxed on your host! (yes / press Enter): ").strip().lower()
        if ans2 not in ("", "y", "yes"):
            print("[*] Aborted safely.")
            return False

        print("\nJust so you know, this is dangerous.")
        ans3 = input("If you really know what you're doing, type 'I know': ")
        compact = re.sub(r"\s+", "", ans3.strip()).lower()
        if "iknow" not in compact:
            print("[!] Confirmation phrase 'I know' not detected. Aborting safely.")
            return False
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Aborted safely.")
        return False

    print("[!] Sandbox disabled by user confirmation. Proceeding directly on host.\n")
    return True


class SandboxEnv:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        if self.enabled:
            if not shutil.which("bwrap"):
                sys.exit(
                    "[!] FATAL: 'bwrap' (Bubblewrap) is required for sandboxed debugging.\n"
                    "    Install with: sudo pacman -S bubblewrap\n"
                    "    (Or pass --no-sandbox if you accept full host risk.)"
                )
            self._verify_self_test()

    def build_bwrap_prefix(self, work_dir: Path, allow_loopback: bool = False) -> list[str]:
        cmd = ["bwrap"]
        for sys_dir in ("/usr", "/bin", "/sbin", "/lib", "/lib64"):
            if os.path.islink(sys_dir):
                try:
                    cmd.extend(["--symlink", os.readlink(sys_dir), sys_dir])
                except OSError:
                    pass
            elif os.path.exists(sys_dir):
                cmd.extend(["--ro-bind", sys_dir, sys_dir])

        for etc_item in (
            "/etc/ld.so.cache",
            "/etc/ld.so.conf",
            "/etc/ld.so.conf.d",
            "/etc/localtime",
            "/etc/hostname",
        ):
            if os.path.exists(etc_item):
                cmd.extend(["--ro-bind", etc_item, etc_item])

        for extra_dir in ("/usr/aarch64-linux-gnu", "/usr/arm-linux-gnueabihf"):
            if os.path.exists(extra_dir):
                cmd.extend(["--ro-bind", extra_dir, extra_dir])

        cmd.extend([
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--bind", str(work_dir.resolve()), "/tmp/work",
            "--unshare-all",
            "--cap-drop", "ALL",
            "--new-session",
            "--die-with-parent",
            "--chdir", "/tmp/work",
            "--clearenv",
            "--setenv", "PATH", "/usr/bin:/bin:/usr/sbin:/sbin",
            "--setenv", "TMPDIR", "/tmp",
            "--setenv", "HOME", "/tmp",
        ])
        return cmd

    def _verify_self_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            echo_bin = shutil.which("echo") or "/bin/echo"
            bwrap_cmd = self.build_bwrap_prefix(Path(tmp)) + [echo_bin, "BDF_SANDBOX_OK"]
            p = subprocess.run(bwrap_cmd, capture_output=True, timeout=SANDBOX_SELFTEST_TIMEOUT_S)
            if p.returncode != 0 or p.stdout != b"BDF_SANDBOX_OK\n":
                sys.exit(
                    f"[!] FATAL: Bubblewrap self-test failed: {p.stderr.decode(errors='replace')}"
                )
        print("[*] Bubblewrap Sandbox active: /home hidden, --unshare-all, --cap-drop ALL, no internet")
