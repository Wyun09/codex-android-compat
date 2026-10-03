from __future__ import annotations

import errno
import fcntl
import os
import platform
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from .core import Check, Mount, parse_mountinfo, parse_version, read_text


def run_cmd(cmd: Sequence[str], timeout: float = 5.0, env: Optional[dict[str, str]] = None) -> tuple[int, str]:
    try:
        p = subprocess.run(list(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, env=env, check=False)
        return p.returncode, p.stdout.strip()
    except FileNotFoundError:
        return 127, f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        return 124, (out + "\ncommand timed out").strip()
    except OSError as exc:
        return 126, f"{type(exc).__name__}: {exc}"


def detect_codex(codex_bin: str) -> tuple[Optional[tuple[int, int, int]], str]:
    rc, out = run_cmd([codex_bin, "--version"], 4)
    return (parse_version(out), out) if rc == 0 else (None, out)


def detect_environments(mounts: Sequence[Mount]) -> set[str]:
    envs: set[str] = set()
    proc_version = read_text("/proc/version").lower()
    uname = " ".join(platform.uname()).lower()
    mount_blob = "\n".join(f"{m.root} {m.mount_point} {m.source} {m.fs_type}" for m in mounts).lower()
    environ = " ".join(f"{k}={v}" for k, v in os.environ.items()).lower()
    is_android = "android" in proc_version or Path("/system/build.prop").exists() or "termux" in environ
    is_termux = bool(os.environ.get("TERMUX_VERSION") or os.environ.get("PREFIX", "").startswith("/data/data/com.termux")) or "com.termux" in mount_blob
    is_proot = "proot" in proc_version or "proot-distro" in mount_blob or "proot" in environ
    if is_android: envs.add("android")
    if is_termux and is_proot: envs.add("termux-proot")
    elif is_termux: envs.add("native-termux")
    if is_proot: envs.add("proot")
    if "microsoft-standard-wsl" in uname or "wsl_interop" in environ or any(m.mount_point == "/mnt/wslg/distro" for m in mounts): envs.add("wsl2")
    if any(m.fs_type == "btrfs" for m in mounts): envs.add("btrfs")
    if any(m.mount_point == "/run/host/tmp" for m in mounts) or Path("/run/.containerenv").exists(): envs.update({"toolbx", "podman"})
    if "toolbox" in environ: envs.add("toolbx")
    if any(".pam_namespace" in m.root or ".pam_namespace" in m.mount_point for m in mounts) or any(m.mount_point == "/cray/tmp" for m in mounts): envs.add("pam-namespace")
    if any(m.mount_point == "/nix" for m in mounts) and "nix" in mount_blob: envs.add("nix-user-chroot")
    if Path("/dev/.cros_milestone").exists() or Path("/mnt/chromeos").exists() or "cros" in uname: envs.add("crostini")
    if not envs: envs.add("standard-linux")
    return envs


def check_bwrap(run_smoke: bool = True) -> Check:
    path = shutil.which("bwrap")
    if not path:
        return Check("bwrap", "info", "bubblewrap not installed; mount-normalization backend unavailable")
    if not run_smoke:
        return Check("bwrap", "ok", f"bubblewrap found at {path}")
    rc, out = run_cmd([path, "--ro-bind", "/", "/", "--proc", "/proc", "--dev-bind", "/dev", "/dev", "/bin/true"], 5)
    return Check("bwrap", "ok" if rc == 0 else "warn", "bubblewrap smoke test passed" if rc == 0 else "bubblewrap smoke test failed", {"returncode": rc, "output": out[:1000]})


def check_userns() -> Check:
    unshare = shutil.which("unshare")
    if not unshare:
        return Check("userns", "info", "unshare not installed; user namespace support not directly tested")
    rc, out = run_cmd([unshare, "--user", "--map-root-user", "/bin/true"], 5)
    return Check("userns", "ok" if rc == 0 else "warn", "user namespaces work" if rc == 0 else "user namespace smoke test failed", {"returncode": rc, "output": out[:1000]})


def check_selinux() -> Check:
    enforce = read_text("/sys/fs/selinux/enforce").strip()
    enabled = enforce in {"0", "1"}
    try:
        Path("/proc/sys/kernel/overflowuid").read_text()
        readable = True
    except OSError as exc:
        readable = False
        err = f"{type(exc).__name__}: {exc}"
    if enabled and not readable:
        return Check("selinux", "warn", "SELinux is present and overflowuid is not readable", {"enforce": enforce, "error": err})
    return Check("selinux", "ok" if readable else "info", "SELinux/overflowuid check passed" if readable else "overflowuid not readable", {"enforce": enforce or None})


def check_tmp() -> Check:
    tmp = Path("/tmp")
    exists, writable = tmp.exists(), os.access(tmp, os.W_OK) if tmp.exists() else False
    return Check("tmp", "ok" if exists and writable else "warn", "/tmp is writable" if exists and writable else "/tmp is missing or not writable", {"exists": exists, "writable": writable})


def check_unix_socket() -> Check:
    try:
        with tempfile.TemporaryDirectory(prefix="codex-compat-") as td:
            path = os.path.join(td, "probe.sock")
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(path); s.close()
        return Check("unix_socket", "ok", "Unix-domain socket creation works")
    except OSError as exc:
        return Check("unix_socket", "warn", "Unix-domain socket creation failed", {"error": str(exc)})


def check_flock() -> Check:
    try:
        with tempfile.NamedTemporaryFile() as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return Check("flock", "ok", "flock works")
    except OSError as exc:
        status = "info" if exc.errno in {errno.ENOSYS, errno.EOPNOTSUPP, errno.ENOTSUP} else "warn"
        return Check("flock", status, "flock unsupported or failed", {"error": str(exc)})


def codex_sandbox_probe(codex_bin: str, prefix: Optional[Sequence[str]] = None) -> tuple[int, str, list[str]]:
    command = [codex_bin, "sandbox", "linux", "--", "/bin/true"]
    if prefix:
        command = list(prefix) + command
    rc, out = run_cmd(command, 12)
    return rc, out, command


def build_mount_normalizer_prefix() -> Optional[list[str]]:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return None
    cmd = [bwrap, "--unshare-user", "--unshare-pid", "--bind", "/", "/"]
    for path in ("/dev", "/proc", "/sys", "/tmp", "/run"):
        if Path(path).exists():
            cmd += ["--bind", path, path]
    home, cwd = os.path.expanduser("~"), os.getcwd()
    for path in (home, cwd):
        if Path(path).exists():
            cmd += ["--bind", path, path]
    cmd += ["--chdir", cwd, "--"]
    return cmd


def live_mounts() -> list[Mount]:
    return parse_mountinfo(read_text("/proc/self/mountinfo"))
