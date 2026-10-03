from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import Optional, Sequence

REGRESSION_BASE = (0, 156, 0)


@dataclasses.dataclass(frozen=True)
class Mount:
    mount_id: int
    parent_id: int
    device: str
    root: str
    mount_point: str
    options: str
    fs_type: str
    source: str
    super_options: str


@dataclasses.dataclass
class Check:
    key: str
    status: str
    summary: str
    details: dict[str, object] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class IssueRule:
    number: int
    title: str
    environments: tuple[str, ...]
    error_needles: tuple[str, ...]
    mount_needles: tuple[str, ...] = ()
    advice: str = ""

    @property
    def url(self) -> str:
        return f"https://github.com/openai/codex/issues/{self.number}"


ISSUE_RULES: tuple[IssueRule, ...] = (
    IssueRule(47429, "WSL2/WSLg unsupported host mount", ("wsl2",), ("unsupported host mount", "/mnt/wslg/distro"), ("/mnt/wslg/distro",), "Try the verified mount-normalization backend; avoid globally unmounting WSLg unless you understand the impact."),
    IssueRule(47402, "Termux + proot app-server socket mount isolation", ("termux-proot", "proot"), ("cannot establish app-server socket mount isolation",), (), "The failure is in Codex mount-isolation setup. Keep unsafe fallback opt-in only."),
    IssueRule(30153, "Termux + proot bwrap oldroot failure", ("termux-proot", "proot"), ("fchdir to oldroot",), (), "Prefer a compatible backend or supported host instead of disabling all isolation."),
    IssueRule(36399, "Native Termux overflowuid blocked by Android SELinux", ("native-termux", "android"), ("overflowuid", "permission denied"), (), "Android SELinux is blocking a Linux sysctl read; chmod is not a fix."),
    IssueRule(47415, "Btrfs device identity / mountinfo mismatch", ("btrfs",), ("cannot establish app-server socket mount isolation",), (), "Test current Codex first because upstream has Btrfs-specific handling."),
    IssueRule(47455, "nix-user-chroot overmounted alias", ("nix-user-chroot",), ("unsupported host mount", "/nix"), ("/nix",), "Try the verified mount-normalization backend if its inner Codex probe passes."),
    IssueRule(47640, "pam_namespace private /tmp alias", ("pam-namespace",), ("unsupported host mount",), ("/cray/tmp", "/tmp/.pam_namespace"), "Prefer a local compatibility namespace over changing site-wide PAM mount policy."),
    IssueRule(47674, "Podman Toolbx /run/host/tmp alias", ("toolbx", "podman"), ("unsupported host mount", "/run/host/tmp"), ("/run/host/tmp",), "A mount-normalization namespace can hide the duplicate host /tmp alias while keeping Codex's inner sandbox."),
    IssueRule(48523, "Chromebook Crostini socket mount isolation", ("crostini",), ("cannot establish app-server socket mount isolation",), (), "Try current Codex and the verified mount-normalization backend; do not default to danger-full-access."),
)


def _decode_mount_field(value: str) -> str:
    for old, new in {"\\040": " ", "\\011": "\t", "\\012": "\n", "\\134": "\\"}.items():
        value = value.replace(old, new)
    return value


def parse_mountinfo(text: str) -> list[Mount]:
    mounts: list[Mount] = []
    for raw in text.splitlines():
        parts = raw.split()
        if not parts or "-" not in parts:
            continue
        sep = parts.index("-")
        if sep < 6 or len(parts) < sep + 4:
            continue
        try:
            mount_id, parent_id = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        mounts.append(Mount(
            mount_id, parent_id, parts[2], _decode_mount_field(parts[3]),
            _decode_mount_field(parts[4]), parts[5], parts[sep + 1],
            _decode_mount_field(parts[sep + 2]), " ".join(parts[sep + 3:]),
        ))
    return mounts


def read_text(path: str) -> str:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""


def parse_version(text: str) -> Optional[tuple[int, int, int]]:
    m = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", text)
    return tuple(int(x) for x in m.groups()) if m else None  # type: ignore[return-value]


def known_mount_needles(mounts: Sequence[Mount]) -> set[str]:
    found: set[str] = set()
    for rule in ISSUE_RULES:
        for needle in rule.mount_needles:
            if any(needle in m.mount_point or needle in m.root for m in mounts):
                found.add(needle)
    return found


def topology_findings(mounts: Sequence[Mount]) -> list[Check]:
    checks: list[Check] = []
    points = {m.mount_point: m for m in mounts}
    if "/mnt/wslg/distro" in points:
        checks.append(Check("mount.wslg_alias", "warn", "WSLg exposes a second view of the distro filesystem at /mnt/wslg/distro"))
    if "/run/host/tmp" in points:
        checks.append(Check("mount.toolbx_tmp_alias", "warn", "Toolbx exposes host /tmp through /run/host/tmp"))
    if "/cray/tmp" in points or any(".pam_namespace" in m.root or ".pam_namespace" in m.mount_point for m in mounts):
        checks.append(Check("mount.pam_namespace", "warn", "pam_namespace/private-tmp topology detected"))
    nix = [m for m in mounts if m.mount_point == "/nix"]
    if len(nix) > 1 or nix:
        checks.append(Check("mount.nix_stack", "warn", "nix mount/overmount topology detected", {"count": len(nix)}))
    if any(m.fs_type == "btrfs" for m in mounts):
        checks.append(Check("mount.btrfs", "warn", "Btrfs filesystem detected; device identity may differ from mountinfo semantics"))
    if not checks:
        checks.append(Check("mount.topology", "ok", "No known problematic mount topology marker detected"))
    return checks


def _env_matches(rule: IssueRule, envs: set[str]) -> bool:
    return not rule.environments or any(e in envs for e in rule.environments)


def _text_matches(rule: IssueRule, text: str) -> bool:
    low = text.lower()
    return all(n.lower() in low for n in rule.error_needles)


def _mount_matches(rule: IssueRule, mounts: Sequence[Mount]) -> bool:
    if not rule.mount_needles:
        return True
    blob = "\n".join(f"{m.root} {m.mount_point}" for m in mounts).lower()
    return any(n.lower() in blob for n in rule.mount_needles)


def match_issues(text: str, envs: set[str], mounts: Sequence[Mount]) -> list[IssueRule]:
    matches = [r for r in ISSUE_RULES if _env_matches(r, envs) and _text_matches(r, text) and _mount_matches(r, mounts)]
    if matches:
        return sorted(matches, key=lambda r: (-len(r.error_needles), r.number))
    return sorted([r for r in ISSUE_RULES if _env_matches(r, envs) and _text_matches(r, text)], key=lambda r: (-len(r.error_needles), r.number))


def predict_issues(version: Optional[tuple[int, int, int]], envs: set[str], mounts: Sequence[Mount]) -> list[IssueRule]:
    if version is None or version < REGRESSION_BASE:
        return []
    predicted: list[IssueRule] = []
    for rule in ISSUE_RULES:
        if rule.number in {30153, 36399}:
            continue
        if _env_matches(rule, envs) and (not rule.mount_needles or _mount_matches(rule, mounts)):
            predicted.append(rule)
    return predicted


def issue_dict(rule: IssueRule) -> dict[str, object]:
    return {"number": rule.number, "title": rule.title, "url": rule.url, "advice": rule.advice}
