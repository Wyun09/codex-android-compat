from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Optional, Sequence

from .core import Check, issue_dict, known_mount_needles, match_issues, predict_issues, topology_findings
from .system import build_mount_normalizer_prefix, check_bwrap, check_flock, check_selinux, check_tmp, check_unix_socket, check_userns, codex_sandbox_probe, detect_codex, detect_environments, live_mounts

TOOL_VERSION = "0.1.0"


def report(codex_bin: str, do_codex_probe: bool = False, do_bwrap_smoke: bool = True) -> dict[str, object]:
    mounts = live_mounts()
    envs = detect_environments(mounts)
    version, version_text = detect_codex(codex_bin)
    checks: list[Check] = topology_findings(mounts)
    checks.extend([check_bwrap(do_bwrap_smoke), check_userns(), check_selinux(), check_tmp(), check_unix_socket(), check_flock()])
    observed = []
    probe = None
    if do_codex_probe and version is not None:
        rc, out, cmd = codex_sandbox_probe(codex_bin)
        observed = match_issues(out, envs, mounts)
        probe = {"returncode": rc, "command": cmd, "output": out, "sandbox_ok": rc == 0, "matched_issues": [r.number for r in observed]}
        checks.append(Check("codex.sandbox_probe", "ok" if rc == 0 else "fail", "Codex sandbox smoke test passed" if rc == 0 else "Codex sandbox smoke test failed", {"returncode": rc}))
    return {
        "tool_version": TOOL_VERSION,
        "environments": sorted(envs),
        "codex": {"binary": codex_bin, "version_text": version_text, "version": version},
        "checks": [dataclasses.asdict(c) for c in checks],
        "predicted_issues": [issue_dict(r) for r in predict_issues(version, envs, mounts)],
        "observed_issues": [issue_dict(r) for r in observed],
        "probe": probe,
        "mount_count": len(mounts),
        "known_mount_markers": sorted(known_mount_needles(mounts)),
    }


def print_human_report(data: dict[str, object]) -> None:
    print(f"Codex Compatibility Layer {data['tool_version']}")
    print("Environment: " + ", ".join(data["environments"]))
    codex = data["codex"]; assert isinstance(codex, dict)
    print(f"Codex: {codex.get('version_text') or 'not detected'}\n")
    for raw in data["checks"]:
        assert isinstance(raw, dict)
        mark = {"ok": "[OK]", "warn": "[!!]", "fail": "[XX]", "info": "[..]"}.get(str(raw.get("status")), "[--]")
        print(f"{mark} {raw.get('key')}: {raw.get('summary')}")
    observed = data.get("observed_issues") or []
    predicted = data.get("predicted_issues") or []
    if observed:
        print("\nObserved issue mapping:")
        for i in observed:
            print(f"  #{i['number']}  {i['title']}\n    {i['url']}\n    {i['advice']}")
    elif predicted:
        print("\nTopology/version risk matches (prediction, not proof):")
        for i in predicted:
            print(f"  #{i['number']}  {i['title']}\n    {i['url']}")
    probe = data.get("probe")
    if isinstance(probe, dict) and probe.get("output"):
        print("\nCodex sandbox probe output:\n" + str(probe["output"])[:4000])


def command_doctor(args: argparse.Namespace) -> int:
    data = report(args.codex, args.probe_codex, not args.no_bwrap_smoke)
    print(json.dumps(data, indent=2, ensure_ascii=False, default=list) if args.json else "", end="") if args.json else print_human_report(data)
    checks = data["checks"]; assert isinstance(checks, list)
    return 1 if any(isinstance(c, dict) and c.get("status") == "fail" for c in checks) else 0


def command_map_error(args: argparse.Namespace) -> int:
    mounts = live_mounts(); envs = detect_environments(mounts)
    text = Path(args.file).read_text(errors="replace") if args.file else args.text or sys.stdin.read()
    matches = match_issues(text, envs, mounts)
    if args.json:
        print(json.dumps([issue_dict(m) for m in matches], indent=2, ensure_ascii=False))
    elif matches:
        for m in matches:
            print(f"#{m.number} {m.title}\n{m.url}\n{m.advice}\n")
    else:
        print("No exact known-Issue mapping found for this environment/error text.")
    return 0 if matches else 1


def prepare_child_args(codex_bin: str, passthrough: Sequence[str], unsafe: bool) -> list[str]:
    return [codex_bin] + (["-s", "danger-full-access"] if unsafe else []) + list(passthrough)


def command_run(args: argparse.Namespace) -> int:
    codex_bin = args.codex
    if not shutil.which(codex_bin) and not Path(codex_bin).exists():
        print(f"codex binary not found: {codex_bin}", file=sys.stderr); return 127
    mounts = live_mounts(); envs = detect_environments(mounts)
    _, version_text = detect_codex(codex_bin)
    print(f"[codex-compat] {version_text or codex_bin}; env={','.join(sorted(envs))}", file=sys.stderr)
    normal_rc, normal_out, _ = codex_sandbox_probe(codex_bin)
    if normal_rc == 0:
        child = prepare_child_args(codex_bin, args.codex_args, False)
        if args.dry_run:
            print(json.dumps({"mode": "normal", "command": child}, ensure_ascii=False)); return 0
        os.execvp(child[0], child)
    print("[codex-compat] normal Codex sandbox probe failed.", file=sys.stderr)
    if normal_out:
        print("[codex-compat] " + normal_out.replace("\n", "\n[codex-compat] ")[:4000], file=sys.stderr)
    for m in match_issues(normal_out, envs, mounts):
        print(f"[codex-compat] maps to #{m.number}: {m.title} ({m.url})", file=sys.stderr)
    prefix = build_mount_normalizer_prefix() if args.backend in ("auto", "bwrap-normalize") else None
    if prefix:
        rc, out, probe = codex_sandbox_probe(codex_bin, prefix)
        if rc == 0:
            child = prefix + prepare_child_args(codex_bin, args.codex_args, False)
            print("[codex-compat] verified mount-normalization backend; inner Codex sandbox still passes.", file=sys.stderr)
            if args.dry_run:
                print(json.dumps({"mode": "bwrap-normalize", "probe": probe, "command": child}, ensure_ascii=False)); return 0
            os.execvp(child[0], child)
        print("[codex-compat] mount-normalization backend did not pass the inner Codex sandbox probe.", file=sys.stderr)
        if out:
            print("[codex-compat] backend: " + out.replace("\n", "\n[codex-compat] backend: ")[:4000], file=sys.stderr)
    if args.allow_unsafe_fallback:
        child = prepare_child_args(codex_bin, args.codex_args, True)
        print("[codex-compat] WARNING: explicit unsafe fallback selected; Codex filesystem sandbox will be disabled.", file=sys.stderr)
        if args.dry_run:
            print(json.dumps({"mode": "danger-full-access", "command": child}, ensure_ascii=False)); return 0
        os.execvp(child[0], child)
    print("[codex-compat] No verified compatibility backend succeeded. Refusing to silently disable the Codex sandbox.", file=sys.stderr)
    return 2


def command_backend_test(args: argparse.Namespace) -> int:
    prefix = build_mount_normalizer_prefix()
    if not prefix:
        print("bubblewrap not found; bwrap-normalize backend unavailable"); return 1
    rc, out, cmd = codex_sandbox_probe(args.codex, prefix)
    result = {"backend": "bwrap-normalize", "returncode": rc, "sandbox_ok": rc == 0, "command": cmd, "output": out}
    if args.json: print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"backend: bwrap-normalize\ninner Codex sandbox: {'PASS' if rc == 0 else 'FAIL'}\ncommand: {' '.join(cmd)}")
        if out: print(out)
    return 0 if rc == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="codex-compat", description="Diagnose and safely work around Codex Linux sandbox failures on unusual mount topologies.")
    p.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)
    d = sub.add_parser("doctor"); d.add_argument("--codex", default="codex"); d.add_argument("--probe-codex", action="store_true"); d.add_argument("--no-bwrap-smoke", action="store_true"); d.add_argument("--json", action="store_true"); d.set_defaults(func=command_doctor)
    m = sub.add_parser("map-error"); m.add_argument("text", nargs="?"); m.add_argument("--file"); m.add_argument("--json", action="store_true"); m.set_defaults(func=command_map_error)
    b = sub.add_parser("backend-test"); b.add_argument("--codex", default="codex"); b.add_argument("--json", action="store_true"); b.set_defaults(func=command_backend_test)
    r = sub.add_parser("run"); r.add_argument("--codex", default="codex"); r.add_argument("--backend", choices=("auto", "none", "bwrap-normalize"), default="auto"); r.add_argument("--allow-unsafe-fallback", action="store_true"); r.add_argument("--dry-run", action="store_true"); r.add_argument("codex_args", nargs=argparse.REMAINDER); r.set_defaults(func=command_run)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "codex_args", None) and args.codex_args[:1] == ["--"]:
        args.codex_args = args.codex_args[1:]
    return int(args.func(args))
