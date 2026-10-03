# Codex Android/Termux Compatibility Layer

A **zero-dependency compatibility and diagnostics layer** for OpenAI Codex on Linux-like systems with unusual mount topologies.

It is **not** a Codex fork, does not repackage Codex, and can coexist with the official CLI or community builds. Its job is to answer four questions before you lose time debugging:

1. Will this host likely trip Codex's filesystem sandbox initialization?
2. Which layer is failing: mount topology, bubblewrap, user namespaces, SELinux, `/tmp`/socket handling, or file locking?
3. Does the observed error map to a known upstream Codex issue?
4. Can Codex be launched through a reversible compatibility namespace **while keeping Codex's own sandbox enabled**?

## Why this exists

Codex's Linux sandbox contains app-server socket mount-isolation logic that examines `/proc/self/mountinfo`. Non-standard topologies can expose aliases or mount identities that are safe/normal for the host but are rejected by Codex before the requested command executes.

This project tracks the failure families reported in:

| Issue | Environment | Signature |
|---|---|---|
| #47429 | WSL2 / WSLg | `unsupported host mount at /mnt/wslg/distro` |
| #47402 | Termux + proot Debian | `cannot establish app-server socket mount isolation` |
| #30153 | Termux + proot | `bwrap: fchdir to oldroot` |
| #36399 | native Termux | Android SELinux blocks `overflowuid` |
| #47415 | Btrfs | mount/device identity mismatch family |
| #47455 | nix-user-chroot | stacked/overmounted `/nix` alias |
| #47640 | pam_namespace | private `/tmp` alias through `/cray/tmp` |
| #47674 | Podman Toolbx | `/run/host/tmp` aliases `/tmp` |
| #48523 | Chromebook Crostini | socket mount isolation failure |

Upstream issue URLs use `https://github.com/openai/codex/issues/<number>`.

## Design principles

- **No root required.**
- **Python standard library only.**
- **No Codex patching or binary replacement.**
- **Predictive checks are labeled as predictions.** The actual `codex sandbox ... /bin/true` smoke test is the authority.
- **Never silently disables the sandbox.** `danger-full-access` is available only with an explicit user flag.
- **Compatibility backend must prove that the inner Codex sandbox still works before it is used.**

## Requirements

- Python 3.9+ (Termux: `pkg install python`)
- Codex already installed if you want live Codex probing or launch wrapping
- `bwrap` is optional. It is only needed for the rootless mount-normalization backend.

## Quick start

```bash
chmod +x codex-compat
./codex-compat doctor
```

Run the harmless live Codex sandbox probe:

```bash
./codex-compat doctor --probe-codex
```

Machine-readable report:

```bash
./codex-compat doctor --probe-codex --json
```

Map a copied Codex error to a known issue:

```bash
./codex-compat map-error 'error building bubblewrap command: app-server socket directory has an unsupported host mount at /mnt/wslg/distro'
```

or:

```bash
codex ... 2>codex-error.txt
./codex-compat map-error --file codex-error.txt
```

## Layered checks

`doctor` checks, in order:

1. Environment classification: native Termux / proot / Android / WSL2 / Btrfs / Toolbx / pam_namespace / nix-user-chroot / Crostini.
2. Codex version and whether it is in the `>= 0.156.0` mount-isolation regression family.
3. `/proc/self/mountinfo` parsing and known alias/topology markers.
4. `bwrap` presence and a minimal bubblewrap smoke test.
5. User namespace support (`unshare --user --map-root-user /bin/true` when available).
6. SELinux state and whether `/proc/sys/kernel/overflowuid` is readable.
7. `/tmp` presence/writability.
8. Unix domain socket creation.
9. `flock` support.
10. Optional live Codex sandbox smoke test.

## Safe launch wrapper

```bash
./codex-compat run --
```

You can pass normal Codex arguments after `--`:

```bash
./codex-compat run -- --model gpt-5.6
```

The launch algorithm is deliberately conservative:

1. Run a harmless normal Codex sandbox smoke test.
2. If it passes, execute Codex normally.
3. If it fails, map the error to known issues.
4. If `bwrap` is available, construct a **mount-normalization namespace** and run the Codex sandbox smoke test again *inside it*.
5. Only if that inner Codex sandbox passes does the wrapper launch the requested Codex session through the same namespace.
6. If nothing passes, stop. The tool does not silently weaken protection.

Inspect what would run without executing the final Codex session:

```bash
./codex-compat run --dry-run --
```

Test only the mount-normalization backend:

```bash
./codex-compat backend-test
```

### What the `bwrap-normalize` backend is

It is an **outer mount namespace**, not the security sandbox. A non-recursive bind of `/` prevents problematic nested host aliases from automatically appearing in the child namespace; essential runtime mounts (`/dev`, `/proc`, `/sys`, `/tmp`, `/run`, HOME, and the current working directory) are rebound explicitly.

The backend is accepted only when `codex sandbox ... /bin/true` succeeds inside it. Security enforcement remains Codex's inner sandbox.

This is particularly aimed at alias families such as WSLg `/mnt/wslg/distro` and Toolbx `/run/host/tmp`. It is expected to fail on some proot/Android configurations; failure is safe and simply means the backend will not be used.

## Explicit last resort

Only when the user explicitly opts in:

```bash
./codex-compat run --allow-unsafe-fallback --
```

If the normal and compatibility backends both fail, this permits:

```text
codex -s danger-full-access ...
```

The tool prints a warning first. This removes the filesystem sandbox boundary and is intentionally **not** the default repair.

## Known limitations

- The tool does not modify system mounts, `/etc/fstab`, WSL configuration, PAM policy, SELinux policy, or Android kernel settings.
- It cannot make a kernel feature exist when user namespaces or required syscalls are unavailable.
- Native Android/Termux errors caused directly by Android SELinux may require an Android-aware Codex build/backend; a userspace wrapper cannot safely bypass SELinux.
- Some upstream Codex releases may already fix individual issue families. For that reason, version/topology matches are only warnings until the live sandbox probe reproduces the failure.
- The `bwrap-normalize` backend is intentionally self-testing and may refuse environments where nested bubblewrap is unsupported.
- `/tmp` handling in some Codex releases is internal to Codex. Setting `TMPDIR` alone is not presented as a guaranteed fix.

## Tests

The tests use synthetic mountinfo fixtures derived from the topology described in the upstream reports. They require no root and do not execute Codex.

```bash
python3 -m unittest discover -s tests -v
```

Covered fixture families:

- WSL2 / WSLg
- Podman Toolbx
- pam_namespace
- nix-user-chroot
- Btrfs
- proot `oldroot` error mapping
- native Termux `overflowuid` error mapping

## Installation

For a personal command:

```bash
install -Dm755 codex-compat "$HOME/.local/bin/codex-compat"
export PATH="$HOME/.local/bin:$PATH"
```

On Termux you can instead place it in `$PREFIX/bin`:

```bash
install -m755 codex-compat "$PREFIX/bin/codex-compat"
```

## Security notes

This project treats Codex's sandbox as a security boundary. A workaround is considered successful only when the normal Codex sandbox smoke test passes after the workaround is applied. Diagnostic checks do not mutate host mount configuration.

If you are handling sensitive code, prefer an officially supported Linux/macOS environment when practical, especially if your only alternative is `danger-full-access`.

## Project status

`0.1.0` is a functional diagnostic/launcher baseline. The next useful work is to collect sanitized `doctor --probe-codex --json` reports from affected environments and turn each reproducible topology into a fixture plus a backend regression test.
