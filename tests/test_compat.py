import pathlib
import unittest

import codex_compat as mod

ROOT = pathlib.Path(__file__).resolve().parents[1]
def fixture(name):
    return (ROOT / "tests" / "fixtures" / name).read_text()


class MountInfoTests(unittest.TestCase):
    def test_wslg_alias(self):
        mounts = mod.parse_mountinfo(fixture("wslg.mountinfo"))
        checks = mod.topology_findings(mounts)
        self.assertTrue(any(c.key == "mount.wslg_alias" for c in checks))
        matches = mod.match_issues(
            "error building bubblewrap command: app-server socket directory has an unsupported host mount at /mnt/wslg/distro; remove the bind-mount alias",
            {"wsl2"}, mounts,
        )
        self.assertEqual(matches[0].number, 47429)

    def test_toolbx_alias(self):
        mounts = mod.parse_mountinfo(fixture("toolbx.mountinfo"))
        checks = mod.topology_findings(mounts)
        self.assertTrue(any(c.key == "mount.toolbx_tmp_alias" for c in checks))
        matches = mod.match_issues("unsupported host mount at /run/host/tmp", {"toolbx", "podman"}, mounts)
        self.assertEqual(matches[0].number, 47674)

    def test_pam_namespace(self):
        mounts = mod.parse_mountinfo(fixture("pam.mountinfo"))
        checks = mod.topology_findings(mounts)
        self.assertTrue(any(c.key == "mount.pam_namespace" for c in checks))
        matches = mod.match_issues("unsupported host mount at /cray/tmp", {"pam-namespace"}, mounts)
        self.assertEqual(matches[0].number, 47640)

    def test_nix_stacked_mount(self):
        mounts = mod.parse_mountinfo(fixture("nix.mountinfo"))
        checks = mod.topology_findings(mounts)
        self.assertTrue(any(c.key == "mount.nix_stack" for c in checks))
        matches = mod.match_issues("unsupported host mount at /nix", {"nix-user-chroot"}, mounts)
        self.assertEqual(matches[0].number, 47455)

    def test_btrfs_generic_error(self):
        mounts = mod.parse_mountinfo(fixture("btrfs.mountinfo"))
        matches = mod.match_issues("cannot establish app-server socket mount isolation", {"btrfs"}, mounts)
        self.assertEqual(matches[0].number, 47415)

    def test_mount_escape_decode(self):
        text = "1 0 0:1 /a\\040b /x\\040y rw - ext4 /dev/x rw\n"
        m = mod.parse_mountinfo(text)[0]
        self.assertEqual(m.root, "/a b")
        self.assertEqual(m.mount_point, "/x y")


class ErrorMappingTests(unittest.TestCase):
    def test_proot_oldroot(self):
        matches = mod.match_issues("bwrap: fchdir to oldroot: No such file or directory", {"termux-proot", "proot"}, [])
        self.assertEqual(matches[0].number, 30153)

    def test_native_termux_overflowuid(self):
        matches = mod.match_issues("bwrap: Can't read /proc/sys/kernel/overflowuid: Permission denied", {"native-termux", "android"}, [])
        self.assertEqual(matches[0].number, 36399)

    def test_version_parser(self):
        self.assertEqual(mod.parse_version("codex-cli 0.159.3"), (0, 159, 3))
        self.assertIsNone(mod.parse_version("no version"))


if __name__ == "__main__":
    unittest.main()
