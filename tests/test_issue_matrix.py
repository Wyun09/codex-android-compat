import pathlib
import unittest

import codex_compat as mod

ROOT = pathlib.Path(__file__).resolve().parents[1]
class KnownIssueMatrixTests(unittest.TestCase):
    CASES = [
        (47429, {"wsl2"}, "unsupported host mount at /mnt/wslg/distro", "/mnt/wslg/distro"),
        (47402, {"termux-proot", "proot"}, "cannot establish app-server socket mount isolation", None),
        (30153, {"termux-proot", "proot"}, "bwrap: fchdir to oldroot: No such file or directory", None),
        (36399, {"native-termux", "android"}, "bwrap: Can't read /proc/sys/kernel/overflowuid: Permission denied", None),
        (47415, {"btrfs"}, "cannot establish app-server socket mount isolation", None),
        (47455, {"nix-user-chroot"}, "unsupported host mount at /nix", "/nix"),
        (47640, {"pam-namespace"}, "unsupported host mount at /cray/tmp", "/cray/tmp"),
        (47674, {"toolbx", "podman"}, "unsupported host mount at /run/host/tmp", "/run/host/tmp"),
        (48523, {"crostini"}, "cannot establish app-server socket mount isolation", None),
    ]

    def fake_mounts(self, point):
        if not point:
            return []
        return [mod.Mount(1, 0, "0:1", "/", point, "rw", "ext4", "/dev/fake", "rw")]

    def test_all_known_issue_signatures(self):
        for number, envs, error, point in self.CASES:
            with self.subTest(issue=number):
                matches = mod.match_issues(error, envs, self.fake_mounts(point))
                self.assertIn(number, [m.number for m in matches])

    def test_0155_does_not_predict_0156_mount_regressions(self):
        mounts = self.fake_mounts("/mnt/wslg/distro")
        predicted = mod.predict_issues((0, 155, 1), {"wsl2"}, mounts)
        self.assertNotIn(47429, [m.number for m in predicted])

    def test_0156_predicts_wslg_risk(self):
        mounts = self.fake_mounts("/mnt/wslg/distro")
        predicted = mod.predict_issues((0, 156, 0), {"wsl2"}, mounts)
        self.assertIn(47429, [m.number for m in predicted])


if __name__ == "__main__":
    unittest.main()
