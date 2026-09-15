#!/usr/bin/env python3
"""Real-media checks for the QUBES_OEM kickstart partition.

Unlike the rest of the suite these run the actual tools — sgdisk, mkfs, mount —
against a loop device holding a synthetic hybrid ISO. That is the point: the
claim being tested is about what happens to a partition table on real media,
and no amount of string matching establishes it.

Skipped, loudly, when the prerequisites are absent (not root, no loop device, no
sgdisk). A skip is reported as a skip and never as a pass.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_iso", ROOT / "build_iso.py")
bi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bi)

CHECKS = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not ok:
        raise AssertionError(f"{name}{': ' + detail if detail else ''}")


def read_sector0(dev: str) -> bytes:
    """Sector 0 verbatim. It is binary, so it is read as bytes, not decoded."""
    with open(dev, "rb") as fh:
        return fh.read(512)


def sh(*argv: str, check_rc: bool = True) -> str:
    p = subprocess.run(argv, capture_output=True, text=True)
    if check_rc and p.returncode != 0:
        raise AssertionError(f"{' '.join(argv)} failed: {p.stderr.strip()}")
    return p.stdout


def missing_prerequisite() -> str | None:
    if os.geteuid() != 0:
        return "not running as root"
    for tool in ("sgdisk", "losetup", "blkid", "mkfs.ext4"):
        if not shutil.which(tool):
            return f"{tool} is not installed"
    if not Path("/dev/loop-control").exists():
        return "no loop device support"
    return None


def build_synthetic_hybrid_iso(path: Path, mib: int = 48) -> None:
    """A GPT + hybrid-MBR image shaped like the one xorrisofs produces.

    Partition 1 is the ISO data, partition 2 the EFI image appended by
    `-append_partition 2 0xef`, and `sgdisk -h` writes the hybrid MBR that
    isohybrid booting needs — the structure that matters for this test.
    """
    with path.open("wb") as fh:
        fh.truncate(mib * 1024 * 1024)
    sh("sgdisk", "-o", str(path))
    sh("sgdisk", "-n", "1:2048:81919", "-t", "1:0700", "-c", "1:ISO9660", str(path))
    sh("sgdisk", "-n", "2:81920:90111", "-t", "2:ef00", "-c", "2:EFI", str(path))
    sh("sgdisk", "-h", "1:2", str(path))


def ctx(work: Path, fstype: str) -> bi.Ctx:
    cfg = dict(bi.DEFAULT_CONFIG)
    cfg["work_dir"] = str(work)
    cfg["install"] = dict(cfg["install"], oem_fstype=fstype)
    args = SimpleNamespace(action="write-usb", dry_run=False, device=None,
                           oem_device=None, no_oem=False, force=False,
                           allow_fixed_disk=False, wait=False)
    return bi.Ctx(cfg, args)


def main() -> int:
    reason = missing_prerequisite()
    if reason:
        print(f"\n  SKIP  QUBES_OEM media checks — {reason}.")
        print("        These need root and a loop device; they are the only "
              "proof that\n        appending the partition leaves the hybrid "
              "MBR intact.")
        return 0

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        iso = work / "iso.img"
        stick = work / "stick.img"
        build_synthetic_hybrid_iso(iso)
        # A stick larger than the image, written the way write-usb writes it.
        with stick.open("wb") as fh:
            fh.truncate(256 * 1024 * 1024)
        sh("dd", f"if={iso}", f"of={stick}", "conv=notrunc", "status=none")

        loop = sh("losetup", "-f", "--show", "-P", str(stick)).strip()
        check("loop device attached", loop.startswith("/dev/loop"), loop)
        try:
            mbr_before = read_sector0(loop)
            gpt_before = _partition_numbers(loop)
            check("synthetic ISO has the two ISO partitions",
                  gpt_before == {1, 2}, str(gpt_before))

            x = ctx(work, "ext4")
            ks = bi.oem_kickstart_path(x)
            ks.parent.mkdir(parents=True, exist_ok=True)
            ks.write_text("# install-time kickstart\n%post\necho hi\n%end\n")

            bi.write_oem_partition(x, loop, ks)

            # 1. The isohybrid MBR is what BIOS boots from. If appending a
            #    partition rewrote it, every stick made this way would be
            #    unbootable on legacy firmware.
            mbr_after = read_sector0(loop)
            check("sector 0 (isohybrid MBR) is byte-identical",
                  mbr_after == mbr_before)

            # 2. Exactly one partition was added, and the ISO's own two are
            #    untouched.
            after = _partition_numbers(loop)
            new = sorted(after - gpt_before)
            check("exactly one partition added", len(new) == 1, str(new))
            check("the ISO partitions survive", {1, 2} <= after, str(after))

            part = bi.partition_node(loop, new[0])
            # 3. GRUB's `search -l QUBES_OEM` matches on the filesystem label
            #    and nothing else. The literal is spelled out rather than
            #    compared against bi.OEM_LABEL: this has to agree with
            #    qubes-lorax-templates' grub2-bios.cfg and grub2-efi.cfg, so
            #    checking our own constant against itself would pass no matter
            #    what either said.
            label = sh("blkid", "-s", "LABEL", "-o", "value", part).strip()
            check("filesystem label is exactly QUBES_OEM (the label Qubes' "
                  "own GRUB searches for)", label == "QUBES_OEM", label)
            check("the constant matches the label Qubes' GRUB searches for",
                  bi.OEM_LABEL == "QUBES_OEM", bi.OEM_LABEL)

            # 3b. The partition has to claim the free space on the STICK, not
            #     the sliver left inside the ISO's extent. `dd` of a hybrid ISO
            #     leaves the backup GPT — and with it "last usable sector" —
            #     at the end of the image, so without relocating it first the
            #     new partition is capped at whatever slack the ISO happened
            #     to have. Measured: 4 MiB without the relocation against
            #     212 MiB with it, on this 256 MiB stick over a 48 MiB image.
            #     A real ISO with no slack leaves no room at all.
            end_sector = _partition_end(loop, new[0])
            device_sectors = int(sh("blockdev", "--getsz", loop).strip())
            iso_sectors = iso.stat().st_size // 512
            check("the OEM partition extends past the end of the ISO image",
                  end_sector > iso_sectors,
                  f"ends at {end_sector}, ISO ends at {iso_sectors}")
            check("the OEM partition claims most of the remaining stick",
                  end_sector > device_sectors * 0.9,
                  f"ends at {end_sector} of {device_sectors}")

            # 4. The kickstart is really on the stick, not just in a cache.
            mnt = work / "mnt"
            mnt.mkdir()
            sh("mount", part, str(mnt))
            try:
                got = (mnt / "ks.cfg").read_text()
            finally:
                sh("umount", str(mnt), check_rc=False)
            check("ks.cfg on the media matches the generated kickstart",
                  got == ks.read_text())

            # 5. partition_node has to be right for both naming conventions or
            #    the mkfs lands on the wrong device.
            check("partition_node handles sdX", bi.partition_node("/dev/sdb", 3)
                  == "/dev/sdb3")
            check("partition_node handles nvme",
                  bi.partition_node("/dev/nvme0n1", 3) == "/dev/nvme0n1p3")
            # An operator may name the stick by its stable id. The suffix
            # belongs on the kernel node the link resolves to, not on the link:
            # /dev/disk/by-id/usb-X3 does not exist, /dev/sdb3 does.
            link = work / "usb-Vendor_Model_SERIAL-0:0"
            link.symlink_to("/dev/sdb")
            check("partition_node resolves a by-id style symlink first",
                  bi.partition_node(str(link), 3) == "/dev/sdb3",
                  bi.partition_node(str(link), 3))

            # 5b. A second device named with --oem-device gets the guards the
            #     image stick got: removable, nothing mounted, confirmed.
            from unittest import mock
            g = ctx(work, "ext4")
            with mock.patch.object(bi, "removable_devices", return_value=[]), \
                    mock.patch.object(bi, "_mounted_partitions", return_value=[]):
                try:
                    bi.guard_second_device(g, "/dev/sdz")
                except bi.Fatal as exc:
                    check("a non-removable --oem-device is refused",
                          "not a removable device" in str(exc), str(exc))
                else:
                    raise AssertionError("fixed disk accepted as --oem-device")
            stick = [{"dev": "/dev/sdz", "size": 8e9, "model": "Stick"}]
            with mock.patch.object(bi, "removable_devices", return_value=stick), \
                    mock.patch.object(bi, "_mounted_partitions", return_value=["/dev/sdz1"]):
                try:
                    bi.guard_second_device(g, "/dev/sdz")
                except bi.Fatal as exc:
                    check("a mounted --oem-device is refused", "mounted" in str(exc))
                else:
                    raise AssertionError("mounted device accepted as --oem-device")
            with mock.patch.object(bi, "removable_devices", return_value=stick), \
                    mock.patch.object(bi, "_mounted_partitions", return_value=[]), \
                    mock.patch.object(bi, "confirmed", return_value=False):
                try:
                    bi.guard_second_device(g, "/dev/sdz")
                except bi.Fatal as exc:
                    check("declining the question aborts", "aborted" in str(exc))
                else:
                    raise AssertionError("append proceeded without confirmation")
            with mock.patch.object(bi, "removable_devices", return_value=stick), \
                    mock.patch.object(bi, "_mounted_partitions", return_value=[]), \
                    mock.patch.object(bi, "confirmed", return_value=True):
                bi.guard_second_device(g, "/dev/sdz")
                check("a removable, unmounted, confirmed device passes", True)

            # 6. An unsupported filesystem is refused before anything is
            #    written, rather than producing a stick with no label.
            bad = ctx(work, "btrfs")
            try:
                bi.write_oem_partition(bad, loop, ks)
            except bi.Fatal as exc:
                check("an unsupported oem_fstype is refused",
                      "oem_fstype" in str(exc), str(exc))
            else:
                raise AssertionError("expected Fatal for oem_fstype=btrfs")
        finally:
            sh("losetup", "-d", loop, check_rc=False)

    print(f"  {CHECKS}/{CHECKS} QUBES_OEM media checks pass")
    return 0


def _partition_end(dev: str, number: int) -> int:
    """Last sector of a partition, straight from sgdisk."""
    import re
    for line in sh("sgdisk", "-p", dev, check_rc=False).splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+)\s+(\d+)\s", line)
        if m and int(m.group(1)) == number:
            return int(m.group(3))
    raise AssertionError(f"partition {number} not found on {dev}")


def _partition_numbers(dev: str) -> set[int]:
    import re
    found = set()
    for line in sh("sgdisk", "-p", dev, check_rc=False).splitlines():
        m = re.match(r"\s*(\d+)\s+\d+\s+\d+\s", line)
        if m:
            found.add(int(m.group(1)))
    return found


if __name__ == "__main__":
    sys.exit(main())
