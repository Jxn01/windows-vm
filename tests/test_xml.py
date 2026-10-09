"""Generated libvirt XML and the audit the hook runs on every start: clean XML passes (positive control), and
each forbidden edit someone could make in virt-manager is refused."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

import helpers  # noqa: F401 - sets sys.path
from winvm import config, xmlgen

RW, TEST = config.DOMAIN, config.TEST_DOMAIN


def edit(xml: str, fn) -> str:
    root = ET.fromstring(xml)
    fn(root)
    return ET.tostring(root, encoding="unicode")


class Generated(unittest.TestCase):
    def test_audit_clean(self):  # positive control for every mutation below
        for d in config.DOMAINS:
            self.assertEqual(xmlgen.audit(xmlgen.domain_xml(d), d), [], d)
        self.assertEqual(xmlgen.audit(xmlgen.domain_xml(TEST, marker=False), TEST), [])
        self.assertEqual(xmlgen.audit_network(xmlgen.network_xml()), [])

    def test_no_kernel_disk_names_anywhere(self):  # T21
        for d in config.DOMAINS:
            x = xmlgen.domain_xml(d)
            self.assertIsNone(re.search(r"/dev/(nvme\d|sd[a-z]|dm-\d|loop\d)", x), d)

    def test_facts_in_the_generated_xml(self):
        root = ET.fromstring(xmlgen.domain_xml(RW))
        self.assertIsNone(root.find("devices/tpm"))
        self.assertEqual(root.find("os/loader").get("secure"), "no")
        self.assertEqual(root.find("os/loader").text, str(config.OVMF_CODE))
        self.assertEqual(root.find("clock").get("offset"), "utc")
        self.assertEqual(root.find("pm/suspend-to-mem").get("enabled"), "no")
        self.assertEqual(root.find("pm/suspend-to-disk").get("enabled"), "no")
        self.assertEqual(root.find("devices/disk/target").get("bus"), "sata")
        self.assertEqual(root.find("devices/disk/source").get("dev"), "/dev/mapper/winvm-rw")
        self.assertEqual(root.find("devices/interface/model").get("type"), "e1000e")
        self.assertEqual(root.find("devices/graphics/listen").get("type"), "socket")
        self.assertEqual(root.find("vcpu").text, "8")
        self.assertTrue(xmlgen.has_marker(root))
        self.assertFalse(xmlgen.has_marker(ET.fromstring(xmlgen.domain_xml(TEST, marker=False))))

    @unittest.skipUnless(shutil.which("virt-xml-validate"), "libvirt schemas not installed")
    def test_validates_against_libvirt_schema(self):
        for kind, x in (("domain", xmlgen.domain_xml(RW)), ("domain", xmlgen.domain_xml(TEST)),
                        ("network", xmlgen.network_xml())):
            with tempfile.NamedTemporaryFile("w", suffix=".xml") as f:
                f.write(x)
                f.flush()
                cp = subprocess.run(["virt-xml-validate", f.name, kind], capture_output=True, text=True)
                self.assertEqual(cp.returncode, 0, cp.stderr)


class Audit(unittest.TestCase):
    def refused(self, domain, fn, text):
        x = edit(xmlgen.domain_xml(domain), fn)
        p = xmlgen.audit(x, domain)
        self.assertTrue(any(text in m for m in p), f"{text!r} not in {p}")

    def test_tpm(self):  # T4
        self.refused(RW, lambda r: ET.SubElement(r.find("devices"), "tpm", model="tpm-crb"), "TPM")

    def test_secure_boot_loader(self):  # D3
        def f(r):
            r.find("os/loader").set("secure", "yes")
        self.refused(RW, f, "Secure Boot")

    def test_secboot_firmware_file(self):
        def f(r):
            r.find("os/loader").text = "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd"
        self.refused(RW, f, "firmware must be")

    def test_nvram_elsewhere(self):  # T16
        def f(r):
            r.find("os/nvram").text = "/var/lib/libvirt/qemu/nvram/windows_VARS.fd"
        self.refused(RW, f, "nvram")

    def test_s3_s4(self):  # T3
        def f(r):
            r.remove(r.find("pm"))
        self.refused(RW, f, "suspend-to-mem")
        self.refused(RW, f, "suspend-to-disk")

    def test_nested_virtualisation(self):  # T24
        def f(r):
            for feat in r.findall("cpu/feature"):
                if feat.get("name") == "svm":
                    feat.set("policy", "require")
        self.refused(RW, f, "svm")

    def test_invtsc_removed(self):  # the save/migration blocker
        def f(r):
            cpu = r.find("cpu")
            for feat in cpu.findall("feature"):
                if feat.get("name") == "invtsc":
                    cpu.remove(feat)
        self.refused(RW, f, "invtsc")

    def test_localtime_clock(self):
        def f(r):
            r.find("clock").set("offset", "localtime")
        self.refused(RW, f, "utc")

    def test_whole_real_disk_attached(self):  # T1
        def f(r):
            r.find("devices/disk/source").set("dev", "/dev/disk/by-id/nvme-KINGSTON_SFYR2S4T0_50026B7283A6141C")
        self.refused(RW, f, "must be exactly")

    def test_second_disk_shared_drive(self):  # T1: S:/G: as disks
        def f(r):
            d = ET.SubElement(r.find("devices"), "disk", type="block", device="disk")
            ET.SubElement(d, "source", dev="/dev/sdg")
            ET.SubElement(d, "target", dev="sda", bus="sata")
        self.refused(RW, f, "2 disks")
        self.refused(RW, f, "forbidden disk source /dev/sdg")

    def test_cdrom(self):
        def f(r):
            r.find("devices/disk").set("device", "cdrom")
        self.refused(RW, f, "cdrom")

    def test_qcow2_on_the_persistent_disk(self):
        def f(r):
            r.find("devices/disk/driver").set("type", "qcow2")
        self.refused(RW, f, "raw")

    def test_test_domain_without_backing_store(self):  # D7: writes would hit the real disk
        def f(r):
            disk = r.find("devices/disk")
            disk.remove(disk.find("backingStore"))
        self.refused(TEST, f, "backing store")

    def test_test_domain_on_the_rw_device(self):
        def f(r):
            r.find("devices/disk/backingStore/source").set("dev", "/dev/mapper/winvm-rw")
        self.refused(TEST, f, "test disk must be")

    def test_wrong_block_size(self):  # T17
        def f(r):
            r.find("devices/disk/blockio").set("logical_block_size", "4096")
        self.refused(RW, f, "512")

    def test_nvme_bus(self):  # T29: QEMU NVMe -> INACCESSIBLE_BOOT_DEVICE (measured in P2)
        def f(r):
            r.find("devices/disk/target").set("bus", "nvme")
        self.refused(RW, f, "SATA")

    def test_virtio_bus(self):  # no inbox virtio driver in Windows
        def f(r):
            r.find("devices/disk/target").set("bus", "virtio")
        self.refused(RW, f, "SATA")

    def test_hostdev(self):
        self.refused(RW, lambda r: ET.SubElement(r.find("devices"), "hostdev", mode="subsystem", type="usb"),
                     "hostdev")

    def test_bridged_nic(self):  # .3 is Garuda's; the VM stays on NAT
        def f(r):
            i = r.find("devices/interface")
            i.set("type", "bridge")
            i.find("source").attrib = {"bridge": "br0"}
        self.refused(RW, f, "NAT")

    def test_mac_changed(self):
        def f(r):
            r.find("devices/interface/mac").set("address", "52:54:00:00:00:01")
        self.refused(RW, f, "MAC")

    def test_display_on_the_network(self):  # D6: no remote display
        def f(r):
            g = r.find("devices/graphics")
            g.set("type", "vnc")
            g.find("listen").attrib = {"type": "address", "address": "0.0.0.0"}
        self.refused(RW, f, "local socket")

    def test_no_panic_device(self):  # T30
        def f(r):
            d = r.find("devices")
            d.remove(d.find("panic"))
        self.refused(RW, f, "panic")

    def test_crash_reboots(self):  # T30
        def f(r):
            r.find("on_crash").text = "restart"
        self.refused(RW, f, "on_crash")

    def test_crash_preserve_is_allowed(self):  # preserve freezes the BSOD; it does not reboot into repair
        x = edit(xmlgen.domain_xml(RW), lambda r: r.find("on_crash").__setattr__("text", "preserve"))
        self.assertEqual([m for m in xmlgen.audit(x, RW) if "on_crash" in m], [])

    def test_marker_missing_on_persistent(self):  # T8
        def f(r):
            r.remove(r.find("sysinfo"))
        self.refused(RW, f, "marker")

    def test_wrong_name(self):
        self.assertTrue(xmlgen.audit(xmlgen.domain_xml(TEST), RW))

    def test_network_mutations(self):
        net = xmlgen.network_xml()
        self.assertTrue(any("sinkhole" in m for m in xmlgen.audit_network(net.replace("local=/windowsupdate.com/", "x"))))
        self.assertTrue(any("NAT" in m for m in xmlgen.audit_network(net.replace("mode='nat'", "mode='route'"))))
        self.assertTrue(any("fixed lease" in m for m in xmlgen.audit_network(net.replace(config.GUEST_IP, "192.168.122.11"))))


if __name__ == "__main__":
    unittest.main()
