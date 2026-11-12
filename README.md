# windows-vm — run your real dual-boot Windows as a KVM VM from Linux

[![Platform: Linux](https://img.shields.io/badge/host-Linux%20%C2%B7%20KVM%20%C2%B7%20libvirt-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://libvirt.org/)
[![Guest: Windows](https://img.shields.io/badge/guest-the%20installed%20Windows%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)

Boot the **actual** Windows installation of a dual-boot machine — its own `C:` partition, not a copy — as a virtual
machine while Linux is running, so anything that needs the Windows side (a setting, an extension, a scheduled task) can
be done without rebooting. Written for the author's rig (Garuda Linux and Windows 11 on one NVMe drive), but every
machine-specific value is recorded and checked, never assumed.

Built to be safe for **both** installations: the VM sees only Windows' own partitions, at their exact on-disk
offsets, through a device-mapper disk that zero-fills everything else; it never sees the real EFI partition, the
Linux root, other drives or the real partition table. A pre-flight refuses to start whenever Windows or its volume
could be in an unsafe state, and a guard inside Windows switches off its hardware-driving autostarts (RGB, home
automation agents, updates) on a VM boot and restores them on the next real boot.

## Status

**In daily use** — `winvm start`, `winvm ssh`, `winvm stop` (142 unit tests and a root
end-to-end test on a synthetic disk with the real geometry). The one hard problem on the way is written up below
(*The 0x7B boot, solved*): worth reading if you try the same thing.

## Safety model (how both installations stay intact)

- The VM's disk is an **identity-layout device-mapper disk**: the real `p4` (MSR), `p5` (C:) and `p6` (WinRE)
  are mapped at their real byte offsets, a **private copy of the ESP** stands in for `p1`, and everything else
  (Garuda's btrfs `p2`, the FASTGAMES `p3`, all gaps) is a dm **zero** target. The disk GUID, partition GUIDs,
  numbers and LBAs are byte-identical to the real disk, so Windows sees nothing moved.
- The device-mapper target **claims `p4`/`p5`/`p6` exclusively**: Garuda cannot mount C: while the VM disk
  exists, and the disk cannot be built while C: is mounted (proven live).
- **Every test boot is read-only**: the dm device is created `--readonly` and the VM writes to a disposable
  qcow2 overlay. The read-only-ness is proven by an actual write into a dm `zero` segment, which the kernel
  refuses, before the VM is allowed to start. The real `p5` is never written or mounted.
- The **real ESP (`/boot/efi`) and the real GPT are never written.** A sha256 manifest of the ESP is compared
  against a baseline on demand (`winvm esp-manifest`); it has stayed identical across every phase.
- **No vTPM, no Secure Boot**, S3/S4 disabled, `svm` hidden from the guest (so VBS/Hyper-V cannot start in the
  VM). A `<panic>` device plus `on_crash` ∈ {destroy, preserve} means a guest bugcheck **stops** the VM instead
  of rebooting it into Automatic Repair (which would "repair" the real C:).
- Samba serves one share (`~/Shared`, mapped as S: in the VM) **only on the VM NAT network** — 445/139 are
  closed on the LAN.

## Install

```
sudo ~/Projects/windows-vm/install.sh          # idempotent; --check reports drift, changes nothing
```

Dependencies (all present on Garuda): `qemu`/`libvirt`/`virt-manager`/`virt-viewer`, `edk2-ovmf`, `samba`,
`ntfs-3g`, `dosfstools`+`mtools`, `gptfdisk`, `hivex`. What it installs and how to undo it is in
`install.sh`'s header.

## Everyday commands — `winvm`

| Command | What it does |
|---|---|
| `winvm start` | pre-flight, start the persistent VM (real C:, read-write), wait for SSH |
| `winvm stop [--timeout S]` | clean shutdown (SSH `shutdown /s /f`, else ACPI); waits, never hard-kills |
| `winvm status` | both domains, the assembled disk, the overlay, guest SSH |
| `winvm console` | **the GUI** — the whole Windows desktop in a window (virt-viewer) |
| `winvm ssh [CMD…]` | SSH into the VM (alias `windows-vm`, 192.168.122.10) |
| `winvm screenshot [FILE]` | PNG of the VM screen (`virsh screenshot`) |
| `winvm preflight` | run every pre-flight check (sudo) |
| `winvm layout [show\|verify]` | the identity layout / the live GPT vs the recorded one (sudo) |
| `winvm esp-manifest [LABEL]` | sha256 manifest of the real ESP, compared with the baseline (sudo) |
| `winvm restore-help` | how to undo guard changes / where the rollback material is |
| `winvm test new` | discard the test VM's overlay (next start makes a fresh one) |
| `winvm test start` | start the **read-only** test VM (real C: read-only + throwaway overlay) |
| `winvm test stop [--guarded]` | **destroy** the test VM (throwaway); `--guarded` shuts down cleanly if the guard reports VM mode |
| `winvm test status\|console\|ssh\|screenshot` | as above, for the test VM |

Only one of the two VMs runs at a time — they share the real C:, and the pre-flight enforces it.

### GUI

`winvm console` opens the full Windows desktop in a window (keyboard + absolute-pointer tablet; the display is
served on a local socket only). The window does **not** auto-resize and there is **no shared clipboard** —
both need guest drivers/agents installed inside Windows (virtio-gpu + spice-vdagent), which this project deliberately does
not install. The in-VM resolution is set once in
OVMF's own menu and stored in the VM's nvram, not in Windows.

More: the maintenance commands (`winvm-root`), what runs at every start, each pre-flight check and audit rule, and
the installed files are in [docs/reference.md](docs/reference.md).

## Tests

`cd tests && python3 -m unittest discover` — GPT and layout, every pre-flight refusal, the XML audit, the ESP
builder, NTFS parsing, BCD flags and the guest guard's static invariants, each with a positive control. A root
end-to-end test runs on a synthetic disk with the real geometry, and `guest\test-guard-policies.ps1` exercises the
guard's own functions on Windows. Details: [docs/reference.md](docs/reference.md).

## The 0x7B boot, solved

The first boots bugchecked **`INACCESSIBLE_BOOT_DEVICE` (0x7B, P2 `0xC0000034`)** in early kernel init — although
WinRE and winload booted fine from the same virtual disk. It looked like the classic physical-to-virtual storage
problem (filter drivers, controller bindings in the SYSTEM hive), and three such fixes were tried. All were red herrings.

**Root cause, found by dumping the crashed VM's RAM and reading `KiBugCheckData`:** P1 was the ARC name
`\ArcName\multi(0)disk(0)rdisk(0)partition(5)`. `C:` is GPT partition 5. The first version of the layout *removed*
the GPT entries of the two Linux partitions so the guest could not see them. winload builds the boot ARC name by
counting GPT **slots** (`partition(5)`), but the kernel's partition manager numbers only the **present** partitions
(1, 4, 5, 6 → 1, 2, 3, 4), so `partition(5)` did not exist. **Fix:** keep every GPT entry, so slot numbers match the
real disk, and hide the Linux partitions' *contents* instead (the device-mapper `zero` target). One line in
`layout.vm_images`; Windows booted to the login screen at once. A guard test keeps the entries from being blanked again.
