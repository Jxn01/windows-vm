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

## Root/maintenance commands — `winvm-root` (sudo)

| Command | What it does |
|---|---|
| `winvm-root preflight` | run the pre-flight, exit 1 on any refusal |
| `winvm-root layout show\|verify\|record` | the segment map / live-GPT check / a TOML record of the live GPT |
| `winvm-root esp-manifest LABEL` | sha256 manifest of the real ESP vs the baseline |
| `winvm-root define [--test-no-marker]` | (re)define the network + both domains, keeping their UUIDs; `--test-no-marker` builds the test domain without the SMBIOS marker (for the guard's restore test, P3) |
| `winvm-root inspect start [--rw]\|stop\|cat PATH\|ls PATH` | read (or, with `--rw`, mount read-write) the **throwaway overlay's** C: from Garuda, via qemu-nbd with `max_part=0` + a loop at C:'s offset. Writes land in the overlay, never real C:. For logs a failed boot left behind, and for offline hive edits. |
| `winvm-root overlay new\|discard\|check` | the test VM's throwaway overlay |
| `winvm-root teardown DOMAIN` | remove a leftover assembled disk (both VMs off) |
| `winvm-root destroy-test` | destroy the test VM (used by `windows-vm-test-guard.service` at host shutdown) |
| `winvm-root hook …` | the libvirt qemu hook entry point (not called by hand) |

Recovery/diagnostic BCD flags for the **test** VM only: write `/run/windows-vm/bcd-flags` (root, 0600) with
lines like `safeboot=minimal` or `hypervisorlaunchtype=off`; they are applied to the private ESP's BCD, never
to real C:.

## What runs when the VM starts

1. `winvm start` runs the pre-flight; on any refusal nothing starts.
2. `virsh start` fires the libvirt **qemu hook** (`/etc/libvirt/hooks/qemu.d/windows-vm`). On `prepare` it, for
   the two domains it owns only: **audits the domain XML** (every safety rule below), **re-runs the pre-flight**,
   then **assembles the dm disk** — reads the live GPT, refuses on any drift, writes the private GPT head/tail
   images (p2/p3 blanked), rebuilds the private ESP from the real one, loop-attaches the three images, resolves
   each mapped partition by PARTUUID, `dmsetup create`s the identity table, and **proves** it (GPT equals the VM
   table, identity offsets match, and for a read-only build a real write is refused). Any failure aborts the
   start. On `release` it tears the disk down. Saved-state restores and migrations are refused outright.
3. libvirt-guests (`ON_SHUTDOWN=shutdown`, ordered after libvirtd and smb) shuts the VM down cleanly at Garuda
   shutdown; `windows-vm-test-guard.service` destroys the throwaway test VM first.

## Pre-flight checks (every reason a start is refused)

`disk` (the recorded by-id disk is a whole disk) · `fresh-reads` (the disk's and the Windows partitions' page
cache is invalidated first — the VM writes below it) · `block-size` (512/512) · `gpt` (both GPT copies valid
and identical to the recorded layout) · `partitions` (each recorded PARTUUID is that partition of that disk,
start/size as recorded) · `not-in-use` (no Windows partition mounted, swap or claimed) · `no-vm-disk` (no
`winvm-*` dm device already) · `no-saved-state` (no managed-save image) · `hibernation` (hiberfil.sys absent
or its first page zero) · `ntfs-clean` (C:'s $Volume flags are 0) · `ntfs-sector` (NTFS sector size = disk
logical) · `no-servicing` (no `WinSxS\pending.xml`) · `no-feature-update` (no `$WINDOWS.~BT\NewOS` or
`\Sources\SafeOS`) · `esp-source` (/boot/efi is the real ESP with Windows Boot Manager + BCD) · `state-dir`
(`/var/lib/windows-vm` is a NOCOW btrfs subvolume). A check that cannot look is a refusal, never a pass.

## Domain-XML audit (enforced on every start)

No TPM; firmware is the non-secureboot OVMF with Secure Boot off; nvram inside the state subvolume; S3/S4
disabled; `svm` disabled and `invtsc` required with `migratable=off` (blocks nested virt and any save/suspend);
clock `utc`; a `<panic model='hyperv'/>` device and `on_crash` ∈ {destroy, preserve, coredump-destroy};
exactly one disk, on the SATA/AHCI bus, 512-byte blocks, being exactly the assembled dm device (or, for the
test domain, the overlay over it with a backing store); no hostdev/filesystem/redirdev/smartcard; one NIC on
the NAT network with the fixed MAC; the display on a local socket only; and, for the persistent domain, the
SMBIOS marker present. The network audit checks NAT, the fixed lease and the Windows-Update sinkhole.

## Files and paths

- Code: `/usr/local/lib/windows-vm/{winvm/*.py, winvm-root}`, `/usr/local/bin/winvm`.
- Config: `/etc/windows-vm/layout.toml` (the recorded disk), `/etc/windows-vm/smb-password` (0600, generated).
- State (nested btrfs subvolume, NOCOW, outside snapper): `/var/lib/windows-vm/` — `disk/` (GPT images +
  private ESP), `qemu/` (OVMF nvram, the overlay), `log/` (hook log, ESP refresh/manifest).
- libvirt: domains `windows` and `windows-test`; network `default`; hooks `qemu.d/windows-vm`,
  `network.d/windows-vm-smb`.
- Units/config: `/etc/conf.d/libvirt-guests` + a drop-in; `windows-vm-test-guard.service`; udev
  `61-windows-vm.rules`; Samba `/etc/samba/smb.conf` (old one kept as `smb.conf.pre-windows-vm`).
- Rollback material (from P0): `~/Dolgok/windows-vm-backup/` (GPT, ESP tar + manifest, hives, Tasks).

## Modules (`lib/winvm/`)

`gpt.py` GPT read/rewrite (pure stdlib) · `layout.py` the identity layout, drift check, segments, dm table ·
`ntfs.py` offline NTFS reads (ntfs-3g) · `esp.py` the private ESP builder/verifier · `dm.py` assemble/prove/
tear down the disk · `bcd.py` patch the private BCD (hivex) · `probe.py` what the pre-flight reads ·
`preflight.py` the checks · `xmlgen.py` the domain/network XML and the audit · `config.py` every shared name ·
`rootcmd.py` the root CLI + hook · `cli.py` the user CLI.

## Tests

`cd tests && python3 -m unittest discover` — 142 tests: GPT/layout/dm table, every pre-flight refusal, the XML
audit, the ESP builder, NTFS parsing, BCD flags, the guest guard's static invariants (`test_guard_static.py`: no
forced registry `New-Item`, no `Move-Item` or ACL write outside their primitives, the policy table, the late start) — each with a positive control. (`Test-SafeDir` refuses reparse-point Startup folders, closing the *static* junction vector; a timed junction swap during the pre-logon restore is a residual race that needs an enabled non-admin account to exploit — none on the rig/laptop — acknowledged and recorded in KB 11-windows.md T33, where the registry-only redesign that would remove the class is proposed.)
The root end-to-end test on a synthetic disk with the real geometry: `sudo python3 -I tests/root_integration.py`.
On Windows (PowerShell 5.1, no elevation, scratch keys and a scratch folder under `%TEMP%` only), the guard's own
functions for real: policy save/apply/restore for both state.json shapes (A–C), Run parking across two VM boots (D),
and Startup shortcuts keeping their folder's permissions through park → re-secure → restore, with a planted hard
link restored untouched, and a junctioned Startup folder refused with nothing moved or written through it (E — its control proves the harness can see the junction
trap):
`powershell -NoProfile -ExecutionPolicy Bypass -File guest\test-guard-policies.ps1 [-Guard <guard.ps1>]` (exit 0 =
all PASS). `-Guard` points it at another copy, e.g. the installed `C:\ProgramData\jxn-vm\guard.ps1`.

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
