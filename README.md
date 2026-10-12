# windows-vm — run the real Windows half as a KVM VM on Garuda

Boot the **actual** Windows installation (`C:` = `nvme0n1p5`) as a virtual machine on Garuda, so anything that
needs the Windows side — a Chrome extension, a setting, a scheduled task — can be done from here without
rebooting. Built to be absolutely safe for both installations: the VM only ever sees Windows' own partitions
through a read-only-by-default virtual disk, and never the real EFI partition, Garuda's root, the shared drives
or the real partition table.

Plan, decisions and status: `~/.claude/kb/records/2026-10-08-windows-vm-plan.md`. This repo is private
(`Jxn01/windows-vm`), lives in the shared tree, and follows its rules (no Linux venv inside the tree, personal
git identity).

## Status (2026-10-09)

- **P0/P1 complete.** Facts recorded, rollback material saved, host tooling built, installed and tested
  (110 unit tests + a root end-to-end test on a synthetic disk with the real geometry).
- **P2 blocked by a physical-to-virtual boot issue.** The installed Windows reaches early kernel init and
  bugchecks **`INACCESSIBLE_BOOT_DEVICE` (0x7B / `0xC0000034`)** when the kernel switches from UEFI firmware
  I/O to its own storage stack to mount `C:`. Identical on emulated NVMe and SATA and in Safe Mode, and with
  the hypervisor disabled. WinRE boots from the same virtual disk and reads `C:` fine. The fix is a
  boot-start storage change in **C:'s SYSTEM hive** (the classic P2V remedy), applied first on the throwaway
  overlay. See *Known issue* below.

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
`install.sh`'s header and in KB `10-jxn-garuda.md` → *Windows-VM host side*.

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
both need guest drivers/agents installed inside Windows (virtio-gpu + spice-vdagent), which the "limited
Windows changes" rule excludes, so they are left as an owner decision. The in-VM resolution is set once in
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

`cd tests && python3 -m unittest discover` — 124 tests: GPT/layout/dm table, every pre-flight refusal, the XML
audit, the ESP builder, NTFS parsing, BCD flags, the guest guard's static invariants (`test_guard_static.py`) —
each with a positive control. The root end-to-end test on a synthetic disk with the real geometry:
`sudo python3 -I tests/root_integration.py`. On Windows (PowerShell 5.1, no elevation, scratch keys only), the
guard's policy save/apply/restore round-trip for both state.json shapes:
`powershell -NoProfile -ExecutionPolicy Bypass -File guest\test-guard-policies.ps1` (exit 0 = all PASS).

## Known issue — the P2V boot blocker

The installed Windows bugchecks `0x7B / 0xC0000034` in early kernel init. Diagnosis (see the plan record §7/§8):
the kernel cannot attach `C:` through its own storage stack once it leaves UEFI firmware I/O, although WinRE
and winload (which use firmware I/O) work from the same virtual disk. This is the classic physical-to-virtual
storage-binding problem, and the leading cause is a boot-start disk filter / controller binding in **C:'s
SYSTEM hive** (notably the `EhStorClass` lower-filter on the disk class, and the AHCI class not being mapped to
`storahci` on this NVMe-only install). The fix is a SYSTEM-hive edit, applied and tested **on the throwaway
overlay first** via `winvm-root inspect --rw`, and only then (for the persistent VM) on real C:. Both require
read-write access to the Windows volume, which the host's auto-mode guard gates.
