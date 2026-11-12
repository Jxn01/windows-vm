# Reference

The maintenance commands, what happens at every start, each pre-flight check and audit rule, the installed files,
the modules and the tests in detail.

## Root/maintenance commands — `winvm-root` (sudo)

| Command | What it does |
|---|---|
| `winvm-root preflight` | run the pre-flight, exit 1 on any refusal |
| `winvm-root layout show\|verify\|record` | the segment map / live-GPT check / a TOML record of the live GPT |
| `winvm-root esp-manifest LABEL` | sha256 manifest of the real ESP vs the baseline |
| `winvm-root define [--test-no-marker]` | (re)define the network + both domains, keeping their UUIDs; `--test-no-marker` builds the test domain without the SMBIOS marker (for the guard's restore test, P3) |
| `winvm-root inspect start [--rw]\|stop\|cat PATH\|ls PATH` | read (or, with `--rw`, mount read-write) the **throwaway overlay's** C: from the host, via qemu-nbd with `max_part=0` + a loop at C:'s offset. Writes land in the overlay, never real C:. For logs a failed boot left behind, and for offline hive edits. |
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
3. libvirt-guests (`ON_SHUTDOWN=shutdown`, ordered after libvirtd and smb) shuts the VM down cleanly at host
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
- Rollback material: the backup taken before first use (GPT, ESP tar + manifest, registry hives, the Tasks folder).

## Modules (`lib/winvm/`)

`gpt.py` GPT read/rewrite (pure stdlib) · `layout.py` the identity layout, drift check, segments, dm table ·
`ntfs.py` offline NTFS reads (ntfs-3g) · `esp.py` the private ESP builder/verifier · `dm.py` assemble/prove/
tear down the disk · `bcd.py` patch the private BCD (hivex) · `probe.py` what the pre-flight reads ·
`preflight.py` the checks · `xmlgen.py` the domain/network XML and the audit · `config.py` every shared name ·
`rootcmd.py` the root CLI + hook · `cli.py` the user CLI.

## Tests in detail

`cd tests && python3 -m unittest discover` — 142 tests: GPT/layout/dm table, every pre-flight refusal, the XML
audit, the ESP builder, NTFS parsing, BCD flags, the guest guard's static invariants (`test_guard_static.py`: no
forced registry `New-Item`, no `Move-Item` or ACL write outside their primitives, the policy table, the late start) — each with a positive control. (`Test-SafeDir` refuses reparse-point Startup folders, closing the *static* junction vector; a timed junction swap during the pre-logon restore is a residual race that needs an enabled non-admin account to exploit; a registry-only design would remove the class.)
The root end-to-end test on a synthetic disk with the real geometry: `sudo python3 -I tests/root_integration.py`.
On Windows (PowerShell 5.1, no elevation, scratch keys and a scratch folder under `%TEMP%` only), the guard's own
functions for real: policy save/apply/restore for both state.json shapes (A–C), Run parking across two VM boots (D),
and Startup shortcuts keeping their folder's permissions through park → re-secure → restore, with a planted hard
link restored untouched, and a junctioned Startup folder refused with nothing moved or written through it (E — its control proves the harness can see the junction
trap):
`powershell -NoProfile -ExecutionPolicy Bypass -File guest\test-guard-policies.ps1 [-Guard <guard.ps1>]` (exit 0 =
all PASS). `-Guard` points it at another copy, e.g. the installed `C:\ProgramData\jxn-vm\guard.ps1`.
