"""libvirt XML for the two domains and the VM network, and the AUDIT that every start must pass.

`domain_xml()` generates; `audit()` checks any domain XML against the safety rules. The audit runs in the tests,
at install time, AND in the libvirt hook on every `prepare` (libvirt hands the hook the live XML on stdin), so a
domain edited later in virt-manager - a TPM added, the real disk attached, Secure Boot switched on - refuses to
start instead of quietly breaking a rule. Each rule names the plan trap it closes.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from . import config

DNSMASQ_NS = "http://libvirt.org/schemas/network/dnsmasq/1.0"

HYPERV = """
      <relaxed state='on'/>
      <vapic state='on'/>
      <spinlocks state='on' retries='8191'/>
      <vpindex state='on'/>
      <runtime state='on'/>
      <synic state='on'/>
      <stimer state='on'/>
      <reset state='on'/>
      <frequencies state='on'/>
      <tlbflush state='on'/>
      <ipi state='on'/>"""


def domain_xml(domain: str, marker: bool = True, uuid: str | None = None) -> str:
    """The domain definition. `marker=False` exists only for the guard's restore test (P3): the same VM
    without the SMBIOS marker looks like the hardware to the guard."""
    if domain not in config.DOMAINS:
        raise ValueError(domain)
    test = domain == config.TEST_DOMAIN
    dm = f"/dev/mapper/{config.DM_NAME[domain]}"
    if test:
        disk = f"""
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' cache='none' discard='ignore'/>
      <source file='{config.OVERLAY}'/>
      <backingStore type='block'>
        <format type='raw'/>
        <source dev='{dm}'/>
        <backingStore/>
      </backingStore>
      <target dev='sda' bus='sata'/>
      <serial>{config.DISK_SERIAL}</serial>
      <blockio logical_block_size='512' physical_block_size='512'/>
    </disk>"""
    else:
        disk = f"""
    <disk type='block' device='disk'>
      <driver name='qemu' type='raw' cache='none' io='native' discard='ignore'/>
      <source dev='{dm}'/>
      <target dev='sda' bus='sata'/>
      <serial>{config.DISK_SERIAL}</serial>
      <blockio logical_block_size='512' physical_block_size='512'/>
    </disk>"""
    sysinfo = ""
    smbios = ""
    if marker:
        sysinfo = f"""
  <sysinfo type='smbios'>
    <system>
      <entry name='manufacturer'>{config.SMBIOS_MANUFACTURER}</entry>
      <entry name='product'>{config.SMBIOS_PRODUCT}</entry>
      <entry name='family'>{config.SMBIOS_FAMILY}</entry>
    </system>
  </sysinfo>"""
        smbios = "\n    <smbios mode='sysinfo'/>"
    title = "Windows (real C:, read-write)" if not test else "Windows TEST (real C: read-only + throwaway overlay)"
    uuid_el = f"\n  <uuid>{uuid}</uuid>" if uuid else ""
    return f"""<domain type='kvm'>
  <name>{domain}</name>{uuid_el}
  <title>{escape(title)}</title>
  <description>Managed by ~/Projects/windows-vm (winvm). Do not edit here: the libvirt hook audits this XML at every start and refuses one that breaks the safety rules. Regenerate with install.sh.</description>
  <memory unit='MiB'>{config.MEMORY_MIB}</memory>
  <currentMemory unit='MiB'>{config.MEMORY_MIB}</currentMemory>
  <vcpu placement='static'>{config.VCPUS}</vcpu>{sysinfo}
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <loader readonly='yes' secure='no' type='pflash' format='raw'>{config.OVMF_CODE}</loader>
    <nvram template='{config.OVMF_VARS_TEMPLATE}' format='raw'>{config.NVRAM[domain]}</nvram>
    <boot dev='hd'/>{smbios}
  </os>
  <features>
    <acpi/>
    <apic/>
    <hyperv mode='custom'>{HYPERV}
    </hyperv>
    <vmport state='off'/>
  </features>
  <cpu mode='host-passthrough' check='none' migratable='off'>
    <topology sockets='1' dies='1' clusters='1' cores='{config.CORES}' threads='{config.THREADS}'/>
    <feature policy='disable' name='svm'/>
    <feature policy='require' name='invtsc'/>
    <feature policy='require' name='topoext'/>
  </cpu>
  <clock offset='utc'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
    <timer name='hypervclock' present='yes'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <pm>
    <suspend-to-mem enabled='no'/>
    <suspend-to-disk enabled='no'/>
  </pm>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <controller type='sata' index='0'/>{disk}
    <controller type='usb' index='0' model='qemu-xhci' ports='15'/>
    <controller type='pci' index='0' model='pcie-root'/>
    <interface type='network'>
      <mac address='{config.MAC}'/>
      <source network='{config.NETWORK}'/>
      <model type='e1000e'/>
    </interface>
    <input type='tablet' bus='usb'/>
    <input type='keyboard' bus='ps2'/>
    <input type='mouse' bus='ps2'/>
    <graphics type='spice'>
      <listen type='socket'/>
      <image compression='off'/>
    </graphics>
    <video>
      <model type='vga' vram='65536' heads='1' primary='yes'/>
    </video>
    <memballoon model='none'/>
    <panic model='hyperv'/>
  </devices>
</domain>
"""


def network_xml(uuid: str | None = None) -> str:
    """The `default` NAT network: fixed lease for the VM, the Windows Update sinkhole (T26)."""
    opts = "\n".join(f"    <dnsmasq:option value='local=/{d}/'/>" for d in config.WU_SINKHOLE)
    uuid_el = f"\n  <uuid>{uuid}</uuid>" if uuid else ""
    return f"""<network xmlns:dnsmasq='{DNSMASQ_NS}'>
  <name>{config.NETWORK}</name>{uuid_el}
  <forward mode='nat'/>
  <bridge name='{config.BRIDGE}' stp='on' delay='0'/>
  <ip address='{config.HOST_IP}' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.100' end='192.168.122.254'/>
      <host mac='{config.MAC}' name='windows-vm' ip='{config.GUEST_IP}'/>
    </dhcp>
  </ip>
  <dnsmasq:options>
{opts}
  </dnsmasq:options>
</network>
"""


# --------------------------------------------------------------------------------------------- audit ----

FORBIDDEN_SOURCES = ("/dev/sd", "/dev/nvme", "/dev/disk/", "/dev/dm-", "/dev/loop", "/boot/efi")


def audit(xml_text: str, domain: str) -> list[str]:
    """Every safety rule the domain XML breaks. Empty list == safe to start."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return [f"XML does not parse: {e}"]
    p: list[str] = []
    name = root.findtext("name")
    if name != domain:
        p.append(f"domain name is {name!r}, expected {domain!r}")
    dev = root.find("devices")
    if dev is None:
        return p + ["no <devices>"]
    # T4 / D3: no TPM, no Secure Boot
    if dev.find("tpm") is not None:
        p.append("a TPM is attached (T4: BitLocker could seal to it)")
    os_el = root.find("os")
    loader = os_el.find("loader") if os_el is not None else None
    if loader is None or (loader.text or "").strip() != str(config.OVMF_CODE):
        p.append(f"firmware must be {config.OVMF_CODE} (no Secure Boot build)")
    elif loader.get("secure", "no") != "no":
        p.append("Secure Boot is on (D3)")
    if os_el is not None and os_el.get("firmware") == "efi":
        fw = os_el.find("firmware")
        for f in (fw.findall("feature") if fw is not None else []):
            if f.get("name") == "secure-boot" and f.get("enabled") == "yes":
                p.append("Secure Boot is on (D3)")
    nv = os_el.find("nvram") if os_el is not None else None
    if nv is None or (nv.text or "").strip() != str(config.NVRAM[domain]):
        p.append(f"nvram must be {config.NVRAM[domain]} (inside the state subvolume, T16)")
    # T3: no S3/S4
    pm = root.find("pm")
    for tag in ("suspend-to-mem", "suspend-to-disk"):
        el = pm.find(tag) if pm is not None else None
        if el is None or el.get("enabled") != "no":
            p.append(f"<pm><{tag} enabled='no'/> missing (T3: Windows could sleep/hibernate in the VM)")
    # T24: no nested virtualisation; save/migration blocked by invtsc
    cpu = root.find("cpu")
    feats = {f.get("name"): f.get("policy") for f in (cpu.findall("feature") if cpu is not None else [])}
    if feats.get("svm") != "disable":
        p.append("svm is not disabled (T24: Hyper-V/VBS would start inside the VM)")
    if feats.get("invtsc") != "require":
        p.append("invtsc not required (it is what makes QEMU refuse any save/suspend-to-file of this VM)")
    if cpu is None or cpu.get("migratable") != "off":
        p.append("cpu migratable must be 'off' (invtsc is dropped otherwise)")
    # clock (RealTimeIsUniversal=1)
    clock = root.find("clock")
    if clock is None or clock.get("offset") != "utc":
        p.append("clock offset must be utc (Windows keeps the RTC in UTC here)")
    # disks: exactly one, the assembled dm device (directly, or as the overlay's backing store)
    disks = dev.findall("disk")
    want_dm = f"/dev/mapper/{config.DM_NAME[domain]}"
    if len(disks) != 1:
        p.append(f"{len(disks)} disks attached, expected exactly 1 (the assembled VM disk)")
    for d in disks:
        if d.get("device") != "disk":
            p.append(f"a {d.get('device')} device is attached (no CD-ROMs/floppies: install media comes over SMB)")
        tgt = d.find("target")
        if tgt is None or tgt.get("bus") != "sata":
            p.append("the disk must be on the SATA bus: Windows boots it with the inbox storahci driver (boot-start, "
                     "used by the hardware too). QEMU's NVMe ends in INACCESSIBLE_BOOT_DEVICE (T29), virtio has no "
                     "inbox driver")
        bio = d.find("blockio")
        if bio is None or bio.get("logical_block_size") != "512":
            p.append("disk logical block size must be 512 (T17)")
        srcs = [s.get("dev") or s.get("file") or "" for s in d.iter("source")]
        if domain == config.DOMAIN:
            if d.get("type") != "block" or srcs != [want_dm]:
                p.append(f"the disk must be exactly {want_dm}, found {srcs}")
            drv = d.find("driver")
            if drv is None or drv.get("type") != "raw":
                p.append("the persistent disk must be raw (no snapshot/overlay layers on the real C:)")
        else:
            if srcs != [str(config.OVERLAY), want_dm]:
                p.append(f"the test disk must be {config.OVERLAY} over {want_dm}, found {srcs}")
            ro_chain = d.find("backingStore")
            if ro_chain is None:
                p.append("the test disk has no backing store - writes would hit the real disk")
        for s in srcs:
            if s != want_dm and any(s.startswith(f) for f in FORBIDDEN_SOURCES):
                p.append(f"forbidden disk source {s} (T1)")
    for tag in ("hostdev", "filesystem", "redirdev", "smartcard"):
        if dev.find(tag) is not None:
            p.append(f"<{tag}> attached - nothing of the host may be passed through")
    # T30: a blue screen stops the VM (with its code + parameters in libvirt's log) instead of rebooting into
    # Windows' Automatic Repair, which would "repair" the REAL C:
    if not any(pn.get("model") == "hyperv" for pn in dev.findall("panic")):
        p.append("no <panic model='hyperv'/> device (T30: crashes must be caught, logged and stop the VM)")
    # T30: a crashed VM must never REBOOT (that would run Automatic Repair against the real C:). destroy,
    # preserve and the coredump-*-destroy variants all stop instead of rebooting; preserve freezes the BSOD
    # on screen for diagnosis. restart/coredump-restart are refused.
    if root.findtext("on_crash") not in ("destroy", "preserve", "coredump-destroy"):
        p.append("on_crash must be destroy/preserve/coredump-destroy (T30: a crashed VM must never reboot into Automatic Repair)")
    # T26/D5: the network, fixed MAC
    ifs = dev.findall("interface")
    if len(ifs) != 1:
        p.append(f"{len(ifs)} network interfaces, expected 1")
    for i in ifs:
        src = i.find("source")
        if i.get("type") != "network" or src is None or src.get("network") != config.NETWORK:
            p.append("the NIC must be on the libvirt 'default' NAT network (never bridged onto the LAN: .3 is Garuda's)")
        mac = i.find("mac")
        if mac is None or mac.get("address", "").lower() != config.MAC:
            p.append(f"the NIC MAC must be {config.MAC} (its fixed lease is {config.GUEST_IP})")
    # display: local socket only (D6, no RDP, nothing on the LAN)
    for g in dev.findall("graphics"):
        lst = g.find("listen")
        if lst is None or lst.get("type") not in ("socket", "none"):
            p.append(f"{g.get('type')} display listens on a network address; it must be a local socket")
    # T8: the persistent domain must carry the marker (the test domain may omit it for the restore test)
    if domain == config.DOMAIN and not has_marker(root):
        p.append("the SMBIOS marker is missing - the guard would treat the VM as the hardware (T8)")
    return p


def has_marker(root: ET.Element) -> bool:
    os_el = root.find("os")
    sm = os_el.find("smbios") if os_el is not None else None
    if sm is None or sm.get("mode") != "sysinfo":
        return False
    sysinfo = root.find("sysinfo")
    if sysinfo is None:
        return False
    entries = {e.get("name"): (e.text or "") for e in sysinfo.iter("entry")}
    return (entries.get("manufacturer") == config.SMBIOS_MANUFACTURER and entries.get("product") == config.SMBIOS_PRODUCT
            and entries.get("family") == config.SMBIOS_FAMILY)


def audit_network(xml_text: str) -> list[str]:
    root = ET.fromstring(xml_text)
    p = []
    fwd = root.find("forward")
    if fwd is None or fwd.get("mode") != "nat":
        p.append("the VM network must be NAT (never bridged to the LAN)")
    ip = root.find("ip")
    if ip is None or ip.get("address") != config.HOST_IP:
        p.append(f"the host address must be {config.HOST_IP}")
    hosts = ip.findall("dhcp/host") if ip is not None else []
    if not any(h.get("mac", "").lower() == config.MAC and h.get("ip") == config.GUEST_IP for h in hosts):
        p.append(f"no fixed lease {config.MAC} -> {config.GUEST_IP}")
    opts = {o.get("value") for o in root.iter(f"{{{DNSMASQ_NS}}}option")}
    for d in config.WU_SINKHOLE:
        if f"local=/{d}/" not in opts:
            p.append(f"Windows Update sinkhole missing for {d} (T26)")
    return p
