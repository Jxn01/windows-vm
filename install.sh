#!/usr/bin/env bash
# install.sh - install the windows-vm host tooling on Garuda (idempotent; run with sudo from the repo).
#
#   sudo ./install.sh            install / update everything (refuses while a Windows VM runs)
#   sudo ./install.sh --check    report what is installed and what differs, change nothing
#
# What it does, in order (README.md -> "What install.sh changes" documents each item and how to undo it):
#   1. state subvolume /var/lib/windows-vm (nested btrfs subvolume, NOCOW; disk/ 0700, qemu/ 0711, log/ 0700)
#   2. code: /usr/local/lib/windows-vm/{winvm/,winvm-root} (root-owned), /usr/local/bin/winvm
#   3. /etc/windows-vm/layout.toml; /etc/windows-vm/smb-password (generated once, 0600 root, never printed)
#   4. libvirt hooks: /etc/libvirt/hooks/qemu.d/windows-vm, /etc/libvirt/hooks/network.d/windows-vm-smb
#   5. udev rule /etc/udev/rules.d/61-windows-vm.rules
#   6. libvirt-guests: /etc/conf.d/libvirt-guests + drop-in; enabled. windows-vm-test-guard.service enabled
#   7. libvirtd restarted (it only discovers hook scripts at start) - only while no VM runs
#   8. network `default` + domains `windows`, `windows-test` audited and defined (winvm-root define)
#   9. Samba: smb.conf replaced (old one kept once as smb.conf.pre-windows-vm), jxn's Samba password set from
#      the generated file, nmb (NetBIOS) disabled, smbd restarted -> listens on 127.0.0.1 + 192.168.122.1 only
#  10. for jxn: the `windows-vm` SSH alias and a known_hosts pin of Windows' own host key (read from C:)
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
OWNER=jxn
OWNER_HOME=/home/$OWNER
LIB=/usr/local/lib/windows-vm
STATE=/var/lib/windows-vm
URI=qemu:///system

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
differs() { ! cmp -s "$1" "$2"; }

need=(python3 qemu-system-x86_64 qemu-img virsh mkfs.fat mmd mcopy ntfsinfo ntfscat ntfsls losetup dmsetup
      blockdev smbpasswd testparm virt-viewer btrfs chattr sgdisk)
missing=()
for t in "${need[@]}"; do command -v "$t" >/dev/null || missing+=("$t"); done
if ((${#missing[@]})); then echo "missing tools: ${missing[*]}" >&2; exit 1; fi

if ((CHECK)); then
    rc=0
    chk() { if differs "$1" "$2"; then echo "DIFFERS  $2"; rc=1; else echo "ok       $2"; fi; }
    chk "$REPO/bin/winvm" /usr/local/bin/winvm
    chk "$REPO/bin/winvm-root" $LIB/winvm-root
    for f in "$REPO"/lib/winvm/*.py; do chk "$f" "$LIB/winvm/$(basename "$f")"; done
    chk "$REPO/etc/layout.toml" /etc/windows-vm/layout.toml
    chk "$REPO/hooks/qemu.d/windows-vm" /etc/libvirt/hooks/qemu.d/windows-vm
    chk "$REPO/hooks/network.d/windows-vm-smb" /etc/libvirt/hooks/network.d/windows-vm-smb
    chk "$REPO/etc/udev/61-windows-vm.rules" /etc/udev/rules.d/61-windows-vm.rules
    chk "$REPO/etc/libvirt-guests.conf" /etc/conf.d/libvirt-guests
    chk "$REPO/etc/systemd/libvirt-guests-windows-vm.conf" /etc/systemd/system/libvirt-guests.service.d/windows-vm.conf
    chk "$REPO/etc/systemd/windows-vm-test-guard.service" /etc/systemd/system/windows-vm-test-guard.service
    chk "$REPO/etc/samba/smb.conf" /etc/samba/smb.conf
    exit $rc
fi

for d in windows windows-test; do
    st=$(virsh -c $URI domstate "$d" 2>/dev/null || true)
    if [[ -n "$st" && "$st" != "shut off" ]]; then echo "$d is $st - stop it first" >&2; exit 1; fi
done

say "1. state subvolume $STATE"
if [[ ! -e $STATE ]]; then
    btrfs subvolume create "$STATE" >/dev/null
    chattr +C "$STATE"
fi
[[ "$(stat -c %i "$STATE")" == 256 ]] || { echo "$STATE exists but is not a btrfs subvolume" >&2; exit 1; }
lsattr -d "$STATE" | awk '{print $1}' | grep -q C || chattr +C "$STATE"
install -d -m 0711 -o root -g root "$STATE"
install -d -m 0700 -o root -g root "$STATE/disk" "$STATE/log"
install -d -m 0711 -o root -g root "$STATE/qemu"

say "2. code -> $LIB, /usr/local/bin/winvm"
install -d -m 0755 "$LIB" "$LIB/winvm"
find "$LIB/winvm" -name '__pycache__' -prune -exec rm -rf {} +
for f in "$REPO"/lib/winvm/*.py; do install -m 0644 "$f" "$LIB/winvm/"; done
for f in "$LIB"/winvm/*.py; do [[ -e "$REPO/lib/winvm/$(basename "$f")" ]] || rm -f "$f"; done
install -m 0755 "$REPO/bin/winvm-root" "$LIB/winvm-root"
install -m 0755 "$REPO/bin/winvm" /usr/local/bin/winvm
# The user command must use the installed copy, not the shared tree, once installed:
sed -i 's|^_repo = .*|_repo = Path("/nonexistent")  # installed copy: always /usr/local/lib/windows-vm|' /usr/local/bin/winvm

say "3. /etc/windows-vm"
install -d -m 0755 /etc/windows-vm
install -m 0644 "$REPO/etc/layout.toml" /etc/windows-vm/layout.toml
if [[ ! -s /etc/windows-vm/smb-password ]]; then
    ( umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > /etc/windows-vm/smb-password )
    echo "   generated /etc/windows-vm/smb-password (0600, not shown)"
fi
chown root:root /etc/windows-vm/smb-password; chmod 0600 /etc/windows-vm/smb-password

say "4. libvirt hooks"
install -D -m 0755 "$REPO/hooks/qemu.d/windows-vm" /etc/libvirt/hooks/qemu.d/windows-vm
install -D -m 0755 "$REPO/hooks/network.d/windows-vm-smb" /etc/libvirt/hooks/network.d/windows-vm-smb

say "5. udev rule"
install -m 0644 "$REPO/etc/udev/61-windows-vm.rules" /etc/udev/rules.d/61-windows-vm.rules
udevadm control --reload

say "6. libvirt-guests + test guard unit"
install -m 0644 "$REPO/etc/libvirt-guests.conf" /etc/conf.d/libvirt-guests
install -D -m 0644 "$REPO/etc/systemd/libvirt-guests-windows-vm.conf" \
    /etc/systemd/system/libvirt-guests.service.d/windows-vm.conf
install -m 0644 "$REPO/etc/systemd/windows-vm-test-guard.service" /etc/systemd/system/windows-vm-test-guard.service
systemctl daemon-reload
systemctl enable --now libvirt-guests.service windows-vm-test-guard.service >/dev/null 2>&1

say "7. restart libvirtd (hook discovery)"
systemctl restart libvirtd.service
for _ in $(seq 20); do virsh -c $URI version >/dev/null 2>&1 && break; sleep 0.5; done

say "8. define network + domains"
"$LIB/winvm-root" define
if [[ "$(virsh -c $URI net-info default | awk '/^Active:/{print $2}')" == yes ]]; then
    virsh -c $URI net-destroy default >/dev/null
fi
virsh -c $URI net-start default >/dev/null

say "9. Samba (VM network only)"
[[ -e /etc/samba/smb.conf.pre-windows-vm ]] || cp -a /etc/samba/smb.conf /etc/samba/smb.conf.pre-windows-vm
install -m 0644 "$REPO/etc/samba/smb.conf" /etc/samba/smb.conf
testparm -s /etc/samba/smb.conf >/dev/null 2>&1 || { echo "testparm rejects smb.conf" >&2; exit 1; }
pw=$(cat /etc/windows-vm/smb-password)
printf '%s\n%s\n' "$pw" "$pw" | smbpasswd -s -a "$OWNER" >/dev/null
unset pw
smbpasswd -e "$OWNER" >/dev/null
systemctl disable --now nmb.service >/dev/null 2>&1 || true
systemctl enable smb.service >/dev/null 2>&1
systemctl restart smb.service
sleep 1
ss -Htlnp 'sport = :445' | awk '{print "   smbd listens on " $4}'

say "10. SSH alias + host key pin for $OWNER"
cfg=$OWNER_HOME/.ssh/config
if ! grep -q '^# >>> windows-vm' "$cfg" 2>/dev/null; then
    cat >> "$cfg" <<EOF
# >>> windows-vm (installed by ~/Projects/windows-vm) - the Windows VM on libvirt's NAT network
Host windows-vm
    HostName 192.168.122.10
    User jxn
    HostKeyAlias windows-vm
    StrictHostKeyChecking yes
# <<< windows-vm
EOF
    chown $OWNER:$OWNER "$cfg"
fi
kh=$OWNER_HOME/.ssh/known_hosts
if ! sudo -u $OWNER ssh-keygen -F windows-vm -f "$kh" >/dev/null 2>&1; then
    if ls /dev/mapper/winvm-* >/dev/null 2>&1; then
        echo "   C: is in use by a VM disk - host key pin skipped (rerun install.sh with the VMs off)"
    else
        cdev=/dev/disk/by-partuuid/$(python3 -I -c 'import sys; sys.path.insert(0, "/usr/local/lib/windows-vm"); from winvm import layout; L = layout.load("/etc/windows-vm/layout.toml"); print(L.part(L.windows_partition).unique_guid)')
        n=0
        for k in ssh_host_ed25519_key.pub ssh_host_ecdsa_key.pub ssh_host_rsa_key.pub; do
            key=$(ntfscat "$cdev" "/ProgramData/ssh/$k" 2>/dev/null | tr -d '\r' | awk '{print $1, $2}')
            if [[ -n "$key" ]]; then echo "windows-vm $key" >> "$kh"; n=$((n+1)); fi
        done
        chown $OWNER:$OWNER "$kh"
        echo "   pinned $n of Windows' own host keys (read from C:\\ProgramData\\ssh, read-only)"
    fi
fi

say "11. GUI launchers + app-menu entries + Desktop shortcuts for the owner (start + stop)"
install -m 0755 "$REPO/bin/windows-vm-gui"      /usr/local/bin/windows-vm-gui
install -m 0755 "$REPO/bin/windows-vm-stop-gui" /usr/local/bin/windows-vm-stop-gui
# Desktop shortcuts (double-click icons). GNOME needs each executable AND trusted; "trusted" is per-user
# gvfs metadata, so set it as the owner with their session bus (best-effort - otherwise the owner
# right-clicks the icon once and picks "Allow Launching").
dsk=$(sudo -u $OWNER xdg-user-dir DESKTOP 2>/dev/null); [ -d "$dsk" ] || dsk="$OWNER_HOME/Desktop"
bus="unix:path=/run/user/$(id -u $OWNER)/bus"
for de in windows-vm windows-vm-stop; do
    install -D -m 0644 -o $OWNER -g $OWNER "$REPO/etc/$de.desktop" \
        "$OWNER_HOME/.local/share/applications/$de.desktop"
    if [ -d "$dsk" ]; then
        install -m 0755 -o $OWNER -g $OWNER "$REPO/etc/$de.desktop" "$dsk/$de.desktop"
        sudo -u $OWNER env DBUS_SESSION_BUS_ADDRESS="$bus" gio set "$dsk/$de.desktop" \
            metadata::trusted true 2>/dev/null || true
    fi
done
update-desktop-database "$OWNER_HOME/.local/share/applications" 2>/dev/null || true

say "done - try: winvm preflight"
