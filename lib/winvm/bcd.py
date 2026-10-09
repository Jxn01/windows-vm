r"""Patch the VM's PRIVATE copy of the BCD (boot configuration) via the hivex tools.

Used only for the throwaway test VM, to force a recovery/diagnostic boot (Safe Mode, no hypervisor) WITHOUT
touching the real ESP or real C:. The real BCD is copied into the private ESP image by esp.build(); this then
edits only that copy. Every change is logged. The persistent `windows` domain never carries flags.

BCD elements are a registry hive; each element is \Objects\{loader}\Elements\<hexcode> with one REG_BINARY
value `Element`. Integer elements hold an 8-byte little-endian value. Read with hivexget, write with hivexsh,
so the installed tooling needs only the `hivex` package (no Python registry library).
"""

from __future__ import annotations

import subprocess

BOOTMGR = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"  # well-known Windows Boot Manager object
DEFAULT_ELEMENT = "23000003"                         # bootmgr's "default" -> the loader object GUID

# flag name -> element hex code. All are OS-loader integer elements (stored as 8-byte LE REG_BINARY).
INT_ELEMENTS = {
    "safeboot": "25000080",              # 0 Minimal, 1 Network, 2 DsRepair
    "hypervisorlaunchtype": "250000f0",  # 0 Off, 1 Auto
}
SAFEBOOT = {"minimal": 0, "network": 1, "dsrepair": 2}


class BcdError(RuntimeError):
    pass


def _get(bcd_file: str, path: str, value: str = "Element") -> bytes:
    cp = subprocess.run(["hivexget", bcd_file, path, value], capture_output=True)
    if cp.returncode != 0:
        raise BcdError(f"hivexget {path} failed: {cp.stderr.decode(errors='replace').strip()}")
    return cp.stdout


def default_loader(bcd_file: str) -> str:
    g = _get(bcd_file, rf"\Objects\{BOOTMGR}\Elements\{DEFAULT_ELEMENT}").decode(errors="replace").strip()
    if not (g.startswith("{") and g.endswith("}")):
        raise BcdError(f"default loader element is not a GUID: {g!r}")
    return g


def resolve(flags: dict) -> dict[str, int]:
    """Validate flags -> {element_hex: int_value}. Raises on anything unsupported."""
    out: dict[str, int] = {}
    for k, val in flags.items():
        if k not in INT_ELEMENTS:
            raise BcdError(f"unsupported BCD flag {k!r}")
        if k == "safeboot":
            if val not in SAFEBOOT:
                raise BcdError(f"safeboot must be one of {sorted(SAFEBOOT)}")
            out[INT_ELEMENTS[k]] = SAFEBOOT[val]
        elif k == "hypervisorlaunchtype":
            iv = {"off": 0, "auto": 1}.get(str(val).lower())
            if iv is None:
                raise BcdError("hypervisorlaunchtype must be off or auto")
            out[INT_ELEMENTS[k]] = iv
    return out


def _hivexsh(bcd_file: str, script: str) -> None:
    cp = subprocess.run(["hivexsh", "-w", bcd_file], input=script, capture_output=True, text=True)
    if cp.returncode != 0 or "error" in cp.stderr.lower():
        raise BcdError(f"hivexsh failed: {cp.stderr.strip() or cp.stdout.strip()}")


def apply_flags(bcd_file: str, flags: dict, log=print) -> None:
    """Set each flag on the default loader object of the BCD hive file (in place)."""
    elements = resolve(flags)
    loader = default_loader(bcd_file)
    for code, value in elements.items():
        le = value.to_bytes(8, "little")
        hexv = ",".join(f"{b:02x}" for b in le)
        try:
            _get(bcd_file, rf"\Objects\{loader}\Elements\{code}")
            add = ""  # the element key already exists; setval overwrites it
        except BcdError:
            add = f"add {code}\n"
        script = (f"cd \\Objects\\{loader}\\Elements\n"
                  f"{add}"
                  f"cd {code}\n"
                  f"setval 1\nElement\nhex:3:{hexv}\n"
                  f"commit\n")
        _hivexsh(bcd_file, script)
        log(f"BCD: set element {code} = {value} (0x{le.hex()}) on loader {loader}")
    verify(bcd_file, elements, loader)


def verify(bcd_file: str, elements: dict[str, int], loader: str | None = None) -> None:
    loader = loader or default_loader(bcd_file)
    for code, value in elements.items():
        raw = _get(bcd_file, rf"\Objects\{loader}\Elements\{code}")
        found = int.from_bytes(raw[:8].ljust(8, b"\0"), "little")
        if found != value:
            raise BcdError(f"BCD element {code} is {found}, expected {value}")
