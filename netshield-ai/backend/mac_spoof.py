"""
Cross-platform MAC address spoofing.

MAC address changing is inherently OS-specific because it is implemented by
each operating system's network driver layer differently:

- Linux:   the kernel lets you set a NIC's hardware address directly via
           `ip link` (part of iproute2, installed on every distro) as long
           as the interface is brought down first.
- Windows: most NIC drivers expose an optional "NetworkAddress" property in
           the registry, under that adapter's driver key. Setting it and
           restarting the adapter makes Windows report the new MAC. This is
           exactly what GUI tools like SMAC/TMAC automate.
- macOS:   `ifconfig <iface> ether ...` used to work universally; newer
           macOS (especially Apple Silicon Wi-Fi) increasingly blocks this.

This module detects the OS with `platform.system()` and dispatches to the
matching implementation, so the FastAPI route stays OS-agnostic.

All of this requires administrator/root privileges on every OS, because
changing a network interface's hardware address is a privileged operation
everywhere.
"""

import platform
import random
import re
import subprocess

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


class MacSpoofError(Exception):
    """Raised when a MAC change/restore operation fails."""


# Remembers, per interface, the MAC address it had immediately before we
# spoofed it. Physical NICs expose a burned-in "permanent address" via
# ethtool that we can always fall back on, but virtual interfaces (Docker
# bridges, veth pairs, etc.) have no such concept — for those, this process
# memory is the only record of what to restore to.
_original_macs: dict[str, str] = {}


def is_valid_mac(mac: str) -> bool:
    return bool(MAC_RE.match(mac))


def generate_random_mac() -> str:
    """Generate a random, locally-administered, unicast MAC address.

    The first byte has bit 1 (locally administered) set and bit 0
    (multicast) cleared, which is the standard convention for
    software-generated MAC addresses so they never collide with a
    real vendor-assigned OUI.
    """
    first_byte = random.randint(0, 255) & 0b11111100 | 0b00000010
    remaining = [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02X}" for b in [first_byte, *remaining])


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=15)


def _linux_set_mac(interface: str, new_mac: str) -> None:
    steps = [
        ["ip", "link", "set", interface, "down"],
        ["ip", "link", "set", interface, "address", new_mac],
        ["ip", "link", "set", interface, "up"],
    ]
    for step in steps:
        result = _run(step)
        if result.returncode != 0:
            # best-effort: try to bring the interface back up before failing
            _run(["ip", "link", "set", interface, "up"])
            raise MacSpoofError(
                f"Command '{' '.join(step)}' failed: {result.stderr.strip() or result.stdout.strip()}"
            )


def _linux_permanent_mac(interface: str) -> str:
    try:
        with open(f"/sys/class/net/{interface}/address") as f:
            current = f.read().strip()
    except OSError as e:
        raise MacSpoofError(f"Could not read current MAC for '{interface}': {e}")

    # The kernel exposes the burned-in hardware address separately from the
    # currently-active one under some drivers via ethtool -P; fall back to
    # the current address if ethtool isn't available or doesn't support it.
    result = _run(["ethtool", "-P", interface])
    if result.returncode == 0:
        match = re.search(r"([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})", result.stdout)
        if match:
            return match.group(1).upper()

    return current.upper()


def _windows_set_mac(interface: str, new_mac: str) -> None:
    # Windows NIC drivers take the NetworkAddress registry value without
    # colons. PowerShell's Set-NetAdapterAdvancedProperty is the modern,
    # documented way to set it (replaces manual registry editing), followed
    # by a disable/enable cycle so the driver picks up the new value.
    mac_no_colons = new_mac.replace(":", "")
    ps_script = (
        f"Set-NetAdapterAdvancedProperty -Name '{interface}' "
        f"-RegistryKeyword NetworkAddress -RegistryValue '{mac_no_colons}' -ErrorAction Stop; "
        f"Disable-NetAdapter -Name '{interface}' -Confirm:$false; "
        f"Start-Sleep -Seconds 2; "
        f"Enable-NetAdapter -Name '{interface}' -Confirm:$false"
    )
    result = _run(["powershell", "-NoProfile", "-Command", ps_script])
    if result.returncode != 0:
        raise MacSpoofError(
            f"PowerShell command failed: {result.stderr.strip() or result.stdout.strip()}"
        )


def _windows_restore_mac(interface: str) -> None:
    ps_script = (
        f"Set-NetAdapterAdvancedProperty -Name '{interface}' "
        f"-RegistryKeyword NetworkAddress -RegistryValue '' -ErrorAction Stop; "
        f"Disable-NetAdapter -Name '{interface}' -Confirm:$false; "
        f"Start-Sleep -Seconds 2; "
        f"Enable-NetAdapter -Name '{interface}' -Confirm:$false"
    )
    result = _run(["powershell", "-NoProfile", "-Command", ps_script])
    if result.returncode != 0:
        raise MacSpoofError(
            f"PowerShell command failed: {result.stderr.strip() or result.stdout.strip()}"
        )


def _macos_set_mac(interface: str, new_mac: str) -> None:
    result = _run(["ifconfig", interface, "ether", new_mac])
    if result.returncode != 0:
        raise MacSpoofError(
            f"ifconfig failed (recent macOS often blocks this for Wi-Fi): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def set_mac_address(interface: str, new_mac: str, current_mac: str | None = None) -> None:
    """Change `interface`'s MAC address to `new_mac`.

    `current_mac` is the address the interface had immediately before this
    call (the route already knows it from /network-adapter-info). It is
    remembered so restore_mac_address() can undo the change later even on
    virtual interfaces (Docker bridges, veth pairs, ...) that have no
    OS-reported "permanent" hardware address to fall back on.
    """
    if not is_valid_mac(new_mac):
        raise MacSpoofError(f"'{new_mac}' is not a valid MAC address (expected XX:XX:XX:XX:XX:XX).")

    system = platform.system()
    if system == "Linux":
        _linux_set_mac(interface, new_mac)
    elif system == "Windows":
        _windows_set_mac(interface, new_mac)
    elif system == "Darwin":
        _macos_set_mac(interface, new_mac)
    else:
        raise MacSpoofError(f"Unsupported operating system: {system}")

    if current_mac and interface not in _original_macs:
        _original_macs[interface] = current_mac


def restore_mac_address(interface: str) -> str:
    """Restore the adapter's original MAC address.

    Prefers the address remembered from the last set_mac_address() call on
    this interface (works for every interface, physical or virtual). Falls
    back to the OS-reported permanent hardware address — only meaningful on
    Linux physical NICs — if nothing was remembered (e.g. after a backend
    restart).

    Returns the MAC address it was restored to.
    """
    remembered = _original_macs.get(interface)
    system = platform.system()

    if system == "Linux":
        target = remembered or _linux_permanent_mac(interface)
        _linux_set_mac(interface, target)
        _original_macs.pop(interface, None)
        return target
    elif system == "Windows":
        if remembered:
            _windows_set_mac(interface, remembered)
            _original_macs.pop(interface, None)
            return remembered
        _windows_restore_mac(interface)
        return ""  # Windows doesn't expose the permanent MAC as easily; caller re-reads it
    elif system == "Darwin":
        if remembered:
            _macos_set_mac(interface, remembered)
            _original_macs.pop(interface, None)
            return remembered
        raise MacSpoofError(
            "No original MAC on record for this interface (e.g. backend was restarted "
            "since it was spoofed), and macOS does not expose a permanent hardware "
            "address to fall back on."
        )
    else:
        raise MacSpoofError(f"Unsupported operating system: {system}")
