"""
Firewall rule generation for the Security Analysis module (rubric point 3).

Given a risky/unnecessary open port, produce concrete, copy-pasteable firewall
commands in the three common formats a student/admin would actually use:

  - ufw     (Uncomplicated Firewall — the default on Ubuntu/Mint/Debian)
  - iptables(the lower-level Linux firewall)
  - netsh   (Windows Defender Firewall command line)

Each rule carries a human comment explaining *why*, so the output doubles as a
hardening checklist. These commands are generated as text only — the app never
runs them; the user reviews and applies them deliberately.

`action`:
  "deny"     -> block the port entirely (for UNNECESSARY services)
  "restrict" -> allow only from the local/private network, block the internet
                (for services that are legitimate on a LAN but shouldn't be
                exposed externally, e.g. databases)
"""

# A representative private/LAN range used in "restrict" examples. In a real
# deployment the admin substitutes their actual subnet.
PRIVATE_SUBNET = "192.168.0.0/16"


def rules_for(port: int, service: str, os_name: str, action: str = "deny") -> dict:
    """Return {ufw, iptables, netsh, explanation} command strings for one port."""
    os_name = (os_name or "linux").lower()
    svc = service if service and service != "unknown" else f"port {port}"

    if action == "deny":
        explanation = f"Block all traffic to {svc} (port {port}/tcp) — service is unnecessary or insecure."
        ufw = f"sudo ufw deny {port}/tcp  # block {svc}"
        iptables = f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP  # block {svc}"
        netsh = (
            f'netsh advfirewall firewall add rule name="Block {svc} {port}" '
            f'dir=in action=block protocol=TCP localport={port}'
        )
    else:  # restrict
        explanation = (
            f"Allow {svc} (port {port}/tcp) only from the local network "
            f"({PRIVATE_SUBNET}); block it from the internet."
        )
        ufw = (
            f"sudo ufw allow from {PRIVATE_SUBNET} to any port {port} proto tcp  # LAN only\n"
            f"sudo ufw deny {port}/tcp  # block everyone else"
        )
        iptables = (
            f"sudo iptables -A INPUT -p tcp --dport {port} -s {PRIVATE_SUBNET} -j ACCEPT  # LAN only\n"
            f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP  # block everyone else"
        )
        netsh = (
            f'netsh advfirewall firewall add rule name="Restrict {svc} {port}" '
            f'dir=in action=allow protocol=TCP localport={port} remoteip={PRIVATE_SUBNET}'
        )

    # Pick the "primary" command matching the user's OS, but always return all
    # three so the UI can show the relevant one (and the others as reference).
    primary = "netsh" if os_name.startswith("win") else "ufw"

    return {
        "action": action,
        "explanation": explanation,
        "primary": primary,
        "ufw": ufw,
        "iptables": iptables,
        "netsh": netsh,
    }
