"""
Wi-Fi network security scanner.

Scans for nearby Wi-Fi ACCESS POINTS (networks), not the people/devices
connected to them — a deliberately network-level analysis. This is the
privacy-appropriate counterpart to "track individual devices/people by MAC
sighting", which is itself a privacy violation and out of scope for a
defensive security/privacy tool. A BSSID here identifies a router/access
point, not a person's phone or laptop.

Cross-platform: dispatches to the OS-native scan command via
`platform.system()`, same pattern as mac_spoof.py.

- Linux:   `nmcli` (NetworkManager CLI, present on virtually every modern
           Linux desktop) in terse mode for reliable, delimiter-based
           parsing. No raw-socket access or root privileges needed.
- Windows: `netsh wlan show networks mode=bssid`, present on every Windows
           install with a Wi-Fi adapter. No admin privileges needed.
- macOS:   the `airport` utility (bundled with every macOS Wi-Fi driver,
           though Apple has deprecated it in some releases). Falls back to
           a clear error if it's missing.
"""

import platform
import re
import subprocess

# Risk classification per security type reported by the OS scan. Open
# networks have no encryption at all (anyone can read all traffic); WEP is a
# broken cipher broken in minutes with commodity tools; WPA (1) has known
# weaknesses; WPA2/WPA3 are the current reasonable-to-good standards.
SECURITY_RISK = {
    "":      ("HIGH",   "Open network — no encryption. All traffic is readable by anyone in range."),
    "--":    ("HIGH",   "Open network — no encryption. All traffic is readable by anyone in range."),
    "WEP":   ("HIGH",   "WEP encryption is broken; crackable in minutes with widely available tools."),
    "WPA":   ("MEDIUM", "WPA(1) has known cryptographic weaknesses; upgrade to WPA2/WPA3 if possible."),
    "WPA2":  ("LOW",    "WPA2 is broadly acceptable, though vulnerable to KRACK-style attacks if unpatched."),
    "WPA3":  ("INFO",   "WPA3 is the current best-practice standard."),
}


def _classify_security(security: str) -> tuple[str, str]:
    security = (security or "").strip()
    # Scan tools report combinations like "WPA2 WPA3" (transition mode) or
    # "WPA2-Personal"; classify by the strongest cipher actually offered as
    # a fallback (an attacker downgrades to the weakest one advertised), but
    # note the mode for transparency.
    if "WEP" in security:
        return SECURITY_RISK["WEP"]
    if "WPA3" in security:
        return SECURITY_RISK["WPA3"]
    if "WPA2" in security:
        return SECURITY_RISK["WPA2"]
    if "WPA" in security:
        return SECURITY_RISK["WPA"]
    return SECURITY_RISK[""]


def _band_for_freq(freq_mhz: int | None) -> str:
    if freq_mhz is None:
        return "unknown"
    if freq_mhz < 3000:
        return "2.4GHz"
    if freq_mhz < 6000:
        return "5GHz"
    return "6GHz"


def _channel_to_freq_mhz(channel: int | None) -> int | None:
    """Approximate center frequency from a Wi-Fi channel number.

    Used on platforms (Windows) whose scan tool reports channel but not
    frequency directly. Good enough for 2.4/5/6GHz band classification.
    """
    if channel is None:
        return None
    if channel == 14:
        return 2484
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if channel < 200:
        return 5000 + channel * 5
    return 5950 + channel * 5


def _detect_rogue_aps(networks: list[dict]) -> list[dict]:
    """Flag possible rogue / evil-twin access points.

    An evil twin impersonates a legitimate network's SSID to lure devices
    into connecting to an attacker-controlled AP instead — a realistic
    on-premises attack against a building's official Wi-Fi (e.g. "Office-Guest"
    broadcast by a hidden rogue router in a stairwell). We flag it purely from
    what a normal scan already exposes, no extra privileges:

      1. Security downgrade: the same SSID broadcast by multiple BSSIDs with
         different encryption strength (attacker offers an open/weaker clone
         next to the real, stronger one, hoping victims connect to the weak one).
      2. OUI (vendor prefix) mismatch: the same SSID broadcast by BSSIDs from
         different hardware vendors — legitimate multi-AP deployments (mesh,
         enterprise controllers) are almost always same-vendor gear, so a
         vendor split under one SSID is a strong impersonation signal. This
         check is skipped for BSSIDs with the locally-administered bit set
         (the second-least-significant bit of the first octet), since many
         enterprise controllers assign virtual/randomized BSSIDs per radio —
         those don't carry a real vendor OUI, so comparing them as "vendors"
         produces false positives on legitimate multi-AP deployments.
      3. Excess BSSID count: an SSID broadcast by an unusually high number of
         distinct BSSIDs (3+) is unusual for anything but large enterprise
         mesh deployments and worth a human look.
    """
    by_ssid: dict[str, list[dict]] = {}
    for n in networks:
        if n["ssid"] == "(hidden network)":
            continue
        by_ssid.setdefault(n["ssid"], []).append(n)

    alerts = []
    for ssid, group in by_ssid.items():
        if len(group) < 2:
            continue

        bssids = [n["bssid"] for n in group]
        security_levels = {n["security"] for n in group}

        # Only compare OUIs for BSSIDs using a real, globally-assigned
        # vendor prefix — skip locally-administered (virtual/randomized)
        # addresses, which don't encode a meaningful vendor.
        def _is_locally_administered(bssid: str) -> bool:
            try:
                first_octet = int(bssid.split(":")[0], 16)
                return bool(first_octet & 0x02)
            except (ValueError, IndexError):
                return True  # malformed BSSID — don't use it for vendor comparison

        real_oui_bssids = [b for b in bssids if not _is_locally_administered(b)]
        ouis = {b[:8].upper() for b in real_oui_bssids if len(b) >= 8}

        reasons = []
        severity = "MEDIUM"

        if len(security_levels) > 1:
            reasons.append(
                f"Broadcast with inconsistent security across access points ({', '.join(sorted(security_levels))}) "
                "— a weaker clone next to the real network is a classic evil-twin downgrade attack."
            )
            severity = "HIGH"

        if len(ouis) > 1:
            reasons.append(
                f"Access points share this SSID but come from {len(ouis)} different hardware vendors "
                "(different BSSID prefixes) — legitimate multi-AP setups are almost always uniform hardware."
            )
            severity = "HIGH"

        if len(group) >= 3 and len(security_levels) == 1 and len(ouis) == 1:
            reasons.append(
                f"SSID is broadcast by {len(group)} access points. Confirm this matches your actual "
                "building deployment (mesh/enterprise controller) — otherwise investigate the extras."
            )

        if not reasons:
            continue

        alerts.append({
            "ssid": ssid,
            "bssids": bssids,
            "severity": severity,
            "reasons": reasons,
        })

    alerts.sort(key=lambda a: (a["severity"] != "HIGH", -len(a["bssids"])))
    return alerts


def _scan_linux() -> list[dict] | dict:
    """Scan via `nmcli`. Returns a list of raw network dicts, or an
    {"error": ...} dict on failure."""
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,CHAN,FREQ,BSSID", "dev", "wifi", "list"],
            capture_output=True, text=True, timeout=20,
        )
    except FileNotFoundError:
        return {"error": "nmcli not found. Wi-Fi scanning requires NetworkManager (nmcli) to be installed."}
    except subprocess.TimeoutExpired:
        return {"error": "Wi-Fi scan timed out."}

    if result.returncode != 0:
        return {"error": f"Wi-Fi scan failed: {result.stderr.strip() or 'unknown nmcli error'}"}

    networks = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        # nmcli escapes literal colons in field values (e.g. inside the
        # BSSID) as "\:" so a naive split(':') would shred the MAC address.
        # Split on unescaped colons only.
        fields = []
        current = ""
        i = 0
        while i < len(line):
            if line[i] == "\\" and i + 1 < len(line) and line[i + 1] == ":":
                current += ":"
                i += 2
            elif line[i] == ":":
                fields.append(current)
                current = ""
                i += 1
            else:
                current += line[i]
                i += 1
        fields.append(current)

        if len(fields) < 6:
            continue
        ssid, signal, security, chan, freq, bssid = fields[:6]

        # nmcli reports e.g. "2412 MHz"
        try:
            freq_mhz = int(freq.strip().split()[0])
        except (ValueError, IndexError):
            freq_mhz = None

        networks.append({
            "ssid": ssid or "(hidden network)",
            "bssid": bssid,
            "signal": int(signal) if signal.isdigit() else None,
            "security": security,
            "channel": chan,
            "freq_mhz": freq_mhz,
        })

    return networks


def _scan_windows() -> list[dict] | dict:
    """Scan via `netsh wlan show networks mode=bssid`. Returns a list of raw
    network dicts, or an {"error": ...} dict on failure."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=20, errors="replace",
        )
    except FileNotFoundError:
        return {"error": "netsh not found. Wi-Fi scanning requires the Windows netsh utility."}
    except subprocess.TimeoutExpired:
        return {"error": "Wi-Fi scan timed out."}

    combined = f"{result.stdout}\n{result.stderr}"
    if "location permission" in combined.lower() or "location services" in combined.lower():
        return {
            "error": "Wi-Fi scanning needs Windows Location services turned on for network "
            "shell commands. Enable it at Settings > Privacy & security > Location "
            "(or run: start ms-settings:privacy-location), then try again."
        }
    if "requires elevation" in combined.lower():
        return {"error": "Wi-Fi scan requires administrator privileges. Restart the backend as an administrator and try again."}

    if result.returncode != 0:
        return {"error": f"Wi-Fi scan failed: {(result.stderr or result.stdout).strip() or 'unknown netsh error'}"}

    output = result.stdout
    if "no wireless interface" in output.lower():
        return {"error": "No wireless interface found. Is Wi-Fi hardware present and enabled?"}

    networks: list[dict] = []
    ssid = None
    security = ""
    bssid = None
    signal = None
    channel = None

    def flush_bssid():
        if bssid is not None:
            networks.append({
                "ssid": ssid or "(hidden network)",
                "bssid": bssid,
                "signal": signal,
                "security": security,
                "channel": str(channel) if channel is not None else "",
                "freq_mhz": _channel_to_freq_mhz(channel),
            })

    for raw_line in output.splitlines():
        line = raw_line.strip()

        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            flush_bssid()
            ssid = m.group(1).strip()
            security, bssid, signal, channel = "", None, None, None
            continue

        m = re.match(r"^Authentication\s*:\s*(.*)$", line)
        if m:
            auth = m.group(1).strip()
            security = "" if auth.lower() == "open" else auth
            continue

        m = re.match(r"^BSSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            flush_bssid()
            bssid = m.group(1).strip()
            signal, channel = None, None
            continue

        m = re.match(r"^Signal\s*:\s*(\d+)\s*%$", line)
        if m:
            signal = int(m.group(1))
            continue

        m = re.match(r"^Channel\s*:\s*(\d+)$", line)
        if m:
            channel = int(m.group(1))
            continue

    flush_bssid()
    return networks


def _scan_macos() -> list[dict] | dict:
    """Scan via Apple's (deprecated but still widely present) `airport`
    utility. Returns a list of raw network dicts, or an {"error": ...} dict
    on failure."""
    airport = (
        "/System/Library/PrivateFrameworks/Apple80211.framework/"
        "Versions/Current/Resources/airport"
    )
    try:
        result = subprocess.run(
            [airport, "-s"], capture_output=True, text=True, timeout=20,
        )
    except FileNotFoundError:
        return {
            "error": "airport utility not found. Recent macOS versions restrict Wi-Fi "
            "scanning from the command line; try enabling Location Services for "
            "Terminal, or scan from System Settings > Wi-Fi instead."
        }
    except subprocess.TimeoutExpired:
        return {"error": "Wi-Fi scan timed out."}

    if result.returncode != 0:
        return {"error": f"Wi-Fi scan failed: {result.stderr.strip() or 'unknown airport error'}"}

    lines = result.stdout.splitlines()
    if not lines:
        return []

    # Header: "SSID BSSID RSSI CHANNEL HT CC SECURITY (auth/unicast/group)"
    # Columns are whitespace-aligned but SSID can contain spaces, so we
    # locate each column by its header's start offset instead of splitting.
    header = lines[0]
    col_names = ["SSID", "BSSID", "RSSI", "CHANNEL", "HT", "CC", "SECURITY"]
    offsets = []
    for name in col_names:
        idx = header.find(name)
        if idx == -1:
            return {"error": "Unrecognized airport output format."}
        offsets.append(idx)
    offsets.append(len(header) + 1000)  # sentinel end for the last column

    networks = []
    for line in lines[1:]:
        if not line.strip():
            continue
        values = []
        for i in range(len(col_names)):
            values.append(line[offsets[i]:offsets[i + 1]].strip())
        ssid, bssid, rssi, channel, _ht, _cc, security = values

        # e.g. "36" or "36,+1" (extension channel) — keep the primary number.
        channel_num = channel.split(",")[0].strip()
        try:
            freq_mhz = _channel_to_freq_mhz(int(channel_num))
        except ValueError:
            freq_mhz = None

        try:
            signal = int(rssi)
        except ValueError:
            signal = None

        networks.append({
            "ssid": ssid or "(hidden network)",
            "bssid": bssid,
            "signal": signal,
            "security": "" if security.upper() in ("NONE", "") else security,
            "channel": channel_num,
            "freq_mhz": freq_mhz,
        })

    return networks


def scan_networks() -> dict:
    """Scan for nearby Wi-Fi access points and classify each by security risk."""
    system = platform.system()
    if system == "Windows":
        raw = _scan_windows()
    elif system == "Darwin":
        raw = _scan_macos()
    elif system == "Linux":
        raw = _scan_linux()
    else:
        return {"error": f"Wi-Fi scanning is not supported on this operating system ({system})."}

    if isinstance(raw, dict):  # {"error": ...}
        return raw

    networks = []
    seen_bssids = set()

    for entry in raw:
        bssid = entry["bssid"]
        if not bssid or bssid in seen_bssids:
            continue  # duplicate scan entry for the same AP (or unparseable)
        seen_bssids.add(bssid)

        security = entry["security"]
        risk, reason = _classify_security(security)

        networks.append({
            "ssid": entry["ssid"],
            "bssid": bssid,
            "signal": entry["signal"],
            "security": security or "Open",
            "risk": risk,
            "reason": reason,
            "channel": entry["channel"],
            "band": _band_for_freq(entry["freq_mhz"]),
            "freq_mhz": entry["freq_mhz"],
        })

    networks.sort(key=lambda n: n["signal"] or 0, reverse=True)

    summary = {
        "total_networks": len(networks),
        "unique_ssids": len({n["ssid"] for n in networks}),
        "security_counts": {},
        "risk_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "band_counts": {},
    }
    for n in networks:
        summary["security_counts"][n["security"]] = summary["security_counts"].get(n["security"], 0) + 1
        summary["risk_counts"][n["risk"]] += 1
        summary["band_counts"][n["band"]] = summary["band_counts"].get(n["band"], 0) + 1

    rogue_alerts = _detect_rogue_aps(networks)
    summary["rogue_ap_count"] = len(rogue_alerts)

    return {"networks": networks, "summary": summary, "rogue_alerts": rogue_alerts}
