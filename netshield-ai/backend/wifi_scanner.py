"""
Wi-Fi network security scanner.

Scans for nearby Wi-Fi ACCESS POINTS (networks), not the people/devices
connected to them — a deliberately network-level analysis. This is the
privacy-appropriate counterpart to "track individual devices/people by MAC
sighting", which is itself a privacy violation and out of scope for a
defensive security/privacy tool. A BSSID here identifies a router/access
point, not a person's phone or laptop.

Uses `nmcli` (NetworkManager CLI, present on virtually every modern Linux
desktop) in terse mode for reliable, delimiter-based parsing. No raw-socket
access or root privileges needed — a normal Wi-Fi scan.
"""

import subprocess

# Risk classification per security type nmcli reports. Open networks have no
# encryption at all (anyone can read all traffic); WEP is a broken cipher
# broken in minutes with commodity tools; WPA (1) has known weaknesses;
# WPA2/WPA3 are the current reasonable-to-good standards.
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
    # nmcli reports combinations like "WPA2 WPA3" (transition mode) or
    # "WPA1 WPA2"; classify by the strongest cipher actually offered as a
    # fallback (an attacker downgrades to the weakest one advertised), but
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


def _parse_freq_mhz(freq: str) -> int | None:
    # nmcli reports e.g. "2412 MHz"
    try:
        return int(freq.strip().split()[0])
    except (ValueError, IndexError):
        return None


def _band_for_freq(freq_mhz: int | None) -> str:
    if freq_mhz is None:
        return "unknown"
    if freq_mhz < 3000:
        return "2.4GHz"
    if freq_mhz < 6000:
        return "5GHz"
    return "6GHz"


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


def scan_networks() -> dict:
    """Scan for nearby Wi-Fi access points and classify each by security risk."""
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
    seen_bssids = set()

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

        if bssid in seen_bssids:
            continue  # duplicate scan entry for the same AP
        seen_bssids.add(bssid)

        risk, reason = _classify_security(security)
        freq_mhz = _parse_freq_mhz(freq)

        networks.append({
            "ssid": ssid or "(hidden network)",
            "bssid": bssid,
            "signal": int(signal) if signal.isdigit() else None,
            "security": security or "Open",
            "risk": risk,
            "reason": reason,
            "channel": chan,
            "band": _band_for_freq(freq_mhz),
            "freq_mhz": freq_mhz,
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
