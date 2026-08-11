"""
Security analysis of open ports discovered by an nmap scan.

Implements the four Phase-4 requirements plus extras:
  1. Identify unnecessary open ports  -> necessity classification
  2. Identify insecure protocols       -> plaintext / outdated-protocol detection
  3. Recommend firewall rules          -> firewall_rules.py (per-OS, copy-paste)
  4. Recommend security improvements   -> actionable recommendation per finding
Extras:
  - Overall security score + A-F grade
  - Curated, offline known-exploit ("CVE") hints for notorious services

Everything here is static/offline and derived from the scan data — no network
calls, no external lookups — so it is safe, deterministic, and always available.
"""

import firewall_rules

# risk, whether the protocol itself is insecure (plaintext / deprecated),
# and a human recommendation. The port's "necessity" is decided separately.
#   fields: (risk, insecure, reason, recommendation)
PORT_TABLE = {
    21:   ("HIGH",   True,  "FTP transmits credentials and data in plaintext.",
           "Disable FTP. Use SFTP (over SSH, port 22) or FTPS for file transfer."),
    23:   ("HIGH",   True,  "Telnet sends everything — including passwords — unencrypted.",
           "Disable Telnet entirely. Use SSH (port 22) for remote shell access."),
    25:   ("MEDIUM", True,  "SMTP without TLS can leak mail contents and credentials.",
           "Require STARTTLS/SMTPS; do not expose an open relay to the internet."),
    69:   ("HIGH",   True,  "TFTP has no authentication and no encryption.",
           "Disable TFTP unless strictly needed on an isolated network."),
    110:  ("MEDIUM", True,  "POP3 sends mail and credentials in plaintext.",
           "Use POP3S (995) or IMAPS (993) with TLS instead."),
    111:  ("MEDIUM", False, "RPC portmapper is a common reconnaissance and attack target.",
           "Firewall it off from untrusted networks; disable if NFS/RPC is unused."),
    135:  ("MEDIUM", False, "Windows RPC endpoint mapper is heavily targeted for recon.",
           "Block at the firewall from all untrusted networks."),
    139:  ("HIGH",   True,  "NetBIOS session service is legacy and exploitable.",
           "Disable NetBIOS over TCP/IP; block 137-139 at the firewall."),
    143:  ("MEDIUM", True,  "IMAP without TLS exposes mail and credentials.",
           "Use IMAPS (993) with TLS instead."),
    161:  ("MEDIUM", True,  "SNMP (esp. v1/v2c) uses plaintext community strings.",
           "Use SNMPv3 with auth+privacy, or disable SNMP; never expose it externally."),
    389:  ("MEDIUM", True,  "LDAP without TLS exposes directory queries and binds.",
           "Use LDAPS (636) or StartTLS."),
    445:  ("HIGH",   False, "SMB has a history of critical exploits (WannaCry/EternalBlue).",
           "Never expose SMB to untrusted networks; patch and restrict to LAN only."),
    512:  ("HIGH",   True,  "rexec is a legacy remote-exec service with weak/no encryption.",
           "Disable the r-services (rexec/rlogin/rsh); use SSH."),
    513:  ("HIGH",   True,  "rlogin trusts source hosts and sends data in plaintext.",
           "Disable rlogin; use SSH."),
    514:  ("HIGH",   True,  "rsh executes remote commands with weak trust and no encryption.",
           "Disable rsh; use SSH."),
    1433: ("HIGH",   False, "Microsoft SQL Server should not be exposed to the network.",
           "Bind to localhost/trusted hosts only; firewall it off externally."),
    3306: ("HIGH",   False, "MySQL/MariaDB should not be exposed to the network.",
           "Bind to localhost or a private subnet; require TLS; firewall externally."),
    3389: ("HIGH",   False, "RDP exposed to scanning is a top ransomware entry point.",
           "Put RDP behind a VPN; enable NLA; never expose it directly to the internet."),
    5432: ("HIGH",   False, "PostgreSQL should not be exposed to the network.",
           "Bind to localhost/trusted hosts; require TLS; firewall externally."),
    5900: ("HIGH",   True,  "VNC is often unauthenticated or weakly encrypted.",
           "Tunnel VNC over SSH/VPN; never expose it directly."),
    6379: ("HIGH",   False, "Redis has no auth by default and is a common breach vector.",
           "Bind to localhost; enable auth; never expose Redis to the internet."),
    8080: ("LOW",    True,  "HTTP-alt is unencrypted web traffic.",
           "Serve over HTTPS; redirect 8080 to a TLS-terminated endpoint."),
    27017:("HIGH",   False, "MongoDB has historically shipped with no authentication.",
           "Enable auth; bind to localhost/private subnet; firewall externally."),
    80:   ("LOW",    True,  "HTTP is unencrypted; traffic can be read or modified in transit.",
           "Redirect all HTTP to HTTPS (443) and enable HSTS."),
    22:   ("INFO",   False, "SSH is an encrypted service (standard, generally safe).",
           "Keep it patched; use key-based auth; consider rate-limiting/fail2ban."),
    443:  ("INFO",   False, "HTTPS is the standard encrypted web service.",
           "Keep TLS config and certificates up to date."),
    53:   ("INFO",   False, "DNS is expected on resolvers/servers.",
           "If not a DNS server, this may be unnecessary — verify it's intended."),
}

# Ports that are normal/expected to see open on typical machines.
EXPECTED_PORTS = {22, 53, 80, 443}

# Curated, offline known-exploit notes for notorious services (educational).
CVE_HINTS = {
    445:  "Associated with MS17-010 'EternalBlue' — exploited by WannaCry/NotPetya ransomware.",
    139:  "NetBIOS; combined with SMB, part of the EternalBlue attack surface.",
    3389: "Target of BlueKeep (CVE-2019-0708), a wormable pre-auth RDP vulnerability.",
    23:   "Telnet is routinely brute-forced by IoT botnets such as Mirai.",
    5900: "Open VNC instances are mass-scanned and frequently found unauthenticated.",
    6379: "Unauthenticated Redis is widely exploited for cryptomining and data theft.",
    27017:"Thousands of open MongoDB instances have been wiped in ransom campaigns.",
}

UNKNOWN = ("MEDIUM", False, "Unrecognized service on an open port.",
           "Verify this service is intentional and necessary; close it if not.")


def _classify_necessity(port: int, risk: str, insecure: bool) -> str:
    """EXPECTED (normal), REVIEW (unusual, verify), or UNNECESSARY (should close)."""
    if insecure and risk == "HIGH":
        return "UNNECESSARY"  # legacy/plaintext high-risk services rarely justified
    if port in EXPECTED_PORTS:
        return "EXPECTED"
    return "REVIEW"


def analyze(scan_result: dict, os_name: str = "linux") -> dict:
    """Turn a port-scan result into a full security assessment.

    `scan_result` is the dict from main._scan_ports: {"target", "open_ports": [...]}.
    Returns findings, aggregate metrics, a score/grade, and firewall rules.

    Risk, necessity, insecure-protocol flag, and CVE hints are always
    deterministic (PORT_TABLE lookup). The recommendation text and firewall
    command are upgraded to AI-generated (Groq) when configured — a single
    batched call for the whole scan — and fall back to the deterministic
    template/firewall_rules output if no key is set or the call fails.
    """
    target = scan_result["target"]
    findings = []
    metrics = {
        "open_ports": 0,
        "insecure_protocols": 0,
        "unnecessary_ports": 0,
        "high": 0, "medium": 0, "low": 0, "info": 0,
    }

    for entry in scan_result["open_ports"]:
        port = entry["port"]
        service = entry.get("service", "unknown")
        version = entry.get("version", "unknown")

        risk, insecure, reason, recommendation = PORT_TABLE.get(port, UNKNOWN)
        necessity = _classify_necessity(port, risk, insecure)
        action = "deny" if necessity == "UNNECESSARY" else "restrict"

        finding = {
            "port": port,
            "service": service,
            "version": version,
            "risk": risk,
            "necessity": necessity,
            "insecure_protocol": insecure,
            "reason": reason,
            "recommendation": recommendation,
            "cve_hint": CVE_HINTS.get(port, ""),
            "firewall_rules": firewall_rules.rules_for(port, service, os_name, action=action),
        }
        findings.append(finding)

        metrics["open_ports"] += 1
        metrics[risk.lower()] += 1
        if insecure:
            metrics["insecure_protocols"] += 1
        if necessity == "UNNECESSARY":
            metrics["unnecessary_ports"] += 1

    score, grade = _score(metrics)
    recommendation_source = "template"

    if findings:
        try:
            import ai_firewall
            ai_by_port = ai_firewall.generate_ai_recommendations(findings, os_name=os_name)
            if ai_by_port is not None:
                for f in findings:
                    ai = ai_by_port.get(f["port"])
                    if not ai:
                        continue
                    f["recommendation"] = ai["recommendation"]
                    # Overlay the AI-written command as the primary display
                    # command, but keep the deterministic ufw/iptables/netsh
                    # trio intact underneath as a verified reference.
                    f["firewall_rules"]["ai_command"] = ai["command"]
                    f["firewall_rules"]["explanation"] = ai["explanation"]
                recommendation_source = "groq"
        except Exception:
            recommendation_source = "template"

    return {
        "target": target,
        "findings": findings,
        "metrics": metrics,
        "score": score,
        "grade": grade,
        "recommendation_source": recommendation_source,
    }


def _score(metrics: dict) -> tuple[int, str]:
    """Compute a 0-100 security score and an A-F grade from the findings.

    Starts at 100 and deducts per issue, weighted by severity. A host with no
    open ports (or only expected encrypted ones) scores highest.
    """
    score = 100
    score -= metrics["high"] * 25
    score -= metrics["medium"] * 10
    score -= metrics["low"] * 3
    score -= metrics["unnecessary_ports"] * 5
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade
