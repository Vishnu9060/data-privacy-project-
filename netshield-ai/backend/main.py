import ipaddress
import socket

import psutil
import nmap
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff, IP, TCP, UDP, ICMP

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _detect_network_range() -> str:
    local_ip = _get_local_ip()

    try:
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip and addr.netmask:
                    network = ipaddress.IPv4Network(f"{local_ip}/{addr.netmask}", strict=False)
                    return str(network)
    except Exception:
        pass

    octets = local_ip.split(".")
    return f"{'.'.join(octets[:3])}.0/24"


NETWORK_RANGE = _detect_network_range()


@app.get("/")
def read_root():
    return {"message": "NetShield AI backend is running"}


@app.get("/scan")
def scan_network():
    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=NETWORK_RANGE, arguments="-sn")
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}

    devices = []
    for host in scanner.all_hosts():
        host_info = scanner[host]
        hostname = host_info.hostname() or "unknown"
        devices.append({
            "ip": host,
            "hostname": hostname,
            "status": host_info.state(),
        })

    if not devices:
        return {"error": "No devices found on the network."}

    return {"devices": devices}


@app.get("/capture-live")
def capture_live():
    try:
        captured = sniff(timeout=15)
    except Exception as e:
        return {"error": f"Capture failed: {str(e)}"}

    packets = []
    for pkt in captured:
        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]

        if pkt.haslayer(TCP):
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            protocol = "UDP"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "other"

        packets.append({
            "source_ip": ip_layer.src,
            "destination_ip": ip_layer.dst,
            "protocol": protocol,
            "length": len(pkt),
        })

        if len(packets) >= 200:
            break

    return {"packets": packets}


@app.get("/network-adapter-info")
def network_adapter_info():
    try:
        interfaces = psutil.net_if_addrs()
    except Exception as e:
        return {"error": f"Failed to read network adapters: {str(e)}"}

    adapters = []
    for name, addr_list in interfaces.items():
        for addr in addr_list:
            if addr.family == psutil.AF_LINK and addr.address:
                mac_address = addr.address.replace("-", ":").upper()
                adapters.append({
                    "name": name,
                    "mac_address": mac_address,
                })
                break

    if not adapters:
        return {"error": "No network adapters with a MAC address were found."}

    return {"adapters": adapters}


def _scan_ports(target: str) -> dict:
    if not target:
        return {"error": "Missing required query parameter 'target'."}

    try:
        ipaddress.ip_address(target)
    except ValueError:
        return {"error": f"'{target}' is not a valid IP address."}

    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=target, arguments="-F -sV")
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}

    if target not in scanner.all_hosts():
        return {"target": target, "open_ports": []}

    open_ports = []
    host_info = scanner[target]
    for proto in host_info.all_protocols():
        if proto != "tcp":
            continue
        for port, port_info in host_info[proto].items():
            if port_info.get("state") == "open":
                open_ports.append({
                    "port": port,
                    "service": port_info.get("name", "unknown"),
                    "version": port_info.get("version", "") or "unknown",
                })

    return {"target": target, "open_ports": open_ports}


@app.get("/port-scan")
def port_scan(target: str = ""):
    return _scan_ports(target)


RISK_TABLE = {
    21: ("HIGH", "FTP transmits credentials and data unencrypted"),
    23: ("HIGH", "Telnet transmits everything unencrypted, including passwords"),
    445: ("HIGH", "SMB has a history of critical exploits (e.g. WannaCry) and shouldn't be exposed"),
    3389: ("HIGH", "RDP exposed to network scanning is a common ransomware entry point"),
    135: ("MEDIUM", "Windows RPC endpoint mapper, often targeted for reconnaissance"),
    5432: ("MEDIUM", "Database port should not be exposed outside trusted networks"),
    3306: ("MEDIUM", "Database port should not be exposed outside trusted networks"),
    1433: ("MEDIUM", "Database port should not be exposed outside trusted networks"),
    80: ("LOW", "Unencrypted web traffic; prefer HTTPS (443) if available"),
    22: ("INFO", "Standard encrypted service"),
    443: ("INFO", "Standard encrypted service"),
}


@app.get("/security-analysis")
def security_analysis(target: str = ""):
    scan_result = _scan_ports(target)

    if "error" in scan_result:
        return scan_result

    findings = []
    summary = {"high": 0, "medium": 0, "low": 0, "info": 0}

    for port_entry in scan_result["open_ports"]:
        port = port_entry["port"]
        risk, reason = RISK_TABLE.get(
            port, ("MEDIUM", "Unrecognized service; verify it is intentional and necessary")
        )
        findings.append({
            "port": port,
            "service": port_entry["service"],
            "risk": risk,
            "reason": reason,
        })
        summary[risk.lower()] += 1

    return {
        "target": scan_result["target"],
        "findings": findings,
        "summary": summary,
    }
