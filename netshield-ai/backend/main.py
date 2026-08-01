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

NETWORK_RANGE = "192.168.1.0/24"


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
