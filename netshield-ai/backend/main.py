import nmap
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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
