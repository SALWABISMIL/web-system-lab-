from flask import Flask, request, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import socket
import platform

app = Flask(__name__)

# Local-only server: it is not exposed to the internet.
HOST = "127.0.0.1"
PORT = 8765
TIMEOUT = 0.25
MAX_HOSTS = 256

# Common ports used for basic service discovery.
PORTS = [80, 443, 554, 8000, 8080, 8443, 6000, 37777, 34567]


def detect_local_ip():
    """Find the local interface selected by the system routing table."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect selects an interface; it sends no application data.
        sock.connect(("192.0.2.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def suggest_subnet(local_ip):
    """Suggest a /24 network; actual LAN masks may be different."""
    try:
        address = ipaddress.ip_address(local_ip)
        if address.is_private and not address.is_loopback:
            return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except ValueError:
        pass
    return None


def identify_device(open_ports):
    """Make cautious guesses from observed open TCP ports."""
    if 554 in open_ports:
        return {
            "type": "Possible IP camera / NVR",
            "confidence": "Low to medium",
            "reason": "RTSP commonly uses TCP port 554; other devices can use it too."
        }

    if 37777 in open_ports:
        return {
            "type": "Possible Dahua-family video device",
            "confidence": "Low",
            "reason": "Port 37777 is associated with some Dahua devices, but is not proof."
        }

    if 8000 in open_ports and 80 in open_ports:
        return {
            "type": "Possible camera / NVR / web device",
            "confidence": "Low",
            "reason": "Ports 80 and 8000 are used by many different products."
        }

    if 6000 in open_ports:
        return {
            "type": "Possible automation or custom service",
            "confidence": "Low",
            "reason": "Port 6000 is used by some systems, but does not identify a device."
        }

    if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
        return {
            "type": "Web service detected",
            "confidence": "High for service; unknown device",
            "reason": "An HTTP/HTTPS-related port accepted a TCP connection."
        }

    return {
        "type": "Unknown device",
        "confidence": "Not enough evidence",
        "reason": "No tested TCP port responded."
    }


def check_host(ip):
    """Check a single address for a small set of common TCP services."""
    open_ports = []

    for port in PORTS:
        try:
            with socket.create_connection((str(ip), port), timeout=TIMEOUT):
                open_ports.append(port)
        except (OSError, TimeoutError):
            pass

    if not open_ports:
        return None

    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
    except (OSError, socket.herror):
        hostname = None

    return {
        "ip": str(ip),
        "hostname": hostname,
        "open_tcp_ports": open_ports,
        "identity": identify_device(open_ports),
        "status": "Responding on tested TCP port(s)"
    }


@app.get("/")
def home():
    return jsonify({
        "service": "Web System Lab - Local Engine",
        "status": "online",
        "endpoints": ["/api/health", "/api/network", "/api/scan"]
    })


@app.get("/api/health")
def health():
    return jsonify({"status": "online", "engine": "local"})


@app.get("/api/network")
def network_info():
    local_ip = detect_local_ip()
    return jsonify({
        "local_ip": local_ip,
        "suggested_subnet": suggest_subnet(local_ip),
        "note": "The suggested /24 mask is an estimate. Verify it against your network settings."
    })


@app.get("/api/scan")
def scan():
    raw_subnet = request.args.get("subnet", "").strip()

    if not raw_subnet:
        local_ip = detect_local_ip()
        raw_subnet = suggest_subnet(local_ip) or ""

    try:
        network = ipaddress.ip_network(raw_subnet, strict=False)
    except ValueError:
        return jsonify({
            "success": False,
            "error": "Enter a valid subnet, for example 192.168.1.0/24."
        }), 400

    if not network.is_private or network.is_loopback or network.is_link_local:
        return jsonify({
            "success": False,
            "error": "Only authorized private LAN subnets are allowed."
        }), 400

    if network.num_addresses > MAX_HOSTS:
        return jsonify({
            "success": False,
            "error": "This version scans up to 256 addresses per scan."
        }), 400

    addresses = list(network.hosts())
    devices = []

    with ThreadPoolExecutor(max_workers=64) as executor:
        jobs = [executor.submit(check_host, ip) for ip in addresses]
        for job in as_completed(jobs):
            try:
                result = job.result()
                if result:
                    devices.append(result)
            except Exception:
                # One failed host must not stop the whole scan.
                continue

    devices.sort(key=lambda device: ipaddress.ip_address(device["ip"]))

    return jsonify({
        "success": True,
        "subnet": str(network),
        "checked_addresses": len(addresses),
        "devices_found": len(devices),
        "devices": devices,
        "limitations": [
            "Only the listed TCP ports were tested.",
            "Devices without those ports open will not appear.",
            "A missing result does not prove a device is offline.",
            "Device types are guesses, not confirmed identities.",
            "MAC addresses and vendor names are not collected by this version."
        ]
    })


if __name__ == "__main__":
    print("Web System Lab local engine")
    print(f"Open http://{HOST}:{PORT}/api/health")
    print("Scan only networks you own or are authorized to test.")
    app.run(host=HOST, port=PORT, debug=False)
