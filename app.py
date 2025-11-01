import sys
import threading
import time
from datetime import datetime
import os
import ctypes

import nmap
from flask import Flask, jsonify, render_template
from scapy.all import ARP, IP, TCP, sniff

# --- Configuration ---
YOUR_NETWORK_SUBNET = "10.86.0.0/21"  # !!! Use the subnet from Milestone 1 !!!
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_TIME_WINDOW = 10
DEVICE_SCAN_INTERVAL = 300  # Scan for devices every 300 seconds (5 minutes)

# --- Global Variables ---
# These lists will store our live data.
# They are "global" so all threads can access them.
live_alerts = []
live_devices = []
# This dictionary is used by the port scan detector
scan_tracker = {}
# A thread-safe lock to prevent issues when multiple threads write to the lists
data_lock = threading.Lock()

# --- Flask App Setup ---
app = Flask(__name__)


# =======================================
# == DETECTOR LOGIC (Milestones 1, 2, 3) ==
# =======================================

# --- Milestone 1: Device Discovery ---
def run_device_discovery_loop():
    """
    This function runs in its own thread, continuously scanning
    for devices every X seconds.
    """
    global live_devices
    while True:
        print("[Discovery Thread] Scanning for devices...")
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=YOUR_NETWORK_SUBNET, arguments='-sn')
            discovered_devices = []
            for host_ip in nm.all_hosts():
                if nm[host_ip]['status']['state'] == 'up':
                    try:
                        mac_address = nm[host_ip]['addresses']['mac']
                    except KeyError:
                        mac_address = 'Not found'
                    discovered_devices.append({'ip': host_ip, 'mac': mac_address, 'type': 'Unknown'})

            # Update the global list (with a lock)
            with data_lock:
                live_devices = discovered_devices
            print(f"[Discovery Thread] Scan complete. Found {len(live_devices)} devices.")

        except Exception as e:
            print(f"[Discovery Thread] Error: {e}")

        # Wait for the next scan
        time.sleep(DEVICE_SCAN_INTERVAL)


# --- Milestone 2: ARP Spoof Detector ---
ip_to_mac_truth = {}  # Our "ground truth" table


def process_arp_packet(packet):
    """Callback for the ARP sniffer."""
    global live_alerts
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # 2 == "is-at" (a reply)
        try:
            source_ip = packet[ARP].psrc
            source_mac = packet[ARP].hwsrc

            with data_lock:
                if source_ip in ip_to_mac_truth:
                    known_mac = ip_to_mac_truth[source_ip]
                    if known_mac != source_mac:
                        # !!! ARP SPOOF DETECTED !!!
                        alert = {
                            "time": datetime.now().strftime("%H:%M:%S"),
                            "type": "ARP Spoof",
                            "severity": "CRITICAL",
                            "source": source_ip,
                            "details": f"MAC mismatch! {known_mac} vs {source_mac}"
                        }
                        live_alerts.insert(0, alert)  # Insert at the front
                else:
                    # New device, add to our truth table
                    ip_to_mac_truth[source_ip] = source_mac
        except Exception as e:
            print(f"[ARP Detector] Error: {e}")


def start_arp_detector():
    """This function runs in its own thread."""
    print("[ARP Detector Thread] Starting...")
    try:
        sniff(filter="arp", prn=process_arp_packet, store=False)
    except PermissionError:
        print("[ARP Detector Thread] Permission error. Please run as Administrator/sudo.")
    except Exception as e:
        print(f"[ARP Detector Thread] Exiting due to error: {e}")


# --- Milestone 3: Port Scan Detector ---
def process_scan_packet(packet):
    """Callback for the Port Scan sniffer."""
    global live_alerts, scan_tracker
    try:
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # SYN packet
            source_ip = packet[IP].src
            dest_port = packet[TCP].dport
            current_time = time.time()

            with data_lock:
                if source_ip not in scan_tracker:
                    scan_tracker[source_ip] = {'ports': {dest_port}, 'start_time': current_time, 'alerted': False}
                    return

                record = scan_tracker[source_ip]
                if current_time - record['start_time'] > PORT_SCAN_TIME_WINDOW:
                    record['ports'] = {dest_port}
                    record['start_time'] = current_time
                    record['alerted'] = False
                else:
                    record['ports'].add(dest_port)

                if len(record['ports']) > PORT_SCAN_THRESHOLD and not record['alerted']:
                    # !!! PORT SCAN DETECTED !!!
                    alert = {
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "type": "Port Scan",
                        "severity": "Medium",
                        "source": source_ip,
                        "details": f"Targeted {len(record['ports'])} ports."
                    }
                    live_alerts.insert(0, alert)  # Insert at the front
                    record['alerted'] = True
    except Exception as e:
        print(f"[Scan Detector] Error: {e}")


def start_scan_detector():
    """This function runs in its own thread."""
    print("[Scan Detector Thread] Starting...")
    try:
        sniff(filter="tcp", prn=process_scan_packet, store=False)
    except PermissionError:
        print("[Scan Detector Thread] Permission error. Please run as Administrator/sudo.")
    except Exception as e:
        print(f"[Scan Detector Thread] Exiting due to error: {e}")


# =======================================
# == FLASK ROUTES (The Web Pages) ======
# =======================================

@app.route("/")
def dashboard_page():
    """Renders our 'index.html' file."""
    return render_template("index.html")


@app.route("/api/data")
def get_api_data():
    """
    This is the API route that our dashboard calls.
    It now returns the LIVE data.
    """
    with data_lock:
        # Return a copy of the lists
        response_data = {
            "alerts": list(live_alerts),
            "devices": list(live_devices)
        }
    return jsonify(response_data)


# =======================================
# == MAIN EXECUTION =====================
# =======================================

if __name__ == "__main__":

    def is_admin():
        """Check if the script is running with Administrator privileges."""
        if sys.platform.startswith('win'):
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            # Check for root on Linux/macOS
            return os.geteuid() == 0


    if not is_admin():
        print("\n[!] Error: This script must be run as Administrator.")
        print("[!] Please re-launch PyCharm (or your terminal) with 'Run as Administrator'")
        print("[!] and run the script again.")
        sys.exit(1)

    # If we get here, the check passed!
    print("[*] Admin check passed.")
    print("[*] Starting background threads for detectors...")

    print("[*] Starting background threads for detectors...")

    # Create and start all our background threads
    # daemon=True means these threads will automatically exit
    # when the main application (Flask) exits.

    arp_thread = threading.Thread(target=start_arp_detector, daemon=True)
    scan_thread = threading.Thread(target=start_scan_detector, daemon=True)
    discover_thread = threading.Thread(target=run_device_discovery_loop, daemon=True)

    arp_thread.start()
    scan_thread.start()
    discover_thread.start()

    print("[*] Starting the Flask web server...")
    print("[*] Open your browser and go to http://127.0.0.1:5000")

    # We set debug=False for the final version, as debug mode
    # can cause the background threads to run twice.
    app.run(host="0.0.0.0", port=5000, debug=False)