import sys
import time
from scapy.all import sniff, TCP, IP

# --- Configuration ---
# If an IP hits this many ports...
PORT_THRESHOLD = 20
# ...within this many seconds...
TIME_WINDOW = 10
# ...it's a scan.

# This dictionary will store our tracking data
# { "attacker_ip": {"ports": {22, 80, 443...}, "start_time": 1678886400, "alerted": False} }
scan_tracker = {}


def process_packet(packet):
    """
    This function is called for every packet sniffed.
    It checks for port scan patterns.
    """
    try:
        # We only care about TCP packets that are SYN packets (the start of a connection)
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # 'S' is for SYN

            source_ip = packet[IP].src
            dest_port = packet[TCP].dport
            current_time = time.time()

            # Check if we are already tracking this IP
            if source_ip not in scan_tracker:
                # First time seeing this IP. Start tracking.
                scan_tracker[source_ip] = {
                    'ports': {dest_port},
                    'start_time': current_time,
                    'alerted': False
                }
                return

            # IP is already in our tracker
            record = scan_tracker[source_ip]

            # Check if the time window has expired. If so, reset.
            if current_time - record['start_time'] > TIME_WINDOW:
                # Reset the record for a new time window
                record['ports'] = {dest_port}
                record['start_time'] = current_time
                record['alerted'] = False
            else:
                # Still within the time window. Add the new port.
                record['ports'].add(dest_port)

            # Check if the threshold has been breached and we haven't alerted yet
            if len(record['ports']) > PORT_THRESHOLD and not record['alerted']:
                print("\n[!!!] ALERT: PORT SCAN DETECTED [!!!]")
                print(f"[*] Source IP:     {source_ip}")
                print(f"[*] Ports Targeted: {len(record['ports'])} (e.g., {list(record['ports'])[:5]}...)")
                print(f"[*] Time Window:   {TIME_WINDOW} seconds\n")

                # Set alert flag so we don't spam alerts for this same scan
                record['alerted'] = True

            # Save the updated record
            scan_tracker[source_ip] = record

    except IndexError:
        # Handle malformed packets
        pass
    except Exception as e:
        print(f"[!] Error processing packet: {e}")


# --- Main execution ---
if __name__ == "__main__":
    if sys.platform.startswith('win') and not sys.stdin.isatty():
        print("[!] Note: On Windows, please run this from a Command Prompt or PowerShell")
        print("[!] with 'Run as Administrator'.")

    print("[*] Starting Port Scan detector...")
    print(f"[*] Alert threshold: {PORT_THRESHOLD} ports in {TIME_WINDOW} seconds.")

    try:
        # filter="tcp": We only care about TCP packets
        sniff(filter="tcp", prn=process_packet, store=False)
    except PermissionError:
        print("\n[!] Error: Permission denied.")
        print("[!] Please run this script with administrator/root privileges.")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")