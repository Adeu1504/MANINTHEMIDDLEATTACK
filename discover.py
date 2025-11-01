import nmap
import json


def discover_devices(network_subnet):
    """
    Scans the given network subnet and returns a list of active devices.
    """
    nm = nmap.PortScanner()
    print(f"[*] Scanning network: {network_subnet} ... This may take a moment.")

    # -sn: Ping Scan. Disables port scanning.
    # This is a 'host discovery' scan.
    try:
        nm.scan(hosts=network_subnet, arguments='-sn')
    except nmap.nmap.PortScannerError:
        print("\n[!] Error: Nmap not found. Make sure it's installed and in your system's PATH.")
        return []
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        return []

    device_list = []

    for host_ip in nm.all_hosts():
        # nm[host] contains all info about that host
        host_data = nm[host_ip]

        # Check if host is up
        if host_data['status']['state'] == 'up':
            device_info = {'ip': host_ip}

            # Try to get MAC address (vendor info is nested)
            try:
                # 'mac' is usually in the 'addresses' dictionary
                mac_address = host_data['addresses']['mac']
                device_info['mac'] = mac_address
            except KeyError:
                # Sometimes MAC isn't available (e.g., scanning localhost)
                device_info['mac'] = 'Not found'

            device_list.append(device_info)

    return device_list


# --- Main execution ---
if __name__ == "__main__":

    # !!! IMPORTANT: CHANGE THIS to your network subnet !!!
    network_to_scan = "10.86.0.0/21"

    devices = discover_devices(network_to_scan)

    if devices:
        print(f"\n[+] Scan complete. Found {len(devices)} active devices:")
        # Pretty print the list of dictionaries
        print(json.dumps(devices, indent=2))
    else:
        print("\n[*] Scan finished. No devices found or an error occurred.")