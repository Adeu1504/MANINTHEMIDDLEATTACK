import sys
from scapy.all import sniff, ARP

# This dictionary will store the "ground truth" of our network.
# We will map IPs to their correct MAC addresses as we see them.
# { "10.86.0.2": "08:55:31:EB:74:E1" }
ip_to_mac = {}


def process_arp_packet(packet):
    """
    This function is called for every ARP packet sniffed.
    It checks for anomalies.
    """

    # Check if the packet is an ARP packet and is an "is-at" (reply)
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # 2 == "is-at" (a reply)
        try:
            source_ip = packet[ARP].psrc  # The IP address claimed
            source_mac = packet[ARP].hwsrc  # The MAC address claimed

            # Check if this IP is already in our table
            if source_ip in ip_to_mac:

                # Compare the MAC we have on file with the one in the packet
                known_mac = ip_to_mac[source_ip]

                if known_mac != source_mac:
                    # !!! ALARM !!!
                    # The MAC address for a known IP has changed.
                    # This is the signature of an ARP spoofing attack.
                    print("\n[!!!] ALERT: ARP SPOOFING DETECTED [!!!]")
                    print(f"[*] IP Address:     {source_ip}")
                    print(f"[+] Original MAC:   {known_mac}")
                    print(f"[-] Malicious MAC:  {source_mac}\n")

            else:
                # This is the first time we've seen this IP.
                # Let's trust it for now and add it to our table.
                print(f"[*] New device found. Logging {source_ip} -> {source_mac}")
                ip_to_mac[source_ip] = source_mac

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

    print("[*] Starting ARP spoof detector...")
    print("[*] Any new devices will be logged.")
    print("[*] Any ARP anomalies will trigger an ALERT.")

    # Start the sniffer.
    # filter="arp": only capture ARP packets
    # prn=process_arp_packet: call this function for every packet
    # store=False: don't keep packets in memory
    try:
        sniff(filter="arp", prn=process_arp_packet, store=False)
    except PermissionError:
        print("\n[!] Error: Permission denied.")
        print("[!] Please run this script with administrator/root privileges (e.g., 'sudo python arp_detector.py')")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        print("[!] Make sure you have 'Npcap' (for Windows) or 'libpcap' (for Linux) installed.")