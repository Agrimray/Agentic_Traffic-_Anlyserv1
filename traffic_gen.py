from scapy.all import *
import time
import random

# Your Wi-Fi interface
iface = r"\Device\NPF_{4844C545-DEB4-403E-9339-012CE7CCB081}"

print("🔥 Sending BENIGN unusual traffic (multicast heartbeat) through Wi-Fi")

while True:
    # Layer 2 packet so it FORCES Wi-Fi NIC usage
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff") /   # broadcast MAC
        IP(src="172.29.1.53", dst="224.0.0.251") /  # multicast DNS traffic
        UDP(dport=5353) /
        Raw(load=b"\x01")
    )

    sendp(pkt, iface=iface, verbose=False)

    time.sleep(random.choice([0.1, 0.2, 0.4, 1.0]))

