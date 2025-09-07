from scapy.all import IP, TCP
from ids1 import ConnectionTracker, PortScanDetector

tracker = ConnectionTracker()
detector = PortScanDetector(tracker)

src_ip = "192.168.1.100"
dst_ip = "192.168.1.200"

for port in range(1, 25):
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=port, sport=12345)
    tracker.store_packet(pkt)
    detector.detect_multiport_scan(pkt)
