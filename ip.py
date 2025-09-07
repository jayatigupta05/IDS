from scapy.all import sniff, get_if_list, conf, IP
import time

# Replace this with your local IP
LOCAL_IP = "192.168.1.7"

# -----------------------------
# Find the interface GUID for the local IP
# -----------------------------
def get_iface_for_ip(ip_address):
    for iface in get_if_list():
        try:
            addrs = conf.ifaces.dev_from_name(iface).ip
            if addrs == ip_address:
                return iface
        except Exception:
            continue
    raise ValueError(f"No interface found with IP {ip_address}")

# -----------------------------
# Sniffer class
# -----------------------------
class Sniffer:
    def __init__(self, iface):
        self.iface = iface
        self.last_periodic_scan = time.time()
        self.periodic_interval = 5

    def process_packet(self, packet):
        try:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                print(f"{src} -> {dst}")
            # Here you would call your detectors, e.g.,
            # self.tracker.store_packet(packet)
            # self.portscan_detector.detect_multiport_scan(packet)
            # Run periodic scans
            current_time = time.time()
            if current_time - self.last_periodic_scan >= self.periodic_interval:
                # self.portscan_detector.detect_batch_port_scans()
                # self.session_detector.detect_high_rate_sessions()
                # self.ping_flood.detect_ping_flood()
                self.last_periodic_scan = current_time
        except Exception as e:
            print(f"[WARNING] Skipping packet: {e}")

    def sniff_packets(self):
        print(f"[*] Starting sniffer on interface {self.iface}")
        sniff(iface=self.iface, filter="icmp", prn=self.process_packet, store=0)

# -----------------------------
# Main execution
# -----------------------------
if __name__ == "__main__":
    try:
        iface = get_iface_for_ip(LOCAL_IP)
        sniffer = Sniffer(iface)
        sniffer.sniff_packets()
    except ValueError as e:
        print(e)
