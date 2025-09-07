from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import signal


class ConnectionTracker:
    """Tracks packet/session statistics for active connections."""
    def __init__(self):
        self.connections = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'ports': set()
        })

    def store_packet(self, packet):
        try:
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                port_src = packet.sport if TCP in packet else None
                port_dst = packet.dport if UDP in packet else None

                key = (ip_src, ip_dst, port_src, port_dst)
                conn = self.connections[key]
                conn['packet_count'] += 1
                conn['byte_count'] += len(packet)
                current_time = packet.time
                if not conn['start_time']:
                    conn['start_time'] = current_time
                conn['last_time'] = current_time
                if port_dst is not None:
                    conn['ports'].add(port_dst)

                print(f"{ip_src} -> {ip_dst}")
        except Exception as e:
            print(f"[WARNING] Skipping packet: {e}")

    def print_pkt(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            print(f"{src} -> {dst}")


class PortScanDetector:
    """Detects port scans based on connection tracking data."""
    def __init__(self, tracker):
        self.tracker = tracker
        self.src_ports = {}  # src_ip -> set of dst_ports

    def detect_multiport_scan(self, packet):
        if IP in packet and ICMP not in packet:
            src_ip = packet[IP].src
            dst_port = getattr(packet[IP], "dport", None)

            # Track destination ports per source IP
            if src_ip not in self.src_ports:
                self.src_ports[src_ip] = set()
            if dst_port:
                self.src_ports[src_ip].add(dst_port)

            # Trigger alert if > 20 unique ports
            if len(self.src_ports[src_ip]) > 20:
                print(f"[ALERT] Port scan from {src_ip} "
                      f"({len(self.src_ports[src_ip])} ports)")

    def detect_batch_port_scans(self):
        """Analyzes all connections for signs of broad scans."""
        scan_tracker = {}
        for (src, _, _, dport), _ in self.tracker.connections.items():
            if src not in scan_tracker and dport is not None:
                scan_tracker[src] = set()
            if dport is not None:
                scan_tracker[src].add(dport)

        for src, dports in scan_tracker.items():
            if len(dports) >= 20:
                print(f"[ALERT] Batch scan detected from {src} "
                      f"(scanned {len(dports)} ports)")


class SessionRateDetector:
    """Detects abnormal session behavior like DoS or brute-force attempts."""
    def __init__(self, tracker):
        self.tracker = tracker

    def detect_high_rate_sessions(self):
        for key, conn in self.tracker.connections.items():
            if conn['start_time'] and conn['last_time']:
                time_passed = conn['last_time'] - conn['start_time']
                if conn['packet_count'] >= 50 and time_passed >= 5:
                    src, dst, sport, dport = key
                    print(f"[ALERT] Flooding/scan from {src}:{sport} to {dst}:{dport} "
                          f"({conn['packet_count']} packets in {time_passed:.2f}s)")


class PingFlood:
    """Detects if an IP sends too many ICMP echo requests in a small time window"""
    def __init__(self, tracker):
        self.tracker = tracker

    def detect_ping_flood(self):
        for key, conn in self.tracker.connections.items():
            src_ip, _, sport, dport = key
            if sport is None and dport is None:
                time_passed = conn["last_time"] - conn['start_time']
                if conn["packet_count"] > 100 and time_passed >= 5 and conn['byte_count'] < 20000:
                    print(f"[ALERT] Possible ICMP flood from {src_ip} "
                          f"({conn['packet_count']} echo in {time_passed:.2f}s)")


class Sniffer:
    """Main class that ties everything together."""
    def __init__(self):
        self.tracker = ConnectionTracker()
        self.portscan_detector = PortScanDetector(self.tracker)
        self.session_detector = SessionRateDetector(self.tracker)
        self.ping_flood = PingFlood(self.tracker)
        self.last_periodic_scan = time.time()
        self.periodic_interval = 5
        self.running = True

    def process_packet(self, packet):
        if not self.running:
            return True  # just in case
        self.tracker.store_packet(packet)
        self.portscan_detector.detect_multiport_scan(packet)

        current_time = time.time()
        if current_time - self.last_periodic_scan >= self.periodic_interval:
            self.portscan_detector.detect_batch_port_scans()
            self.session_detector.detect_high_rate_sessions()
            self.ping_flood.detect_ping_flood()
            self.last_periodic_scan = current_time

    def sniff_packets(self, interface="Wi-Fi"):
        sniff(
            iface=interface,
            filter="ip",
            prn=self.process_packet,
            store=0,
            stop_filter=lambda _: not self.running
        )

    def stop_sniffing(self):
        self.running = False
        print("Stopped")


def signal_handler(sig, frame):
    print('Stopping sniffer...')
    sniffer.stop_sniffing()


if __name__ == "__main__":
    sniffer = Sniffer()

    # Set up signal handler for graceful termination
    signal.signal(signal.SIGINT, signal_handler)

    sniffer.sniff_packets(interface="Wi-Fi")
