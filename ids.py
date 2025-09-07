from scapy.all import sniff, IP
from collections import defaultdict
import time

class Sniff:
    def __init__(self):
        self.connections = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def sniff_packets(self, interface="eth0"):
        sniff(iface=interface, filter="tcp", prn=self.process_packet, store=0)

    def print_pkt(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            print(f"{src} -> {dst}")
    
    def store_packet(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[IP].sport
            port_dst = packet[IP].dport

            key = (ip_src, ip_dst, port_src, port_dst)

            conn = self.connections[key]
            conn['packet_count'] += 1
            conn['byte_count'] += len(packet)
            current_time = packet.time
            
            if not conn['start_time']:
                conn['start_time'] = current_time
            conn['last_time'] = current_time

    def detect_multiport_scan(self, packet):
        """
        Detects port scans by checking if one source IP tries multiple destination
        ports on the same host in a short time window.
        """
        if IP in packet:
            src_ip = packet[IP].src
            dst_port = packet[IP].dport

            # Port scan detection
            if "ports" not in self.connections[src_ip]:
                self.connections[src_ip]["ports"] = set()
            self.connections[src_ip]["ports"].add(dst_port)

            if len(self.connections[src_ip]["ports"]) > 20:
                print(f"[ALERT] Port scan from {src_ip} — {len(self.connections[src_ip]['ports'])} ports contacted")

    def detect_session_rates(self):
        """
        Detects abnormal sessions where a single connection sends too many packets
        in a short time window (DoS/brute-force behavior).
        """
        for key, conn in self.connections.items():
            time_passed = conn['last_time'] - conn['start_time']
            if time_passed >= 5 and conn['packet_count'] >= 50:
                src, dst, sport, dport = key
                print(f"[ALERT] Possible port scan from {src}:{sport} to {dst}:{dport} "
                      f"({conn['packet_count']} packets in {time_passed:.2f}s)")
                
        # time_passed = self.connections['last_time'] - self.comnnections['start_time']
        # if time_passed > 5 and self.connections['packet_count'] > 50:
        #     print(f"[ALERT] Sessoin requestion too many packets")

    def port_scan(self):
        """
        Detects ongoing port scans in real time by tracking unique destination ports
        contacted by each source IP.
        """
        scan_tracker = {}
        for (src, _, _, dport), _ in self.connections.items():
            if src not in scan_tracker:
                scan_tracker[src] = set()
            scan_tracker[src].add(dport)
        
        for src, dport in scan_tracker.items():
            if len(dport) >= 20:
                print(f"[ALERT] Possible port scan from {src} (scanned {len(dport)} ports)")
    
    def process_packet(self, packet):
        self.print_pkt(packet)
        self.store_packet(packet)
        self.detect_multiport_scan(packet)
        # self.check_session()

if __name__ == "__main__":
    sniffer = Sniff()
    sniffer.sniff_packets(interface="Wi-Fi")