from scapy.all import ARP
from datetime import datetime

# Tracking
arp_tracker = {}  # IP -> MAC mapping

def detect_arp_spoofing(packet, alert_logger):
    if packet.haslayer(ARP):
        # Only check ARP replies (op=2) or announcements
        arp_op = packet[ARP].op
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        
        # Skip broadcast and invalid IPs
        if src_ip == '0.0.0.0' or src_mac == '00:00:00:00:00:00':
            return
        
        # Only log significant ARP activity (not every single packet)
        if src_ip in arp_tracker:
            old_mac = arp_tracker[src_ip]
            # Check if MAC changed
            if old_mac != src_mac:
                alert = {
                    'type': 'ARP Spoofing',
                    'source_ip': src_ip,
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'critical',
                    'details': f'MAC changed from {old_mac} to {src_mac} (ARP op={arp_op})'
                }
                alert_logger(alert)
                print(f"[ALERT] ⚠️  ARP Spoofing detected! IP {src_ip} changed MAC: {old_mac} -> {src_mac}")
        else:
            # First time seeing this IP - just log it quietly
            print(f"[DEBUG] ARP learned: {src_ip} = {src_mac}")
        
        # Update tracker
        arp_tracker[src_ip] = src_mac