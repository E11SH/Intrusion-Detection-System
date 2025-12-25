from scapy.all import TCP, IP
from datetime import datetime
from collections import defaultdict
import time

# Configuration
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 10
ALERT_COOLDOWN = 60

# Tracking
port_scan_tracker = defaultdict(lambda: {'ports': set(), 'last_reset': time.time()})
last_alert_time = defaultdict(lambda: 0)

def detect_port_scan(packet, alert_logger):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        current_time = time.time()
        
        # Skip only invalid IPs and broadcast
        if src_ip.startswith('0.') or src_ip == '255.255.255.255' or src_ip == '0.0.0.0':
            return
        
        # Skip if we alerted recently for this IP
        if current_time - last_alert_time[src_ip] < ALERT_COOLDOWN:
            return
            
        tracker = port_scan_tracker[src_ip]
        
        # Reset if window expired
        if current_time - tracker['last_reset'] > PORT_SCAN_WINDOW:
            tracker['ports'] = set()
            tracker['last_reset'] = current_time
        
        tracker['ports'].add(dst_port)
        
        # Debug output
        if len(tracker['ports']) > 8:
            print(f"[DEBUG] Port scan tracking: {src_ip} -> {dst_ip} scanned {len(tracker['ports'])} ports")
        
        # Check threshold
        if len(tracker['ports']) >= PORT_SCAN_THRESHOLD:
            alert = {
                'type': 'Port Scan',
                'source_ip': src_ip,
                'timestamp': datetime.now().isoformat(),
                'severity': 'high',
                'details': f'Scanned {len(tracker["ports"])} ports on {dst_ip} in {PORT_SCAN_WINDOW}s'
            }
            alert_logger(alert)
            # Update last alert time
            last_alert_time[src_ip] = current_time
            # Reset to avoid duplicate alerts
            tracker['ports'] = set()
            tracker['last_reset'] = current_time