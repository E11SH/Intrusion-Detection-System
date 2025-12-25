from scapy.all import IP
from datetime import datetime
from collections import defaultdict
import time

# Configuration
DOS_THRESHOLD = 500
DOS_WINDOW = 3
ALERT_COOLDOWN = 60

# Tracking
dos_tracker = defaultdict(lambda: {'count': 0, 'last_reset': time.time()})
last_alert_time = defaultdict(lambda: 0)

def detect_dos_attack(packet, alert_logger):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()
        
        # Skip only invalid IPs, broadcast, and multicast
        if (src_ip.startswith('0.') or 
            src_ip.startswith('224.') or 
            src_ip.startswith('255.') or
            src_ip == '0.0.0.0'):
            return
        
        # Skip if we alerted recently for this IP
        if current_time - last_alert_time[src_ip] < ALERT_COOLDOWN:
            return
        
        tracker = dos_tracker[src_ip]
        
        # Reset if window expired
        if current_time - tracker['last_reset'] > DOS_WINDOW:
            tracker['count'] = 0
            tracker['last_reset'] = current_time
        
        tracker['count'] += 1
        
        # Debug output for high packet counts (only if significant)
        if tracker['count'] > 300 and tracker['count'] % 50 == 0:
            print(f"[DEBUG] DoS tracking: {src_ip} -> {dst_ip} sent {tracker['count']} packets in {DOS_WINDOW}s window (threshold: {DOS_THRESHOLD})")
        
        # Check threshold
        if tracker['count'] >= DOS_THRESHOLD:
            alert = {
                'type': 'DoS Attack',
                'source_ip': src_ip,
                'timestamp': datetime.now().isoformat(),
                'severity': 'critical',
                'details': f'{tracker["count"]} packets to {dst_ip} in {DOS_WINDOW}s'
            }
            alert_logger(alert)
            # Update last alert time
            last_alert_time[src_ip] = current_time
            # Reset to avoid duplicate alerts
            tracker['count'] = 0
            tracker['last_reset'] = current_time