from flask import Flask, jsonify
from flask_cors import CORS
from scapy.all import sniff, IP, TCP, ARP
from datetime import datetime
from collections import defaultdict
import threading
import time
import os

# Import detection modules
from detectors.port_scan import detect_port_scan, port_scan_tracker
from detectors.dos_attack import detect_dos_attack, dos_tracker
from detectors.arp_spoof import detect_arp_spoofing, arp_tracker
from utils.logger import log_alert, alerts, alert_lock

app = Flask(__name__)
CORS(app)

# Packet counter for debugging
packet_count = {'total': 0, 'ip': 0, 'tcp': 0, 'arp': 0}

def packet_callback(packet):
    try:
        packet_count['total'] += 1
        
        # Count packet types
        if packet.haslayer(IP):
            packet_count['ip'] += 1
        if packet.haslayer(TCP):
            packet_count['tcp'] += 1
        if packet.haslayer(ARP):
            packet_count['arp'] += 1
        
        # Print periodic status
        if packet_count['total'] % 100 == 0:
            print(f"[INFO] Packets captured: {packet_count['total']} (IP: {packet_count['ip']}, TCP: {packet_count['tcp']}, ARP: {packet_count['arp']})")
        
        # Run detectors
        detect_port_scan(packet, log_alert)
        detect_dos_attack(packet, log_alert)
        detect_arp_spoofing(packet, log_alert)
        
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing():
    print("\n" + "="*60)
    print("INTRUSION DETECTION SYSTEM - STARTING")
    print("="*60)
    
    # Show available interfaces
    print("\n[INFO] Available network interfaces:")
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces):
            print(f"  [{i}] {iface}")
    except:
        print("  Could not list interfaces")
    
    print("\n[INFO] Starting packet capture on all interfaces...")
    print("[INFO] Detection thresholds:")
    print(f"  - Port Scan: 15 ports in 10s")
    print(f"  - DoS Attack: 500 packets in 3s")
    print("  - ARP Spoofing: Immediate detection on MAC change")
    print(f"  - Alert cooldown: 60s between same alerts")
    print("\n[INFO] Waiting for packets...")
    print("="*60 + "\n")
    
    try:
        # Try to sniff on all interfaces with a filter
        sniff(
            prn=packet_callback, 
            store=False,
            filter="tcp or arp",
        )
    except PermissionError:
        print("\n[ERROR] Permission denied! Run with sudo/administrator privileges:")
        print("  Linux/Mac: sudo python3 main.py")
        print("  Windows: Run terminal as Administrator\n")
    except Exception as e:
        print(f"\n[ERROR] Error starting packet capture: {e}")
        print("Note: Make sure you have proper permissions and Scapy is installed correctly\n")

# API Routes
@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        'status': 'running',
        'timestamp': datetime.now().isoformat(),
        'packets_captured': packet_count['total'],
        'monitored_ips': len(set(list(port_scan_tracker.keys()) + list(dos_tracker.keys())))
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    with alert_lock:
        return jsonify({
            'alerts': alerts,
            'total': len(alerts)
        })

@app.route('/api/alerts/recent', methods=['GET'])
def get_recent_alerts():
    with alert_lock:
        recent = alerts[-50:] if len(alerts) > 50 else alerts
        return jsonify({
            'alerts': list(reversed(recent)),
            'total': len(alerts)
        })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    with alert_lock:
        if not alerts:
            return jsonify({
                'total_attacks': 0,
                'by_type': {},
                'by_severity': {},
                'most_common_attacker': None
            })
        
        # Calculate statistics
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        by_ip = defaultdict(int)
        
        for alert in alerts:
            by_type[alert['type']] += 1
            by_severity[alert['severity']] += 1
            by_ip[alert['source_ip']] += 1
        
        most_common_attacker = max(by_ip.items(), key=lambda x: x[1]) if by_ip else None
        
        return jsonify({
            'total_attacks': len(alerts),
            'by_type': dict(by_type),
            'by_severity': dict(by_severity),
            'most_common_attacker': {
                'ip': most_common_attacker[0],
                'count': most_common_attacker[1]
            } if most_common_attacker else None
        })

@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    with alert_lock:
        alerts.clear()
    return jsonify({'status': 'cleared'})

@app.route('/api/test', methods=['POST'])
def create_test_alert():
    test_alert = {
        'type': 'Test Alert',
        'source_ip': '192.168.1.100',
        'timestamp': datetime.now().isoformat(),
        'severity': 'high',
        'details': 'This is a test alert to verify the system is working'
    }
    log_alert(test_alert)
    return jsonify({'status': 'test alert created', 'alert': test_alert})

@app.route('/api/arp/list', methods=['GET'])
def list_arp_cache():
    return jsonify({
        'arp_cache': {ip: mac for ip, mac in arp_tracker.items()},
        'total_entries': len(arp_tracker)
    })

@app.route('/api/test/arp', methods=['POST'])
def test_arp_spoofing():
    # Pick a random IP from the cache and change its MAC
    if arp_tracker:
        test_ip = list(arp_tracker.keys())[0]
        old_mac = arp_tracker[test_ip]
        fake_mac = "00:11:22:33:44:55"
        
        # Temporarily change the MAC to trigger detection
        alert = {
            'type': 'ARP Spoofing',
            'source_ip': test_ip,
            'timestamp': datetime.now().isoformat(),
            'severity': 'critical',
            'details': f'TEST: MAC changed from {old_mac} to {fake_mac}'
        }
        log_alert(alert)
        
        return jsonify({
            'status': 'test arp spoofing alert created',
            'alert': alert
        })
    else:
        return jsonify({
            'status': 'no IPs in ARP cache yet',
            'message': 'Wait for some network traffic first'
        })

if __name__ == '__main__':
    # Start packet sniffing in background thread
    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()
    
    # Give sniffer a moment to start
    time.sleep(2)
    
    # Run Flask API
    print("\n[INFO] Starting Flask API on http://localhost:5000")
    print("[INFO] Access the dashboard at http://localhost:8000")
    print("[INFO] Test the system with: curl -X POST http://localhost:5000/api/test\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)