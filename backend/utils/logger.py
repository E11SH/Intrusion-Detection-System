from datetime import datetime
import threading
import json
import os

# Global storage for alerts
alerts = []
alert_lock = threading.Lock()
MAX_ALERTS = 1000

def log_alert(alert):
    print(f"[ALERT] {alert['type']} from {alert['source_ip']} - {alert['details']}")
    
    with alert_lock:
        alerts.append(alert)
        # Keep only last MAX_ALERTS
        if len(alerts) > MAX_ALERTS:
            alerts.pop(0)
    
    # Log to file
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"ids_log_{datetime.now().strftime('%Y%m%d')}.json")
    
    try:
        with open(log_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')
    except Exception as e:
        print(f"Error logging alert: {e}")