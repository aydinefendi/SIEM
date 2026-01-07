import uuid
from datetime import datetime

class Alerter:
    
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    
    def __init__(self, min_severity):
        self.min_severity = min_severity
    
    def generate_alerts(self, anomalies):
        alerts = []
        
        for anomaly in anomalies:
            severity = anomaly.get("severity", "low")
            
            if self.SEVERITY_ORDER.get(severity, 99) > self.SEVERITY_ORDER.get(self.min_severity, 99):
                continue
            
            alert = {
                "alert_id": str(uuid.uuid4()),
                "severity": severity,
                "rule_name": anomaly.get("rule_name", "unknown"),
                "alert_message": self._format_alert_message(anomaly),
                "timestamp": datetime.now(),
                "anomaly": anomaly
            }
            alerts.append(alert)
        
        alerts.sort(key=lambda x: self.SEVERITY_ORDER.get(x["severity"], 99))
        
        return alerts
    
    def _format_alert_message(self, anomaly):
        severity = anomaly.get("severity", "unknown").upper()
        rule_name = anomaly.get("rule_name", "unknown")
        reason = anomaly.get("reason", "")
        entry = anomaly.get("entry", {})
        
        ip = entry.get("ip", "N/A")
        timestamp = entry.get("timestamp")
        if timestamp:
            timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        else:
            timestamp_str = "N/A"
        
        return f"[{severity}] {rule_name}: {reason} | IP: {ip} | Time: {timestamp_str}"
    
    def get_critical_alerts(self, alerts):
        critical_alerts = []
        for alert in alerts:
            if alert.get("severity") == "critical":
                critical_alerts.append(alert)
        return critical_alerts

    def get_high_alerts(self, alerts):
        high_alerts = []
        for alert in alerts:
            if alert.get("severity") == "high":
                high_alerts.append(alert)
        return high_alerts
