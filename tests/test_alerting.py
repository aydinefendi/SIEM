import unittest
from datetime import datetime
from alerting.alerter import Alerter


class TestAlerter(unittest.TestCase):
    
    def setUp(self):
        self.alerter = Alerter(min_severity="medium")
    
    def test_generate_alerts_from_anomalies(self):
        """Test alert generation from anomalies"""
        anomalies = [
            {
                "rule_name": "sql_injection",
                "severity": "critical",
                "reason": "SQL injection detected",
                "entry": {
                    "timestamp": datetime.now(),
                    "ip": "192.168.1.1",
                    "event_type": "get",
                    "source": "web"
                }
            },
            {
                "rule_name": "xss",
                "severity": "high",
                "reason": "XSS detected",
                "entry": {
                    "timestamp": datetime.now(),
                    "ip": "192.168.1.2",
                    "event_type": "post",
                    "source": "web"
                }
            }
        ]
        
        alerts = self.alerter.generate_alerts(anomalies)
        
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["severity"], "critical")
        self.assertEqual(alerts[1]["severity"], "high")
        self.assertIn("alert_id", alerts[0])
        self.assertIn("alert_message", alerts[0])
    
    def test_min_severity_filtering(self):
        """Test that alerts below minimum severity are filtered"""
        alerter_low = Alerter(min_severity="low")
        alerter_high = Alerter(min_severity="high")
        
        anomalies = [
            {
                "rule_name": "test",
                "severity": "low",
                "reason": "Low severity",
                "entry": {"timestamp": datetime.now(), "ip": "1.1.1.1", "event_type": "get", "source": "web"}
            },
            {
                "rule_name": "test",
                "severity": "high",
                "reason": "High severity",
                "entry": {"timestamp": datetime.now(), "ip": "2.2.2.2", "event_type": "get", "source": "web"}
            }
        ]
        
        alerts_low = alerter_low.generate_alerts(anomalies)
        alerts_high = alerter_high.generate_alerts(anomalies)
        
        self.assertEqual(len(alerts_low), 2)
        self.assertEqual(len(alerts_high), 1)
    
    def test_alerts_sorted_by_severity(self):
        """Test that alerts are sorted"""
        anomalies = [
            {
                "rule_name": "test",
                "severity": "high",
                "reason": "High",
                "entry": {"timestamp": datetime.now(), "ip": "1.1.1.1", "event_type": "get", "source": "web"}
            },
            {
                "rule_name": "test",
                "severity": "critical",
                "reason": "Critical",
                "entry": {"timestamp": datetime.now(), "ip": "2.2.2.2", "event_type": "get", "source": "web"}
            },
            {
                "rule_name": "test",
                "severity": "medium",
                "reason": "Medium",
                "entry": {"timestamp": datetime.now(), "ip": "3.3.3.3", "event_type": "get", "source": "web"}
            }
        ]
        
        alerts = self.alerter.generate_alerts(anomalies)
        
        self.assertEqual(alerts[0]["severity"], "critical")
        self.assertEqual(alerts[1]["severity"], "high")
        self.assertEqual(alerts[2]["severity"], "medium")
    
    def test_get_critical_alerts(self):
        """Test filtering critical alerts"""
        anomalies = [
            {
                "rule_name": "sql_injection",
                "severity": "critical",
                "reason": "SQL injection",
                "entry": {"timestamp": datetime.now(), "ip": "1.1.1.1", "event_type": "get", "source": "web"}
            },
            {
                "rule_name": "xss",
                "severity": "high",
                "reason": "XSS",
                "entry": {"timestamp": datetime.now(), "ip": "2.2.2.2", "event_type": "get", "source": "web"}
            }
        ]
        
        alerts = self.alerter.generate_alerts(anomalies)
        critical = self.alerter.get_critical_alerts(alerts)
        
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0]["severity"], "critical")
    
    def test_get_high_alerts(self):
        """Test filtering high severity alerts"""
        anomalies = [
            {
                "rule_name": "sql_injection",
                "severity": "critical",
                "reason": "SQL injection",
                "entry": {"timestamp": datetime.now(), "ip": "1.1.1.1", "event_type": "get", "source": "web"}
            },
            {
                "rule_name": "xss",
                "severity": "high",
                "reason": "XSS",
                "entry": {"timestamp": datetime.now(), "ip": "2.2.2.2", "event_type": "get", "source": "web"}
            }
        ]
        
        alerts = self.alerter.generate_alerts(anomalies)
        high = self.alerter.get_high_alerts(alerts)
        
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0]["severity"], "high")
    
    def test_alert_message_format(self):
        """Test that alert messages contain required information"""
        anomaly = {
            "rule_name": "sql_injection",
            "severity": "critical",
            "reason": "SQL injection detected in URL",
            "entry": {
                "timestamp": datetime(2025, 11, 20, 10, 30, 0),
                "ip": "192.168.1.1",
                "event_type": "get",
                "source": "web"
            }
        }
        
        alerts = self.alerter.generate_alerts([anomaly])
        message = alerts[0]["alert_message"]
        
        self.assertIn("CRITICAL", message)
        self.assertIn("sql_injection", message)
        self.assertIn("192.168.1.1", message)
        self.assertIn("2025-11-20", message)



