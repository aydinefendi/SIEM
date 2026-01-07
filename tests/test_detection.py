import unittest
import os
import tempfile
import json
from datetime import datetime
from detection.detector import Detector


class TestDetector(unittest.TestCase):
    
    def setUp(self):
        self.temp_rules = {
            "sql_injection": {
                "enabled": True,
                "patterns": ["admin'--", "' OR '1'='1"],
                "severity": "critical"
            },
            "xss": {
                "enabled": True,
                "patterns": ["<script>alert('xss')</script>", "<script>alert(1)</script>", "<script>"],
                "severity": "high"
            },
            "path_traversal": {
                "enabled": True,
                "patterns": ["../../etc/passwd"],
                "severity": "high"
            },
            "failed_login": {"enabled": False},
            "blacklist": {"enabled": False},
            "out_of_business_hours": {"enabled": False}
        }
        
        self.temp_rules_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.temp_rules, self.temp_rules_file)
        self.temp_rules_file.close()
        
        self.detector = Detector(rules_file=self.temp_rules_file.name)
    
    def tearDown(self):
        os.unlink(self.temp_rules_file.name)
    
    def test_detect_sql_injection_in_url(self):
        """Test SQL injection detection in url"""
        entries = [{
            "timestamp": datetime.now(),
            "ip": "192.168.1.1",
            "event_type": "get",
            "user": None,
            "url": "/login?user=admin'--",
            "payload": None,
            "source": "web"
        }]
        
        anomalies = self.detector._detect_sql_injection(entries)
        
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["rule_name"], "sql_injection")
        self.assertEqual(anomalies[0]["severity"], "critical")
        self.assertIn("admin'--", anomalies[0]["reason"])
    
    def test_detect_sql_injection_in_payload(self):
        """Test SQL injection detection in payload"""
        entries = [{
            "timestamp": datetime.now(),
            "ip": None,
            "event_type": "post",
            "user": None,
            "url": None,
            "payload": '{"username": "admin\'--", "password": "test"}',
            "source": "system"
        }]
        
        anomalies = self.detector._detect_sql_injection(entries)
        
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["rule_name"], "sql_injection")
    
    def test_detect_xss_in_url(self):
        """Test XSS detection in URL"""
        entries = [{
            "timestamp": datetime.now(),
            "ip": "192.168.1.1",
            "event_type": "get",
            "user": None,
            "url": "/search?q=<script>alert('xss')</script>",
            "payload": None,
            "source": "web"
        }]
        
        anomalies = self.detector._detect_xss(entries)
        
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["rule_name"], "xss")
        self.assertEqual(anomalies[0]["severity"], "high")
    
    def test_detect_path_traversal(self):
        """Test path traversal detection"""
        entries = [{
            "timestamp": datetime.now(),
            "ip": "192.168.1.1",
            "event_type": "get",
            "user": None,
            "url": "/../../etc/passwd",
            "payload": None,
            "source": "web"
        }]
        
        anomalies = self.detector._detect_path_traversal(entries)
        
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["rule_name"], "path_traversal")
        self.assertEqual(anomalies[0]["severity"], "high")
    
    def test_no_detection_for_clean_entry(self):
        """Test that clean entries don't trigger detection"""
        entries = [{
            "timestamp": datetime.now(),
            "ip": "192.168.1.1",
            "event_type": "get",
            "user": None,
            "url": "/index.html",
            "payload": None,
            "source": "web"
        }]
        
        sql_anomalies = self.detector._detect_sql_injection(entries)
        xss_anomalies = self.detector._detect_xss(entries)
        path_anomalies = self.detector._detect_path_traversal(entries)
        
        self.assertEqual(len(sql_anomalies), 0)
        self.assertEqual(len(xss_anomalies), 0)
        self.assertEqual(len(path_anomalies), 0)
    
    def test_detection_skips_entries_without_url_or_payload(self):
        """Test that entries without URL or payload are skipped"""
        entries = [{
            "timestamp": datetime.now(),
            "ip": "192.168.1.1",
            "event_type": "info",
            "user": None,
            "url": None,
            "payload": None,
            "source": "system"
        }]
        
        anomalies = self.detector._detect_sql_injection(entries)
        self.assertEqual(len(anomalies), 0)
    
    def test_run_detects_all_attack_types(self):
        """Test that run() method detects all attack types"""
        entries = [
            {
                "timestamp": datetime.now(),
                "ip": "192.168.1.1",
                "event_type": "get",
                "user": None,
                "url": "/login?user=admin'--",
                "payload": None,
                "source": "web"
            },
            {
                "timestamp": datetime.now(),
                "ip": "192.168.1.2",
                "event_type": "get",
                "user": None,
                "url": "/search?q=<script>alert(1)</script>",
                "payload": None,
                "source": "web"
            },
            {
                "timestamp": datetime.now(),
                "ip": "192.168.1.3",
                "event_type": "get",
                "user": None,
                "url": "/../../etc/passwd",
                "payload": None,
                "source": "web"
            }
        ]
        
        anomalies = self.detector.run(entries)
        
        self.assertEqual(len(anomalies), 3)
        rule_names = [anomaly["rule_name"] for anomaly in anomalies]
        self.assertIn("sql_injection", rule_names)
        self.assertIn("xss", rule_names)
        self.assertIn("path_traversal", rule_names)
    
    def test_detect_repeated_failed_logins(self):
        """Test detection of repeated failed login attempts (REQUIRED RULE)"""
        temp_rules = {
            "failed_login": {
                "enabled": True,
                "threshold": 3,
                "time_window_minutes": 15
            },
            "sql_injection": {"enabled": False},
            "xss": {"enabled": False},
            "path_traversal": {"enabled": False},
            "blacklist": {"enabled": False},
            "out_of_business_hours": {"enabled": False}
        }
        
        temp_rules_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(temp_rules, temp_rules_file)
        temp_rules_file.close()
        
        detector = Detector(rules_file=temp_rules_file.name)
        
        base_time = datetime(2025, 11, 20, 10, 0, 0)
        entries = []
        for i in range(5):
            entries.append({
                "timestamp": base_time.replace(minute=i*2),
                "ip": "192.168.1.100",
                "event_type": "get",
                "user": None,
                "url": "/login",
                "payload": None,
                "source": "web",
                "status_code": 401
            })
        
        anomalies = detector.run(entries)
        
        failed_login_anomalies = [anomaly for anomaly in anomalies if anomaly["rule_name"] == "repeated_failed_login"]
        self.assertGreater(len(failed_login_anomalies), 0)
        self.assertEqual(failed_login_anomalies[0]["severity"], "high")
        self.assertIn("192.168.1.100", failed_login_anomalies[0]["reason"])
        
        os.unlink(temp_rules_file.name)
    
    def test_detect_blacklisted_access(self):
        """Test detection of access from blacklisted IPs (REQUIRED RULE)"""
        temp_rules = {
            "blacklist": {
                "enabled": True,
                "ips": ["192.168.1.200", "10.0.0.100"]
            },
            "sql_injection": {"enabled": False},
            "xss": {"enabled": False},
            "path_traversal": {"enabled": False},
            "failed_login": {"enabled": False},
            "out_of_business_hours": {"enabled": False}
        }
        
        temp_rules_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(temp_rules, temp_rules_file)
        temp_rules_file.close()
        
        detector = Detector(rules_file=temp_rules_file.name)
        
        entries = [
            {
                "timestamp": datetime.now(),
                "ip": "192.168.1.200",
                "event_type": "get",
                "user": None,
                "url": "/index.html",
                "payload": None,
                "source": "web"
            },
            {
                "timestamp": datetime.now(),
                "ip": "192.168.1.1",
                "event_type": "get",
                "user": None,
                "url": "/index.html",
                "payload": None,
                "source": "web"
            }
        ]
        
        anomalies = detector.run(entries)
        
        blacklist_anomalies = [anomaly for anomaly in anomalies if anomaly["rule_name"] == "blacklisted_access"]
        self.assertEqual(len(blacklist_anomalies), 1)
        self.assertEqual(blacklist_anomalies[0]["severity"], "critical")
        self.assertIn("192.168.1.200", blacklist_anomalies[0]["reason"])
        
        os.unlink(temp_rules_file.name)
    
    def test_detect_out_of_business_hours(self):
        """Test detection of access outside business hours (REQUIRED RULE)"""
        temp_rules = {
            "out_of_business_hours": {
                "enabled": True
            },
            "business_hours": {
                "start": "09:00",
                "end": "17:00"
            },
            "sql_injection": {"enabled": False},
            "xss": {"enabled": False},
            "path_traversal": {"enabled": False},
            "failed_login": {"enabled": False},
            "blacklist": {"enabled": False}
        }
        
        temp_rules_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(temp_rules, temp_rules_file)
        temp_rules_file.close()
        
        detector = Detector(rules_file=temp_rules_file.name)
        
        entries = [
            {
                "timestamp": datetime(2025, 11, 20, 8, 30, 0),
                "ip": "192.168.1.1",
                "event_type": "get",
                "user": None,
                "url": "/index.html",
                "payload": None,
                "source": "web"
            },
            {
                "timestamp": datetime(2025, 11, 20, 10, 0, 0),
                "ip": "192.168.1.1",
                "event_type": "get",
                "user": None,
                "url": "/index.html",
                "payload": None,
                "source": "web"
            },
            {
                "timestamp": datetime(2025, 11, 20, 18, 0, 0),
                "ip": "192.168.1.1",
                "event_type": "get",
                "user": None,
                "url": "/index.html",
                "payload": None,
                "source": "web"
            }
        ]
        
        anomalies = detector.run(entries)
        
        oob_anomalies = [anomaly for anomaly in anomalies if anomaly["rule_name"] == "out_of_business_hours"]
        self.assertEqual(len(oob_anomalies), 2) 
        self.assertEqual(oob_anomalies[0]["severity"], "medium")
        
        os.unlink(temp_rules_file.name)



