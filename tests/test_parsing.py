import unittest
from parsing.parser import Parser


class TestParser(unittest.TestCase):
    
    def setUp(self):
        self.parser = Parser()
    
    def test_parse_system_json_entry(self):
        """Test parsing JSON system logs"""
        entry = {
            "timestamp": "2025-11-20T10:00:00",
            "level": "ERROR",
            "message": "Test message",
            "details": {"payload": '{"script": "<script>alert(1)</script>"}'}
        }
        
        result = self.parser._parse_system_entry(entry)
        
        self.assertEqual(result["event_type"], "error")
        self.assertEqual(result["source"], "system")
        self.assertIsNotNone(result["timestamp"])
        self.assertIsNone(result["ip"])
        self.assertIsNone(result["user"])
        self.assertIsNone(result["url"])
        self.assertIsNotNone(result["payload"])
    
    def test_parse_web_apache_entry(self):
        """Test parsing Apache web logs"""
        entry = '192.168.1.1 - - [20/Nov/2025:10:00:00] "GET /login?user=admin HTTP/1.1" 200 1234'
        
        result = self.parser._parse_web_entry(entry)
        
        self.assertEqual(result["ip"], "192.168.1.1")
        self.assertEqual(result["event_type"], "get")
        self.assertEqual(result["source"], "web")
        self.assertIn("/login", result["url"])
        self.assertIsNotNone(result["timestamp"])
    
    def test_parse_extracts_url(self):
        """Test that URL is extracted from Apache logs"""
        entry = '10.0.0.1 - - [20/Nov/2025:10:00:00] "GET /products?id=1 HTTP/1.1" 200 987'
        
        result = self.parser._parse_web_entry(entry)
        
        self.assertIsNotNone(result["url"])
        self.assertEqual(result["url"], "/products?id=1")
    
    def test_parse_extracts_payload(self):
        """Test that payload is extracted from JSON logs"""
        entry = {
            "timestamp": "2025-11-20T10:00:00",
            "level": "WARNING",
            "message": "Test",
            "details": {"payload": '{"path": "../../etc/passwd"}'}
        }
        
        result = self.parser._parse_system_entry(entry)
        
        self.assertIsNotNone(result["payload"])
        self.assertIn("etc/passwd", result["payload"])
    
    def test_parse_invalid_source_raises_error(self):
        """Test that invalid source raises ValueError"""
        entries = [{"test": "data"}]
        
        with self.assertRaises(ValueError):
            self.parser.parse(entries, "invalid_source")
    
    def test_parse_normalizes_structure(self):
        """Test that all parsed entries have consistent structure"""
        system_entry = {"timestamp": "2025-11-20T10:00:00", "level": "INFO", "message": "Test", "details": {}}
        web_entry = '192.168.1.1 - - [20/Nov/2025:10:00:00] "GET /test HTTP/1.1" 200 1234'
        
        sys_result = self.parser._parse_system_entry(system_entry)
        web_result = self.parser._parse_web_entry(web_entry)
        
        expected_keys = {"timestamp", "ip", "event_type", "user", "url", "payload", "source"}
        self.assertEqual(set(sys_result.keys()), expected_keys)
        web_keys = set(web_result.keys())
        self.assertTrue(expected_keys.issubset(web_keys))


