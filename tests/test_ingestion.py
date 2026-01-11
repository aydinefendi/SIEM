import unittest
import os
import tempfile
from ingestion.system_ingestor import SystemIngestor
from ingestion.web_ingestor import WebIngestor


class TestSystemIngestor(unittest.TestCase):
    
    def setUp(self):
        self.ingestor = SystemIngestor()
    
    def test_ingest_valid_json_logs(self):
        """Test ingesting valid json log entries"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write('{"timestamp": "2025-11-20T10:00:00","level": "INFO", "message": "Test"}\n')
            f.write('{"timestamp": "2025-11-20T11:00:00", "level": "ERROR", "message": "Error"}\n')
            temp_file = f.name
        
        try:
            result = self.ingestor.ingest(temp_file)
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["level"], "INFO")
            self.assertEqual(result[1]["level"], "ERROR")
        finally:
            os.unlink(temp_file)
    
    def test_ingest_skips_invalid_json(self):
        """Test that invalid json lines are skipped"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write('{"timestamp": "2025-11-20T10:00:00","level": "INFO"}\n')
            f.write('invalid json line\n')
            f.write('{"timestamp": "2025-11-20T11:00:00","level": "ERROR"}\n')
            temp_file = f.name
        
        try:
            result = self.ingestor.ingest(temp_file)
            self.assertEqual(len(result), 2)
        finally:
            os.unlink(temp_file)
    
    def test_ingest_empty_file(self):
        """Test ingesting an empty file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name
        
        try:
            result = self.ingestor.ingest(temp_file)
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_file)
    
    def test_ingest_file_not_found(self):
        """Test that FileNotFoundError is raised for non existent file"""
        with self.assertRaises(FileNotFoundError):
            self.ingestor.ingest('nonexistent_file.json')


class TestWebIngestor(unittest.TestCase):
    
    def setUp(self):
        self.ingestor = WebIngestor()
    
    def test_ingest_valid_apache_logs(self):
        """Test ingesting valid Apache log entries"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            f.write('192.168.1.1 - - [20/Nov/2025:10:00:00] "GET /index.html HTTP/1.1" 200 1234\n')
            f.write('10.0.0.1 - - [20/Nov/2025:11:00:00] "POST /login HTTP/1.1" 200 5678\n')
            temp_file = f.name
        
        try:
            result = self.ingestor.ingest(temp_file)
            self.assertEqual(len(result), 2)
            self.assertIn("192.168.1.1", result[0])
            self.assertIn("10.0.0.1", result[1])
        finally:
            os.unlink(temp_file)
    
    def test_ingest_empty_file(self):
        """Test ingesting an empty file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            temp_file = f.name
        
        try:
            result = self.ingestor.ingest(temp_file)
            self.assertEqual(len(result), 0)
        finally:
            os.unlink(temp_file)
    
    def test_ingest_file_not_found(self):
        """Test that FileNotFoundError is raised for non-existent file"""
        with self.assertRaises(FileNotFoundError):
            self.ingestor.ingest('nonexistent_file.log')


if __name__ == '__main__':
    unittest.main()
