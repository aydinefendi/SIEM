import re
from datetime import datetime


class Parser:
    
    def parse(self, entries, source):
        """Parse raw log entries into normalized format"""
        if source == 'system':
            return [self._parse_system_entry(entry) for entry in entries]
        elif source == 'web':
            return [self._parse_web_entry(entry) for entry in entries]
        else:
            raise ValueError(f"Invalid source type: {source}")
    
    def _parse_system_entry(self, entry):
        """Parse a JSON system log entry"""
        normalized = {
            "timestamp": self._parse_timestamp(entry.get("timestamp")),
            "ip": None,
            "event_type": entry.get("level", "").lower() if entry.get("level") else None,
            "user": None,
            "url": None,
            "payload": entry.get("details", {}).get("payload") if entry.get("details") else None,
            "source": "system"
        }
        
        message = entry.get("message", "")
        user_match = re.search(r'user[:\s]+(\w+)', message, re.IGNORECASE)
        if user_match:
            normalized["user"] = user_match.group(1)
        
        return normalized
    
    def _parse_web_entry(self, entry):
        """Parse an Apache Common Log Format entry"""
        pattern = r'(\S+) - - \[([^\]]+)\] "(\w+) ([^"\s]+)(?:\s+HTTP/[^"]+)?" (\d+) (\d+)'
        match = re.match(pattern, entry)
        
        if not match:
            return {
                "timestamp": datetime.now(),
                "ip": None,
                "event_type": None,
                "user": None,
                "url": None,
                "payload": None,
                "source": "web"
            }
        
        ip, timestamp_str, method, url_path, status_code, _ = match.groups()
        
        timestamp = self._parse_apache_timestamp(timestamp_str)
        
        url = url_path
        
        user = None
        if 'user=' in url_path:
            user_match = re.search(r'user=([^&\s]+)', url_path)
            if user_match:
                user = user_match.group(1)
        
        normalized = {
            "timestamp": timestamp,
            "ip": ip,
            "event_type": method.lower(),
            "user": user,
            "url": url, 
            "payload": None,
            "source": "web",
            "status_code": int(status_code)  
        }
        
        return normalized
    
    def _parse_timestamp(self, timestamp_str):
        """Parse ISO format timestamp"""
        if not timestamp_str:
            return datetime.now()
        
        try:
            if '.' in timestamp_str:
                return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
            else:
                return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return datetime.now()
    
    def _parse_apache_timestamp(self, timestamp_str):
        """Parse Apache log timestamp format"""
        try:
            return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return datetime.now()

