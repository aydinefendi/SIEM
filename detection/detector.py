import json
import re
import os
from datetime import time
from collections import defaultdict


class Detector:
    
    def __init__(self, rules_file=None):
        if rules_file and os.path.exists(rules_file):
            with open(rules_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = self._get_default_config()
        
        self.failed_login_attempts = defaultdict(list)
        
        self.business_hours_start = time(9, 0)
        self.business_hours_end = time(17, 0)
        
        if 'business_hours' in self.config:
            start = self.config['business_hours'].get('start', '09:00')
            end = self.config['business_hours'].get('end', '17:00')
            self.business_hours_start = time(*map(int, start.split(':')))
            self.business_hours_end = time(*map(int, end.split(':')))
    
    def _get_default_config(self):
        """Return default detection rules configuration"""
        return {
            "sql_injection": {"enabled": True, "patterns": [r"' OR '1'='1", r"admin'--"], "severity": "critical"},
            "xss": {"enabled": True, "patterns": [r"<script[^>]*>", r"<script>alert\('xss'\)</script>"], "severity": "high"},
            "path_traversal": {"enabled": True, "patterns": [r"\.\./\.\./etc/passwd", r"\.\.\/\.\.\/etc\/passwd"], "severity": "high"},
            "failed_login": {"enabled": True, "threshold": 5, "time_window_minutes": 15},
            "blacklist": {"enabled": True, "ips": []},
            "out_of_business_hours": {"enabled": True},
            "business_hours": {"start": "09:00", "end": "17:00"}
        }
    
    def run(self, entries):
        """Run all enabled detection rules on log entries"""
        anomalies = []
        
        self._track_failed_logins(entries)
        
        if self.config.get("sql_injection", {}).get("enabled", True):
            anomalies.extend(self._detect_sql_injection(entries))
        
        if self.config.get("xss", {}).get("enabled", True):
            anomalies.extend(self._detect_xss(entries))
        
        if self.config.get("path_traversal", {}).get("enabled", True):
            anomalies.extend(self._detect_path_traversal(entries))
        
        if self.config.get("failed_login", {}).get("enabled", True):
            anomalies.extend(self._detect_repeated_failed_logins(entries))
        
        if self.config.get("blacklist", {}).get("enabled", True):
            anomalies.extend(self._detect_blacklisted_access(entries))
        
        if self.config.get("out_of_business_hours", {}).get("enabled", True):
            anomalies.extend(self._detect_out_of_business_hours(entries))
        
        return anomalies
    
    def _track_failed_logins(self, entries):
        """Track failed login attempts by IP address"""
        for entry in entries:
            is_failed = False
            
            status_code = entry.get("status_code")
            if status_code in [401, 403] and entry.get("url", "").lower().find("/login") != -1:
                is_failed = True
            
            if entry.get("source") == "system":
                payload = str(entry.get("payload", "")).lower()
                if any(kw in payload for kw in ["failed login", "authentication failed", "invalid password"]):
                    is_failed = True
            
            if is_failed:
                ip = entry.get("ip") or "unknown"
                self.failed_login_attempts[ip].append(entry.get("timestamp"))
    
    def _match_pattern(self, pattern, text):
        """Match a regex pattern against text, fallback to simple string search"""
        try:
            return bool(re.search(pattern, text, re.IGNORECASE))
        except re.error:
            return pattern.lower() in text.lower()
    
    def _detect_pattern_based(self, entries, rule_name):
        """Generic pattern-based detection for SQL injection, XSS, path traversal"""
        anomalies = []
        rule_config = self.config.get(rule_name, {})
        patterns = rule_config.get("patterns", [])
        severity = rule_config.get("severity", "high")
        
        for entry in entries:
            texts = []
            if entry.get("url"):
                texts.append(entry["url"])
            if entry.get("payload"):
                texts.append(str(entry["payload"]))
            
            for text in texts:
                for pattern in patterns:
                    if self._match_pattern(pattern, text):
                        anomalies.append({
                            "rule_name": rule_name,
                            "severity": severity,
                            "reason": f"{rule_name.replace('_', ' ').title()} pattern detected: {pattern}",
                            "entry": entry
                        })
                        break
                if anomalies and anomalies[-1]["entry"] == entry:
                    break
        
        return anomalies
    
    def _detect_sql_injection(self, entries):
        """Detect SQL injection attempts in URLs and payloads"""
        return self._detect_pattern_based(entries, "sql_injection")
    
    def _detect_xss(self, entries):
        """Detect cross-site scripting attempts in URLs and payloads"""
        return self._detect_pattern_based(entries, "xss")
    
    def _detect_path_traversal(self, entries):
        """Detect directory traversal attempts in URLs and payloads"""
        return self._detect_pattern_based(entries, "path_traversal")
    
    def _detect_repeated_failed_logins(self, entries):
        """Detect multiple failed login attempts from same IP within time window"""
        anomalies = []
        threshold = self.config.get("failed_login", {}).get("threshold", 5)
        time_window = self.config.get("failed_login", {}).get("time_window_minutes", 15)
        
        for ip, timestamps in self.failed_login_attempts.items():
            if len(timestamps) < threshold:
                continue
            
            recent = []
            for ts in sorted(timestamps):
                if recent:
                    if (ts - recent[0]).total_seconds() / 60 <= time_window:
                        recent.append(ts)
                    else:
                        recent = [ts]
                else:
                    recent.append(ts)
                
                if len(recent) >= threshold:
                    for entry in entries:
                        if entry.get("ip") == ip and entry.get("timestamp") == ts:
                            anomalies.append({
                                "rule_name": "repeated_failed_login",
                                "severity": "high",
                                "reason": f"Repeated failed login attempts: {len(recent)} attempts from {ip} within {time_window} minutes",
                                "entry": entry,
                                "attempt_count": len(recent)
                            })
                            break
                    break
        
        return anomalies
    
    def _detect_blacklisted_access(self, entries):
        """Detect access attempts from blacklisted IP addresses"""
        anomalies = []
        blacklisted = set(self.config.get("blacklist", {}).get("ips", []))
        
        for entry in entries:
            ip = entry.get("ip")
            if ip and ip in blacklisted:
                anomalies.append({
                    "rule_name": "blacklisted_access",
                    "severity": "critical",
                    "reason": f"Access from blacklisted IP: {ip}",
                    "entry": entry
                })
        
        return anomalies
    
    def _detect_out_of_business_hours(self, entries):
        """Detect access attempts occurring outside configured business hours"""
        anomalies = []
        
        for entry in entries:
            timestamp = entry.get("timestamp")
            if not timestamp:
                continue
            
            entry_time = timestamp.time()
            if entry_time < self.business_hours_start or entry_time > self.business_hours_end:
                anomalies.append({
                    "rule_name": "out_of_business_hours",
                    "severity": "medium",
                    "reason": f"Access outside business hours: {entry_time.strftime('%H:%M:%S')}",
                    "entry": entry
                })
        
        return anomalies
