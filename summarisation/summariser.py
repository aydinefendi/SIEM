import os
from datetime import datetime
from typing import Dict, Any
from collections import defaultdict

class Summariser:
    
    def generate_summary(self, anomalies, entries):
        """Generate summary statistics from anomalies and entries"""
        summary = {
            "timestamp": datetime.now(),
            "total_entries": len(entries),
            "total_anomalies": len(anomalies),
            "anomalies_by_type": defaultdict(int),
            "anomalies_by_severity": defaultdict(int),
            "anomalies": anomalies
        }
        
        for anomaly in anomalies:
            rule_name = anomaly.get("rule_name", "unknown")
            severity = anomaly.get("severity", "unknown")
            summary["anomalies_by_type"][rule_name] += 1
            summary["anomalies_by_severity"][severity] += 1
        
        return summary
    
    def format_summary(self, summary):
        """Format summary as human readable text"""
        lines = []
        lines.append("=" * 50)
        lines.append("Log analysis summary")
        lines.append("=" * 50)
        lines.append(f"Generated: {summary['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total log entries processed: {summary['total_entries']}")
        lines.append(f"Total anomalies detected: {summary['total_anomalies']}")
        lines.append("")
        
        lines.append("Anomalies by Severity:")
        for severity in ["critical", "high", "medium", "low"]:
            count = summary["anomalies_by_severity"].get(severity, 0)
            if count > 0:
                lines.append(f"  {severity.upper()}: {count}")
        lines.append("")
        
        lines.append("Anomalies by Type:")
        for rule_name, count in sorted(summary["anomalies_by_type"].items()):
            lines.append(f"  {rule_name}: {count}")
        lines.append("")
        
        if summary["anomalies"]:
            lines.append("=" * 50)
            lines.append("Detailed anomaly report")
            lines.append("=" * 50)
            lines.append("")
            
            anomalies_by_rule = defaultdict(list)
            for anomaly in summary["anomalies"]:
                rule_name = anomaly.get("rule_name", "unknown")
                anomalies_by_rule[rule_name].append(anomaly)
            
            for rule_name, rule_anomalies in sorted(anomalies_by_rule.items()):
                lines.append(f"\n{rule_name.upper().replace('_', ' ')}")
                lines.append("-" * 50)
                
                for anomaly in rule_anomalies[:10]:
                    entry = anomaly.get("entry", {})
                    lines.append(f"Title: {anomaly.get('reason', 'N/A')}")
                    lines.append(f"Source log: {self._get_source_file(entry)}")
                    lines.append(f"Timestamp: {self._format_timestamp(entry.get('timestamp'))}")
                    lines.append(f"Event type: {entry.get('event_type', 'N/A')}")
                    
                    if entry.get("ip"):
                        lines.append(f"IP address: {entry['ip']}")
                    if entry.get("user"):
                        lines.append(f"User identifier: {entry['user']}")
                    
                    lines.append(f"Severity: {anomaly.get('severity', 'N/A').upper()}")
                    lines.append("")
                
                if len(rule_anomalies) > 10:
                    lines.append(f"  ... and {len(rule_anomalies) - 10} more {rule_name} anomalies")
                    lines.append("")
        else:
            lines.append("No anomalies detected.")
        
        return "\n".join(lines)
    
    def _get_source_file(self, entry: Dict[str, Any]) -> str:
        """Determine source log file name from entry."""
        source = entry.get("source", "unknown")
        if source == "system":
            return "application_log.json"
        elif source == "web":
            return "http_access.log"
        return "unknown"
    
    def _format_timestamp(self, timestamp):
        """Format timestamp for display"""
        if timestamp:
            if isinstance(timestamp, datetime):
                return timestamp.strftime("%Y-%m-%d %H:%M:%S")
            return str(timestamp)
        return "N/A"
    
    def save_summary_to_file(self, summary, output_dir):
        """Save summary to timestamped file"""
        timestamp = summary["timestamp"]
        filename = f"anomaly_summary_{timestamp.strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        filepath = os.path.join(output_dir, filename)
        
        summary_text = self.format_summary(summary)
        
        with open(filepath, 'w') as f:
            f.write(summary_text)
        
        return filepath
