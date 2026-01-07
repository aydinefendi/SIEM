from ingestion.system_ingestor import SystemIngestor
from ingestion.web_ingestor import WebIngestor
from parsing.parser import Parser
from detection.detector import Detector
from alerting.alerter import Alerter
from summarisation.summariser import Summariser

def main():
    sys_ingestor = SystemIngestor()
    sys_raw = sys_ingestor.ingest('sample_logs/application_log.json')
    print(f"System logs: {len(sys_raw)} entries")
    
    web_ingestor = WebIngestor()
    web_raw = web_ingestor.ingest('sample_logs/http_access.log')
    print(f"Web logs: {len(web_raw)} entries")
    
    parser = Parser()
    sys_parsed = parser.parse(sys_raw, 'system')
    web_parsed = parser.parse(web_raw, 'web')
    
    normalized_entries = sys_parsed + web_parsed
    print(f"Total normalised entries: {len(normalized_entries)}")
    
    detector = Detector(rules_file='detection_rules.json')
    anomalies = detector.run(normalized_entries)
    
    alerter = Alerter(min_severity="medium")
    alerts = alerter.generate_alerts(anomalies)
    
    summariser = Summariser()
    summary = summariser.generate_summary(anomalies, normalized_entries)
    
    print("\n" + summariser.format_summary(summary))
    
    summariser.save_summary_to_file(summary)
    
    print("\nAlerts")

    print(f"\nTotal alerts generated: {len(alerts)}")
    
    critical_alerts = alerter.get_critical_alerts(alerts)
    high_alerts = alerter.get_high_alerts(alerts)
    
    if critical_alerts:
        print(f"\nCritical Alerts ({len(critical_alerts)}):")
        for index, alert in enumerate(critical_alerts[:5], 1):
            print(f"\n{index}. {alert['alert_message']}")
        if len(critical_alerts) > 5:
            print(f"\n... and {len(critical_alerts) - 5} more critical alerts")
    
    if high_alerts:
        print(f"\nHigh Severity Alerts ({len(high_alerts)}):")
        for index, alert in enumerate(high_alerts[:5], 1):
            print(f"\n{index}. {alert['alert_message']}")
        if len(high_alerts) > 5:
            print(f"\n... and {len(high_alerts) - 5} more high severity alerts")
        
        return {"anomalies": anomalies, "alerts": alerts, "summary": summary}

if __name__ == "__main__":
    main()
