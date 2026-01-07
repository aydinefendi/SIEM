# LogSentinel

Log analysis application for detecting suspicious activities in system and web server logs.

## Features

- **Log Ingestion**: Supports JSON system logs and Apache web logs
- **Parsing & Normalisation**: Converts logs into consistent format
- **Suspicious Activity Detection**:
  - Repeated failed login attempts
  - Access from blacklisted IPs
  - Access outside business hours
  - SQL injection attempts
  - XSS attacks
  - Path traversal attempts
- **Alerting**: Generates alerts with severity levels
- **Daily Summaries**: Creates timestamped summary reports

## Requirements

- Python 3.7+

## Usage

Run the application:
```bash
python3 main.py
```

Run tests:
```bash
python3 -m unittest discover tests
```

## Configuration

Detection rules are configured in `detection_rules.json`. You can:
- Enable/disable detection rules
- Modify detection patterns
- Set thresholds for failed login detection
- Configure blacklisted IPs
- Set business hours

## Architecture

```
ingestion/     - Log ingestion from multiple sources
parsing/       - Parse and normalize log entries
detection/     - Rule-based anomaly detection
alerting/      - Generate alerts from anomalies
summarisation/ - Create daily summary reports
```

## Detection Rules

**Repeated Failed Login Attempts**: Detects multiple failed authentication attempts from the same IP within a time window (default: 5 attempts in 15 minutes).

**Blacklisted Access**: Blocks access from configured IP addresses.

**Out-of-Business Hours**: Identifies access occurring outside configured business hours (default: 09:00-17:00).

**SQL Injection**: Pattern-based detection of SQL injection attempts in URLs and payloads.

**XSS**: Detects cross-site scripting attempts.

**Path Traversal**: Identifies directory traversal attempts.

## Output

The application generates:
- Console output with summary statistics
- Timestamped summary file: `anomaly_summary_YYYY-MM-DD_HH-MM-SS.txt`
- Alerts grouped by severity (critical, high, medium)

## Project Structure

```
pcs_coursework_2/
├── ingestion/          - Log ingestion modules
├── parsing/            - Log parsing and normalization
├── detection/          - Anomaly detection rules
├── alerting/           - Alert generation
├── summarisation/      - Summary report generation
├── tests/              - Unit tests
├── sample_logs/        - Sample log files
├── detection_rules.json - Configuration file
└── main.py             - Application entry point
```
