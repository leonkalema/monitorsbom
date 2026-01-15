# SBOM Vulnerability Scanner

A comprehensive vulnerability scanner that analyzes Software Bill of Materials (SBOM) files using multiple security databases.

## Features

- **Multi-source scanning (configurable)**: NVD (NIST) + Google OSV (additional sources can be enabled)
- **CycloneDX SBOM support**: Automatically parses `.cdx.json` files
- **Email alerting**: Sends alerts when vulnerabilities are detected
- **Severity classification**: CRITICAL, HIGH, MEDIUM, LOW priority levels
- **JSON reporting**: Detailed machine-readable output

## Prerequisites

### Required Tools
```bash
# Install OSV Scanner (Google's vulnerability scanner)
brew install osv-scanner

# Or download from: https://github.com/google/osv-scanner
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

### Email Setup (macOS)
```bash
# Configure mail command (required for email alerts)
# Option 1: Use built-in mail with Gmail
# Option 2: Configure postfix/sendmail
```

## Quick Start

### 1. Setup
```bash
git clone <your-repo>
cd sbom
pip install -r requirements.txt
```

### 2. Add SBOM Files
Place your CycloneDX SBOM files (`.cdx.json`) in the `sbom/` directory:
```bash
# Example structure:
sbom/
├── frontend.cdx.json
├── backend.cdx.json
└── mobile-app.cdx.json
```

### 3. Run Scan
```bash
# Full combined scan (recommended)
python3 combined-vuln-scanner.py

# Individual NVD search
python3 nvd-search.py "component-name"

# Quick shell script scan
./scan-sboms.sh
```

## Usage Examples

### Basic Scan
```bash
python3 combined-vuln-scanner.py
```

### Search Specific Component
```bash
python3 nvd-search.py "mbedtls" 20
python3 nvd-search.py "apache httpd" 10
```

### Automated Scanning (Cron)
```bash
# Add to crontab for daily scans
0 9 * * * cd /path/to/sbom && python3 combined-vuln-scanner.py
```

## Output Files

- **Console**: Real-time scan progress and summary
- **`/tmp/combined-vuln-scan.json`**: Detailed JSON report
- **Email**: Sent only when `EMAIL_ALERTS=true` and `TO_EMAIL` is set

## Configuration

### Email Settings
Email alerts are disabled by default.

Set the following environment variables:
```bash
EMAIL_ALERTS=true
TO_EMAIL=security-team@company.com
```

If `TO_EMAIL` is not set, the tool will refuse to send email.

### Source Controls (Outbound Network Calls)
This tool can query multiple vulnerability sources. You control which sources are contacted via environment variables:
```bash
ENABLE_NVD=true
ENABLE_OSV_API=true
ENABLE_OSV_CLI=false

ENABLE_GITHUB=false
GITHUB_TOKEN=

ENABLE_CISA_KEV=false
ENABLE_CISA_ICS=false
ENABLE_CVE_ORG=false
ENABLE_CERT_CC=false
ENABLE_SONATYPE=false
ENABLE_VULNERS=false
VULNERS_API_KEY=
```

### Scan Parameters
- **NVD API**: 20 results per component (configurable)
- **OSV timeout**: 60 seconds per SBOM file
- **Email threshold**: Only CRITICAL/HIGH severity vulnerabilities

## Troubleshooting

### Common Issues

1. **OSV Scanner Not Found**
   ```bash
   brew install osv-scanner
   # Or download binary from GitHub releases
   ```

2. **Email Not Sending**
   ```bash
   # Test mail command
   echo "test" | mail -s "test" your-email@domain.com
   
   # Configure postfix if needed
   sudo postfix start
   ```

3. **NVD API Rate Limiting**
   - The scanner includes proper headers and delays
   - For high-volume usage, consider NVD API key

4. **No SBOM Files Found**
   ```bash
   # Ensure files are in correct location
   ls -la sbom/*.cdx.json
   ```

## Security Considerations

- **API Keys**: NVD API doesn't require keys for basic usage
- **Rate Limiting**: Built-in delays prevent API abuse  
- **Email Security**: Uses system mail command (configure TLS/encryption)
- **File Permissions**: Ensure SBOM files are readable

## Integration Examples

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: SBOM Vulnerability Scan
  run: |
    pip install -r requirements.txt
    python3 combined-vuln-scanner.py
    # Fail build if vulnerabilities found (exit code 1)
```

### Docker Integration
```dockerfile
RUN pip install -r requirements.txt
COPY sbom/ ./sbom/
RUN python3 combined-vuln-scanner.py
```

## Output Format

### Console Output
```
🔍 Combined Vulnerability Scan Report
📅 Scan Time: 2025-01-10T13:12:55
📦 Components Scanned: 5
🚨 Total Vulnerabilities: 12
   - NVD: 8
   - OSV: 4

🔴 CRITICAL Vulnerabilities (2):
  • CVE-2023-1234 (CVSS: 9.8) - NVD [mbedtls 2.28.1]
    🔗 https://nvd.nist.gov/vuln/detail/CVE-2023-1234
```

### JSON Report Structure
```json
{
  "scan_time": "2025-01-10T13:12:55",
  "components_scanned": 5,
  "vulnerabilities": [
    {
      "source": "NVD",
      "id": "CVE-2023-1234",
      "severity": "CRITICAL",
      "cvss_score": "9.8",
      "description": "Buffer overflow in...",
      "component": {
        "name": "mbedtls",
        "version": "2.28.1"
      }
    }
  ],
  "summary": {
    "nvd": 8,
    "osv": 4,
    "total": 12
  }
}
```

## Advanced Usage

### Custom SBOM Directory
```python
scanner = CombinedScanner(sbom_dir="custom-sboms")
```

### Programmatic Usage
```python
from combined_vuln_scanner import CombinedScanner

scanner = CombinedScanner()
results = scanner.scan_all()
report = scanner.format_results(results)
```
