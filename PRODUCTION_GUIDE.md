# SBOM Vulnerability Scanner - Production Guide

## 🎯 Executive Summary

Your SBOM vulnerability scanner is **production-ready** and successfully detected vulnerabilities. The system:

- ✅ **Scans multiple databases**: NVD (NIST) + Google OSV (additional sources optional)
- ✅ **Email alerts (optional)**: Disabled by default; enabled only when configured
- ✅ **Found real vulnerabilities**: CVE-2022-35409 (CRITICAL, CVSS 9.1) in mbedtls 2.28.1
- ✅ **Professional reporting**: JSON + console + email formats

## 🚀 How to Run (3 Methods)

### Method 1: Simple Run (Recommended)
```bash
cd /Users/leonkalema/Dev/sbom
python3 combined-vuln-scanner.py
```

### Method 2: Production Script (Best for automation)
```bash
cd /Users/leonkalema/Dev/sbom
./run_scan.sh
```

### Method 3: Legacy Shell Script
```bash
cd /Users/leonkalema/Dev/sbom
./scan-sboms.sh
```

## 📧 Email Configuration

### Default Behavior (Safe)
- **Email alerts are disabled by default**.
- **No default recipient is configured**.
- If `EMAIL_ALERTS=true` is set but `TO_EMAIL` is missing, the tool will refuse to send email.

### Enhanced SMTP Setup (Optional)
Create `.env` file for Gmail/corporate email:
```bash
cp .env.example .env
# Edit .env with your SMTP settings
```

Example `.env` for Gmail:
```
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
TO_EMAIL=security-team@company.com
EMAIL_ALERTS=true
```

## 🌐 Source Controls (Outbound Network Calls)
By default, only NVD and OSV API are enabled. You can explicitly enable/disable sources:
```
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

## 📊 Current Scan Results

**Last scan detected:**
- 🔴 **1 CRITICAL** vulnerability (CVE-2022-35409, CVSS 9.1)
- 🟡 **1 MEDIUM** vulnerability (CVE-2025-27809, CVSS 5.4)
- 📦 **Component**: mbedtls 2.28.1

**Immediate Action Required:**
- Update mbedtls to latest patched version
- Review detailed report: `/tmp/combined-vuln-scan.json`

## 🔄 Automation Options

### Daily Cron Job
```bash
# Add to crontab (crontab -e)
0 9 * * * cd /Users/leonkalema/Dev/sbom && ./run_scan.sh
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: SBOM Security Scan
  run: |
    cd sbom-scanner
    python3 combined-vuln-scanner.py
  # Fails build if vulnerabilities found (exit code 1)
```

## 📁 File Structure

```
/Users/leonkalema/Dev/sbom/
├── combined-vuln-scanner.py    # Main scanner (enhanced)
├── email_sender.py             # Professional email system
├── config.py                   # Configuration management
├── setup.py                    # One-time setup script
├── run_scan.sh                 # Production runner script
├── requirements.txt            # Python dependencies
├── README.md                   # Comprehensive documentation
├── .env.example               # Sample configuration
└── sbom/
    └── mbedtls.cdx.json       # Your SBOM files
```

## 🛠️ Adding New SBOM Files

1. **Generate SBOM** (using your build tools):
   ```bash
   # Example with syft
   syft packages dir:. -o cyclonedx-json > sbom/myapp.cdx.json
   
   # Example with cdxgen
   cdxgen -o sbom/frontend.cdx.json ./frontend/
   ```

2. **Add to scanner**:
   ```bash
   cp your-app.cdx.json /Users/leonkalema/Dev/sbom/sbom/
   ```

3. **Run scan**:
   ```bash
   python3 combined-vuln-scanner.py
   ```

## 🚨 Alert Thresholds

**Email sent when:**
- Any vulnerability found (configurable)
- Minimum severity: MEDIUM (configurable)
- Exit code 1 = vulnerabilities found
- Exit code 0 = clean scan

**Customize in config.py:**
```python
'min_severity_for_email': 'HIGH'  # Only CRITICAL/HIGH
```

## 📈 Monitoring & Metrics

### Key Metrics to Track
- **Vulnerability count trends**
- **Time to patch** (from detection to resolution)
- **Component coverage** (number of SBOM files)
- **False positive rate**

### Log Files
- Console output: Real-time progress
- JSON report: `/tmp/combined-vuln-scan.json`
- Production logs: `/tmp/sbom-scan-YYYYMMDD-HHMMSS.log`

## 🔧 Troubleshooting

### Common Issues

1. **"OSV scanner not found"**
   ```bash
   brew install osv-scanner
   ```

2. **"Mail command failed"**
   ```bash
   # Test mail setup
   echo "test" | mail -s "test" your-email@domain.com
   ```

3. **"No SBOM files found"**
   ```bash
   ls -la sbom/*.cdx.json
   # Ensure files have .cdx.json extension
   ```

4. **Rate limiting from NVD**
   - Built-in delays prevent most issues
   - For high volume, get NVD API key

### Debug Mode
```bash
# Verbose logging
python3 -c "
import logging
logging.basicConfig(level=logging.DEBUG)
from combined_vuln_scanner import main
main()
"
```

## 🏆 Best Practices

### Security
- ✅ Run scans on every build/deployment
- ✅ Set up automated alerts
- ✅ Track vulnerability remediation
- ✅ Regular SBOM updates

### Operations  
- ✅ Monitor scan execution time
- ✅ Archive scan reports
- ✅ Set up dashboard/metrics
- ✅ Document response procedures

## 📞 Support & Maintenance

### Regular Tasks
- **Weekly**: Review vulnerability trends
- **Monthly**: Update scanner dependencies
- **Quarterly**: Review email recipients and thresholds

### Updates
```bash
# Update Python dependencies
pip install -r requirements.txt --upgrade

# Update OSV scanner
brew upgrade osv-scanner
```

---

## ✅ Production Readiness Checklist

- [x] **Scanner functional** - Detecting real vulnerabilities
- [x] **Email alerts working** - Successfully sending to tullapeople@gmail.com
- [x] **Multiple scan sources** - NVD + OSV databases
- [x] **Professional reporting** - JSON, console, email formats
- [x] **Error handling** - Graceful failures and logging
- [x] **Configuration management** - Environment variables + .env support
- [x] **Documentation** - Comprehensive guides and examples
- [x] **Automation ready** - Scripts for cron/CI/CD integration

**Status: 🟢 PRODUCTION READY**

Your vulnerability scanner is enterprise-grade and ready for production use!
