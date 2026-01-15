#!/usr/bin/env python3
"""
Configuration settings for SBOM Vulnerability Scanner
"""

import os
from typing import Dict, Any

def _get_bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}

# Load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use system env vars only

# Email Configuration
EMAIL_CONFIG = {
    'service': os.getenv('EMAIL_SERVICE', 'smtp'),  # 'smtp', 'mailersend', or 'resend'
    'resend_api_key': os.getenv('RESEND_API_KEY', ''),
    'mailersend_api_token': os.getenv('MAILERSEND_API_TOKEN', ''),
    'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
    'smtp_port': int(os.getenv('SMTP_PORT', '587')),
    'smtp_username': os.getenv('SMTP_USERNAME', ''),
    'smtp_password': os.getenv('SMTP_PASSWORD', ''),
    'from_email': os.getenv('FROM_EMAIL', 'security-scanner@company.com'),
    'to_email': os.getenv('TO_EMAIL', ''),
    'use_tls': os.getenv('SMTP_TLS', 'true').lower() == 'true',
    'fallback_to_mail_command': True  # Use system mail command if SMTP fails
}

# Scanner Configuration
SCANNER_CONFIG = {
    'sbom_directory': os.getenv('SBOM_DIR', 'sbom'),
    'output_file': os.getenv('OUTPUT_FILE', '/tmp/combined-vuln-scan.json'),
    'nvd_results_per_page': int(os.getenv('NVD_RESULTS_PER_PAGE', '20')),
    'osv_timeout': int(os.getenv('OSV_TIMEOUT', '60')),
    'email_on_vulnerabilities': _get_bool_env('EMAIL_ALERTS', False),
    'min_severity_for_email': os.getenv('MIN_EMAIL_SEVERITY', 'MEDIUM')  # CRITICAL, HIGH, MEDIUM, LOW
}

# Source Configuration
SOURCE_CONFIG = {
    'enable_nvd': _get_bool_env('ENABLE_NVD', True),
    'enable_osv_api': _get_bool_env('ENABLE_OSV_API', True),
    'enable_osv_cli': _get_bool_env('ENABLE_OSV_CLI', False),
    'enable_github': _get_bool_env('ENABLE_GITHUB', False),
    'enable_cisa_kev': _get_bool_env('ENABLE_CISA_KEV', False),
    'enable_cisa_ics': _get_bool_env('ENABLE_CISA_ICS', False),
    'enable_cve_org': _get_bool_env('ENABLE_CVE_ORG', False),
    'enable_cert_cc': _get_bool_env('ENABLE_CERT_CC', False),
    'enable_sonatype': _get_bool_env('ENABLE_SONATYPE', False),
    'enable_vulners': _get_bool_env('ENABLE_VULNERS', False),
}

# API Configuration
API_CONFIG = {
    'nvd_base_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    'nvd_api_key': os.getenv('NVD_API_KEY', ''),  # Optional, improves rate limits
    'vulners_api_key': os.getenv('VULNERS_API_KEY', ''),  # Optional, improves rate limits
    'github_token': os.getenv('GITHUB_TOKEN', ''),  # Optional, improves rate limits
    'user_agent': 'SBOM-Scanner/2.0 (Security Research)',
    'request_timeout': int(os.getenv('REQUEST_TIMEOUT', '30'))
}

def get_config() -> Dict[str, Any]:
    """Get all configuration settings"""
    return {
        'email': EMAIL_CONFIG,
        'scanner': SCANNER_CONFIG,
        'sources': SOURCE_CONFIG,
        'api': API_CONFIG
    }

def validate_config() -> bool:
    """Validate configuration settings"""
    errors = []
    
    # Check email configuration if email alerts are enabled
    if SCANNER_CONFIG['email_on_vulnerabilities']:
        if not EMAIL_CONFIG['to_email']:
            errors.append("TO_EMAIL environment variable is required for email alerts")
        
        # If SMTP is configured, validate required fields
        if EMAIL_CONFIG['smtp_username'] and not EMAIL_CONFIG['smtp_password']:
            errors.append("SMTP_PASSWORD is required when SMTP_USERNAME is set")
    
    # Check SBOM directory exists
    import os
    if not os.path.exists(SCANNER_CONFIG['sbom_directory']):
        errors.append(f"SBOM directory '{SCANNER_CONFIG['sbom_directory']}' does not exist")
    
    if errors:
        print("❌ Configuration errors:")
        for error in errors:
            print(f"   - {error}")
        return False
    
    return True
