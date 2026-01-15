#!/usr/bin/env python3
"""
CISA ICS-CERT Advisory Scanner
Scans components against CISA Industrial Control Systems advisories.
Specifically useful for embedded systems, firmware, and IoT devices.
"""

import requests
import json
import logging
import re
from typing import Dict, List, Tuple
from datetime import datetime
from version_utils import compare_versions, version_in_range, VersionRange, component_name_matches


class CISAICSScanner:
    """Scanner for CISA ICS-CERT Advisories"""
    
    def __init__(self):
        self.advisories_url = "https://www.cisa.gov/sites/default/files/feeds/ics-advisories.json"
        self.headers = {
            'User-Agent': 'SBOM-Scanner/2.0 (Security Research)',
            'Accept': 'application/json'
        }
        self.logger = logging.getLogger(__name__)
        self.advisories_cache = None
        self.cache_time = None
    
    def load_advisories(self) -> List[Dict]:
        """Load CISA ICS advisories from JSON feed"""
        try:
            self.logger.info("📥 Loading CISA ICS-CERT advisories...")
            
            response = requests.get(
                self.advisories_url,
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            advisories = data if isinstance(data, list) else data.get('advisories', [])
            
            self.advisories_cache = advisories
            self.cache_time = datetime.now()
            
            self.logger.info(f"✅ Loaded {len(advisories)} CISA ICS-CERT advisories")
            return advisories
            
        except Exception as e:
            self.logger.error(f"Failed to load CISA ICS advisories: {e}")
            return self._load_fallback_advisories()
    
    def _load_fallback_advisories(self) -> List[Dict]:
        """Load advisories from alternative endpoint if main fails"""
        try:
            alt_url = "https://www.cisa.gov/sites/default/files/feeds/ics-advisories-feed.json"
            response = requests.get(alt_url, headers=self.headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except:
            self.logger.warning("Using empty advisory list - CISA ICS feed unavailable")
            return []
    
    def scan_components(self, components: List[Dict]) -> List[Dict]:
        """Scan components against CISA ICS-CERT advisories"""
        vulnerabilities = []
        
        advisories = self.advisories_cache or self.load_advisories()
        
        if not advisories:
            self.logger.warning("No CISA ICS advisories available for scanning")
            return []
        
        self.logger.info(f"🔍 Scanning {len(components)} components against CISA ICS-CERT...")
        
        for component in components:
            name = component.get('name', '').lower()
            version = component.get('version', '')
            comp_type = component.get('type', '').lower()
            
            if not name:
                continue
            
            for advisory in advisories:
                is_match, confidence = self._check_advisory_match(
                    advisory, name, version, comp_type
                )
                
                if is_match and confidence in ('high', 'medium'):
                    vuln = self._format_vulnerability(advisory, component, confidence)
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_advisory_match(
        self, 
        advisory: Dict, 
        component_name: str, 
        component_version: str,
        component_type: str
    ) -> Tuple[bool, str]:
        """Check if advisory matches component with strict matching"""
        if not component_version:
            return False, "no_version"
        
        title = advisory.get('title', '').lower()
        description = advisory.get('description', '').lower()
        vendor = advisory.get('vendor', '').lower()
        product = advisory.get('product', '').lower()
        
        affected_products = advisory.get('affected_products', [])
        
        norm_name = self._normalize_name(component_name)
        
        if affected_products:
            for affected in affected_products:
                affected_name = affected.get('product', '').lower()
                affected_version = affected.get('version', '')
                affected_vendor = affected.get('vendor', '').lower()
                
                if self._name_matches(norm_name, affected_name):
                    if affected_version:
                        if self._version_affected(component_version, affected_version):
                            return True, "high"
                    else:
                        return True, "medium"
        
        if product and self._name_matches(norm_name, product):
            return True, "medium"
        
        if self._name_in_text_strict(norm_name, title):
            if component_version in title:
                return True, "medium"
            return False, "title_only"
        
        is_embedded = component_type in ('hardware', 'firmware', 'device', 'operating-system')
        if is_embedded and self._name_in_text_strict(norm_name, description):
            return True, "low"
        
        return False, "no_match"
    
    def _normalize_name(self, name: str) -> str:
        """Normalize component name for matching"""
        name = name.lower().strip()
        name = re.sub(r'^(lib|py|node-)', '', name)
        name = re.sub(r'(-js|-py|-java|-go)$', '', name)
        return name
    
    def _name_matches(self, norm_name: str, target: str) -> bool:
        """Check if normalized name matches target"""
        if not target:
            return False
        target_norm = self._normalize_name(target)
        return norm_name == target_norm
    
    def _name_in_text_strict(self, norm_name: str, text: str) -> bool:
        """Check if name appears as word boundary in text"""
        if not text:
            return False
        text_lower = text.lower()
        pattern = rf'\b{re.escape(norm_name)}\b'
        return bool(re.search(pattern, text_lower))
    
    def _version_affected(self, component_version: str, affected_version: str) -> bool:
        """Check if component version matches affected version specification"""
        if not affected_version:
            return False
        
        affected_lower = affected_version.lower()
        
        if 'all versions' in affected_lower or 'all' == affected_lower.strip():
            return True
        
        if 'prior to' in affected_lower or 'before' in affected_lower:
            match = re.search(r'(?:prior to|before)\s*([\d.]+)', affected_lower)
            if match:
                fixed_version = match.group(1)
                return compare_versions(component_version, fixed_version) < 0
        
        if '<' in affected_version:
            match = re.search(r'<\s*([\d.]+)', affected_version)
            if match:
                return compare_versions(component_version, match.group(1)) < 0
        
        if '-' in affected_version and not affected_version.startswith('-'):
            parts = affected_version.split('-')
            if len(parts) == 2:
                try:
                    start, end = parts[0].strip(), parts[1].strip()
                    return (compare_versions(component_version, start) >= 0 and 
                            compare_versions(component_version, end) <= 0)
                except:
                    pass
        
        clean_affected = re.sub(r'[^\d.]', '', affected_version)
        if clean_affected and compare_versions(component_version, clean_affected) == 0:
            return True
        
        return False
    
    def _format_vulnerability(self, advisory: Dict, component: Dict, confidence: str) -> Dict:
        """Format advisory as vulnerability dict"""
        advisory_id = advisory.get('id', advisory.get('advisory_id', 'Unknown'))
        
        cvss_score = advisory.get('cvss_score', advisory.get('cvss', 'N/A'))
        if isinstance(cvss_score, dict):
            cvss_score = cvss_score.get('score', 'N/A')
        
        severity = self._get_severity(cvss_score)
        
        cve_ids = advisory.get('cve_ids', advisory.get('cves', []))
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        
        url = advisory.get('url', advisory.get('link', ''))
        if not url and advisory_id:
            url = f"https://www.cisa.gov/news-events/ics-advisories/{advisory_id.lower()}"
        
        return {
            'source': 'CISA ICS-CERT',
            'id': advisory_id,
            'cve_ids': cve_ids,
            'title': advisory.get('title', 'No title'),
            'description': advisory.get('description', 'No description')[:500],
            'severity': severity,
            'cvss_score': str(cvss_score) if cvss_score != 'N/A' else 'N/A',
            'vendor': advisory.get('vendor', 'Unknown'),
            'product': advisory.get('product', 'Unknown'),
            'published': advisory.get('published', advisory.get('release_date', 'Unknown')),
            'url': url,
            'component': component,
            'confidence': confidence,
            'advisory_type': 'ICS'
        }
    
    def _get_severity(self, cvss_score) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score == 'N/A' or cvss_score is None:
            return 'Unknown'
        
        try:
            score = float(cvss_score)
            if score >= 9.0:
                return 'CRITICAL'
            elif score >= 7.0:
                return 'HIGH'
            elif score >= 4.0:
                return 'MEDIUM'
            elif score > 0.0:
                return 'LOW'
            return 'NONE'
        except (ValueError, TypeError):
            return 'Unknown'
    
    def get_stats(self) -> Dict:
        """Get scanner statistics"""
        return {
            'name': 'CISA ICS-CERT',
            'source': 'cisa_ics',
            'description': 'CISA Industrial Control Systems Cyber Emergency Response Team',
            'url': 'https://www.cisa.gov/news-events/cybersecurity-advisories',
            'focus': 'Embedded systems, firmware, IoT, industrial control systems',
            'advisories_loaded': len(self.advisories_cache) if self.advisories_cache else 0
        }


def test_cisa_ics_scanner():
    """Test CISA ICS scanner"""
    scanner = CISAICSScanner()
    
    test_components = [
        {'name': 'mbedtls', 'version': '2.28.1', 'type': 'library'},
        {'name': 'safertos', 'version': '5.11', 'type': 'operating-system'},
        {'name': 'stm32f745zet6', 'version': '1.0', 'type': 'hardware'},
    ]
    
    print("🧪 Testing CISA ICS-CERT Scanner...")
    vulnerabilities = scanner.scan_components(test_components)
    
    print(f"Found {len(vulnerabilities)} ICS advisories")
    for vuln in vulnerabilities[:3]:
        print(f"  • {vuln['id']} - {vuln['severity']} - {vuln['title'][:50]}...")
    
    stats = scanner.get_stats()
    print(f"\nAdvisories loaded: {stats['advisories_loaded']}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_cisa_ics_scanner()
