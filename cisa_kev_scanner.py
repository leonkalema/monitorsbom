#!/usr/bin/env python3
"""
CISA KEV (Known Exploited Vulnerabilities) Catalog Scanner
Scans components against CISA's Known Exploited Vulnerabilities catalog
"""

import requests
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
import re

class CISAKEVScanner:
    """Scanner for CISA Known Exploited Vulnerabilities Catalog"""
    
    def __init__(self):
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        self.kev_data = None
        self.last_updated = None
        
        self.session.headers.update({
            'User-Agent': 'SBOM-Vulnerability-Scanner/1.0'
        })
    
    def load_kev_catalog(self) -> bool:
        """Load the CISA KEV catalog"""
        try:
            self.logger.info("📥 Loading CISA KEV catalog...")
            
            response = self.session.get(self.kev_url, timeout=30)
            response.raise_for_status()
            
            self.kev_data = response.json()
            self.last_updated = datetime.now()
            
            catalog_info = self.kev_data.get('catalogVersion', 'Unknown')
            vuln_count = len(self.kev_data.get('vulnerabilities', []))
            
            self.logger.info(f"✅ Loaded CISA KEV catalog v{catalog_info} with {vuln_count} vulnerabilities")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load CISA KEV catalog: {e}")
            return False
    
    def scan_components(self, components: List[Dict]) -> List[Dict]:
        """Scan components against CISA KEV catalog"""
        if not self.kev_data:
            if not self.load_kev_catalog():
                return []
        
        vulnerabilities = []
        kev_vulns = self.kev_data.get('vulnerabilities', [])
        
        self.logger.info(f"🔍 Scanning {len(components)} components against CISA KEV catalog...")
        
        for component in components:
            try:
                component_vulns = self._scan_component(component, kev_vulns)
                vulnerabilities.extend(component_vulns)
                
                if component_vulns:
                    self.logger.info(f"  🚨 {component.get('name', 'unknown')} {component.get('version', '')} - {len(component_vulns)} KEV matches")
                
            except Exception as e:
                self.logger.error(f"Error scanning component {component.get('name', 'unknown')}: {e}")
                continue
        
        return vulnerabilities
    
    def _scan_component(self, component: Dict, kev_vulns: List[Dict]) -> List[Dict]:
        """Scan a single component against KEV vulnerabilities"""
        vulnerabilities = []
        component_name = component.get('name', '').lower()
        component_version = component.get('version', '')
        
        if not component_name:
            return []
        
        for kev_vuln in kev_vulns:
            try:
                # Check if this KEV vulnerability affects the component
                if self._is_component_affected(component, kev_vuln):
                    vuln = self._create_vulnerability_record(component, kev_vuln)
                    vulnerabilities.append(vuln)
                    
            except Exception as e:
                self.logger.debug(f"Error processing KEV vulnerability {kev_vuln.get('cveID', 'unknown')}: {e}")
                continue
        
        return vulnerabilities
    
    def _is_component_affected(self, component: Dict, kev_vuln: Dict) -> bool:
        """Check if component is affected by KEV vulnerability"""
        component_name = component.get('name', '').lower()
        vendor_project = kev_vuln.get('vendorProject', '').lower()
        product = kev_vuln.get('product', '').lower()
        
        # Check if component name matches vendor/product information
        name_matches = [
            component_name in vendor_project,
            component_name in product,
            vendor_project in component_name,
            product in component_name,
            self._fuzzy_match(component_name, vendor_project),
            self._fuzzy_match(component_name, product)
        ]
        
        return any(name_matches)
    
    def _fuzzy_match(self, name1: str, name2: str) -> bool:
        """Perform fuzzy matching between component names"""
        if not name1 or not name2:
            return False
        
        # Remove common prefixes/suffixes and special characters
        clean_name1 = re.sub(r'[^a-zA-Z0-9]', '', name1.lower())
        clean_name2 = re.sub(r'[^a-zA-Z0-9]', '', name2.lower())
        
        # Check for substring matches
        if len(clean_name1) > 3 and len(clean_name2) > 3:
            return clean_name1 in clean_name2 or clean_name2 in clean_name1
        
        return False
    
    def _create_vulnerability_record(self, component: Dict, kev_vuln: Dict) -> Dict:
        """Create vulnerability record from KEV data"""
        return {
            'id': kev_vuln.get('cveID', ''),
            'cve_id': kev_vuln.get('cveID', ''),
            'summary': f"CISA KEV: {kev_vuln.get('vulnerabilityName', 'Unknown vulnerability')}",
            'description': kev_vuln.get('shortDescription', ''),
            'severity': 'CRITICAL',  # All KEV vulnerabilities are considered critical
            'cvss_score': 9.0,  # Assume high score for KEV vulnerabilities
            'cvss_vector': '',
            'published_date': kev_vuln.get('dateAdded', ''),
            'updated_date': kev_vuln.get('dateAdded', ''),
            'url': f"https://nvd.nist.gov/vuln/detail/{kev_vuln.get('cveID', '')}",
            'source': 'CISA KEV',
            'component': component,
            'vendor_project': kev_vuln.get('vendorProject', ''),
            'product': kev_vuln.get('product', ''),
            'vulnerability_name': kev_vuln.get('vulnerabilityName', ''),
            'required_action': kev_vuln.get('requiredAction', ''),
            'due_date': kev_vuln.get('dueDate', ''),
            'known_ransomware': kev_vuln.get('knownRansomwareCampaignUse', 'Unknown'),
            'notes': kev_vuln.get('notes', ''),
            'kev_priority': True  # Mark as KEV priority vulnerability
        }
    
    def get_kev_summary(self) -> Dict:
        """Get summary of KEV catalog"""
        if not self.kev_data:
            return {}
        
        vulnerabilities = self.kev_data.get('vulnerabilities', [])
        
        # Count by vendor
        vendors = {}
        ransomware_count = 0
        
        for vuln in vulnerabilities:
            vendor = vuln.get('vendorProject', 'Unknown')
            vendors[vendor] = vendors.get(vendor, 0) + 1
            
            if vuln.get('knownRansomwareCampaignUse', '').lower() == 'known':
                ransomware_count += 1
        
        return {
            'catalog_version': self.kev_data.get('catalogVersion', 'Unknown'),
            'date_released': self.kev_data.get('dateReleased', 'Unknown'),
            'total_vulnerabilities': len(vulnerabilities),
            'ransomware_related': ransomware_count,
            'top_vendors': dict(sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]),
            'last_updated': self.last_updated.isoformat() if self.last_updated else None
        }
    
    def get_stats(self) -> Dict:
        """Get scanner statistics"""
        return {
            'name': 'CISA KEV Catalog',
            'source': 'cisa_kev',
            'description': 'CISA Known Exploited Vulnerabilities Catalog',
            'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
            'requires_auth': False,
            'rate_limit': 'No specific limit',
            'priority': 'CRITICAL - All KEV vulnerabilities are actively exploited'
        }

def test_cisa_kev_scanner():
    """Test CISA KEV scanner"""
    scanner = CISAKEVScanner()
    
    # Test with some common components that might have KEV vulnerabilities
    test_components = [
        {
            'name': 'apache',
            'version': '2.4.41',
            'purl': 'pkg:generic/apache@2.4.41'
        },
        {
            'name': 'microsoft',
            'version': '1.0',
            'purl': 'pkg:generic/microsoft@1.0'
        },
        {
            'name': 'cisco',
            'version': '1.0',
            'purl': 'pkg:generic/cisco@1.0'
        }
    ]
    
    print("🧪 Testing CISA KEV Scanner...")
    
    # Load KEV catalog
    if scanner.load_kev_catalog():
        summary = scanner.get_kev_summary()
        print(f"📊 KEV Catalog: {summary['total_vulnerabilities']} vulnerabilities, {summary['ransomware_related']} ransomware-related")
        
        vulnerabilities = scanner.scan_components(test_components)
        print(f"Found {len(vulnerabilities)} KEV matches")
        
        for vuln in vulnerabilities[:3]:  # Show first 3
            print(f"  - {vuln['id']}: {vuln['vulnerability_name'][:60]}...")
    else:
        print("❌ Failed to load KEV catalog")

if __name__ == "__main__":
    test_cisa_kev_scanner()
