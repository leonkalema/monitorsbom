#!/usr/bin/env python3
"""
CVE.org Scanner
Scans components against the official CVE.org database
"""

import requests
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import time

class CVEOrgScanner:
    """Scanner for CVE.org official database"""
    
    def __init__(self, api_token: Optional[str] = None):
        self.base_url = "https://cveawg.mitre.org/api"
        self.api_token = api_token
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        
        self.session.headers.update({
            'User-Agent': 'SBOM-Vulnerability-Scanner/1.0',
            'Accept': 'application/json'
        })
        
        # Add authentication if token provided
        if self.api_token:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_token}'
            })
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 2.0  # 2 seconds between requests (be respectful)
    
    def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def scan_components(self, components: List[Dict]) -> List[Dict]:
        """Scan components against CVE.org database"""
        vulnerabilities = []
        
        self.logger.info(f"🔍 Scanning {len(components)} components with CVE.org...")
        
        for component in components:
            try:
                component_vulns = self._scan_component(component)
                vulnerabilities.extend(component_vulns)
                
                if component_vulns:
                    self.logger.info(f"  🔎 {component.get('name', 'unknown')} {component.get('version', '')} - {len(component_vulns)} CVEs")
                
            except Exception as e:
                self.logger.error(f"Error scanning component {component.get('name', 'unknown')}: {e}")
                continue
        
        return vulnerabilities
    
    def _scan_component(self, component: Dict) -> List[Dict]:
        """Scan a single component for CVEs"""
        name = component.get('name', '').lower()
        version = component.get('version', '')
        
        if not name:
            return []
        
        vulnerabilities = []
        
        # Search for CVEs by keyword
        search_terms = [name]
        
        # Add additional search terms based on component info
        if 'purl' in component:
            purl_parts = component['purl'].split('/')
            if len(purl_parts) > 1:
                search_terms.append(purl_parts[-1].split('@')[0])
        
        for search_term in search_terms:
            try:
                cves = self._search_cves(search_term)
                
                for cve in cves:
                    if self._is_component_affected(component, cve):
                        vuln = self._create_vulnerability_record(component, cve)
                        vulnerabilities.append(vuln)
                
            except Exception as e:
                self.logger.debug(f"Error searching CVEs for {search_term}: {e}")
                continue
        
        return vulnerabilities
    
    def _search_cves(self, search_term: str, limit: int = 50) -> List[Dict]:
        """Search for CVEs using CVE.org API"""
        self._rate_limit()
        
        try:
            # Use correct CVE search endpoint with proper parameters
            url = f"{self.base_url}/cve"
            params = {
                'keywordSearch': search_term,
                'state': 'PUBLISHED',
                'count': min(limit, 100),  # API max is typically 100
                'page': 1
            }
            
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                # CVE API returns different structure
                cves = data.get('cveRecords', []) or data.get('vulnerabilities', [])
                return cves
            elif response.status_code == 401:
                self.logger.warning("CVE.org API requires authentication for full access")
                return []
            elif response.status_code == 403:
                self.logger.warning("CVE.org API access forbidden - check credentials")
                return []
            else:
                self.logger.debug(f"CVE.org API returned {response.status_code} for {search_term}")
                # Try fallback method for unauthenticated access
                return self._search_cves_fallback(search_term, limit)
                
        except Exception as e:
            self.logger.debug(f"Error searching CVE.org for {search_term}: {e}")
            return []
    
    def _search_cves_fallback(self, search_term: str, limit: int = 50) -> List[Dict]:
        """Fallback CVE search method for unauthenticated access"""
        self._rate_limit()
        
        try:
            # Try direct CVE lookup if search_term looks like CVE ID
            if search_term.upper().startswith('CVE-'):
                cve_id = search_term.upper()
                url = f"{self.base_url}/cve/{cve_id}"
                
                response = self.session.get(url, timeout=30)
                
                if response.status_code == 200:
                    cve_record = response.json()
                    return [{'cveRecord': cve_record}]
            
            # For unauthenticated access, we have limited options
            # Return empty list and log the limitation
            self.logger.info(f"CVE.org search limited without authentication for: {search_term}")
            return []
            
        except Exception as e:
            self.logger.debug(f"Error in fallback CVE search for {search_term}: {e}")
            return []
    
    def _is_component_affected(self, component: Dict, cve_data: Dict) -> bool:
        """Check if component is affected by CVE"""
        component_name = component.get('name', '').lower()
        
        try:
            # Handle both old and new CVE API response formats
            cve_record = cve_data.get('cveRecord', {})
            if cve_record:
                # New CVE Services API format
                cve_metadata = cve_record.get('cveMetadata', {})
                containers = cve_record.get('containers', {})
                cna_container = containers.get('cna', {})
                
                # Check descriptions
                descriptions = cna_container.get('descriptions', [])
                for desc in descriptions:
                    desc_text = desc.get('value', '').lower()
                    if component_name in desc_text:
                        return True
                
                # Check affected products
                affected = cna_container.get('affected', [])
                for product in affected:
                    product_name = product.get('product', '').lower()
                    vendor = product.get('vendor', '').lower()
                    if component_name in product_name or component_name in vendor:
                        return True
                
                # Check references
                references = cna_container.get('references', [])
                for ref in references:
                    ref_url = ref.get('url', '').lower()
                    if component_name in ref_url:
                        return True
            else:
                # Legacy format fallback
                cve = cve_data.get('cve', {})
                descriptions = cve.get('descriptions', [])
                for desc in descriptions:
                    desc_text = desc.get('value', '').lower()
                    if component_name in desc_text:
                        return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking if component affected: {e}")
            return False
    
    def _create_vulnerability_record(self, component: Dict, cve_data: Dict) -> Dict:
        """Create vulnerability record from CVE.org data"""
        try:
            # Handle new CVE Services API format
            cve_record = cve_data.get('cveRecord', {})
            if cve_record:
                # New format
                cve_metadata = cve_record.get('cveMetadata', {})
                cve_id = cve_metadata.get('cveId', '')
                
                containers = cve_record.get('containers', {})
                cna_container = containers.get('cna', {})
                
                # Get description
                descriptions = cna_container.get('descriptions', [])
                description = ''
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                if not description and descriptions:
                    description = descriptions[0].get('value', '')
                
                # Get CVSS metrics
                metrics = cna_container.get('metrics', [])
                cvss_score = 0
                cvss_vector = ''
                severity = 'UNKNOWN'
                
                for metric in metrics:
                    if 'cvssV3_1' in metric:
                        cvss_data = metric['cvssV3_1']
                        cvss_score = cvss_data.get('baseScore', 0)
                        cvss_vector = cvss_data.get('vectorString', '')
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                        break
                    elif 'cvssV3_0' in metric:
                        cvss_data = metric['cvssV3_0']
                        cvss_score = cvss_data.get('baseScore', 0)
                        cvss_vector = cvss_data.get('vectorString', '')
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                        break
                
                # Get dates
                published_date = cve_metadata.get('datePublished', '')
                updated_date = cve_metadata.get('dateUpdated', '')
                
                # Get references
                references = cna_container.get('references', [])
                
            else:
                # Legacy format fallback
                cve = cve_data.get('cve', {})
                cve_id = cve.get('id', '')
                
                descriptions = cve.get('descriptions', [])
                description = ''
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                if not description and descriptions:
                    description = descriptions[0].get('value', '')
                
                # Legacy CVSS handling
                metrics = cve.get('metrics', {})
                cvss_score = 0
                cvss_vector = ''
                severity = 'UNKNOWN'
                
                for cvss_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if cvss_version in metrics and metrics[cvss_version]:
                        cvss_data = metrics[cvss_version][0].get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore', 0)
                        cvss_vector = cvss_data.get('vectorString', '')
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN').upper()
                        break
                
                published_date = cve.get('published', '')
                updated_date = cve.get('lastModified', '')
                references = cve.get('references', [])
            
            # Create URL
            url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            if references:
                for ref in references:
                    ref_url = ref.get('url', '')
                    if 'nvd.nist.gov' in ref_url or 'cve.mitre.org' in ref_url:
                        url = ref_url
                        break
            
            return {
                'id': cve_id,
                'cve_id': cve_id,
                'summary': description[:200] + '...' if len(description) > 200 else description,
                'description': description,
                'severity': severity,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'published_date': published_date,
                'updated_date': updated_date,
                'url': url,
                'source': 'CVE.org',
                'component': component,
                'references': [ref.get('url', '') for ref in references[:5]]  # Limit references
            }
            
        except Exception as e:
            self.logger.error(f"Error creating vulnerability record: {e}")
            return {}
    
    def get_stats(self) -> Dict:
        """Get scanner statistics"""
        return {
            'name': 'CVE.org Official Database',
            'source': 'cve_org',
            'description': 'Official CVE database maintained by MITRE',
            'url': 'https://cveawg.mitre.org/api-docs/',
            'requires_auth': True,
            'auth_configured': bool(self.api_token),
            'rate_limit': '2 seconds between requests (self-imposed)',
            'coverage': 'All official CVE entries',
            'api_version': 'CVE Services API v1',
            'note': 'Limited functionality without authentication'
        }

def test_cve_org_scanner():
    """Test CVE.org scanner"""
    scanner = CVEOrgScanner()
    
    # Test with a known component
    test_components = [
        {
            'name': 'apache',
            'version': '2.4.41',
            'purl': 'pkg:generic/apache@2.4.41'
        }
    ]
    
    print("🧪 Testing CVE.org Scanner...")
    vulnerabilities = scanner.scan_components(test_components)
    
    print(f"Found {len(vulnerabilities)} vulnerabilities")
    for vuln in vulnerabilities[:3]:  # Show first 3
        print(f"  - {vuln['id']}: {vuln['summary'][:60]}...")

if __name__ == "__main__":
    test_cve_org_scanner()
