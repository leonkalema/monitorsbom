#!/usr/bin/env python3
"""
Vulners.com API Scanner
Free vulnerability database with 10,000 requests/month
API: https://vulners.com/api/v3/
"""

import requests
import json
import logging
import re
from typing import Dict, List, Tuple

class VulnersScanner:
    """Vulners.com vulnerability scanner"""
    
    def __init__(self, api_key: str = None):
        self.base_url = "https://vulners.com/api/v3"
        self.api_key = api_key  # Optional, increases rate limits
        self.headers = {
            'User-Agent': 'SBOM-Scanner/2.0 (Security Research)',
            'Content-Type': 'application/json'
        }
        self.logger = logging.getLogger(__name__)
        
        # Display API key status
        if self.api_key:
            print("✅ Using Vulners.com API key for enhanced rate limits (10k requests/month)")
        else:
            print("ℹ️  Using Vulners.com without API key (limited rate limits)")
    
    def scan_component(self, name: str, version: str = None) -> List[Dict]:
        """Search Vulners for component vulnerabilities"""
        query = name
        if version:
            query += f" {version}"
            
        params = {
            'query': query,
            'type': 'software',
            'size': 50  # Max results
        }
        
        # Add API key to headers instead of params (Vulners uses header-based auth)
        headers = self.headers.copy()
        if self.api_key:
            headers['X-API-Key'] = self.api_key
            
        try:
            response = requests.get(
                f"{self.base_url}/search/lucene/",
                headers=headers,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            return self._parse_results(data, name, version)
            
        except Exception as e:
            self.logger.error(f"Vulners scan error for {name}: {e}")
            return []
    
    def _parse_results(self, data: Dict, component_name: str, component_version: str) -> List[Dict]:
        """Parse Vulners API results"""
        vulnerabilities = []
        
        if data.get('result') == 'OK':
            documents = data.get('data', {}).get('search', [])
            
            for doc in documents:
                # Extract data from _source (Vulners uses Elasticsearch format)
                source_data = doc.get('_source', {})
                doc_id = doc.get('_id', source_data.get('id', 'Unknown'))
                
                # Filter for relevant vulnerabilities with strict matching
                is_relevant, confidence = self._is_relevant_vulnerability(source_data, component_name, component_version)
                
                # Skip non-CVE advisories (Fedora, Ubuntu, Debian advisories are distro-specific)
                doc_type = source_data.get('type', source_data.get('bulletinFamily', '')).lower()
                if doc_type in ('fedora', 'ubuntu', 'debian', 'redhat', 'suse', 'advisory'):
                    continue
                
                # Only include CVEs or high-confidence matches with CVE references
                cve_list = source_data.get('cvelist', [])
                has_cve = any(c.startswith('CVE-') for c in cve_list) if cve_list else False
                
                if not has_cve and confidence != 'high':
                    continue
                
                if is_relevant and confidence in ('high', 'medium'):
                    # Extract CVSS information
                    cvss_info = source_data.get('cvss', {})
                    cvss3_info = source_data.get('cvss3', {})
                    
                    # Get the best available CVSS score
                    cvss_score = 'N/A'
                    if cvss3_info and cvss3_info.get('score'):
                        cvss_score = str(cvss3_info.get('score'))
                    elif cvss_info and cvss_info.get('score'):
                        cvss_score = str(cvss_info.get('score'))
                    
                    vuln = {
                        'source': 'Vulners.com',
                        'id': doc_id,
                        'title': source_data.get('title', 'No title'),
                        'description': source_data.get('description', 'No description')[:500],
                        'type': source_data.get('type', source_data.get('bulletinFamily', 'Unknown')),
                        'published': source_data.get('published', 'Unknown'),
                        'modified': source_data.get('modified', 'Unknown'),
                        'cvss_score': cvss_score,
                        'severity': self._get_severity_from_score(cvss_score),
                        'references': source_data.get('references', []),
                        'href': source_data.get('href', ''),
                        'url': source_data.get('href', f"https://vulners.com/search?query={doc_id}"),
                        'component': {
                            'name': component_name,
                            'version': component_version
                        },
                        'cve_list': source_data.get('cvelist', [])
                    }
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _is_relevant_vulnerability(self, doc: Dict, component_name: str, component_version: str) -> Tuple[bool, str]:
        """Check if vulnerability is relevant to our component with strict matching"""
        if not component_version:
            return False, "no_version"
        
        # Normalize component name for matching
        norm_name = self._normalize_name(component_name)
        
        # Check affected software list first (most reliable)
        affected_software = doc.get('affectedSoftware', [])
        for software in affected_software:
            if isinstance(software, dict):
                sw_name = software.get('name', '')
                sw_version = software.get('version', '')
                version_range = software.get('versionRange', '')
                
                if self._name_matches(norm_name, sw_name):
                    # Check version if available
                    if version_range:
                        if self._version_in_vulners_range(component_version, version_range):
                            return True, "high"
                    elif sw_version:
                        if self._version_matches(component_version, sw_version):
                            return True, "high"
                    else:
                        return True, "medium"  # Name matches but no version info
            elif isinstance(software, str):
                if self._name_matches(norm_name, software):
                    return True, "low"  # String match only, low confidence
        
        # Check title for exact product name match (not just substring)
        title = doc.get('title', '')
        if self._name_in_text_strict(norm_name, title):
            # Also need version evidence to be high confidence
            if component_version in title:
                return True, "medium"
        
        return False, "not_relevant"
    
    def _normalize_name(self, name: str) -> str:
        """Normalize component name for matching"""
        name = name.lower().strip()
        name = re.sub(r'^(lib|py|node-|@[\w-]+/)', '', name)
        name = re.sub(r'(-js|-py|-java|-go)$', '', name)
        return name
    
    def _name_matches(self, norm_name: str, target: str) -> bool:
        """Check if normalized name matches target"""
        target_norm = self._normalize_name(target)
        return norm_name == target_norm or norm_name in target_norm or target_norm in norm_name
    
    def _name_in_text_strict(self, norm_name: str, text: str) -> bool:
        """Check if name appears as a word boundary in text"""
        text_lower = text.lower()
        pattern = rf'\b{re.escape(norm_name)}\b'
        return bool(re.search(pattern, text_lower))
    
    def _version_matches(self, component_version: str, target_version: str) -> bool:
        """Check if versions match"""
        v1 = re.sub(r'^[vV]', '', component_version.strip())
        v2 = re.sub(r'^[vV]', '', target_version.strip())
        return v1 == v2 or v1.startswith(v2) or v2.startswith(v1)
    
    def _version_in_vulners_range(self, version: str, range_str: str) -> bool:
        """Check if version falls within Vulners version range format"""
        version = re.sub(r'^[vV]', '', version.strip())
        
        # Common formats: "< 2.0.0", ">= 1.0.0, < 2.0.0", "1.0.0 - 2.0.0"
        def parse_version(v: str) -> List[int]:
            parts = []
            for p in v.split('.'):
                try:
                    parts.append(int(re.match(r'^\d+', p).group() if re.match(r'^\d+', p) else 0))
                except:
                    break
            return parts or [0]
        
        def compare(v1: str, v2: str) -> int:
            p1, p2 = parse_version(v1), parse_version(v2)
            max_len = max(len(p1), len(p2))
            p1.extend([0] * (max_len - len(p1)))
            p2.extend([0] * (max_len - len(p2)))
            for a, b in zip(p1, p2):
                if a < b: return -1
                if a > b: return 1
            return 0
        
        for constraint in range_str.split(','):
            constraint = constraint.strip()
            if constraint.startswith('>='):
                if compare(version, constraint[2:].strip()) < 0:
                    return False
            elif constraint.startswith('>'):
                if compare(version, constraint[1:].strip()) <= 0:
                    return False
            elif constraint.startswith('<='):
                if compare(version, constraint[2:].strip()) > 0:
                    return False
            elif constraint.startswith('<'):
                if compare(version, constraint[1:].strip()) >= 0:
                    return False
        
        return True
    
    def _get_severity_from_score(self, score_str: str) -> str:
        """Convert CVSS score string to severity level"""
        if score_str == 'N/A':
            return 'Unknown'
            
        try:
            score = float(score_str)
            if score >= 9.0:
                return 'CRITICAL'
            elif score >= 7.0:
                return 'HIGH'
            elif score >= 4.0:
                return 'MEDIUM'
            elif score > 0.0:
                return 'LOW'
            else:
                return 'NONE'
        except (ValueError, TypeError):
            return 'Unknown'
    
    def _get_severity_from_cvss(self, cvss_data: Dict) -> str:
        """Convert CVSS data to severity level (legacy method)"""
        score = cvss_data.get('score')
        if score is None:
            return 'Unknown'
        return self._get_severity_from_score(str(score))

def main():
    """Test the Vulners scanner"""
    from config import API_CONFIG
    
    api_key = API_CONFIG.get('vulners_api_key', '')
    scanner = VulnersScanner(api_key)
    
    print("🔍 Testing Vulners.com Scanner...")
    vulnerabilities = scanner.scan_component('mbedtls', '2.28.1')
    
    print(f"Found {len(vulnerabilities)} vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  • {vuln['id']} - {vuln['severity']} - {vuln['title'][:60]}...")

if __name__ == "__main__":
    main()
