#!/usr/bin/env python3
"""
Sonatype OSS Index Scanner
Free vulnerability scanning for open source components
API: https://ossindex.sonatype.org/api/v3/
Rate Limit: 120 requests/hour (no auth required)
"""

import requests
import json
import logging
from typing import Dict, List
from urllib.parse import quote

class SonatypeOSSScanner:
    """Sonatype OSS Index vulnerability scanner"""
    
    def __init__(self):
        self.base_url = "https://ossindex.sonatype.org/api/v3"
        self.headers = {
            'User-Agent': 'SBOM-Scanner/2.0 (Security Research)',
            'Content-Type': 'application/json'
        }
        self.logger = logging.getLogger(__name__)
    
    def scan_components(self, components: List[Dict]) -> List[Dict]:
        """Scan multiple components for vulnerabilities"""
        vulnerabilities = []
        
        # Group components into batches (API supports up to 128 coordinates per request)
        batch_size = 100
        for i in range(0, len(components), batch_size):
            batch = components[i:i + batch_size]
            batch_vulns = self._scan_component_batch(batch)
            vulnerabilities.extend(batch_vulns)
            
        return vulnerabilities
    
    def _scan_component_batch(self, components: List[Dict]) -> List[Dict]:
        """Scan a batch of components"""
        coordinates = []
        
        for component in components:
            name = component.get('name', '')
            version = component.get('version', '')
            purl = component.get('purl', '')
            
            # Try to construct coordinate from purl or name/version
            if purl:
                coordinates.append(purl)
            elif name and version:
                # Construct generic coordinate
                coordinate = f"pkg:generic/{name}@{version}"
                coordinates.append(coordinate)
        
        if not coordinates:
            return []
            
        try:
            # POST request with coordinates
            response = requests.post(
                f"{self.base_url}/component-report",
                headers=self.headers,
                json={"coordinates": coordinates},
                timeout=30
            )
            response.raise_for_status()
            
            results = response.json()
            return self._parse_results(results, components)
            
        except Exception as e:
            self.logger.error(f"Sonatype OSS Index scan error: {e}")
            return []
    
    def _parse_results(self, results: List[Dict], components: List[Dict]) -> List[Dict]:
        """Parse Sonatype OSS Index results"""
        vulnerabilities = []
        
        for i, result in enumerate(results):
            if i < len(components):
                component = components[i]
                
                # Check if component has vulnerabilities
                if result.get('vulnerabilities'):
                    for vuln in result['vulnerabilities']:
                        vulnerabilities.append({
                            'source': 'Sonatype OSS Index',
                            'id': vuln.get('id', 'Unknown'),
                            'cve': vuln.get('cve', ''),
                            'title': vuln.get('title', 'No title'),
                            'description': vuln.get('description', 'No description'),
                            'cvss_score': str(vuln.get('cvssScore', 'N/A')),
                            'cvss_vector': vuln.get('cvssVector', ''),
                            'severity': self._get_severity_from_score(vuln.get('cvssScore')),
                            'reference': vuln.get('reference', ''),
                            'component': component,
                            'url': f"https://ossindex.sonatype.org/vuln/{vuln.get('id', '')}"
                        })
        
        return vulnerabilities
    
    def _get_severity_from_score(self, score) -> str:
        """Convert CVSS score to severity level"""
        if score is None:
            return 'Unknown'
        
        try:
            score = float(score)
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

def main():
    """Test the Sonatype OSS Index scanner"""
    scanner = SonatypeOSSScanner()
    
    # Test with sample components
    test_components = [
        {
            'name': 'mbedtls',
            'version': '2.28.1',
            'purl': 'pkg:generic/mbedtls@2.28.1'
        }
    ]
    
    print("🔍 Testing Sonatype OSS Index Scanner...")
    vulnerabilities = scanner.scan_components(test_components)
    
    print(f"Found {len(vulnerabilities)} vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"  • {vuln['id']} - {vuln['severity']} - {vuln['title']}")

if __name__ == "__main__":
    main()
