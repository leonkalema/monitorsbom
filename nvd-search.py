#!/usr/bin/env python3
"""
NVD (National Vulnerability Database) Search Tool
Searches for vulnerabilities using NIST's NVD API
"""

import requests
import json
import sys
from datetime import datetime
from typing import Dict, List, Optional

class NVDSearcher:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {
            'User-Agent': 'SBOM-Scanner/1.0 (Security Research)'
        }
    
    def search_by_keyword(self, keyword: str, results_per_page: int = 10) -> Dict:
        """Search NVD by keyword"""
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': results_per_page
        }
        
        try:
            response = requests.get(self.base_url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error searching NVD: {e}")
            return {}
    
    def search_by_cpe(self, cpe_name: str, results_per_page: int = 10) -> Dict:
        """Search NVD by CPE (Common Platform Enumeration)"""
        params = {
            'cpeName': cpe_name,
            'resultsPerPage': results_per_page
        }
        
        try:
            response = requests.get(self.base_url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error searching NVD: {e}")
            return {}
    
    def format_vulnerability(self, vuln: Dict) -> str:
        """Format vulnerability data for display"""
        cve_id = vuln.get('id', 'Unknown')
        published = vuln.get('published', 'Unknown')
        modified = vuln.get('lastModified', 'Unknown')
        
        # Get CVSS score
        cvss_score = "N/A"
        severity = "Unknown"
        
        metrics = vuln.get('metrics', {})
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 'N/A')
            severity = cvss_data.get('baseSeverity', 'Unknown')
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore', 'N/A')
            severity = cvss_data.get('baseSeverity', 'Unknown')
        
        # Get description
        descriptions = vuln.get('descriptions', [])
        description = "No description available"
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', 'No description available')
                break
        
        return f"""
🚨 {cve_id}
   Severity: {severity} (CVSS: {cvss_score})
   Published: {published}
   Modified: {modified}
   Description: {description[:200]}{'...' if len(description) > 200 else ''}
   URL: https://nvd.nist.gov/vuln/detail/{cve_id}
"""

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 nvd-search.py <search_term> [max_results]")
        print("Examples:")
        print("  python3 nvd-search.py mbedtls")
        print("  python3 nvd-search.py 'apache httpd' 5")
        sys.exit(1)
    
    search_term = sys.argv[1]
    max_results = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    searcher = NVDSearcher()
    
    print(f"🔍 Searching NVD for: '{search_term}'")
    print(f"📊 Max results: {max_results}")
    print("=" * 60)
    
    # Search by keyword
    results = searcher.search_by_keyword(search_term, max_results)
    
    if not results or 'vulnerabilities' not in results:
        print("❌ No vulnerabilities found or API error")
        return
    
    vulnerabilities = results['vulnerabilities']
    total_results = results.get('totalResults', 0)
    
    print(f"📈 Found {total_results} total vulnerabilities (showing {len(vulnerabilities)})")
    print("=" * 60)
    
    for vuln_data in vulnerabilities:
        vuln = vuln_data.get('cve', {})
        print(searcher.format_vulnerability(vuln))
    
    if total_results > len(vulnerabilities):
        print(f"\n💡 Showing {len(vulnerabilities)} of {total_results} results")
        print("   Use a larger max_results parameter to see more")

if __name__ == "__main__":
    main()
