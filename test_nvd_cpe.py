#!/usr/bin/env python3
"""
Test NVD CPE version matching
"""

import requests
import json
from config import API_CONFIG

def test_nvd_cpe_matching():
    """Test NVD API with CPE version matching"""
    
    print("🧪 Testing NVD API with mbedtls 2.28.1...")
    
    headers = {
        'User-Agent': API_CONFIG['user_agent']
    }
    
    # Add API key if available
    if API_CONFIG['nvd_api_key']:
        headers['apiKey'] = API_CONFIG['nvd_api_key']
        print("✅ Using NVD API key")
    
    params = {
        'keywordSearch': 'mbedtls 2.28.1',
        'resultsPerPage': 5
    }
    
    try:
        response = requests.get(
            API_CONFIG['nvd_base_url'],
            headers=headers,
            params=params,
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        print(f"✅ Found {len(data.get('vulnerabilities', []))} vulnerabilities")
        
        for vuln_data in data.get('vulnerabilities', []):
            vuln = vuln_data.get('cve', {})
            cve_id = vuln.get('id', 'Unknown')
            print(f"\n🔍 Analyzing {cve_id}...")
            
            # Check configurations
            configurations = vuln_data.get('configurations', [])
            print(f"  Configurations found: {len(configurations)}")
            
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    print(f"  CPE matches: {len(cpe_matches)}")
                    
                    for cpe_match in cpe_matches[:2]:  # Show first 2
                        cpe_name = cpe_match.get('criteria', '')
                        vulnerable = cpe_match.get('vulnerable', False)
                        version_start = cpe_match.get('versionStartIncluding')
                        version_end = cpe_match.get('versionEndExcluding')
                        
                        print(f"    CPE: {cpe_name}")
                        print(f"    Vulnerable: {vulnerable}")
                        if version_start:
                            print(f"    Version >= {version_start}")
                        if version_end:
                            print(f"    Version < {version_end}")
                        
                        # Check if mbedtls 2.28.1 would match
                        if 'mbedtls' in cpe_name.lower() and vulnerable:
                            print(f"    ✅ Would match mbedtls component")
                        
            break  # Only analyze first vulnerability
            
    except Exception as e:
        print(f"❌ Error testing NVD: {e}")

if __name__ == "__main__":
    test_nvd_cpe_matching()
