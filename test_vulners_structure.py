#!/usr/bin/env python3
"""
Analyze Vulners API data structure
"""

import requests
import json
from config import API_CONFIG

def analyze_vulners_structure():
    """Analyze the exact structure of Vulners API responses"""
    
    api_key = API_CONFIG.get('vulners_api_key', '')
    base_url = "https://vulners.com/api/v3"
    
    headers = {
        'User-Agent': 'SBOM-Scanner/2.0 (Security Research)',
        'Content-Type': 'application/json',
        'X-API-Key': api_key
    }
    
    print("🔍 Analyzing Vulners API Response Structure...")
    
    # Test with mbedtls search
    try:
        params = {
            'query': 'mbedtls',
            'type': 'cve',  # Focus on CVEs
            'size': 3
        }
        
        response = requests.get(
            f"{base_url}/search/lucene/",
            headers=headers,
            params=params,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API Response Status: {response.status_code}")
            print(f"📊 Response Structure:")
            print(f"  - result: {data.get('result')}")
            print(f"  - data keys: {list(data.get('data', {}).keys())}")
            
            search_results = data.get('data', {}).get('search', [])
            print(f"  - search results count: {len(search_results)}")
            
            if search_results:
                print(f"\n📋 First Result Structure:")
                first_result = search_results[0]
                print(json.dumps(first_result, indent=2)[:1000] + "...")
                
                print(f"\n🔑 Available Keys in First Result:")
                for key in sorted(first_result.keys()):
                    value = first_result[key]
                    if isinstance(value, str):
                        print(f"  - {key}: '{value[:50]}{'...' if len(str(value)) > 50 else ''}'")
                    else:
                        print(f"  - {key}: {type(value).__name__} ({len(value) if hasattr(value, '__len__') else 'N/A'})")
        else:
            print(f"❌ API Error: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # Test direct vulnerability lookup
    print(f"\n🎯 Testing Direct Vulnerability Lookup (GLSA-202301-08)...")
    try:
        response = requests.get(
            f"{base_url}/search/id/",
            headers=headers,
            params={'id': 'GLSA-202301-08'},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Direct lookup successful")
            
            documents = data.get('data', {}).get('documents', {})
            if 'GLSA-202301-08' in documents:
                vuln_data = documents['GLSA-202301-08']
                print(f"📋 Vulnerability Data Keys:")
                for key in sorted(vuln_data.keys()):
                    value = vuln_data[key]
                    if isinstance(value, str):
                        print(f"  - {key}: '{value[:50]}{'...' if len(str(value)) > 50 else ''}'")
                    else:
                        print(f"  - {key}: {type(value).__name__}")
        else:
            print(f"❌ Direct lookup failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Exception: {e}")

if __name__ == "__main__":
    analyze_vulners_structure()
