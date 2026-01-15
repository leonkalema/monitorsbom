#!/usr/bin/env python3
"""
Debug Vulners API vs Dashboard discrepancy
"""

import requests
import json
from config import API_CONFIG

def test_vulners_api_methods():
    """Test different Vulners API endpoints and methods"""
    
    api_key = API_CONFIG.get('vulners_api_key', '')
    base_url = "https://vulners.com/api/v3"
    
    headers = {
        'User-Agent': 'SBOM-Scanner/2.0 (Security Research)',
        'Content-Type': 'application/json'
    }
    
    if api_key:
        headers['X-API-Key'] = api_key
        print("✅ Using Vulners API key")
    else:
        print("❌ No Vulners API key found")
        return
    
    # Test 1: Search lucene (current method)
    print("\n🧪 Test 1: Search Lucene API")
    try:
        params = {
            'query': 'mbedtls',
            'type': 'software',
            'size': 10
        }
        
        response = requests.get(
            f"{base_url}/search/lucene/",
            headers=headers,
            params=params,
            timeout=30
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Results: {len(data.get('data', {}).get('search', []))}")
            for item in data.get('data', {}).get('search', [])[:3]:
                print(f"  • {item.get('id', 'Unknown')} - {item.get('title', 'No title')[:60]}...")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 2: Search id (direct vulnerability lookup)
    print("\n🧪 Test 2: Direct Vulnerability Lookup")
    try:
        # Test with the specific vulnerability you mentioned
        vuln_id = "GLSA-202301-08"
        
        response = requests.get(
            f"{base_url}/search/id/",
            headers=headers,
            params={'id': vuln_id},
            timeout=30
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Found vulnerability: {data.get('data', {}).get('documents', {}).get(vuln_id, {}).get('title', 'Not found')}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Error: {e}")
    
    # Test 3: Different search types
    print("\n🧪 Test 3: Different Search Types")
    search_types = ['cve', 'exploit', 'bugbounty', 'tools']
    
    for search_type in search_types:
        try:
            params = {
                'query': 'mbedtls',
                'type': search_type,
                'size': 5
            }
            
            response = requests.get(
                f"{base_url}/search/lucene/",
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('data', {}).get('search', [])
                print(f"  {search_type}: {len(results)} results")
                if results:
                    print(f"    • {results[0].get('id', 'Unknown')} - {results[0].get('title', 'No title')[:40]}...")
            else:
                print(f"  {search_type}: Error {response.status_code}")
                
        except Exception as e:
            print(f"  {search_type}: Error - {e}")
    
    # Test 4: Software search with version
    print("\n🧪 Test 4: Software Search with Version")
    try:
        params = {
            'query': 'mbedtls 2.28.1',
            'type': 'software',
            'size': 10
        }
        
        response = requests.get(
            f"{base_url}/search/lucene/",
            headers=headers,
            params=params,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            results = data.get('data', {}).get('search', [])
            print(f"Results for 'mbedtls 2.28.1': {len(results)}")
            for item in results[:3]:
                print(f"  • {item.get('id', 'Unknown')} - {item.get('title', 'No title')[:60]}...")
        else:
            print(f"Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_vulners_api_methods()
