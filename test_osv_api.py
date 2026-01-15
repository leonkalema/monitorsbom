#!/usr/bin/env python3
"""
Test OSV API direct queries
"""

import requests
import json

def test_osv_api():
    """Test OSV API with the example from the user"""
    
    # Test 1: User's example (jinja2)
    print("🧪 Testing OSV API with jinja2 example...")
    
    query_data = {
        "version": "2.4.1",
        "package": {
            "name": "jinja2", 
            "ecosystem": "PyPI"
        }
    }
    
    try:
        response = requests.post(
            "https://api.osv.dev/v1/query",
            headers={'Content-Type': 'application/json'},
            json=query_data,
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        print(f"✅ Found {len(data.get('vulns', []))} vulnerabilities for jinja2 2.4.1")
        
        for vuln in data.get('vulns', [])[:3]:  # Show first 3
            print(f"  • {vuln.get('id', 'Unknown')} - {vuln.get('summary', 'No summary')[:60]}...")
            
    except Exception as e:
        print(f"❌ Error testing jinja2: {e}")
    
    # Test 2: Our mbedtls component
    print("\n🧪 Testing OSV API with mbedtls...")
    
    query_data = {
        "version": "2.28.1",
        "package": {
            "name": "mbedtls",
            "ecosystem": "OSS-Fuzz"  # Generic ecosystem for C libraries
        }
    }
    
    try:
        response = requests.post(
            "https://api.osv.dev/v1/query",
            headers={'Content-Type': 'application/json'},
            json=query_data,
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        print(f"✅ Found {len(data.get('vulns', []))} vulnerabilities for mbedtls 2.28.1")
        
        for vuln in data.get('vulns', [])[:3]:  # Show first 3
            print(f"  • {vuln.get('id', 'Unknown')} - {vuln.get('summary', 'No summary')[:60]}...")
            
    except Exception as e:
        print(f"❌ Error testing mbedtls: {e}")

if __name__ == "__main__":
    test_osv_api()
