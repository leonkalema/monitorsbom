#!/usr/bin/env python3
"""
Test email content formatting
"""

import json
from email_sender import EmailSender
from config import EMAIL_CONFIG

def test_email_formatting():
    """Test the email formatting with sample data"""
    
    # Load the actual scan results
    try:
        with open('/tmp/combined-vuln-scan.json', 'r') as f:
            results = json.load(f)
    except FileNotFoundError:
        print("❌ No scan results found. Run the scanner first.")
        return
    
    email_sender = EmailSender(EMAIL_CONFIG)
    
    # Generate HTML content
    html_content = email_sender._create_html_email_body(results)
    
    # Save to file for inspection
    with open('/tmp/email_preview.html', 'w') as f:
        f.write(html_content)
    
    print("✅ Email HTML content saved to /tmp/email_preview.html")
    print("📧 You can open this file in a browser to see how the email looks")
    
    # Show a snippet of the links
    print("\n🔗 Link examples from the email:")
    for vuln in results.get('vulnerabilities', [])[:3]:
        print(f"  • {vuln['id']}: {vuln.get('url', 'No URL')}")

if __name__ == "__main__":
    test_email_formatting()
