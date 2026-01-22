#!/usr/bin/env python3
"""
Enhanced email sender with SMTP and fallback support
"""

import smtplib
import subprocess
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import Dict, List, Optional
from datetime import datetime
import logging
import json
import os

from config import EMAIL_CONFIG
from email_content_builder import EmailContentBuilder

try:
    from pdf_report_generator import PDFReportGenerator
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# Email service imports (optional)
try:
    from mailersend import MailerSendClient
    from mailersend.builders import EmailBuilder
    MAILERSEND_AVAILABLE = True
except ImportError:
    MAILERSEND_AVAILABLE = False

try:
    import resend
    RESEND_AVAILABLE = True
except ImportError:
    RESEND_AVAILABLE = False

class EmailSender:
    """Enhanced email sender with multiple delivery methods"""
    
    def __init__(self, config: Dict = None):
        self.config = config or EMAIL_CONFIG
        self.logger = logging.getLogger(__name__)
    
    def send_vulnerability_alert(self, results: Dict, custom_recipient: str = None) -> bool:
        """Send scan report email with multiple fallback methods (always sends)"""
        recipient = custom_recipient or self.config['to_email']

        if not recipient:
            self.logger.error("Email recipient is not configured (set TO_EMAIL)")
            return False
        
        # Try Resend API first if configured
        if self.config.get('service') == 'resend' and self._is_resend_configured():
            if self._send_via_resend(results, recipient):
                return True
            self.logger.warning("Resend failed, trying fallback methods...")
        
        # Try MailerSend API if configured
        elif self.config.get('service') == 'mailersend' and self._is_mailersend_configured():
            if self._send_via_mailersend(results, recipient):
                return True
            self.logger.warning("MailerSend failed, trying fallback methods...")
        
        # Try SMTP if configured
        elif self._is_smtp_configured():
            if self._send_via_smtp(results, recipient):
                return True
            self.logger.warning("SMTP failed, trying fallback methods...")
        
        # Fallback to system mail command
        if self.config.get('fallback_to_mail_command', True):
            return self._send_via_mail_command(results, recipient)
        
        self.logger.error("All email delivery methods failed")
        return False
    
    def _is_resend_configured(self) -> bool:
        """Check if Resend is properly configured"""
        return bool(
            RESEND_AVAILABLE and
            self.config.get('resend_api_key')
        )
    
    def _is_mailersend_configured(self) -> bool:
        """Check if MailerSend is properly configured"""
        return bool(
            MAILERSEND_AVAILABLE and
            self.config.get('mailersend_api_token')
        )
    
    def _is_smtp_configured(self) -> bool:
        """Check if SMTP is properly configured"""
        return bool(
            self.config.get('smtp_server') and 
            self.config.get('smtp_username') and 
            self.config.get('smtp_password')
        )
    
    def _send_via_smtp(self, results: Dict, recipient: str) -> bool:
        """Send email via SMTP"""
        try:
            # Parse recipients
            recipients = self._parse_recipients(recipient)
            if not recipients:
                self.logger.error("No valid recipients found")
                return False
            
            # Create message
            msg = MIMEMultipart('mixed')
            msg['From'] = self.config['from_email']
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = self._create_subject(results)
            
            # Create alternative part for text/html
            alt_part = MIMEMultipart('alternative')
            
            # Create email body
            builder = EmailContentBuilder(results)
            alt_part.attach(MIMEText(builder.create_text_body(), 'plain'))
            alt_part.attach(MIMEText(builder.create_html_body(), 'html'))
            
            msg.attach(alt_part)
            
            # Attach JSON report
            output_file = results.get('output_file', '/tmp/combined-vuln-scan.json')
            if os.path.exists(output_file):
                with open(output_file, 'rb') as f:
                    json_attachment = MIMEApplication(f.read(), _subtype='json')
                    json_attachment.add_header(
                        'Content-Disposition', 'attachment',
                        filename='vulnerability-report.json'
                    )
                    msg.attach(json_attachment)
            
            # Attach PDF report
            pdf_bytes = self._generate_pdf_report(results)
            if pdf_bytes:
                pdf_attachment = MIMEApplication(pdf_bytes, _subtype='pdf')
                pdf_attachment.add_header(
                    'Content-Disposition', 'attachment',
                    filename='vulnerability-triage-worksheet.pdf'
                )
                msg.attach(pdf_attachment)
            
            # Send via SMTP
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                if self.config.get('use_tls', True):
                    server.starttls()
                
                server.login(self.config['smtp_username'], self.config['smtp_password'])
                server.send_message(msg)
            
            self.logger.info(f"📧 SMTP email sent successfully to {recipients}")
            return True
            
        except Exception as e:
            self.logger.error(f"SMTP email failed: {e}")
            return False
    
    def _parse_recipients(self, recipient: str) -> List[str]:
        """Parse recipient string into list of valid email addresses"""
        if not recipient:
            return []
        
        # Split by comma and clean up
        recipients = [r.strip() for r in recipient.split(',')]
        # Filter out empty strings
        return [r for r in recipients if r and '@' in r]

    def _generate_pdf_report(self, results: Dict) -> bytes:
        """Generate PDF report with triage checklists"""
        if not PDF_AVAILABLE:
            self.logger.warning("PDF generation not available (reportlab not installed)")
            return None
        
        try:
            generator = PDFReportGenerator(results)
            if generator.is_available():
                pdf_bytes = generator.generate_pdf()
                self.logger.info(f"📄 PDF report generated ({len(pdf_bytes)} bytes)")
                return pdf_bytes
        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
        
        return None

    def _send_via_resend(self, results: Dict, recipient: str) -> bool:
        """Send email via Resend API"""
        try:
            if not RESEND_AVAILABLE:
                self.logger.error("Resend SDK not available")
                return False
            
            # Set API key
            resend.api_key = self.config['resend_api_key']
            
            # Parse recipients properly
            recipients = self._parse_recipients(recipient)
            if not recipients:
                self.logger.error("No valid recipients found")
                return False
            
            # Create email parameters
            builder = EmailContentBuilder(results)
            subject = builder.create_subject()
            html_content = builder.create_html_body()
            
            params = {
                "from": f"SBOM Security Scanner <{self.config['from_email']}>",
                "to": recipients,  # Now a proper list of individual emails
                "subject": subject,
                "html": html_content
            }
            
            # Build attachments list
            attachments = []
            
            # Attach JSON report if available
            output_file = results.get('output_file', '/tmp/combined-vuln-scan.json')
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    json_content = f.read()
                
                attachments.append({
                    "filename": "vulnerability-report.json",
                    "content": base64.b64encode(json_content.encode()).decode()
                })
            
            # Attach PDF report with triage checklists
            pdf_bytes = self._generate_pdf_report(results)
            if pdf_bytes:
                attachments.append({
                    "filename": "vulnerability-triage-worksheet.pdf",
                    "content": base64.b64encode(pdf_bytes).decode()
                })
            
            if attachments:
                params["attachments"] = attachments
            
            # Send email
            response = resend.Emails.send(params)
            
            if response and response.get('id'):
                self.logger.info(f"📧 Resend email sent successfully to {recipients} (ID: {response['id']})")
                return True
            else:
                self.logger.error("Resend API returned empty response")
                return False
                
        except Exception as e:
            self.logger.error(f"Resend email failed: {e}")
            return False
    
    def _send_via_mailersend(self, results: Dict, recipient: str) -> bool:
        """Send email via MailerSend API"""
        try:
            if not MAILERSEND_AVAILABLE:
                self.logger.error("MailerSend SDK not available")
                return False
            
            # Initialize MailerSend client
            client = MailerSendClient(api_key=self.config['mailersend_api_token'])
            self.logger.info("MailerSend client initialized successfully")
            
            # Create email using the builder pattern
            email_builder = EmailBuilder()
            
            # Set sender
            email_builder.from_email(
                name="SBOM Security Scanner",
                email=self.config['from_email']
            )
            
            # Set recipient
            email_builder.to(
                name="Security Team",
                email=recipient
            )
            
            # Set content
            builder = EmailContentBuilder(results)
            subject = builder.create_subject()
            text_content = builder.create_text_body()
            html_content = builder.create_html_body()
            
            email_builder.subject(subject)
            email_builder.text(text_content)
            email_builder.html(html_content)
            
            # Build and send email
            email = email_builder.build()
            response = client.emails.send(email)
            
            if response:
                self.logger.info(f"📧 MailerSend email sent successfully to {recipient}")
                return True
            else:
                self.logger.error("MailerSend API returned empty response")
                return False
                
        except Exception as e:
            self.logger.error(f"MailerSend email failed: {e}")
            return False
    
    def _send_via_mail_command(self, results: Dict, recipient: str) -> bool:
        """Send email via system mail command (fallback)"""
        try:
            builder = EmailContentBuilder(results)
            subject = builder.create_subject()
            body = builder.create_text_body()
            
            process = subprocess.run(
                ['mail', '-s', subject, recipient],
                input=body,
                text=True,
                capture_output=True,
                timeout=30
            )
            
            if process.returncode == 0:
                self.logger.info(f"📧 Mail command email sent successfully to {recipient}")
                return True
            else:
                self.logger.error(f"Mail command failed: {process.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Mail command timed out")
            return False
        except FileNotFoundError:
            self.logger.error("Mail command not found - install mailutils or configure postfix")
            return False
        except Exception as e:
            self.logger.error(f"Mail command error: {e}")
            return False
    
    def _create_subject(self, results: Dict) -> str:
        """Create email subject line"""
        builder = EmailContentBuilder(results)
        return builder.create_subject()
    
    def _create_email_body(self, results: Dict) -> str:
        """Create detailed email body"""
        builder = EmailContentBuilder(results)
        return builder.create_text_body()
    
    def _create_html_email_body(self, results: Dict) -> str:
        """Create HTML email body for better formatting"""
        builder = EmailContentBuilder(results)
        return builder.create_html_body()
    
    def _count_critical_high_vulns(self, results: Dict) -> int:
        """Count critical and high severity vulnerabilities"""
        return len([v for v in results.get('vulnerabilities', []) 
                   if v.get('severity') in ['CRITICAL', 'HIGH']])
    
    def _get_critical_high_vulns(self, results: Dict) -> List[Dict]:
        """Get critical and high severity vulnerabilities"""
        return [v for v in results.get('vulnerabilities', []) 
                if v.get('severity') in ['CRITICAL', 'HIGH']]
    
    def _get_severity_breakdown(self, results: Dict) -> Dict[str, int]:
        """Get count of vulnerabilities by severity"""
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'Unknown': 0}
        
        for vuln in results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'Unknown')
            if severity in breakdown:
                breakdown[severity] += 1
            else:
                breakdown['Unknown'] += 1
        
        return breakdown
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emoji_map = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'Unknown': '⚪'
        }
        return emoji_map.get(severity, '⚪')
    
    def _get_component_info(self, vuln: Dict) -> str:
        """Extract component information from vulnerability"""
        if 'component' in vuln:
            comp = vuln['component']
            name = comp.get('name', 'unknown')
            version = comp.get('version', '')
            return f"{name} {version}".strip()
        return "Unknown component"
    
    def _get_vulnerabilities_2025(self, results: Dict) -> List[Dict]:
        """Get all vulnerabilities from 2025"""
        vulns_2025 = []
        
        for vuln in results.get('vulnerabilities', []):
            # Check published date
            published_date = vuln.get('published_date', '')
            if published_date and '2025' in published_date:
                vulns_2025.append(vuln)
                continue
            
            # Check CVE ID for 2025
            cve_id = vuln.get('id', '') or vuln.get('cve_id', '')
            if 'CVE-2025-' in cve_id:
                vulns_2025.append(vuln)
        
        # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
        vulns_2025.sort(key=lambda x: severity_order.get(x.get('severity', 'UNKNOWN'), 4))
        
        return vulns_2025

def test_email_config():
    """Test email configuration"""
    sender = EmailSender()
    
    print("🧪 Testing email configuration...")
    
    # Test Resend config
    if sender.config.get('service') == 'resend':
        if sender._is_resend_configured():
            print("✅ Resend configuration found")
            print(f"   API Key: {sender.config['resend_api_key'][:20]}...")
            print(f"   SDK Available: {RESEND_AVAILABLE}")
        else:
            print("❌ Resend not properly configured")
            if not RESEND_AVAILABLE:
                print("   Install with: pip install resend")
    
    # Test MailerSend config
    elif sender.config.get('service') == 'mailersend':
        if sender._is_mailersend_configured():
            print("✅ MailerSend configuration found")
            print(f"   API Token: {sender.config['mailersend_api_token'][:20]}...")
            print(f"   SDK Available: {MAILERSEND_AVAILABLE}")
        else:
            print("❌ MailerSend not properly configured")
            if not MAILERSEND_AVAILABLE:
                print("   Install with: pip install mailersend")
    
    # Test SMTP config
    elif sender._is_smtp_configured():
        print("✅ SMTP configuration found")
        print(f"   Server: {sender.config['smtp_server']}:{sender.config['smtp_port']}")
        print(f"   Username: {sender.config['smtp_username']}")
        print(f"   TLS: {sender.config['use_tls']}")
    else:
        print("⚠️  SMTP not configured - will use mail command fallback")
    
    # Test mail command
    try:
        result = subprocess.run(['which', 'mail'], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ System mail command available")
        else:
            print("❌ System mail command not found")
    except Exception as e:
        print(f"❌ Error checking mail command: {e}")
    
    print(f"📧 Target email: {sender.config['to_email']}")
    print(f"📧 From email: {sender.config['from_email']}")
    print(f"🔧 Email service: {sender.config.get('service', 'smtp')}")

if __name__ == "__main__":
    test_email_config()
