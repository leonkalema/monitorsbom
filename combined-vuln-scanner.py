#!/usr/bin/env python3
"""
Enhanced Combined SBOM Vulnerability Scanner
Scans SBOM files against 9 vulnerability databases:
- NVD (NIST National Vulnerability Database) - Enhanced with CPE version matching
- OSV (Google Open Source Vulnerabilities)
- GitHub Security Advisory Database
- CISA KEV (Known Exploited Vulnerabilities) Catalog
- CISA ICS-CERT (Industrial Control Systems advisories)
- CVE.org Official Database
- CERT/CC Vulnerability Database
- Sonatype OSS Index - Free package vulnerability database
- Vulners.com - Comprehensive vulnerability database (10k requests/month)
"""

import json
import os
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Import new scanners
from github_advisory_scanner import GitHubAdvisoryScanner
from cisa_kev_scanner import CISAKEVScanner
from cve_org_scanner import CVEOrgScanner
from cert_cc_scanner import CERTCCScanner
from sonatype_oss_scanner import SonatypeOSSScanner
from vulners_scanner import VulnersScanner
from cisa_ics_scanner import CISAICSScanner
from email_sender import EmailSender
from config import SCANNER_CONFIG, EMAIL_CONFIG, API_CONFIG, SOURCE_CONFIG
from version_utils import (
    VersionRange, compare_versions, version_in_range,
    component_name_matches, extract_cpe_parts, calculate_match_confidence,
    MatchConfidence, VulnerabilityDeduplicator, parse_github_range, parse_osv_range
)

# Import additional modules
import requests
import subprocess
from typing import Tuple

def get_config():
    """Get configuration from environment and config files"""
    return {
        'scanner': SCANNER_CONFIG,
        'email': EMAIL_CONFIG,
        'sources': SOURCE_CONFIG,
        'api': API_CONFIG
    }

class SBOMParser:
    """Parse CycloneDX SBOM files"""
    
    def __init__(self, sbom_dir: str = "sbom"):
        self.sbom_dir = Path(sbom_dir)
    
    def get_components(self) -> List[Dict]:
        """Extract all components from SBOM files"""
        components = []
        
        for sbom_file in self.sbom_dir.glob("*.cdx.json"):
            try:
                with open(sbom_file, 'r') as f:
                    sbom_data = json.load(f)
                
                file_components = sbom_data.get('components', [])
                for component in file_components:
                    component['source_file'] = str(sbom_file)
                    components.append(component)
                
                print(f"📄 Loaded {len(file_components)} components from {sbom_file.name}")
                
            except Exception as e:
                print(f"❌ Error parsing {sbom_file}: {e}")
        
        return components

class NVDScanner:
    """NVD vulnerability scanner"""
    
    def __init__(self):
        config = get_config()
        self.base_url = config['api']['nvd_base_url']
        self.headers = {'User-Agent': config['api']['user_agent']}
        self.timeout = config['api']['request_timeout']
        
        # Add API key to headers if available (improves rate limits)
        if config['api']['nvd_api_key']:
            self.headers['apiKey'] = config['api']['nvd_api_key']
            print("✅ Using NVD API key for enhanced rate limits")
    
    def search_component(self, name: str, version: str = None) -> List[Dict]:
        """Search NVD for component vulnerabilities"""
        # Try multiple search terms to catch all CVEs
        search_terms = [name]
        
        # Add alternate forms for hyphenated names like "shibboleth-sp"
        if '-' in name:
            base_name = name.split('-')[0]
            search_terms.append(base_name)
        
        all_vulns = {}
        for search_term in search_terms:
            params = {
                'keywordSearch': search_term,
                'resultsPerPage': 100
            }
            
            try:
                response = requests.get(self.base_url, headers=self.headers, params=params, timeout=self.timeout)
                response.raise_for_status()
                data = response.json()
                
                for vuln_data in data.get('vulnerabilities', []):
                    cve_id = vuln_data.get('cve', {}).get('id', '')
                    if cve_id not in all_vulns:
                        all_vulns[cve_id] = vuln_data
            except Exception:
                continue
        
        # Now filter the combined results
        vulnerabilities = []
        for cve_id, vuln_data in all_vulns.items():
            vuln = vuln_data.get('cve', {})
            
            is_affected, confidence = self._is_component_affected(vuln_data, name, version)
            affected_versions = self._get_affected_versions(vuln_data)
            
            if is_affected and confidence == "high":
                vulnerabilities.append({
                    'source': 'NVD',
                    'id': vuln.get('id', 'Unknown'),
                    'severity': self._get_severity(vuln),
                    'cvss_score': self._get_cvss_score(vuln),
                    'description': self._get_description(vuln),
                    'published': vuln.get('published', 'Unknown'),
                    'url': f"https://nvd.nist.gov/vuln/detail/{vuln.get('id', '')}",
                    'affected_versions': affected_versions,
                    'version_match': f"Component {name} {version} - {affected_versions}",
                    'confidence': confidence
                })
        
        return vulnerabilities
    
    def _get_severity(self, vuln: Dict) -> str:
        """Extract severity from vulnerability data"""
        metrics = vuln.get('metrics', {})
        for metric_type in ['cvssMetricV31', 'cvssMetricV30']:
            if metric_type in metrics and metrics[metric_type]:
                return metrics[metric_type][0]['cvssData'].get('baseSeverity', 'Unknown')
        return 'Unknown'
    
    def _get_cvss_score(self, vuln: Dict) -> str:
        """Extract CVSS score from vulnerability data"""
        metrics = vuln.get('metrics', {})
        for metric_type in ['cvssMetricV31', 'cvssMetricV30']:
            if metric_type in metrics and metrics[metric_type]:
                return str(metrics[metric_type][0]['cvssData'].get('baseScore', 'N/A'))
        return 'N/A'
    
    def _get_description(self, vuln: Dict) -> str:
        """Extract description from vulnerability data"""
        descriptions = vuln.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', 'No description available')
        return 'No description available'
    
    def _is_component_affected(self, vuln_data: Dict, component_name: str, component_version: str) -> Tuple[bool, str]:
        """Check if the component version is affected by this vulnerability"""
        if not component_version:
            return False, "no_version"
            
        configurations = vuln_data.get('configurations', [])
        
        # If no CPE data, try to parse description for version info
        if not configurations:
            return self._check_description_for_version(vuln_data, component_name, component_version)
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe_match in cpe_matches:
                    is_match, confidence = self._cpe_matches_component(cpe_match, component_name, component_version)
                    if is_match:
                        return True, confidence
        return False, "not_affected"
    
    def _cpe_matches_component(self, cpe_match: Dict, component_name: str, component_version: str) -> Tuple[bool, str]:
        """Check if CPE match affects our specific component version"""
        cpe_string = cpe_match.get('criteria', '')
        cpe_parts = extract_cpe_parts(cpe_string)
        
        # Strict name matching using utility function
        if not component_name_matches(component_name, cpe_parts.get('product', '')):
            return False, "name_mismatch"
            
        # Check version constraints
        if not cpe_match.get('vulnerable', False):
            return False, "not_vulnerable"
        
        version_range = VersionRange(
            start_including=cpe_match.get('versionStartIncluding'),
            start_excluding=cpe_match.get('versionStartExcluding'),
            end_including=cpe_match.get('versionEndIncluding'),
            end_excluding=cpe_match.get('versionEndExcluding')
        )
        
        # If no version constraints, check CPE version field
        if not any([version_range.start_including, version_range.start_excluding,
                    version_range.end_including, version_range.end_excluding]):
            cpe_version = cpe_parts.get('version', '')
            if cpe_version and cpe_version != '*':
                if compare_versions(component_version, cpe_version) == 0:
                    return True, "high"
                return False, "version_mismatch"
            # No version info in CPE - can't determine
            return False, "no_version_constraint"
        
        # Check if version is in affected range
        if version_in_range(component_version, version_range):
            return True, "high"
        
        return False, "outside_range"
    
    def _get_affected_versions(self, vuln_data: Dict) -> str:
        """Extract human-readable affected version ranges"""
        ranges = []
        configurations = vuln_data.get('configurations', [])
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe_match in cpe_matches:
                    if cpe_match.get('vulnerable', False):
                        range_str = self._format_version_range(cpe_match)
                        if range_str:
                            ranges.append(range_str)
        
        return '; '.join(ranges) if ranges else 'All versions'
    
    def _format_version_range(self, cpe_match: Dict) -> str:
        """Format version range for display"""
        parts = []
        
        if cpe_match.get('versionStartIncluding'):
            parts.append(f">= {cpe_match['versionStartIncluding']}")
        if cpe_match.get('versionStartExcluding'):
            parts.append(f"> {cpe_match['versionStartExcluding']}")
        if cpe_match.get('versionEndIncluding'):
            parts.append(f"<= {cpe_match['versionEndIncluding']}")
        if cpe_match.get('versionEndExcluding'):
            parts.append(f"< {cpe_match['versionEndExcluding']}")
            
        return ' and '.join(parts) if parts else ''
    
    def _check_description_for_version(self, vuln_data: Dict, component_name: str, component_version: str) -> Tuple[bool, str]:
        """Parse CVE description for version info when no CPE data exists"""
        import re
        
        vuln = vuln_data.get('cve', {})
        description = self._get_description(vuln).lower()
        
        # Normalize component name for matching
        name_lower = component_name.lower()
        name_variants = [
            name_lower,
            name_lower.replace('-', ' '),
            name_lower.replace('-', ''),
            name_lower.replace('_', ' '),
        ]
        
        # Handle special cases like "shibboleth-sp" -> "shibboleth service provider"
        if 'sp' in name_lower:
            name_variants.append(name_lower.replace('-sp', ' service provider'))
            name_variants.append(name_lower.replace('sp', 'service provider'))
        if 'idp' in name_lower:
            name_variants.append(name_lower.replace('-idp', ' identity provider'))
            name_variants.append(name_lower.replace('idp', 'identity provider'))
        
        # Check if component name is mentioned
        name_found = any(variant in description for variant in name_variants)
        if not name_found:
            return False, "name_not_in_description"
        
        # Parse version patterns from description
        # "through X.Y.Z", "before X.Y.Z", "prior to X.Y.Z", "up to X.Y.Z"
        through_pattern = r'(?:through|before|prior to|up to|<=?)\s*(\d+\.\d+(?:\.\d+)?)'
        through_matches = re.findall(through_pattern, description)
        
        for max_ver in through_matches:
            if compare_versions(component_version, max_ver) <= 0:
                return True, "high"
        
        # "affects X.Y.Z", "version X.Y.Z", "in X.Y.Z"
        exact_pattern = r'(?:affects?|version|in)\s*(\d+\.\d+(?:\.\d+)?)'
        exact_matches = re.findall(exact_pattern, description)
        
        for exact_ver in exact_matches:
            if compare_versions(component_version, exact_ver) == 0:
                return True, "high"
        
        # "from X.Y.Z to A.B.C" or "X.Y.Z - A.B.C"
        range_pattern = r'(\d+\.\d+(?:\.\d+)?)\s*(?:to|-)\s*(\d+\.\d+(?:\.\d+)?)'
        range_matches = re.findall(range_pattern, description)
        
        for min_ver, max_ver in range_matches:
            if (compare_versions(component_version, min_ver) >= 0 and 
                compare_versions(component_version, max_ver) <= 0):
                return True, "high"
        
        return False, "version_not_in_range"

class OSVScanner:
    """Google OSV scanner with direct API and CLI wrapper"""
    
    def __init__(self):
        self.api_url = "https://api.osv.dev/v1/query"
        self.headers = {
            'User-Agent': 'SBOM-Scanner/2.0 (Security Research)',
            'Content-Type': 'application/json'
        }
    
    def query_component_api(self, name: str, version: str, ecosystem: str = None) -> List[Dict]:
        """Query OSV API directly for a specific component version"""
        if not version:
            return []
            
        # Map common ecosystems
        ecosystem_map = {
            'npm': 'npm',
            'pypi': 'PyPI', 
            'maven': 'Maven',
            'nuget': 'NuGet',
            'cargo': 'crates.io',
            'go': 'Go',
            'composer': 'Packagist'
        }
        
        # Try to detect ecosystem from component name or use generic
        if not ecosystem:
            if any(x in name.lower() for x in ['python', 'py']):
                ecosystem = 'PyPI'
            elif any(x in name.lower() for x in ['node', 'js']):
                ecosystem = 'npm'
            else:
                ecosystem = 'OSS-Fuzz'  # Generic ecosystem
        
        query_data = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": ecosystem
            }
        }
        
        try:
            response = requests.post(
                self.api_url,
                headers=self.headers,
                json=query_data,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = []
            
            for vuln in data.get('vulns', []):
                vulnerabilities.append({
                    'source': 'OSV API',
                    'id': vuln.get('id', 'Unknown'),
                    'summary': vuln.get('summary', 'No summary available'),
                    'severity': self._extract_severity(vuln),
                    'cvss_score': self._extract_cvss_score(vuln),
                    'description': vuln.get('details', vuln.get('summary', 'No description')),
                    'published': vuln.get('published', 'Unknown'),
                    'modified': vuln.get('modified', 'Unknown'),
                    'affected_versions': self._extract_affected_versions(vuln),
                    'url': f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
                    'component': {
                        'name': name,
                        'version': version,
                        'ecosystem': ecosystem
                    }
                })
            
            return vulnerabilities
            
        except Exception as e:
            print(f"❌ OSV API query error for {name}@{version}: {e}")
            return []
    
    def _extract_severity(self, vuln: Dict) -> str:
        """Extract severity from OSV vulnerability data"""
        severity = vuln.get('database_specific', {}).get('severity')
        if severity:
            return severity.upper()
        
        # Try to extract from CVSS if available
        cvss_score = self._extract_cvss_score(vuln)
        if cvss_score != 'N/A':
            try:
                score = float(cvss_score)
                if score >= 9.0:
                    return 'CRITICAL'
                elif score >= 7.0:
                    return 'HIGH'
                elif score >= 4.0:
                    return 'MEDIUM'
                elif score > 0.0:
                    return 'LOW'
            except ValueError:
                pass
        
        return 'Unknown'
    
    def _extract_cvss_score(self, vuln: Dict) -> str:
        """Extract CVSS score from OSV vulnerability data"""
        severity_info = vuln.get('severity', [])
        for sev in severity_info:
            if sev.get('type') == 'CVSS_V3':
                return str(sev.get('score', 'N/A'))
        return 'N/A'
    
    def _extract_affected_versions(self, vuln: Dict) -> str:
        """Extract affected version ranges from OSV data"""
        affected = vuln.get('affected', [])
        ranges = []
        
        for affect in affected:
            for range_info in affect.get('ranges', []):
                events = range_info.get('events', [])
                range_parts = []
                
                for event in events:
                    if 'introduced' in event:
                        range_parts.append(f">= {event['introduced']}")
                    elif 'fixed' in event:
                        range_parts.append(f"< {event['fixed']}")
                
                if range_parts:
                    ranges.append(' and '.join(range_parts))
        
        return '; '.join(ranges) if ranges else 'All versions'
    
    def scan_sbom_file(self, sbom_path: str) -> Tuple[List[Dict], str]:
        """Run OSV scanner on SBOM file"""
        try:
            result = subprocess.run(
                ['osv-scanner', '--sbom', sbom_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            vulnerabilities = []
            raw_output = result.stdout + result.stderr
            
            # Parse OSV output for vulnerabilities
            if "Vulnerability" in raw_output or "CVE-" in raw_output:
                # Simple parsing - in production you'd want more sophisticated parsing
                lines = raw_output.split('\n')
                current_vuln = {}
                
                for line in lines:
                    if 'CVE-' in line or 'GHSA-' in line:
                        if current_vuln:
                            vulnerabilities.append(current_vuln)
                        current_vuln = {
                            'source': 'OSV',
                            'id': line.strip(),
                            'severity': 'Unknown',
                            'cvss_score': 'N/A',
                            'description': 'OSV vulnerability detected',
                            'raw_line': line.strip()
                        }
                
                if current_vuln:
                    vulnerabilities.append(current_vuln)
            
            return vulnerabilities, raw_output
            
        except subprocess.TimeoutExpired:
            return [], "OSV scanner timeout"
        except FileNotFoundError:
            return [], "OSV scanner not found - install with: brew install osv-scanner"
        except Exception as e:
            return [], f"OSV scanner error: {e}"

class CombinedScanner:
    """Enhanced vulnerability scanner using 9 data sources"""
    
    def __init__(self, sbom_dir: str = None, config: Dict = None):
        self.config = config or get_config()
        sbom_dir = sbom_dir or self.config['scanner']['sbom_directory']
        
        self.sbom_parser = SBOMParser(sbom_dir)
        
        sources = self.config.get('sources', {})
        self.nvd_scanner = NVDScanner() if sources.get('enable_nvd', True) else None
        self.osv_scanner = OSVScanner()
        self.github_scanner = (
            GitHubAdvisoryScanner(self.config.get('api', {}).get('github_token') or None)
            if sources.get('enable_github', False)
            else None
        )
        self.cisa_kev_scanner = CISAKEVScanner() if sources.get('enable_cisa_kev', False) else None
        self.cisa_ics_scanner = CISAICSScanner() if sources.get('enable_cisa_ics', False) else None
        self.cve_org_scanner = CVEOrgScanner() if sources.get('enable_cve_org', False) else None
        self.cert_cc_scanner = CERTCCScanner() if sources.get('enable_cert_cc', False) else None
        self.sonatype_scanner = SonatypeOSSScanner() if sources.get('enable_sonatype', False) else None
        self.vulners_scanner = (
            VulnersScanner(self.config['api']['vulners_api_key'])
            if sources.get('enable_vulners', False)
            else None
        )
        
        self.email_sender = EmailSender(self.config['email'])
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def scan_all(self) -> Dict:
        """Perform comprehensive vulnerability scan with deduplication"""
        print("🔍 Combined Vulnerability Scan Starting...")
        print("=" * 60)
        
        # Parse SBOM files
        components = self.sbom_parser.get_components()
        if not components:
            print("❌ No components found in SBOM files")
            return {}
        
        # Initialize deduplicator to prevent duplicate CVEs across sources
        deduplicator = VulnerabilityDeduplicator()
        
        results = {
            'scan_time': datetime.now().isoformat(),
            'components_scanned': len(components),
            'scanned_components': components,
            'vulnerabilities': [],
            'duplicates_removed': 0,
            'summary': {
                'nvd': 0, 'osv': 0, 'github': 0, 
                'cisa_kev': 0, 'cisa_ics': 0, 'cve_org': 0, 'cert_cc': 0,
                'sonatype': 0, 'vulners': 0,
                'total': 0, 'unique': 0
            },
            'output_file': self.config['scanner']['output_file']
        }
        
        # Scan each component with NVD
        if self.nvd_scanner:
            print(f"\n🌐 Scanning {len(components)} components with NVD...")
            for component in components:
                name = component.get('name', 'unknown')
                version = component.get('version', '')
                
                print(f"  🔎 {name} {version}")
                nvd_vulns = self.nvd_scanner.search_component(name, version)
                
                for vuln in nvd_vulns:
                    vuln['component'] = component
                    if deduplicator.add_vulnerability(vuln):
                        results['summary']['nvd'] += 1
                    else:
                        results['duplicates_removed'] += 1
        
        # Scan components with OSV API (direct queries)
        if self.config.get('sources', {}).get('enable_osv_api', True):
            print(f"\n🔍 Scanning {len(components)} components with Google OSV API...")
            for component in components:
                name = component.get('name', 'unknown')
                version = component.get('version', '')
                
                print(f"  🔎 {name} {version}")
                osv_api_vulns = self.osv_scanner.query_component_api(name, version)
                
                for vuln in osv_api_vulns:
                    vuln['component'] = component
                    if deduplicator.add_vulnerability(vuln):
                        results['summary']['osv'] += 1
                    else:
                        results['duplicates_removed'] += 1
        
        # Also scan SBOM files with OSV CLI (fallback/additional coverage)
        if self.config.get('sources', {}).get('enable_osv_cli', False):
            print(f"\n📄 Scanning SBOM files with Google OSV CLI...")
            sbom_files = list(Path(self.sbom_parser.sbom_dir).glob("*.cdx.json"))
            
            for sbom_file in sbom_files:
                print(f"  📄 {sbom_file.name}")
                osv_vulns, raw_output = self.osv_scanner.scan_sbom_file(str(sbom_file))
                
                for vuln in osv_vulns:
                    vuln['sbom_file'] = str(sbom_file)
                    if deduplicator.add_vulnerability(vuln):
                        results['summary']['osv'] += 1
                    else:
                        results['duplicates_removed'] += 1
        
        # Scan components with GitHub Security Advisory
        if self.github_scanner:
            print(f"\n🐙 Scanning {len(components)} components with GitHub Security Advisory...")
            github_vulns = self.github_scanner.scan_components(components)
            for vuln in github_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results['summary']['github'] += 1
                else:
                    results['duplicates_removed'] += 1
        
        # Scan components with CISA KEV Catalog
        if self.cisa_kev_scanner:
            print(f"\n🏛️ Scanning {len(components)} components with CISA KEV...")
            cisa_vulns = self.cisa_kev_scanner.scan_components(components)
            for vuln in cisa_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results['summary']['cisa_kev'] += 1
                else:
                    results['duplicates_removed'] += 1
        
        # Scan components with CISA ICS-CERT (embedded/firmware focus)
        if self.cisa_ics_scanner:
            print(f"\n🔧 Scanning {len(components)} components with CISA ICS-CERT...")
            ics_vulns = self.cisa_ics_scanner.scan_components(components)
            for vuln in ics_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results['summary']['cisa_ics'] += 1
                else:
                    results['duplicates_removed'] += 1
        
        # Scan components with CVE.org
        if self.cve_org_scanner:
            print(f"\n📋 Scanning {len(components)} components with CVE.org...")
            cve_vulns = self.cve_org_scanner.scan_components(components)
            for vuln in cve_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results['summary']['cve_org'] += 1
                else:
                    results['duplicates_removed'] += 1
        
        # Scan components with CERT/CC
        if self.cert_cc_scanner:
            print(f"\n🎓 Scanning {len(components)} components with CERT/CC...")
            cert_vulns = self.cert_cc_scanner.scan_components(components)
            for vuln in cert_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results['summary']['cert_cc'] += 1
                else:
                    results['duplicates_removed'] += 1
        
        # Scan components with Sonatype OSS Index
        if self.sonatype_scanner:
            print(f"\n📦 Scanning {len(components)} components with Sonatype OSS Index...")
            sonatype_vulns = self.sonatype_scanner.scan_components(components)
            for vuln in sonatype_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results['summary']['sonatype'] += 1
                else:
                    results['duplicates_removed'] += 1
        
        # Scan components with Vulners.com
        if self.vulners_scanner:
            print(f"\n🔍 Scanning {len(components)} components with Vulners.com...")
            for component in components:
                name = component.get('name', 'unknown')
                version = component.get('version', '')
                
                vulners_vulns = self.vulners_scanner.scan_component(name, version)
                for vuln in vulners_vulns:
                    if deduplicator.add_vulnerability(vuln):
                        results['summary']['vulners'] += 1
                    else:
                        results['duplicates_removed'] += 1
        
        # Get deduplicated results
        results['vulnerabilities'] = deduplicator.get_deduplicated()
        results['summary']['unique'] = len(results['vulnerabilities'])
        results['summary']['total'] = sum([
            results['summary']['nvd'], results['summary']['osv'],
            results['summary']['github'], results['summary']['cisa_kev'],
            results['summary']['cisa_ics'], results['summary']['cve_org'],
            results['summary']['cert_cc'], results['summary']['sonatype'],
            results['summary']['vulners']
        ])
        
        return results
    
    def format_results(self, results: Dict) -> str:
        """Format scan results for display"""
        if not results:
            return "No scan results available"
        
        output = []
        output.append(f"🔍 Combined Vulnerability Scan Report")
        output.append(f"📅 Scan Time: {results['scan_time']}")
        output.append(f"📦 Components Scanned: {results['components_scanned']}")
        output.append(f"🚨 Unique Vulnerabilities: {results['summary'].get('unique', results['summary']['total'])}")
        output.append(f"🔄 Duplicates Removed: {results.get('duplicates_removed', 0)}")
        output.append(f"   Source Breakdown:")
        output.append(f"   - NVD: {results['summary']['nvd']}")
        output.append(f"   - OSV: {results['summary']['osv']}")
        output.append(f"   - GitHub: {results['summary']['github']}")
        output.append(f"   - CISA KEV: {results['summary']['cisa_kev']}")
        output.append(f"   - CISA ICS: {results['summary']['cisa_ics']}")
        output.append(f"   - CVE.org: {results['summary']['cve_org']}")
        output.append(f"   - CERT/CC: {results['summary']['cert_cc']}")
        output.append(f"   - Sonatype OSS: {results['summary']['sonatype']}")
        output.append(f"   - Vulners.com: {results['summary']['vulners']}")
        output.append("=" * 60)
        
        if results['summary']['total'] == 0:
            output.append("✅ No vulnerabilities found!")
            return "\n".join(output)
        
        # Group by severity
        critical = [v for v in results['vulnerabilities'] if v.get('severity') == 'CRITICAL']
        high = [v for v in results['vulnerabilities'] if v.get('severity') == 'HIGH']
        medium = [v for v in results['vulnerabilities'] if v.get('severity') == 'MEDIUM']
        low = [v for v in results['vulnerabilities'] if v.get('severity') == 'LOW']
        unknown = [v for v in results['vulnerabilities'] if v.get('severity') == 'Unknown']
        
        for severity, vulns in [('CRITICAL', critical), ('HIGH', high), ('MEDIUM', medium), ('LOW', low), ('Unknown', unknown)]:
            if vulns:
                output.append(f"\n🔴 {severity} Vulnerabilities ({len(vulns)}):")
                for vuln in vulns[:5]:  # Show first 5 of each severity
                    component_info = ""
                    if 'component' in vuln:
                        comp = vuln['component']
                        component_info = f" [{comp.get('name', 'unknown')} {comp.get('version', '')}]"
                    
                    output.append(f"  • {vuln['id']} (CVSS: {vuln['cvss_score']}) - {vuln['source']}{component_info}")
                    if vuln.get('url'):
                        output.append(f"    🔗 {vuln['url']}")
                
                if len(vulns) > 5:
                    output.append(f"    ... and {len(vulns) - 5} more {severity} vulnerabilities")
        
        return "\n".join(output)

# Legacy function - now handled by EmailSender class
def send_email_alert(results: Dict, email: str) -> bool:
    """Legacy email function - use EmailSender class instead"""
    sender = EmailSender()
    return sender.send_vulnerability_alert(results, email)

def main():
    scanner = CombinedScanner()
    results = scanner.scan_all()
    
    # Display results
    report = scanner.format_results(results)
    print("\n" + report)
    
    # Save detailed results
    output_file = scanner.config['scanner']['output_file']
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n💾 Detailed results saved to: {output_file}")
    
    # Always send email with scan results
    if scanner.config['scanner']['email_on_vulnerabilities']:
        success = scanner.email_sender.send_vulnerability_alert(results)
        if success:
            print("📧 Email report sent successfully")
        else:
            print("❌ Failed to send email report")
    
    # Exit with appropriate code
    if results.get('summary', {}).get('unique', 0) > 0:
        print("🚨 Vulnerabilities found - review required!")
        sys.exit(1)
    else:
        print("✅ No vulnerabilities detected")
        sys.exit(0)

if __name__ == "__main__":
    main()
