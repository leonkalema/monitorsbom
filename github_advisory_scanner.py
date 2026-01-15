#!/usr/bin/env python3
"""
GitHub Security Advisory Database Scanner
Scans components against GitHub's Security Advisory Database
"""

import requests
import json
import logging
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class GitHubAdvisoryScanner:
    """Scanner for GitHub Security Advisory Database"""
    
    def __init__(self, github_token: Optional[str] = None):
        self.base_url = "https://api.github.com/graphql"
        self.github_token = github_token
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        
        # Set up authentication if token provided
        if self.github_token:
            self.session.headers.update({
                'Authorization': f'Bearer {self.github_token}',
                'Accept': 'application/vnd.github.v3+json'
            })
        
        self.session.headers.update({
            'User-Agent': 'SBOM-Vulnerability-Scanner/1.0'
        })
    
    def scan_components(self, components: List[Dict]) -> List[Dict]:
        """Scan components against GitHub Security Advisory Database"""
        vulnerabilities = []
        
        self.logger.info(f"🔍 Scanning {len(components)} components with GitHub Security Advisory...")
        
        for component in components:
            try:
                component_vulns = self._scan_component(component)
                vulnerabilities.extend(component_vulns)
                
                if component_vulns:
                    self.logger.info(f"  🔎 {component.get('name', 'unknown')} {component.get('version', '')} - {len(component_vulns)} advisories")
                
            except Exception as e:
                self.logger.error(f"Error scanning component {component.get('name', 'unknown')}: {e}")
                continue
        
        return vulnerabilities
    
    def _scan_component(self, component: Dict) -> List[Dict]:
        """Scan a single component for vulnerabilities"""
        name = component.get('name', '').lower()
        version = component.get('version', '')
        
        if not name:
            return []
        
        # GitHub GraphQL query for security advisories
        query = """
        query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $first: Int!) {
          securityVulnerabilities(
            ecosystem: $ecosystem
            package: $package
            first: $first
          ) {
            nodes {
              advisory {
                ghsaId
                summary
                description
                severity
                publishedAt
                updatedAt
                permalink
                cvss {
                  score
                  vectorString
                }
                cveId
                cwes(first: 10) {
                  nodes {
                    cweId
                    description
                  }
                }
              }
              vulnerableVersionRange
              firstPatchedVersion {
                identifier
              }
              package {
                name
                ecosystem
              }
            }
          }
        }
        """
        
        # Try different ecosystems based on component type
        ecosystems = self._detect_ecosystem(component)
        vulnerabilities = []
        
        for ecosystem in ecosystems:
            try:
                variables = {
                    "ecosystem": ecosystem,
                    "package": name,
                    "first": 100
                }
                
                response = self.session.post(
                    self.base_url,
                    json={"query": query, "variables": variables},
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if 'errors' in data:
                        self.logger.debug(f"GraphQL errors for {name}: {data['errors']}")
                        continue
                    
                    vulns = self._parse_github_response(data, component)
                    vulnerabilities.extend(vulns)
                    
                elif response.status_code == 401:
                    self.logger.warning("GitHub API authentication required for better rate limits")
                    break
                else:
                    self.logger.debug(f"GitHub API error {response.status_code} for {name}")
                    
            except Exception as e:
                self.logger.debug(f"Error querying GitHub for {name} in {ecosystem}: {e}")
                continue
        
        return vulnerabilities
    
    def _detect_ecosystem(self, component: Dict) -> List[str]:
        """Detect GitHub ecosystem from component information"""
        name = component.get('name', '').lower()
        purl = component.get('purl', '').lower()
        
        ecosystems = []
        
        # Map based on package URL or name patterns
        if 'npm:' in purl or any(x in name for x in ['node_modules', '@']):
            ecosystems.append('NPM')
        elif 'pypi:' in purl or 'python' in purl:
            ecosystems.append('PIP')
        elif 'maven:' in purl or 'java' in purl:
            ecosystems.append('MAVEN')
        elif 'nuget:' in purl or '.net' in purl:
            ecosystems.append('NUGET')
        elif 'gem:' in purl or 'ruby' in purl:
            ecosystems.append('RUBYGEMS')
        elif 'go:' in purl or 'golang' in purl:
            ecosystems.append('GO')
        elif 'cargo:' in purl or 'rust' in purl:
            ecosystems.append('RUST')
        elif 'composer:' in purl or 'php' in purl:
            ecosystems.append('COMPOSER')
        
        # If no specific ecosystem detected, try common ones
        if not ecosystems:
            ecosystems = ['NPM', 'PIP', 'MAVEN']
        
        return ecosystems
    
    def _parse_github_response(self, data: Dict, component: Dict) -> List[Dict]:
        """Parse GitHub GraphQL response into vulnerability format"""
        vulnerabilities = []
        
        try:
            nodes = data.get('data', {}).get('securityVulnerabilities', {}).get('nodes', [])
            
            for node in nodes:
                advisory = node.get('advisory', {})
                
                # Check if version is affected with proper version matching
                is_affected, confidence = self._is_version_affected(
                    component.get('version', ''),
                    node.get('vulnerableVersionRange', ''),
                    node.get('firstPatchedVersion', {}).get('identifier', '')
                )
                
                if not is_affected:
                    continue
                
                vuln = {
                    'id': advisory.get('ghsaId', ''),
                    'cve_id': advisory.get('cveId', ''),
                    'summary': advisory.get('summary', ''),
                    'description': advisory.get('description', ''),
                    'severity': advisory.get('severity', 'UNKNOWN').upper(),
                    'cvss_score': advisory.get('cvss', {}).get('score', 0),
                    'cvss_vector': advisory.get('cvss', {}).get('vectorString', ''),
                    'published_date': advisory.get('publishedAt', ''),
                    'updated_date': advisory.get('updatedAt', ''),
                    'url': advisory.get('permalink', ''),
                    'source': 'GitHub Security Advisory',
                    'component': component,
                    'vulnerable_range': node.get('vulnerableVersionRange', ''),
                    'patched_version': node.get('firstPatchedVersion', {}).get('identifier', ''),
                    'cwes': [cwe.get('cweId', '') for cwe in advisory.get('cwes', {}).get('nodes', [])]
                }
                
                vulnerabilities.append(vuln)
                
        except Exception as e:
            self.logger.error(f"Error parsing GitHub response: {e}")
        
        return vulnerabilities
    
    def _is_version_affected(self, version: str, vulnerable_range: str, patched_version: str) -> Tuple[bool, str]:
        """Check if component version is affected by vulnerability"""
        if not version:
            return False, "no_version"  # Don't assume affected without version
        
        if not vulnerable_range:
            return False, "no_range"  # Don't assume affected without range info
        
        # Parse version into comparable parts
        def parse_version(v: str) -> Tuple[List[int], str]:
            if not v:
                return [], ""
            v = v.strip().lower()
            v = re.sub(r'^[vV]', '', v)
            match = re.match(r'^([\d.]+)(.*)$', v)
            if not match:
                return [], v
            numeric_str, suffix = match.groups()
            parts = []
            for part in numeric_str.split('.'):
                try:
                    parts.append(int(part))
                except ValueError:
                    break
            return parts, suffix.strip('-._')
        
        def compare_versions(v1: str, v2: str) -> int:
            parts1, suf1 = parse_version(v1)
            parts2, suf2 = parse_version(v2)
            max_len = max(len(parts1), len(parts2))
            parts1.extend([0] * (max_len - len(parts1)))
            parts2.extend([0] * (max_len - len(parts2)))
            for p1, p2 in zip(parts1, parts2):
                if p1 < p2:
                    return -1
                if p1 > p2:
                    return 1
            return 0
        
        # Parse vulnerable range (format: ">= 1.0.0, < 2.0.0")
        constraints = [c.strip() for c in vulnerable_range.split(',')]
        
        for constraint in constraints:
            constraint = constraint.strip()
            if constraint.startswith('>='):
                bound = constraint[2:].strip()
                if compare_versions(version, bound) < 0:
                    return False, "below_start"
            elif constraint.startswith('>'):
                bound = constraint[1:].strip()
                if compare_versions(version, bound) <= 0:
                    return False, "below_start"
            elif constraint.startswith('<='):
                bound = constraint[2:].strip()
                if compare_versions(version, bound) > 0:
                    return False, "above_end"
            elif constraint.startswith('<'):
                bound = constraint[1:].strip()
                if compare_versions(version, bound) >= 0:
                    return False, "above_end"
            elif constraint.startswith('='):
                bound = constraint[1:].strip()
                if compare_versions(version, bound) != 0:
                    return False, "not_exact_match"
        
        # Also check if patched version exists and our version is >= patched
        if patched_version:
            if compare_versions(version, patched_version) >= 0:
                return False, "patched"
        
        return True, "high"
    
    def get_stats(self) -> Dict:
        """Get scanner statistics"""
        return {
            'name': 'GitHub Security Advisory',
            'source': 'github',
            'description': 'GitHub Security Advisory Database',
            'url': 'https://github.com/advisories',
            'requires_auth': bool(self.github_token),
            'rate_limit': '5000/hour (authenticated) or 60/hour (unauthenticated)'
        }

def test_github_scanner():
    """Test GitHub Advisory scanner"""
    scanner = GitHubAdvisoryScanner()
    
    # Test with a known vulnerable component
    test_components = [
        {
            'name': 'lodash',
            'version': '4.17.15',
            'purl': 'pkg:npm/lodash@4.17.15'
        }
    ]
    
    print("🧪 Testing GitHub Security Advisory Scanner...")
    vulnerabilities = scanner.scan_components(test_components)
    
    print(f"Found {len(vulnerabilities)} vulnerabilities")
    for vuln in vulnerabilities[:3]:  # Show first 3
        print(f"  - {vuln['id']}: {vuln['summary'][:60]}...")

if __name__ == "__main__":
    test_github_scanner()
