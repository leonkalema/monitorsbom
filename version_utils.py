#!/usr/bin/env python3
"""
Version comparison utilities for accurate vulnerability matching.
Reduces false positives by properly parsing and comparing version strings.
"""

import re
from typing import Optional, Tuple, List
from dataclasses import dataclass
from enum import Enum


class MatchConfidence(Enum):
    """Confidence level for vulnerability matches"""
    HIGH = "high"        # Exact CPE/version match
    MEDIUM = "medium"    # Version in affected range, name matches
    LOW = "low"          # Name matches but version unclear
    NONE = "none"        # Does not match


@dataclass
class VersionRange:
    """Represents a version range for vulnerability matching"""
    start_including: Optional[str] = None
    start_excluding: Optional[str] = None
    end_including: Optional[str] = None
    end_excluding: Optional[str] = None


def normalize_version(version: str) -> Tuple[List[int], str]:
    """
    Normalize version string for comparison.
    Returns tuple of (numeric_parts, suffix)
    """
    if not version:
        return ([], "")
    
    version = version.strip().lower()
    
    # Remove common prefixes
    version = re.sub(r'^[vV]', '', version)
    
    # Split into numeric and suffix parts
    match = re.match(r'^([\d.]+)(.*)$', version)
    if not match:
        return ([], version)
    
    numeric_str, suffix = match.groups()
    
    # Parse numeric parts
    parts = []
    for part in numeric_str.split('.'):
        try:
            parts.append(int(part))
        except ValueError:
            break
    
    # Normalize suffix (alpha < beta < rc < release)
    suffix = suffix.strip('-._')
    
    return (parts, suffix)


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two version strings.
    Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    if not v1 and not v2:
        return 0
    if not v1:
        return -1
    if not v2:
        return 1
    
    parts1, suffix1 = normalize_version(v1)
    parts2, suffix2 = normalize_version(v2)
    
    # Compare numeric parts
    max_len = max(len(parts1), len(parts2))
    parts1.extend([0] * (max_len - len(parts1)))
    parts2.extend([0] * (max_len - len(parts2)))
    
    for p1, p2 in zip(parts1, parts2):
        if p1 < p2:
            return -1
        if p1 > p2:
            return 1
    
    # Compare suffixes (empty suffix = release version, highest)
    suffix_order = {'alpha': 0, 'a': 0, 'beta': 1, 'b': 1, 'rc': 2, 'pre': 2, '': 3}
    
    s1_order = suffix_order.get(suffix1.split('.')[0] if suffix1 else '', 3)
    s2_order = suffix_order.get(suffix2.split('.')[0] if suffix2 else '', 3)
    
    if s1_order < s2_order:
        return -1
    if s1_order > s2_order:
        return 1
    
    return 0


def version_in_range(version: str, version_range: VersionRange) -> bool:
    """Check if version falls within a vulnerability range"""
    if not version:
        return False  # Unknown version = don't assume affected
    
    # Check start constraints
    if version_range.start_including:
        if compare_versions(version, version_range.start_including) < 0:
            return False
    
    if version_range.start_excluding:
        if compare_versions(version, version_range.start_excluding) <= 0:
            return False
    
    # Check end constraints
    if version_range.end_including:
        if compare_versions(version, version_range.end_including) > 0:
            return False
    
    if version_range.end_excluding:
        if compare_versions(version, version_range.end_excluding) >= 0:
            return False
    
    return True


def parse_github_range(range_str: str) -> Optional[VersionRange]:
    """
    Parse GitHub Advisory vulnerable version range format.
    Examples: ">= 1.0.0, < 2.0.0", "< 1.5.0", ">= 2.0.0"
    """
    if not range_str:
        return None
    
    version_range = VersionRange()
    
    # Split by comma for multiple constraints
    constraints = [c.strip() for c in range_str.split(',')]
    
    for constraint in constraints:
        constraint = constraint.strip()
        
        if constraint.startswith('>='):
            version_range.start_including = constraint[2:].strip()
        elif constraint.startswith('>'):
            version_range.start_excluding = constraint[1:].strip()
        elif constraint.startswith('<='):
            version_range.end_including = constraint[2:].strip()
        elif constraint.startswith('<'):
            version_range.end_excluding = constraint[1:].strip()
        elif constraint.startswith('='):
            # Exact version
            exact = constraint[1:].strip()
            version_range.start_including = exact
            version_range.end_including = exact
    
    return version_range


def parse_osv_range(events: List[dict]) -> Optional[VersionRange]:
    """Parse OSV affected version events into VersionRange"""
    if not events:
        return None
    
    version_range = VersionRange()
    
    for event in events:
        if 'introduced' in event:
            version_range.start_including = event['introduced']
        elif 'fixed' in event:
            version_range.end_excluding = event['fixed']
        elif 'last_affected' in event:
            version_range.end_including = event['last_affected']
    
    return version_range


def normalize_component_name(name: str) -> str:
    """Normalize component name for matching"""
    if not name:
        return ""
    
    name = name.lower().strip()
    
    # Remove common prefixes/suffixes
    name = re.sub(r'^(lib|py|node-|@[\w-]+/)', '', name)
    name = re.sub(r'(-js|-py|-java|-go)$', '', name)
    
    # Replace separators with consistent format
    name = re.sub(r'[-_.]', '-', name)
    
    return name


def component_name_matches(component_name: str, cpe_product: str) -> bool:
    """
    Check if component name matches CPE product name.
    More strict than simple 'in' check.
    """
    if not component_name or not cpe_product:
        return False
    
    norm_component = normalize_component_name(component_name)
    norm_cpe = normalize_component_name(cpe_product)
    
    # Exact match after normalization
    if norm_component == norm_cpe:
        return True
    
    # Check if one is contained in the other (for cases like "openssl" vs "openssl-fips")
    if norm_component in norm_cpe or norm_cpe in norm_component:
        # Additional check: ensure it's a word boundary match
        if re.search(rf'\b{re.escape(norm_component)}\b', norm_cpe):
            return True
        if re.search(rf'\b{re.escape(norm_cpe)}\b', norm_component):
            return True
    
    return False


def extract_cpe_parts(cpe_string: str) -> dict:
    """
    Extract vendor, product, and version from CPE 2.3 string.
    Format: cpe:2.3:a:vendor:product:version:...
    """
    if not cpe_string:
        return {}
    
    parts = cpe_string.split(':')
    if len(parts) < 6:
        return {}
    
    return {
        'vendor': parts[3] if len(parts) > 3 else '',
        'product': parts[4] if len(parts) > 4 else '',
        'version': parts[5] if len(parts) > 5 and parts[5] != '*' else ''
    }


def calculate_match_confidence(
    component_name: str,
    component_version: str,
    cpe_string: str,
    version_range: VersionRange
) -> MatchConfidence:
    """Calculate confidence level for a vulnerability match"""
    cpe_parts = extract_cpe_parts(cpe_string)
    
    # Check name match
    name_matches = component_name_matches(component_name, cpe_parts.get('product', ''))
    if not name_matches:
        return MatchConfidence.NONE
    
    # Check version
    if not component_version:
        return MatchConfidence.LOW  # Can't verify version
    
    # If we have a version range, check it
    if version_range and (version_range.start_including or version_range.start_excluding or 
                          version_range.end_including or version_range.end_excluding):
        if version_in_range(component_version, version_range):
            return MatchConfidence.HIGH
        return MatchConfidence.NONE
    
    # If CPE has specific version, check exact match
    cpe_version = cpe_parts.get('version', '')
    if cpe_version and cpe_version != '*':
        if compare_versions(component_version, cpe_version) == 0:
            return MatchConfidence.HIGH
        return MatchConfidence.NONE
    
    # Name matches but no version info available
    return MatchConfidence.LOW


class VulnerabilityDeduplicator:
    """Deduplicate vulnerabilities across multiple sources"""
    
    def __init__(self):
        self.seen_vulns = {}  # CVE ID -> vulnerability data
    
    def add_vulnerability(self, vuln: dict) -> bool:
        """
        Add vulnerability if not duplicate.
        Returns True if added, False if duplicate.
        """
        # Get canonical ID (prefer CVE over GHSA, etc.)
        vuln_id = self._get_canonical_id(vuln)
        
        if vuln_id in self.seen_vulns:
            # Merge sources
            existing = self.seen_vulns[vuln_id]
            existing_sources = existing.get('sources', [existing.get('source', 'Unknown')])
            new_source = vuln.get('source', 'Unknown')
            
            if new_source not in existing_sources:
                if isinstance(existing_sources, list):
                    existing_sources.append(new_source)
                else:
                    existing['sources'] = [existing_sources, new_source]
            
            # Keep higher confidence match
            if vuln.get('confidence', 'low') == 'high' and existing.get('confidence', 'low') != 'high':
                self.seen_vulns[vuln_id] = vuln
                vuln['sources'] = existing.get('sources', [existing.get('source')])
            
            return False
        
        self.seen_vulns[vuln_id] = vuln
        return True
    
    def _get_canonical_id(self, vuln: dict) -> str:
        """Get canonical vulnerability ID"""
        # Prefer CVE ID
        cve_id = vuln.get('cve_id') or vuln.get('id', '')
        
        if cve_id.startswith('CVE-'):
            return cve_id
        
        # Check if CVE is in cve_list
        cve_list = vuln.get('cve_list', [])
        for cve in cve_list:
            if cve.startswith('CVE-'):
                return cve
        
        # Fall back to whatever ID we have
        return vuln.get('id', str(hash(str(vuln))))
    
    def get_deduplicated(self) -> List[dict]:
        """Get list of deduplicated vulnerabilities"""
        return list(self.seen_vulns.values())


def test_version_comparison():
    """Test version comparison functions"""
    test_cases = [
        ("1.0.0", "2.0.0", -1),
        ("2.0.0", "1.0.0", 1),
        ("1.0.0", "1.0.0", 0),
        ("1.0", "1.0.0", 0),
        ("1.0.0-alpha", "1.0.0", -1),
        ("1.0.0-beta", "1.0.0-alpha", 1),
        ("v1.2.3", "1.2.3", 0),
        ("2.28.1", "2.28.0", 1),
        ("2.28.1", "3.0.0", -1),
    ]
    
    print("Testing version comparison...")
    for v1, v2, expected in test_cases:
        result = compare_versions(v1, v2)
        status = "✅" if result == expected else "❌"
        print(f"  {status} compare({v1}, {v2}) = {result} (expected {expected})")
    
    print("\nTesting version range...")
    range1 = VersionRange(start_including="2.0.0", end_excluding="3.0.0")
    test_range_cases = [
        ("2.0.0", range1, True),
        ("2.5.0", range1, True),
        ("1.9.0", range1, False),
        ("3.0.0", range1, False),
        ("2.99.99", range1, True),
    ]
    
    for version, vrange, expected in test_range_cases:
        result = version_in_range(version, vrange)
        status = "✅" if result == expected else "❌"
        print(f"  {status} {version} in [>={vrange.start_including}, <{vrange.end_excluding}] = {result}")


if __name__ == "__main__":
    test_version_comparison()
