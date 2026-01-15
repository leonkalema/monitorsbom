#!/usr/bin/env python3

import re
from typing import Dict, List, Optional, Tuple

import requests

from version_utils import (
    VersionRange,
    compare_versions,
    extract_cpe_parts,
    component_name_matches,
    version_in_range,
)


class NVDScanner:
    def __init__(self, api_config: Dict[str, object]):
        self.base_url = str(api_config["nvd_base_url"])
        self.headers = {"User-Agent": str(api_config["user_agent"])}
        self.timeout = int(api_config["request_timeout"])
        nvd_api_key = str(api_config.get("nvd_api_key", ""))
        if nvd_api_key:
            self.headers["apiKey"] = nvd_api_key
            print("✅ Using NVD API key for enhanced rate limits")

    def search_component(self, name: str, version: Optional[str] = None) -> List[Dict]:
        search_terms: List[str] = [name]
        if "-" in name:
            base_name = name.split("-")[0]
            search_terms.append(base_name)
        all_vulns: Dict[str, Dict] = {}
        for search_term in search_terms:
            params = {"keywordSearch": search_term, "resultsPerPage": 100}
            try:
                response = requests.get(
                    self.base_url,
                    headers=self.headers,
                    params=params,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                data = response.json()
                for vuln_data in data.get("vulnerabilities", []):
                    cve_id = vuln_data.get("cve", {}).get("id", "")
                    if cve_id and cve_id not in all_vulns:
                        all_vulns[cve_id] = vuln_data
            except Exception:
                continue
        vulnerabilities: List[Dict] = []
        for vuln_data in all_vulns.values():
            vuln = vuln_data.get("cve", {})
            is_affected, confidence = self._is_component_affected(vuln_data, name, version)
            affected_versions = self._get_affected_versions(vuln_data)
            if is_affected and confidence == "high":
                vulnerabilities.append(
                    {
                        "source": "NVD",
                        "id": vuln.get("id", "Unknown"),
                        "severity": self._get_severity(vuln),
                        "cvss_score": self._get_cvss_score(vuln),
                        "description": self._get_description(vuln),
                        "published": vuln.get("published", "Unknown"),
                        "url": f"https://nvd.nist.gov/vuln/detail/{vuln.get('id', '')}",
                        "affected_versions": affected_versions,
                        "version_match": f"Component {name} {version} - {affected_versions}",
                        "confidence": confidence,
                    }
                )
        return vulnerabilities

    def _get_severity(self, vuln: Dict) -> str:
        metrics = vuln.get("metrics", {})
        for metric_type in ["cvssMetricV31", "cvssMetricV30"]:
            if metric_type in metrics and metrics[metric_type]:
                return metrics[metric_type][0]["cvssData"].get("baseSeverity", "Unknown")
        return "Unknown"

    def _get_cvss_score(self, vuln: Dict) -> str:
        metrics = vuln.get("metrics", {})
        for metric_type in ["cvssMetricV31", "cvssMetricV30"]:
            if metric_type in metrics and metrics[metric_type]:
                return str(metrics[metric_type][0]["cvssData"].get("baseScore", "N/A"))
        return "N/A"

    def _get_description(self, vuln: Dict) -> str:
        descriptions = vuln.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "No description available")
        return "No description available"

    def _is_component_affected(
        self, vuln_data: Dict, component_name: str, component_version: Optional[str]
    ) -> Tuple[bool, str]:
        if not component_version:
            return False, "no_version"
        configurations = vuln_data.get("configurations", [])
        if not configurations:
            return self._check_description_for_version(
                vuln_data, component_name, component_version
            )
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    is_match, confidence = self._cpe_matches_component(
                        cpe_match, component_name, component_version
                    )
                    if is_match:
                        return True, confidence
        return False, "not_affected"

    def _cpe_matches_component(
        self, cpe_match: Dict, component_name: str, component_version: str
    ) -> Tuple[bool, str]:
        cpe_string = cpe_match.get("criteria", "")
        cpe_parts = extract_cpe_parts(cpe_string)
        if not component_name_matches(component_name, cpe_parts.get("product", "")):
            return False, "name_mismatch"
        if not cpe_match.get("vulnerable", False):
            return False, "not_vulnerable"
        version_range = VersionRange(
            start_including=cpe_match.get("versionStartIncluding"),
            start_excluding=cpe_match.get("versionStartExcluding"),
            end_including=cpe_match.get("versionEndIncluding"),
            end_excluding=cpe_match.get("versionEndExcluding"),
        )
        if not any(
            [
                version_range.start_including,
                version_range.start_excluding,
                version_range.end_including,
                version_range.end_excluding,
            ]
        ):
            cpe_version = cpe_parts.get("version", "")
            if cpe_version and cpe_version != "*":
                if compare_versions(component_version, cpe_version) == 0:
                    return True, "high"
                return False, "version_mismatch"
            return False, "no_version_constraint"
        if version_in_range(component_version, version_range):
            return True, "high"
        return False, "outside_range"

    def _get_affected_versions(self, vuln_data: Dict) -> str:
        ranges: List[str] = []
        configurations = vuln_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        range_str = self._format_version_range(cpe_match)
                        if range_str:
                            ranges.append(range_str)
        return "; ".join(ranges) if ranges else "All versions"

    def _format_version_range(self, cpe_match: Dict) -> str:
        parts: List[str] = []
        if cpe_match.get("versionStartIncluding"):
            parts.append(f">= {cpe_match['versionStartIncluding']}")
        if cpe_match.get("versionStartExcluding"):
            parts.append(f"> {cpe_match['versionStartExcluding']}")
        if cpe_match.get("versionEndIncluding"):
            parts.append(f"<= {cpe_match['versionEndIncluding']}")
        if cpe_match.get("versionEndExcluding"):
            parts.append(f"< {cpe_match['versionEndExcluding']}")
        return " and ".join(parts) if parts else ""

    def _check_description_for_version(
        self, vuln_data: Dict, component_name: str, component_version: str
    ) -> Tuple[bool, str]:
        vuln = vuln_data.get("cve", {})
        description = self._get_description(vuln).lower()
        name_lower = component_name.lower()
        name_variants = [
            name_lower,
            name_lower.replace("-", " "),
            name_lower.replace("-", ""),
            name_lower.replace("_", " "),
        ]
        if "sp" in name_lower:
            name_variants.append(name_lower.replace("-sp", " service provider"))
            name_variants.append(name_lower.replace("sp", "service provider"))
        if "idp" in name_lower:
            name_variants.append(name_lower.replace("-idp", " identity provider"))
            name_variants.append(name_lower.replace("idp", "identity provider"))
        name_found = any(variant in description for variant in name_variants)
        if not name_found:
            return False, "name_not_in_description"
        through_pattern = r"(?:through|before|prior to|up to|<=?)\s*(\d+\.\d+(?:\.\d+)?)"
        through_matches = re.findall(through_pattern, description)
        for max_ver in through_matches:
            if compare_versions(component_version, max_ver) <= 0:
                return True, "high"
        exact_pattern = r"(?:affects?|version|in)\s*(\d+\.\d+(?:\.\d+)?)"
        exact_matches = re.findall(exact_pattern, description)
        for exact_ver in exact_matches:
            if compare_versions(component_version, exact_ver) == 0:
                return True, "high"
        range_pattern = r"(\d+\.\d+(?:\.\d+)?)\s*(?:to|-)\s*(\d+\.\d+(?:\.\d+)?)"
        range_matches = re.findall(range_pattern, description)
        for min_ver, max_ver in range_matches:
            if compare_versions(component_version, min_ver) >= 0 and compare_versions(
                component_version, max_ver
            ) <= 0:
                return True, "high"
        return False, "version_not_in_range"
