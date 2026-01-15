#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple

import requests
import subprocess


class OSVScanner:
    def __init__(self, user_agent: str, request_timeout: int):
        self.api_url = "https://api.osv.dev/v1/query"
        self.headers = {
            "User-Agent": user_agent,
            "Content-Type": "application/json",
        }
        self.request_timeout = request_timeout

    def query_component_api(self, name: str, version: str, ecosystem: Optional[str] = None) -> List[Dict]:
        if not version:
            return []
        if not ecosystem:
            if any(x in name.lower() for x in ["python", "py"]):
                ecosystem = "PyPI"
            elif any(x in name.lower() for x in ["node", "js"]):
                ecosystem = "npm"
            else:
                ecosystem = "OSS-Fuzz"
        query_data = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
        try:
            response = requests.post(
                self.api_url,
                headers=self.headers,
                json=query_data,
                timeout=self.request_timeout,
            )
            response.raise_for_status()
            data = response.json()
            vulnerabilities: List[Dict] = []
            for vuln in data.get("vulns", []):
                vulnerabilities.append(
                    {
                        "source": "OSV API",
                        "id": vuln.get("id", "Unknown"),
                        "summary": vuln.get("summary", "No summary available"),
                        "severity": self._extract_severity(vuln),
                        "cvss_score": self._extract_cvss_score(vuln),
                        "description": vuln.get("details", vuln.get("summary", "No description")),
                        "published": vuln.get("published", "Unknown"),
                        "modified": vuln.get("modified", "Unknown"),
                        "affected_versions": self._extract_affected_versions(vuln),
                        "url": f"https://osv.dev/vulnerability/{vuln.get('id', '')}",
                        "component": {"name": name, "version": version, "ecosystem": ecosystem},
                    }
                )
            return vulnerabilities
        except Exception as exc:
            print(f"❌ OSV API query error for {name}@{version}: {exc}")
            return []

    def scan_sbom_file(self, sbom_path: str, timeout_seconds: int) -> Tuple[List[Dict], str]:
        try:
            result = subprocess.run(
                ["osv-scanner", "--sbom", sbom_path],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            vulnerabilities: List[Dict] = []
            raw_output = result.stdout + result.stderr
            if "Vulnerability" in raw_output or "CVE-" in raw_output:
                lines = raw_output.split("\n")
                current_vuln: Dict = {}
                for line in lines:
                    if "CVE-" in line or "GHSA-" in line:
                        if current_vuln:
                            vulnerabilities.append(current_vuln)
                        current_vuln = {
                            "source": "OSV",
                            "id": line.strip(),
                            "severity": "Unknown",
                            "cvss_score": "N/A",
                            "description": "OSV vulnerability detected",
                            "raw_line": line.strip(),
                        }
                if current_vuln:
                    vulnerabilities.append(current_vuln)
            return vulnerabilities, raw_output
        except subprocess.TimeoutExpired:
            return [], "OSV scanner timeout"
        except FileNotFoundError:
            return [], "OSV scanner not found - install with: brew install osv-scanner"
        except Exception as exc:
            return [], f"OSV scanner error: {exc}"

    def _extract_severity(self, vuln: Dict) -> str:
        severity = vuln.get("database_specific", {}).get("severity")
        if severity:
            return str(severity).upper()
        cvss_score = self._extract_cvss_score(vuln)
        if cvss_score != "N/A":
            try:
                score = float(cvss_score)
                if score >= 9.0:
                    return "CRITICAL"
                if score >= 7.0:
                    return "HIGH"
                if score >= 4.0:
                    return "MEDIUM"
                if score > 0.0:
                    return "LOW"
            except ValueError:
                return "Unknown"
        return "Unknown"

    def _extract_cvss_score(self, vuln: Dict) -> str:
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                return str(sev.get("score", "N/A"))
        return "N/A"

    def _extract_affected_versions(self, vuln: Dict) -> str:
        affected = vuln.get("affected", [])
        ranges: List[str] = []
        for affect in affected:
            for range_info in affect.get("ranges", []):
                events = range_info.get("events", [])
                range_parts: List[str] = []
                for event in events:
                    if "introduced" in event:
                        range_parts.append(f">= {event['introduced']}")
                    elif "fixed" in event:
                        range_parts.append(f"< {event['fixed']}")
                if range_parts:
                    ranges.append(" and ".join(range_parts))
        return "; ".join(ranges) if ranges else "All versions"
