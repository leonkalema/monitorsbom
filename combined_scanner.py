#!/usr/bin/env python3

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from cert_cc_scanner import CERTCCScanner
from cisa_ics_scanner import CISAICSScanner
from cisa_kev_scanner import CISAKEVScanner
from cve_org_scanner import CVEOrgScanner
from github_advisory_scanner import GitHubAdvisoryScanner
from sonatype_oss_scanner import SonatypeOSSScanner
from vulners_scanner import VulnersScanner

from email_sender import EmailSender
from nvd_scanner import NVDScanner
from osv_scanner import OSVScanner
from sbom_parser import SBOMParser
from version_utils import VulnerabilityDeduplicator


class CombinedScanner:
    def __init__(self, sbom_dir: Optional[str] = None, config: Optional[Dict] = None):
        self.config = config or {}
        scanner_cfg = self.config.get("scanner", {})
        api_cfg = self.config.get("api", {})
        sources_cfg = self.config.get("sources", {})
        sbom_dir = sbom_dir or scanner_cfg.get("sbom_directory", "sbom")
        self.sbom_parser = SBOMParser(str(sbom_dir))
        self.nvd_scanner = NVDScanner(api_cfg) if sources_cfg.get("enable_nvd") else None
        self.osv_scanner = OSVScanner(
            user_agent=str(api_cfg.get("user_agent", "SBOM-Scanner/2.0")),
            request_timeout=int(api_cfg.get("request_timeout", 30)),
        )
        self.github_scanner = (
            GitHubAdvisoryScanner(str(api_cfg.get("github_token", "")) or None)
            if sources_cfg.get("enable_github")
            else None
        )
        self.cisa_kev_scanner = CISAKEVScanner() if sources_cfg.get("enable_cisa_kev") else None
        self.cisa_ics_scanner = CISAICSScanner() if sources_cfg.get("enable_cisa_ics") else None
        self.cve_org_scanner = CVEOrgScanner() if sources_cfg.get("enable_cve_org") else None
        self.cert_cc_scanner = CERTCCScanner() if sources_cfg.get("enable_cert_cc") else None
        self.sonatype_scanner = SonatypeOSSScanner() if sources_cfg.get("enable_sonatype") else None
        self.vulners_scanner = (
            VulnersScanner(str(api_cfg.get("vulners_api_key", "")))
            if sources_cfg.get("enable_vulners")
            else None
        )
        self.email_sender = EmailSender(self.config.get("email", {}))
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger(__name__)

    def scan_all(self) -> Dict:
        print("🔍 Combined Vulnerability Scan Starting...")
        print("=" * 60)
        components = self.sbom_parser.get_components()
        if not components:
            print("❌ No components found in SBOM files")
            return {}
        deduplicator = VulnerabilityDeduplicator()
        results: Dict = {
            "scan_time": datetime.now().isoformat(),
            "components_scanned": len(components),
            "scanned_components": components,
            "vulnerabilities": [],
            "duplicates_removed": 0,
            "summary": {
                "nvd": 0,
                "osv": 0,
                "github": 0,
                "cisa_kev": 0,
                "cisa_ics": 0,
                "cve_org": 0,
                "cert_cc": 0,
                "sonatype": 0,
                "vulners": 0,
                "total": 0,
                "unique": 0,
            },
            "output_file": self.config.get("scanner", {}).get("output_file", "/tmp/combined-vuln-scan.json"),
        }
        if self.nvd_scanner:
            print(f"\n🌐 Scanning {len(components)} components with NVD...")
            for component in components:
                name = component.get("name", "unknown")
                version = component.get("version", "")
                print(f"  🔎 {name} {version}")
                nvd_vulns = self.nvd_scanner.search_component(name, version)
                for vuln in nvd_vulns:
                    vuln["component"] = component
                    if deduplicator.add_vulnerability(vuln):
                        results["summary"]["nvd"] += 1
                    else:
                        results["duplicates_removed"] += 1
        sources_cfg = self.config.get("sources", {})
        if sources_cfg.get("enable_osv_api"):
            print(f"\n🔍 Scanning {len(components)} components with Google OSV API...")
            for component in components:
                name = component.get("name", "unknown")
                version = component.get("version", "")
                print(f"  🔎 {name} {version}")
                osv_api_vulns = self.osv_scanner.query_component_api(name, version)
                for vuln in osv_api_vulns:
                    vuln["component"] = component
                    if deduplicator.add_vulnerability(vuln):
                        results["summary"]["osv"] += 1
                    else:
                        results["duplicates_removed"] += 1
        if sources_cfg.get("enable_osv_cli"):
            print("\n📄 Scanning SBOM files with Google OSV CLI...")
            sbom_files = list(Path(self.sbom_parser.sbom_dir).glob("*.cdx.json"))
            timeout_seconds = int(self.config.get("scanner", {}).get("osv_timeout", 60))
            for sbom_file in sbom_files:
                print(f"  📄 {sbom_file.name}")
                osv_vulns, _raw_output = self.osv_scanner.scan_sbom_file(
                    str(sbom_file), timeout_seconds
                )
                for vuln in osv_vulns:
                    vuln["sbom_file"] = str(sbom_file)
                    if deduplicator.add_vulnerability(vuln):
                        results["summary"]["osv"] += 1
                    else:
                        results["duplicates_removed"] += 1
        if self.github_scanner:
            print(f"\n🐙 Scanning {len(components)} components with GitHub Security Advisory...")
            github_vulns = self.github_scanner.scan_components(components)
            for vuln in github_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results["summary"]["github"] += 1
                else:
                    results["duplicates_removed"] += 1
        if self.cisa_kev_scanner:
            print(f"\n🏛️ Scanning {len(components)} components with CISA KEV...")
            cisa_vulns = self.cisa_kev_scanner.scan_components(components)
            for vuln in cisa_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results["summary"]["cisa_kev"] += 1
                else:
                    results["duplicates_removed"] += 1
        if self.cisa_ics_scanner:
            print(f"\n🔧 Scanning {len(components)} components with CISA ICS-CERT...")
            ics_vulns = self.cisa_ics_scanner.scan_components(components)
            for vuln in ics_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results["summary"]["cisa_ics"] += 1
                else:
                    results["duplicates_removed"] += 1
        if self.cve_org_scanner:
            print(f"\n📋 Scanning {len(components)} components with CVE.org...")
            cve_vulns = self.cve_org_scanner.scan_components(components)
            for vuln in cve_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results["summary"]["cve_org"] += 1
                else:
                    results["duplicates_removed"] += 1
        if self.cert_cc_scanner:
            print(f"\n🎓 Scanning {len(components)} components with CERT/CC...")
            cert_vulns = self.cert_cc_scanner.scan_components(components)
            for vuln in cert_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results["summary"]["cert_cc"] += 1
                else:
                    results["duplicates_removed"] += 1
        if self.sonatype_scanner:
            print(f"\n📦 Scanning {len(components)} components with Sonatype OSS Index...")
            sonatype_vulns = self.sonatype_scanner.scan_components(components)
            for vuln in sonatype_vulns:
                if deduplicator.add_vulnerability(vuln):
                    results["summary"]["sonatype"] += 1
                else:
                    results["duplicates_removed"] += 1
        if self.vulners_scanner:
            print(f"\n🔍 Scanning {len(components)} components with Vulners.com...")
            for component in components:
                name = component.get("name", "unknown")
                version = component.get("version", "")
                vulners_vulns = self.vulners_scanner.scan_component(name, version)
                for vuln in vulners_vulns:
                    if deduplicator.add_vulnerability(vuln):
                        results["summary"]["vulners"] += 1
                    else:
                        results["duplicates_removed"] += 1
        results["vulnerabilities"] = deduplicator.get_deduplicated()
        results["summary"]["unique"] = len(results["vulnerabilities"])
        results["summary"]["total"] = sum(
            [
                results["summary"]["nvd"],
                results["summary"]["osv"],
                results["summary"]["github"],
                results["summary"]["cisa_kev"],
                results["summary"]["cisa_ics"],
                results["summary"]["cve_org"],
                results["summary"]["cert_cc"],
                results["summary"]["sonatype"],
                results["summary"]["vulners"],
            ]
        )
        return results

    def format_results(self, results: Dict) -> str:
        if not results:
            return "No scan results available"
        output: List[str] = []
        output.append("🔍 Combined Vulnerability Scan Report")
        output.append(f"📅 Scan Time: {results['scan_time']}")
        output.append(f"📦 Components Scanned: {results['components_scanned']}")
        output.append(
            f"🚨 Unique Vulnerabilities: {results['summary'].get('unique', results['summary']['total'])}"
        )
        output.append(f"🔄 Duplicates Removed: {results.get('duplicates_removed', 0)}")
        output.append("   Source Breakdown:")
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
        if results["summary"]["total"] == 0:
            output.append("✅ No vulnerabilities found!")
            return "\n".join(output)
        critical = [v for v in results["vulnerabilities"] if v.get("severity") == "CRITICAL"]
        high = [v for v in results["vulnerabilities"] if v.get("severity") == "HIGH"]
        medium = [v for v in results["vulnerabilities"] if v.get("severity") == "MEDIUM"]
        low = [v for v in results["vulnerabilities"] if v.get("severity") == "LOW"]
        unknown = [v for v in results["vulnerabilities"] if v.get("severity") == "Unknown"]
        grouped = [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium), ("LOW", low), ("Unknown", unknown)]
        for severity, vulns in grouped:
            if not vulns:
                continue
            output.append(f"\n🔴 {severity} Vulnerabilities ({len(vulns)}):")
            for vuln in vulns[:5]:
                component_info = ""
                if "component" in vuln:
                    comp = vuln["component"]
                    component_info = f" [{comp.get('name', 'unknown')} {comp.get('version', '')}]"
                output.append(
                    f"  • {vuln['id']} (CVSS: {vuln.get('cvss_score', 'N/A')}) - {vuln.get('source', 'Unknown')}{component_info}"
                )
                if vuln.get("url"):
                    output.append(f"    🔗 {vuln['url']}")
            if len(vulns) > 5:
                output.append(f"    ... and {len(vulns) - 5} more {severity} vulnerabilities")
        return "\n".join(output)
