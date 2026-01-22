#!/usr/bin/env python3

from datetime import datetime
from typing import Dict, List, Set, Optional

try:
    from triage_checklist_generator import TriageChecklistGenerator
    CHECKLIST_GENERATOR_AVAILABLE = True
except ImportError:
    CHECKLIST_GENERATOR_AVAILABLE = False


class EmailContentBuilder:
    def __init__(self, results: Dict):
        self.results = results
        self.checklist_data: Optional[Dict] = None
        
        # Generate dynamic checklist based on actual SBOM
        if CHECKLIST_GENERATOR_AVAILABLE:
            try:
                generator = TriageChecklistGenerator(results)
                self.checklist_data = generator.generate_full_checklist()
            except Exception:
                pass

    def create_subject(self) -> str:
        unique_vulns = self.results.get("summary", {}).get(
            "unique", self.results.get("summary", {}).get("total", 0)
        )
        critical_high = self._count_critical_high_vulns()
        if unique_vulns == 0:
            return "✅ SBOM Scan Complete - No Vulnerabilities Found"
        if critical_high > 0:
            return (
                f"🚨 CRITICAL: {critical_high} High-Risk Vulnerabilities Detected "
                f"({unique_vulns} total)"
            )
        return f"⚠️  SBOM Vulnerabilities Detected ({unique_vulns} found)"

    def create_text_body(self) -> str:
        lines: List[str] = [
            "SBOM VULNERABILITY SCAN ALERT",
            "=" * 50,
            "",
            f"Scan Time: {self.results.get('scan_time', 'Unknown')}",
            f"Components Scanned: {self.results.get('components_scanned', 0)}",
            "",
            "COMPONENTS ANALYZED:",
            self._format_component_list(),
            "",
            f"Total Vulnerabilities: {self.results.get('summary', {}).get('total', 0)}",
            f"  - NVD Database: {self.results.get('summary', {}).get('nvd', 0)}",
            f"  - OSV Database: {self.results.get('summary', {}).get('osv', 0)}",
            f"  - GitHub Security Advisory: {self.results.get('summary', {}).get('github', 0)}",
            f"  - CISA KEV Catalog: {self.results.get('summary', {}).get('cisa_kev', 0)}",
            f"  - CISA ICS-CERT: {self.results.get('summary', {}).get('cisa_ics', 0)}",
            f"  - CVE.org Database: {self.results.get('summary', {}).get('cve_org', 0)}",
            f"  - CERT/CC Database: {self.results.get('summary', {}).get('cert_cc', 0)}",
            f"  - Sonatype OSS Index: {self.results.get('summary', {}).get('sonatype', 0)}",
            f"  - Vulners.com: {self.results.get('summary', {}).get('vulners', 0)}",
            "",
            "SEVERITY BREAKDOWN:",
            "-" * 20,
        ]
        severity_counts = self._get_severity_breakdown()
        for severity, count in severity_counts.items():
            if count > 0:
                emoji = self._get_severity_emoji(severity)
                lines.append(f"{emoji} {severity}: {count}")
        lines.extend(["", "ALL VULNERABILITIES FROM 2025:", "=" * 35])
        all_vulns_2025 = self._get_vulnerabilities_2025()
        if not all_vulns_2025:
            lines.append("✅ No vulnerabilities from 2025 found.")
        else:
            lines.append(f"Found {len(all_vulns_2025)} vulnerabilities from 2025:")
            lines.append("")
            for i, vuln in enumerate(all_vulns_2025[:20], 1):
                lines.extend(
                    [
                        f"{i}. 🔴 {vuln['id']} - {vuln.get('severity', 'Unknown')} "
                        f"(CVSS: {vuln.get('cvss_score', 'N/A')})",
                        f"   📦 Component: {self._get_component_info(vuln)}",
                        f"   🏢 Source: {vuln.get('source', 'Unknown')}",
                        f"   📄 Description: {vuln.get('description', 'No description')[:150]}...",
                        f"   🔗 LINK: {vuln.get('url', 'N/A')}",
                        f"   {'='*60}",
                        "",
                    ]
                )
            if len(all_vulns_2025) > 20:
                lines.append(
                    f"... and {len(all_vulns_2025) - 20} more vulnerabilities from 2025"
                )
        lines.extend(
            [
                "",
                "IMMEDIATE ACTIONS REQUIRED:",
                "- Review all vulnerabilities immediately",
                "- Update affected components to patched versions",
                "- Check detailed JSON report for complete information",
                "- Consider implementing additional security controls",
                "",
            ]
        )
        
        # Add triage checklists
        lines.extend(self._create_config_checklist_text())
        lines.extend(self._create_interface_checklist_text())
        
        lines.extend(
            [
                "",
                "DETAILED REPORT:",
                f"- JSON Report: {self.results.get('output_file', '/tmp/combined-vuln-scan.json')}",
                "- PDF Report: Attached (if available)",
                "- Run scanner again after applying patches",
                "",
                "This is an automated security alert from your SBOM vulnerability scanner.",
                f"Generated at: {datetime.now().isoformat()}",
            ]
        )
        return "\n".join(lines)

    def _create_config_checklist_text(self) -> List[str]:
        """Create dynamic config checklist for text email based on actual SBOM"""
        lines = [
            "",
            "=" * 50,
            "TRIAGE CHECKLIST: Component Configuration",
            "=" * 50,
            "Questions generated based on your SBOM components:",
            "",
        ]
        
        if self.checklist_data:
            config_items = self.checklist_data.get('config_checklist', [])
            
            # Group by component
            by_component: Dict[str, List] = {}
            for item in config_items:
                comp = item['component']
                if comp not in by_component:
                    by_component[comp] = []
                by_component[comp].append(item)
            
            for comp_name, items in by_component.items():
                lines.append(f"--- {comp_name.upper()} ---")
                lines.append("")
                for item in items:
                    cves = ', '.join(item['affects_cves'][:3])
                    lines.append(f"☐ {item['config_option']}")
                    lines.append(f"   {item['description']}")
                    lines.append(f"   Affects: {cves}")
                    lines.append(f"   Your Value: _______________")
                    lines.append("")
        else:
            lines.append("(Dynamic checklist not available - see PDF attachment)")
            lines.append("")
        
        return lines

    def _create_interface_checklist_text(self) -> List[str]:
        """Create dynamic interface checklist for text email"""
        lines = [
            "",
            "=" * 50,
            "TRIAGE CHECKLIST: System Interfaces",
            "=" * 50,
        ]
        
        if self.checklist_data:
            comp_types = self.checklist_data.get('component_types', [])
            lines.append(f"Relevant to component types: {', '.join(comp_types)}")
            lines.append("")
            
            interface_items = self.checklist_data.get('interface_checklist', [])
            
            # Group by category
            by_category: Dict[str, List] = {}
            for item in interface_items:
                cat = item['category']
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(item)
            
            for category, items in by_category.items():
                lines.append(f"--- {category.upper()} ---")
                for item in items:
                    lines.append(f"☐ {item['interface']} ({item['description']})")
                    lines.append(f"   Present: YES / NO")
                    lines.append(f"   External Access: YES / NO")
                    lines.append(f"   Auth Required: YES / NO / N/A")
                    lines.append("")
        else:
            lines.append("(Dynamic checklist not available - see PDF attachment)")
            lines.append("")
        
        return lines

    def create_html_body(self) -> str:
        unique_vulns = self.results.get("summary", {}).get(
            "unique", self.results.get("summary", {}).get("total", 0)
        )
        if unique_vulns == 0:
            header = "<h2 style='color: green;'>✅ SBOM SCAN COMPLETE - ALL CLEAR</h2>"
        else:
            header = "<h2 style='color: red;'>🚨 SBOM VULNERABILITY SCAN ALERT</h2>"
        lines: List[str] = [
            "<html><body>",
            header,
            "<hr>",
            f"<p><strong>Scan Time:</strong> {self.results.get('scan_time', 'Unknown')}</p>",
            f"<p><strong>Components Scanned:</strong> {self.results.get('components_scanned', 0)}</p>",
            "<h3>📦 COMPONENTS ANALYZED</h3>",
            self._format_component_list_html(),
            f"<p><strong>Unique Vulnerabilities Found:</strong> {unique_vulns}</p>",
            "<p><strong>Sources Checked:</strong></p>",
            "<ul>",
            f"<li>NVD Database: {self.results.get('summary', {}).get('nvd', 0)}</li>",
            f"<li>OSV Database: {self.results.get('summary', {}).get('osv', 0)}</li>",
            f"<li>GitHub Security Advisory: {self.results.get('summary', {}).get('github', 0)}</li>",
            f"<li>CISA KEV Catalog: {self.results.get('summary', {}).get('cisa_kev', 0)}</li>",
            f"<li>CISA ICS-CERT: {self.results.get('summary', {}).get('cisa_ics', 0)}</li>",
            f"<li>CVE.org Database: {self.results.get('summary', {}).get('cve_org', 0)}</li>",
            f"<li>CERT/CC Database: {self.results.get('summary', {}).get('cert_cc', 0)}</li>",
            f"<li>Sonatype OSS Index: {self.results.get('summary', {}).get('sonatype', 0)}</li>",
            f"<li>Vulners.com: {self.results.get('summary', {}).get('vulners', 0)}</li>",
            "</ul>",
        ]
        all_vulns = self.results.get("vulnerabilities", [])
        if all_vulns:
            lines.append(
                f"<p><strong>Complete list of {len(all_vulns)} vulnerabilities:</strong></p>"
            )
            lines.append(
                "<table border='1' style='border-collapse: collapse; width: 100%; margin-bottom: 20px;'>"
            )
            lines.append(
                "<tr style='background-color: #f2f2f2;'><th>ID</th><th>Severity</th><th>CVSS</th><th>Component</th><th>Source</th><th>Links</th></tr>"
            )
            for vuln in all_vulns:
                component_info = self._get_component_info(vuln)
                url = vuln.get("url", "#")
                source = vuln.get("source", "Unknown")
                link_cell = (
                    f'<a href="{url}" target="_blank" style="color: #0066cc; text-decoration: underline;">🔗 Details</a>'
                )
                if url not in {"#", "N/A"}:
                    link_cell += (
                        f'<br><small style="color: #666; font-size: 10px;">{url[:40]}{"..." if len(url) > 40 else ""}</small>'
                    )
                severity_color = (
                    "red"
                    if vuln.get("severity") in ["CRITICAL", "HIGH"]
                    else "orange"
                    if vuln.get("severity") == "MEDIUM"
                    else "gray"
                )
                lines.append(
                    f"""
                <tr>
                    <td><strong>{vuln['id']}</strong></td>
                    <td><span style=\"color: {severity_color}; font-weight: bold;\">{vuln.get('severity', 'Unknown')}</span></td>
                    <td>{vuln.get('cvss_score', 'N/A')}</td>
                    <td>{component_info}</td>
                    <td>{source}</td>
                    <td>{link_cell}</td>
                </tr>
                """
                )
            lines.append("</table>")
        else:
            lines.extend(
                [
                    "<div style='background-color: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0;'>",
                    "<h3 style='color: #155724; margin: 0;'>✅ No Vulnerabilities Detected</h3>",
                    "<p style='color: #155724; margin: 10px 0 0 0;'>All components passed security checks across enabled vulnerability sources.</p>",
                    "</div>",
                    "<p><strong>📎 Attached:</strong> Full JSON report with scan details</p>",
                ]
            )
        # Add triage checklists
        lines.extend(self._create_config_checklist_html())
        lines.extend(self._create_interface_checklist_html())
        
        lines.extend(
            [
                f"<hr><p><em>Generated at: {datetime.now().isoformat()}</em></p>",
                "<p><strong>📎 Attachments:</strong> JSON Report, PDF Triage Worksheet</p>",
                "</body></html>",
            ]
        )
        return "".join(lines)

    def _create_config_checklist_html(self) -> List[str]:
        """Create dynamic config checklist for HTML email based on actual SBOM"""
        lines = [
            "<h3 style='color: #4a90d9; margin-top: 30px;'>📋 TRIAGE CHECKLIST: Component Configuration</h3>",
            "<p>Questions generated based on your SBOM components:</p>",
        ]
        
        if self.checklist_data:
            config_items = self.checklist_data.get('config_checklist', [])
            
            # Group by component
            by_component: Dict[str, List] = {}
            for item in config_items:
                comp = item['component']
                if comp not in by_component:
                    by_component[comp] = []
                by_component[comp].append(item)
            
            for comp_name, items in by_component.items():
                lines.append(f"<h4 style='color: #333; margin-top: 15px;'>{comp_name.upper()}</h4>")
                lines.append("<table border='1' style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
                lines.append("<tr style='background-color: #4a90d9; color: white;'>")
                lines.append("<th style='padding: 8px;'>Config Option</th>")
                lines.append("<th style='padding: 8px;'>Your Value</th>")
                lines.append("<th style='padding: 8px;'>Affects CVEs</th>")
                lines.append("</tr>")
                
                for i, item in enumerate(items):
                    bg = '#f0f7ff' if i % 2 else 'white'
                    cves = ', '.join(item['affects_cves'][:3])
                    if len(item['affects_cves']) > 3:
                        cves += '...'
                    lines.append(f"<tr style='background-color: {bg};'>")
                    lines.append(f"<td style='padding: 8px;'><strong>☐ {item['config_option']}</strong><br><small>{item['description']}</small></td>")
                    lines.append(f"<td style='padding: 8px; text-align: center;'>___________</td>")
                    lines.append(f"<td style='padding: 8px;'><code>{cves}</code></td>")
                    lines.append("</tr>")
                
                lines.append("</table>")
        else:
            lines.append("<p><em>Dynamic checklist not available - see PDF attachment for full triage worksheet.</em></p>")
        
        return lines

    def _create_interface_checklist_html(self) -> List[str]:
        """Create dynamic interface checklist for HTML email"""
        lines = [
            "<h3 style='color: #5cb85c; margin-top: 30px;'>🔌 TRIAGE CHECKLIST: System Interfaces</h3>",
        ]
        
        if self.checklist_data:
            comp_types = self.checklist_data.get('component_types', [])
            lines.append(f"<p>Interfaces relevant to your component types: <strong>{', '.join(comp_types)}</strong></p>")
            
            interface_items = self.checklist_data.get('interface_checklist', [])
            
            # Group by category
            by_category: Dict[str, List] = {}
            for item in interface_items:
                cat = item['category']
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(item)
            
            for category, items in by_category.items():
                lines.append(f"<h4 style='color: #5cb85c;'>{category.upper()}</h4>")
                lines.append("<table border='1' style='border-collapse: collapse; width: 100%; margin-bottom: 10px;'>")
                lines.append("<tr style='background-color: #5cb85c; color: white;'>")
                lines.append("<th style='padding: 6px;'>Interface</th>")
                lines.append("<th style='padding: 6px;'>Present?</th>")
                lines.append("<th style='padding: 6px;'>External?</th>")
                lines.append("<th style='padding: 6px;'>Auth?</th>")
                lines.append("</tr>")
                
                for i, item in enumerate(items):
                    bg = '#f0fff0' if i % 2 else 'white'
                    lines.append(f"<tr style='background-color: {bg};'>")
                    lines.append(f"<td style='padding: 6px;'>☐ {item['interface']}<br><small>{item['description']}</small></td>")
                    lines.append(f"<td style='padding: 6px; text-align: center;'>☐Y ☐N</td>")
                    lines.append(f"<td style='padding: 6px; text-align: center;'>☐Y ☐N</td>")
                    lines.append(f"<td style='padding: 6px; text-align: center;'>☐Y ☐N ☐N/A</td>")
                    lines.append("</tr>")
                
                lines.append("</table>")
        else:
            lines.append("<p><em>Dynamic checklist not available - see PDF attachment.</em></p>")
        
        return lines

    def _count_critical_high_vulns(self) -> int:
        return len(
            [
                v
                for v in self.results.get("vulnerabilities", [])
                if v.get("severity") in ["CRITICAL", "HIGH"]
            ]
        )

    def _get_severity_breakdown(self) -> Dict[str, int]:
        breakdown: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "Unknown": 0,
        }
        for vuln in self.results.get("vulnerabilities", []):
            severity = vuln.get("severity", "Unknown")
            if severity in breakdown:
                breakdown[severity] += 1
            else:
                breakdown["Unknown"] += 1
        return breakdown

    def _get_severity_emoji(self, severity: str) -> str:
        emoji_map = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "Unknown": "⚪",
        }
        return emoji_map.get(severity, "⚪")

    def _get_component_info(self, vuln: Dict) -> str:
        comp = vuln.get("component")
        if isinstance(comp, dict):
            name = comp.get("name", "unknown")
            version = comp.get("version", "")
            return f"{name} {version}".strip()
        return "Unknown component"

    def _extract_components_from_results(self) -> List[Dict]:
        scanned_components = self.results.get("scanned_components", [])
        if scanned_components:
            return scanned_components
        components: Set[str] = set()
        component_list: List[Dict] = []
        for vuln in self.results.get("vulnerabilities", []):
            comp = vuln.get("component")
            if isinstance(comp, dict):
                comp_key = f"{comp.get('name', '')}-{comp.get('version', '')}"
                if comp_key not in components:
                    components.add(comp_key)
                    component_list.append(comp)
        return component_list

    def _format_component_list(self) -> str:
        components = self._extract_components_from_results()
        if not components:
            return "  No components found"
        lines: List[str] = []
        for i, comp in enumerate(components, 1):
            name = comp.get("name", "unknown")
            version = comp.get("version", "unknown")
            comp_type = comp.get("type", "unknown")
            lines.append(f"  {i}. {name} {version} ({comp_type})")
        return "\n".join(lines)

    def _format_component_list_html(self) -> str:
        components = self._extract_components_from_results()
        if not components:
            return "<p>No components found</p>"
        lines: List[str] = ["<ul>"]
        for comp in components:
            name = comp.get("name", "unknown")
            version = comp.get("version", "unknown")
            comp_type = comp.get("type", "unknown")
            lines.append(
                f"<li><strong>{name}</strong> {version} <em>({comp_type})</em></li>"
            )
        lines.append("</ul>")
        return "".join(lines)

    def _get_vulnerabilities_2025(self) -> List[Dict]:
        vulns_2025: List[Dict] = []
        for vuln in self.results.get("vulnerabilities", []):
            published_date = vuln.get("published_date", "")
            if published_date and "2025" in published_date:
                vulns_2025.append(vuln)
                continue
            cve_id = vuln.get("id", "") or vuln.get("cve_id", "")
            if "CVE-2025-" in cve_id:
                vulns_2025.append(vuln)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        vulns_2025.sort(key=lambda x: severity_order.get(x.get("severity", "UNKNOWN"), 4))
        return vulns_2025
