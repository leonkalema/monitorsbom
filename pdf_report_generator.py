#!/usr/bin/env python3
"""
PDF Report Generator for SBOM Vulnerability Scanner
Generates professional PDF reports with triage checklists
"""

from datetime import datetime
from typing import Dict, List
from io import BytesIO

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, ListFlowable, ListItem
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from triage_checklist_generator import TriageChecklistGenerator
    CHECKLIST_GENERATOR_AVAILABLE = True
except ImportError:
    CHECKLIST_GENERATOR_AVAILABLE = False


class PDFReportGenerator:
    """Generate PDF vulnerability reports with dynamic triage checklists"""

    def __init__(self, results: Dict):
        self.results = results
        self.styles = getSampleStyleSheet() if REPORTLAB_AVAILABLE else None
        self.checklist_data = None
        
        # Generate dynamic checklist based on actual SBOM
        if CHECKLIST_GENERATOR_AVAILABLE:
            generator = TriageChecklistGenerator(results)
            self.checklist_data = generator.generate_full_checklist()

    def is_available(self) -> bool:
        return REPORTLAB_AVAILABLE

    def generate_pdf(self, output_path: str = None) -> bytes:
        """Generate PDF report and return as bytes"""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab not installed. Run: pip install reportlab")

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm
        )

        story = []
        story.extend(self._build_header())
        story.extend(self._build_component_summary())
        story.extend(self._build_summary())
        story.extend(self._build_vulnerability_table())
        story.append(PageBreak())
        story.extend(self._build_dynamic_config_checklist())
        story.extend(self._build_dynamic_interface_checklist())
        story.extend(self._build_signoff_section())

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)

        return pdf_bytes

    def _build_header(self) -> List:
        """Build report header"""
        elements = []

        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            alignment=TA_CENTER
        )

        subtitle_style = ParagraphStyle(
            'Subtitle',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.grey,
            alignment=TA_CENTER
        )

        elements.append(Paragraph("SBOM VULNERABILITY SCAN REPORT", title_style))
        elements.append(Paragraph("ECU Cybersecurity Triage Worksheet", subtitle_style))
        elements.append(Spacer(1, 12))

        scan_time = self.results.get('scan_time', datetime.now().isoformat())
        info_data = [
            ['Scan Date:', scan_time[:19]],
            ['Components Scanned:', str(self.results.get('components_scanned', 0))],
            ['Total Vulnerabilities:', str(self.results.get('summary', {}).get('unique', 0))],
        ]

        info_table = Table(info_data, colWidths=[120, 300])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))

        elements.append(info_table)
        elements.append(Spacer(1, 20))

        return elements

    def _build_summary(self) -> List:
        """Build severity summary section"""
        elements = []

        elements.append(Paragraph("Severity Summary", self.styles['Heading2']))
        elements.append(Spacer(1, 8))

        summary = self.results.get('summary', {})
        severity_counts = self._get_severity_breakdown()

        summary_data = [
            ['Severity', 'Count', 'Action Required'],
            ['CRITICAL', str(severity_counts.get('CRITICAL', 0)), 'Immediate patch required'],
            ['HIGH', str(severity_counts.get('HIGH', 0)), 'Patch within 7 days'],
            ['MEDIUM', str(severity_counts.get('MEDIUM', 0)), 'Patch within 30 days'],
            ['LOW', str(severity_counts.get('LOW', 0)), 'Patch in next release'],
        ]

        summary_table = Table(summary_data, colWidths=[100, 60, 250])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#333333')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#ffcccc')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#ffe6cc')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#ffffcc')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#ccffcc')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))

        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        return elements

    def _build_vulnerability_table(self) -> List:
        """Build vulnerability details table"""
        elements = []

        elements.append(Paragraph("Vulnerability Details", self.styles['Heading2']))
        elements.append(Spacer(1, 8))

        vulns = self.results.get('vulnerabilities', [])
        if not vulns:
            elements.append(Paragraph("No vulnerabilities found.", self.styles['Normal']))
            return elements

        table_data = [['CVE ID', 'Severity', 'CVSS', 'Component', 'Triage Status']]

        for vuln in vulns[:30]:
            comp = vuln.get('component', {})
            comp_name = f"{comp.get('name', 'unknown')} {comp.get('version', '')}"
            table_data.append([
                vuln.get('id', 'Unknown'),
                vuln.get('severity', 'Unknown'),
                str(vuln.get('cvss_score', 'N/A')),
                comp_name[:25],
                '☐ Pending'
            ])

        vuln_table = Table(table_data, colWidths=[95, 65, 45, 140, 80])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#333333')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (1, 0), (2, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
        ]))

        elements.append(vuln_table)

        if len(vulns) > 30:
            elements.append(Spacer(1, 8))
            elements.append(Paragraph(
                f"... and {len(vulns) - 30} more vulnerabilities (see JSON report)",
                self.styles['Normal']
            ))

        elements.append(Spacer(1, 20))

        return elements

    def _build_component_summary(self) -> List:
        """Build component summary section showing what was scanned"""
        elements = []
        
        if not self.checklist_data:
            return elements
        
        comp_summary = self.checklist_data.get('component_summary', [])
        if not comp_summary:
            return elements
        
        elements.append(Paragraph("Components Analyzed", self.styles['Heading2']))
        elements.append(Spacer(1, 8))
        
        table_data = [['Component', 'Version', 'Type', 'CVEs', 'Critical/High']]
        
        for comp in comp_summary:
            crit_high = comp['severity_counts'].get('CRITICAL', 0) + comp['severity_counts'].get('HIGH', 0)
            table_data.append([
                comp['name'],
                comp['version'],
                comp['type'],
                str(comp['total_cves']),
                str(crit_high) if crit_high > 0 else '-'
            ])
        
        comp_table = Table(table_data, colWidths=[120, 70, 100, 50, 80])
        comp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#333333')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (3, 0), (-1, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(comp_table)
        elements.append(Spacer(1, 20))
        
        return elements

    def _build_dynamic_config_checklist(self) -> List:
        """Build configuration checklist dynamically based on actual SBOM components"""
        elements = []
        
        elements.append(Paragraph(
            "TRIAGE CHECKLIST: Component Configuration",
            self.styles['Heading2']
        ))
        elements.append(Spacer(1, 8))
        
        elements.append(Paragraph(
            "Complete this checklist to determine which CVEs affect your system. "
            "Questions are generated based on the components found in your SBOM.",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 12))
        
        if self.checklist_data:
            config_items = self.checklist_data.get('config_checklist', [])
            
            # Group by component
            by_component = {}
            for item in config_items:
                comp = item['component']
                if comp not in by_component:
                    by_component[comp] = []
                by_component[comp].append(item)
            
            for comp_name, items in by_component.items():
                # Component header
                elements.append(Paragraph(
                    f"<b>{comp_name.upper()}</b>",
                    ParagraphStyle('CompHeader', parent=self.styles['Normal'], 
                                   fontSize=10, textColor=colors.HexColor('#4a90d9'))
                ))
                elements.append(Spacer(1, 4))
                
                table_data = [['Config Option', 'Value', 'Affects CVEs']]
                for item in items:
                    cves = ', '.join(item['affects_cves'][:3])
                    if len(item['affects_cves']) > 3:
                        cves += '...'
                    table_data.append([
                        f"☐ {item['config_option']}",
                        '___________',
                        cves
                    ])
                
                config_table = Table(table_data, colWidths=[200, 80, 180])
                config_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a90d9')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f7ff')]),
                ]))
                
                elements.append(config_table)
                elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph(
                "No component-specific checklist available. Using generic questions.",
                self.styles['Normal']
            ))
        
        elements.append(Spacer(1, 10))
        return elements

    def _build_dynamic_interface_checklist(self) -> List:
        """Build interface checklist dynamically based on component types"""
        elements = []
        
        elements.append(Paragraph(
            "TRIAGE CHECKLIST: System Interfaces",
            self.styles['Heading2']
        ))
        elements.append(Spacer(1, 8))
        
        if self.checklist_data:
            comp_types = self.checklist_data.get('component_types', [])
            elements.append(Paragraph(
                f"Interfaces relevant to your component types: {', '.join(comp_types)}",
                self.styles['Normal']
            ))
        
        elements.append(Spacer(1, 12))
        
        if self.checklist_data:
            interface_items = self.checklist_data.get('interface_checklist', [])
            
            # Group by category
            by_category = {}
            for item in interface_items:
                cat = item['category']
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(item)
            
            for category, items in by_category.items():
                table_data = [['Interface', 'Present?', 'External?', 'Auth?']]
                for item in items:
                    table_data.append([
                        f"☐ {item['interface']}",
                        '☐Y ☐N',
                        '☐Y ☐N',
                        '☐Y ☐N ☐N/A'
                    ])
                
                interface_table = Table(table_data, colWidths=[160, 60, 60, 80])
                interface_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#5cb85c')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0fff0')]),
                ]))
                
                elements.append(Paragraph(
                    f"<b>{category.upper()}</b>",
                    ParagraphStyle('CatHeader', parent=self.styles['Normal'],
                                   fontSize=10, textColor=colors.HexColor('#5cb85c'))
                ))
                elements.append(Spacer(1, 4))
                elements.append(interface_table)
                elements.append(Spacer(1, 10))
        else:
            # Fallback to generic interfaces
            interface_data = [
                ['Interface', 'Present?', 'External?', 'Auth?'],
                ['☐ Network (Ethernet/WiFi)', '☐Y ☐N', '☐Y ☐N', '☐Y ☐N'],
                ['☐ CAN Bus', '☐Y ☐N', '☐Y ☐N', 'N/A'],
                ['☐ Debug Interface', '☐Y ☐N', '☐Y ☐N', '☐Y ☐N'],
                ['☐ OTA Updates', '☐Y ☐N', '☐Y ☐N', '☐Y ☐N'],
            ]
            
            interface_table = Table(interface_data, colWidths=[160, 60, 60, 80])
            interface_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#5cb85c')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(interface_table)
        
        elements.append(Spacer(1, 20))
        return elements

    def _build_signoff_section(self) -> List:
        """Build sign-off section"""
        elements = []

        elements.append(Paragraph("TRIAGE SIGN-OFF", self.styles['Heading2']))
        elements.append(Spacer(1, 12))

        signoff_data = [
            ['Role', 'Name', 'Date', 'Signature'],
            ['Triage Lead', '_________________', '_________', '_________________'],
            ['Security Architect', '_________________', '_________', '_________________'],
            ['Product Owner', '_________________', '_________', '_________________'],
            ['Engineering Lead', '_________________', '_________', '_________________'],
        ]

        signoff_table = Table(signoff_data, colWidths=[120, 130, 80, 130])
        signoff_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#333333')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
        ]))

        elements.append(signoff_table)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("Triage Summary", self.styles['Heading3']))
        elements.append(Spacer(1, 8))

        summary_data = [
            ['Status', 'Count', 'CVE IDs'],
            ['NOT_AFFECTED', '______', '_________________________________'],
            ['AFFECTED (patch required)', '______', '_________________________________'],
            ['EXPLOITABLE (urgent)', '______', '_________________________________'],
            ['ACCEPTED (with rationale)', '______', '_________________________________'],
            ['MITIGATED (compensating ctrl)', '______', '_________________________________'],
        ]

        summary_table = Table(summary_data, colWidths=[160, 50, 230])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#333333')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph(
            f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ParagraphStyle('Footer', parent=self.styles['Normal'], fontSize=8, textColor=colors.grey)
        ))

        return elements

    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity"""
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'Unknown': 0}

        for vuln in self.results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'Unknown')
            if severity in breakdown:
                breakdown[severity] += 1
            else:
                breakdown['Unknown'] += 1

        return breakdown


def test_pdf_generator():
    """Test PDF generation"""
    test_results = {
        'scan_time': '2026-01-22T15:13:03',
        'components_scanned': 6,
        'summary': {'unique': 19, 'nvd': 19},
        'vulnerabilities': [
            {'id': 'CVE-2021-44732', 'severity': 'CRITICAL', 'cvss_score': '9.8',
             'component': {'name': 'mbedtls', 'version': '2.28.1'}},
            {'id': 'CVE-2022-35409', 'severity': 'CRITICAL', 'cvss_score': '9.1',
             'component': {'name': 'mbedtls', 'version': '2.28.1'}},
        ]
    }

    generator = PDFReportGenerator(test_results)
    if generator.is_available():
        pdf_bytes = generator.generate_pdf('/tmp/test-vuln-report.pdf')
        print(f"✅ PDF generated: {len(pdf_bytes)} bytes")
        print("📄 Saved to: /tmp/test-vuln-report.pdf")
    else:
        print("❌ reportlab not available")


if __name__ == "__main__":
    test_pdf_generator()
