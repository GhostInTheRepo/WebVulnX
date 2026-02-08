"""
Vulnerability X - Professional PDF Report Generator
Creates branded security assessment reports with full details
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm, mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Rect, Line
from reportlab.graphics import renderPDF
from io import BytesIO
from datetime import datetime
from typing import Dict, Any, List
import traceback


# Brand Colors
BRAND_COLORS = {
    'primary': colors.HexColor('#00d4ff'),      # Cyan
    'secondary': colors.HexColor('#a855f7'),    # Purple  
    'accent': colors.HexColor('#ec4899'),       # Pink
    'dark': colors.HexColor('#0a0a1a'),         # Dark BG
    'card': colors.HexColor('#1a1a2e'),         # Card BG
    'text': colors.HexColor('#f0f0ff'),         # Light text
    'muted': colors.HexColor('#6b6b8a'),        # Muted text
    'success': colors.HexColor('#22c55e'),      # Green
    'warning': colors.HexColor('#f59e0b'),      # Orange
    'danger': colors.HexColor('#ef4444'),       # Red
}

SEVERITY_COLORS = {
    'critical': colors.HexColor('#dc2626'),
    'high': colors.HexColor('#ea580c'),
    'medium': colors.HexColor('#ca8a04'),
    'low': colors.HexColor('#16a34a'),
    'info': colors.HexColor('#0284c7')
}


class VulnerabilityXPDFReport:
    """Branded PDF Report Generator for WebVulnX"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()
        self.page_width, self.page_height = A4
    
    def _setup_styles(self):
        """Setup branded paragraph styles"""
        # Main title
        self.styles.add(ParagraphStyle(
            name='BrandTitle',
            fontSize=32,
            fontName='Helvetica-Bold',
            textColor=BRAND_COLORS['primary'],
            alignment=TA_CENTER,
            spaceAfter=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='BrandSubtitle',
            fontSize=14,
            fontName='Helvetica',
            textColor=BRAND_COLORS['muted'],
            alignment=TA_CENTER,
            spaceAfter=40
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            fontSize=16,
            fontName='Helvetica-Bold',
            textColor=BRAND_COLORS['secondary'],
            spaceBefore=20,
            spaceAfter=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='VulnTitle',
            fontSize=12,
            fontName='Helvetica-Bold',
            textColor=colors.black,
            spaceBefore=10,
            spaceAfter=4
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            fontSize=10,
            fontName='Helvetica',
            textColor=colors.black,
            alignment=TA_JUSTIFY,
            spaceAfter=8
        ))
        
        self.styles.add(ParagraphStyle(
            name='SmallText',
            fontSize=9,
            fontName='Helvetica',
            textColor=colors.gray
        ))
        
        self.styles.add(ParagraphStyle(
            name='CodeText',
            fontSize=9,
            fontName='Courier',
            textColor=colors.darkblue,
            backColor=colors.HexColor('#f5f5f5'),
            leftIndent=10,
            rightIndent=10,
            spaceBefore=5,
            spaceAfter=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='TechCat',
            fontSize=11,
            fontName='Helvetica-Bold',
            textColor=BRAND_COLORS['secondary'],
            spaceBefore=10
        ))
    
    def generate(self, scan_results: Dict[str, Any]) -> bytes:
        """Generate the complete PDF report"""
        try:
            buffer = BytesIO()
            
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=40,
                leftMargin=40,
                topMargin=40,
                bottomMargin=40
            )
            
            story = []
            
            # Cover Page
            story.extend(self._create_cover_page(scan_results))
            story.append(PageBreak())
            
            # Executive Summary
            story.extend(self._create_executive_summary(scan_results))
            story.append(PageBreak())
            
            # Vulnerability Findings
            if scan_results.get('vuln_scan'):
                story.extend(self._create_vulnerability_section(scan_results['vuln_scan']))
            
            # Port Scan Results
            if scan_results.get('port_scan'):
                story.append(PageBreak())
                story.extend(self._create_port_section(scan_results['port_scan']))
            
            # Directory Discovery
            if scan_results.get('dir_fuzz'):
                story.append(PageBreak())
                story.extend(self._create_directory_section(scan_results['dir_fuzz']))
            
            # Technology Detection
            if scan_results.get('tech_detect'):
                story.append(PageBreak())
                story.extend(self._create_technology_section(scan_results['tech_detect']))
                
             # DNS Reconnaissance
            if scan_results.get('dns_recon'):
                story.append(PageBreak())
                story.extend(self._create_dns_section(scan_results['dns_recon']))
            
            # Footer/Appendix
            story.append(PageBreak())
            story.extend(self._create_appendix())
            
            # Build PDF
            doc.build(story)
            
            pdf_bytes = buffer.getvalue()
            buffer.close()
            
            return pdf_bytes
            
        except Exception as e:
            print(f"PDF Generation Error: {str(e)}")
            traceback.print_exc()
            # Return a minimal error PDF
            return self._create_error_pdf(str(e))
    
    def _create_cover_page(self, scan_results: Dict[str, Any]) -> List:
        """Create branded cover page"""
        elements = []
        
        elements.append(Spacer(1, 80))
        
        # Brand Icon (using text-based representation)
        elements.append(Paragraph(
            "🛡️",
            ParagraphStyle(name='Icon', fontSize=60, alignment=TA_CENTER)
        ))
        
        elements.append(Spacer(1, 20))
        
        # Brand Title
        elements.append(Paragraph("WEBVULNX", self.styles['BrandTitle']))
        elements.append(Paragraph("Security Assessment Report", self.styles['BrandSubtitle']))
        
        elements.append(Spacer(1, 60))
        
        # Report Info Box
        target = scan_results.get('target', 'Unknown Target')
        scan_date = scan_results.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        # Try to find IP address from sub-scans
        ip_address = 'Unknown'
        for key in ['tech_detect', 'port_scan', 'vuln_scan', 'dir_fuzz', 'dns_recon']:
            if scan_results.get(key) and isinstance(scan_results[key], dict):
                ip = scan_results[key].get('ip_address') or scan_results[key].get('ip')
                if ip:
                    ip_address = ip
                    break
        
        info_data = [
            ['TARGET', target],
            ['IP ADDRESS', ip_address],
            ['SCAN DATE', scan_date],
            ['GENERATED', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['SCANNER', 'WebVulnX v2.0']
        ]
        
        info_table = Table(info_data, colWidths=[120, 320])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (0, -1), BRAND_COLORS['primary']),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.black),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.lightgrey),
        ]))
        
        elements.append(info_table)
        
        elements.append(Spacer(1, 100))
        
        # Confidential notice
        elements.append(Paragraph(
            "<b>CONFIDENTIAL DOCUMENT</b>",
            ParagraphStyle(
                name='Confidential',
                fontSize=12,
                fontName='Helvetica-Bold',
                textColor=BRAND_COLORS['danger'],
                alignment=TA_CENTER
            )
        ))
        
        elements.append(Spacer(1, 10))
        
        elements.append(Paragraph(
            "This report contains sensitive security information. "
            "Distribution is restricted to authorized personnel only.",
            ParagraphStyle(
                name='ConfNote',
                fontSize=10,
                textColor=colors.gray,
                alignment=TA_CENTER
            )
        ))
        
        return elements
    
    def _create_executive_summary(self, scan_results: Dict[str, Any]) -> List:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("📊 EXECUTIVE SUMMARY", self.styles['SectionTitle']))
        
        # Calculate severity counts
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        max_cvss = 0
        total_cvss = 0
        vuln_count = 0
        
        if scan_results.get('vuln_scan'):
            vulns = scan_results['vuln_scan'].get('vulnerabilities', [])
            for vuln in vulns:
                sev = vuln.get('severity', 'info').lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
                cvss = vuln.get('cvss_score', 0)
                if cvss:
                    max_cvss = max(max_cvss, cvss)
                    total_cvss += cvss
                    vuln_count += 1
        
        avg_cvss = round(total_cvss / vuln_count, 1) if vuln_count > 0 else 0
        total_vulns = sum(severity_counts.values())
        
        # Risk Level
        if severity_counts['critical'] > 0 or max_cvss >= 9.0:
            risk_level = "CRITICAL"
            risk_color = SEVERITY_COLORS['critical']
        elif severity_counts['high'] > 0 or max_cvss >= 7.0:
            risk_level = "HIGH"
            risk_color = SEVERITY_COLORS['high']
        elif severity_counts['medium'] > 0 or max_cvss >= 4.0:
            risk_level = "MEDIUM"
            risk_color = SEVERITY_COLORS['medium']
        else:
            risk_level = "LOW"
            risk_color = SEVERITY_COLORS['low']
        
        elements.append(Paragraph(
            f"<b>Overall Risk Level:</b> <font color='{risk_color.hexval()}'><b>{risk_level}</b></font>",
            ParagraphStyle(name='RiskLevel', fontSize=14, spaceBefore=10, spaceAfter=15)
        ))
        
        # Summary Table
        summary_data = [
            ['Metric', 'Value', 'Status'],
            ['Total Findings', str(total_vulns), '⚠️' if total_vulns > 0 else '✅'],
            ['Critical Issues', str(severity_counts['critical']), '🔴' if severity_counts['critical'] > 0 else '✅'],
            ['High Severity', str(severity_counts['high']), '🟠' if severity_counts['high'] > 0 else '✅'],
            ['Medium Severity', str(severity_counts['medium']), '🟡' if severity_counts['medium'] > 0 else '✅'],
            ['Low Severity', str(severity_counts['low']), '🟢'],
            ['Informational', str(severity_counts['info']), 'ℹ️'],
            ['Highest CVSS', str(max_cvss), ''],
            ['Average CVSS', str(avg_cvss), '']
        ]
        
        summary_table = Table(summary_data, colWidths=[180, 120, 80])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BRAND_COLORS['secondary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(summary_table)
        
        elements.append(Spacer(1, 20))
        
        # Key Recommendations
        elements.append(Paragraph("🎯 KEY RECOMMENDATIONS", self.styles['SectionTitle']))
        
        if severity_counts['critical'] > 0:
            elements.append(Paragraph(
                "• <b>URGENT:</b> Address critical vulnerabilities immediately - they pose severe risk to the system.",
                self.styles['BodyText']
            ))
        
        if severity_counts['high'] > 0:
            elements.append(Paragraph(
                "• <b>HIGH PRIORITY:</b> Remediate high-severity issues within 24-48 hours.",
                self.styles['BodyText']
            ))
        
        if severity_counts['medium'] > 0:
            elements.append(Paragraph(
                "• <b>IMPORTANT:</b> Schedule medium-severity fixes within the next sprint.",
                self.styles['BodyText']
            ))
        
        if total_vulns == 0:
            elements.append(Paragraph(
                "✅ No critical security issues were detected. Continue regular security monitoring.",
                self.styles['BodyText']
            ))
        
        return elements
    
    def _create_vulnerability_section(self, vuln_data: Dict[str, Any]) -> List:
        """Create detailed vulnerability findings section"""
        elements = []
        
        elements.append(Paragraph("🔍 VULNERABILITY FINDINGS", self.styles['SectionTitle']))
        
        vulnerabilities = vuln_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            elements.append(Paragraph(
                "✅ No vulnerabilities were detected during the assessment.",
                self.styles['BodyText']
            ))
            return elements
        
        # Sort by CVSS score
        vulnerabilities.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'info').lower()
            color = SEVERITY_COLORS.get(severity, colors.gray)
            cvss = vuln.get('cvss_score', 'N/A')
            cwe = vuln.get('cwe', 'N/A')
            
            # Vulnerability header
            elements.append(Spacer(1, 10))
            elements.append(Paragraph(
                f"<font color='{color.hexval()}'>[{severity.upper()}]</font> "
                f"<b>{vuln.get('name', 'Unknown Vulnerability')}</b>",
                self.styles['VulnTitle']
            ))
            
            # CVSS and CWE
            elements.append(Paragraph(
                f"<b>CVSS Score:</b> {cvss} | <b>CWE:</b> {cwe}",
                ParagraphStyle(name='CVSSLine', fontSize=10, textColor=colors.gray, leftIndent=10)
            ))
            
            # Description
            if vuln.get('description'):
                elements.append(Paragraph(
                    f"<b>Description:</b> {vuln.get('description', '')}",
                    self.styles['BodyText']
                ))
            
            # Evidence
            if vuln.get('matched_at') or vuln.get('evidence'):
                elements.append(Paragraph("<b>Evidence:</b>", self.styles['SmallText']))
                if vuln.get('matched_at'):
                    elements.append(Paragraph(
                        f"URL: {vuln.get('matched_at', '')}",
                        self.styles['CodeText']
                    ))
                if vuln.get('evidence'):
                    elements.append(Paragraph(
                        vuln.get('evidence', ''),
                        self.styles['CodeText']
                    ))
            
            # Recommendations
            recommendations = vuln.get('recommendation', [])
            if recommendations:
                elements.append(Paragraph("<b>Recommendations:</b>", self.styles['SmallText']))
                for rec in recommendations[:3]:
                    elements.append(Paragraph(
                        f"✓ {rec}",
                        ParagraphStyle(
                            name='RecItem',
                            fontSize=9,
                            leftIndent=15,
                            textColor=BRAND_COLORS['success']
                        )
                    ))
            
            # References  
            references = vuln.get('references', [])
            if references:
                elements.append(Paragraph(
                    f"<b>References:</b> {' | '.join(references[:2])}",
                    ParagraphStyle(name='RefLine', fontSize=8, textColor=colors.blue, leftIndent=10)
                ))
            
            # Separator
            elements.append(Spacer(1, 5))
            elements.append(Paragraph("─" * 70, ParagraphStyle(name='Sep', fontSize=6, textColor=colors.lightgrey)))
        
        return elements
    
    def _create_port_section(self, port_data: Dict[str, Any]) -> List:
        """Create port scan results section"""
        elements = []
        
        elements.append(Paragraph("🔌 PORT SCAN RESULTS", self.styles['SectionTitle']))
        
        ports = port_data.get('ports', [])
        open_count = port_data.get('open_ports', len(ports))
        
        elements.append(Paragraph(
            f"Open Ports Found: <b>{open_count}</b> | Scan Time: {port_data.get('scan_time', 'N/A')}s",
            self.styles['BodyText']
        ))
        
        if not ports:
            elements.append(Paragraph("No open ports were detected.", self.styles['BodyText']))
            return elements
        
        # Port table
        table_data = [['Port', 'State', 'Service', 'Source', 'Risk']]
        
        for port in ports[:20]:
            risk = port.get('risk', 'low')
            risk_icon = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(risk, '⚪')
            source = port.get('source', 'socket').title()
            
            table_data.append([
                str(port.get('port', '')),
                port.get('state', 'open'),
                port.get('service', 'unknown'),
                source,
                f"{risk_icon} {risk.upper()}"
            ])
        
        port_table = Table(table_data, colWidths=[60, 70, 180, 70, 90])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BRAND_COLORS['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(port_table)
        
        return elements
    
    def _create_directory_section(self, dir_data: Dict[str, Any]) -> List:
        """Create directory discovery section"""
        elements = []
        
        elements.append(Paragraph("📁 DIRECTORY DISCOVERY", self.styles['SectionTitle']))
        
        discovered = dir_data.get('discovered', [])
        found_count = dir_data.get('found_count', len(discovered))
        
        elements.append(Paragraph(
            f"Paths Discovered: <b>{found_count}</b> | "
            f"Requests: {dir_data.get('requests_made', 'N/A')} | "
            f"Time: {dir_data.get('scan_time', 'N/A')}s",
            self.styles['BodyText']
        ))
        
        if not discovered:
            elements.append(Paragraph("No hidden directories found.", self.styles['BodyText']))
            return elements
        
        table_data = [['Path', 'Status', 'Type']]
        
        for item in discovered[:25]:
            table_data.append([
                '/' + str(item.get('path', ''))[:45],
                str(item.get('status', '')),
                str(item.get('type', 'other'))
            ])
        
        dir_table = Table(table_data, colWidths=[280, 70, 100])
        dir_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), BRAND_COLORS['accent']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Courier'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
        ]))
        
        elements.append(dir_table)
        
        return elements
    
    def _create_technology_section(self, tech_data: Dict[str, Any]) -> List:
        """Create technology detection section"""
        elements = []
        
        elements.append(Paragraph("🔧 TECHNOLOGY STACK", self.styles['SectionTitle']))
        
        technologies = tech_data.get('technologies', [])
        
        elements.append(Paragraph(
            f"Technologies Detected: <b>{tech_data.get('tech_count', len(technologies))}</b>",
            self.styles['BodyText']
        ))
        
        if not technologies:
            elements.append(Paragraph("No technologies detected.", self.styles['BodyText']))
            return elements
        
        # Group by category
        by_category = tech_data.get('by_category', {})
        
        if by_category:
            for category, techs in by_category.items():
                elements.append(Paragraph(
                    f"<b>{category}</b>",
                    ParagraphStyle(name='TechCat', fontSize=11, spaceBefore=10, textColor=BRAND_COLORS['secondary'])
                ))
                
                for tech in techs:
                    version = f" v{tech['version']}" if tech.get('version') else ""
                    elements.append(Paragraph(
                        f"• {tech.get('icon', '🔧')} {tech['name']}{version}",
                        self.styles['BodyText']
                    ))
        else:
            for tech in technologies:
                version = f" v{tech['version']}" if tech.get('version') else ""
                elements.append(Paragraph(
                    f"• {tech.get('icon', '🔧')} {tech.get('name', 'Unknown')}{version} - {tech.get('category', 'Other')}",
                    self.styles['BodyText']
                ))
        
        return elements
    
    def _create_dns_section(self, dns_data: Dict[str, Any]) -> List:
        """Create DNS reconnaissance section"""
        elements = []
        
        elements.append(Paragraph("🌍 DNS RECONNAISSANCE", self.styles['SectionTitle']))
        
        records = dns_data.get('records', {})
        total_records = dns_data.get('total_records', 0)
        
        elements.append(Paragraph(
            f"Records Found: <b>{total_records}</b> | "
            f"Time: {dns_data.get('scan_time', 'N/A')}s",
            self.styles['BodyText']
        ))
        
        if not records:
            elements.append(Paragraph("No DNS records found.", self.styles['BodyText']))
            return elements

        # A Records Table
        if 'A' in records and records['A']:
            elements.append(Paragraph("<b>A Records (Hosts)</b>", self.styles['TechCat']))
            
            # Group by IP
            ip_map = {}
            for rec in records['A']:
                ip = rec.get('data')
                if ip not in ip_map:
                    ip_map[ip] = set()
                
                host = rec.get('name', '')
                if host.endswith('.'): host = host[:-1]
                ip_map[ip].add(host)
            
            table_data = [['IP Address', 'Hosts']]
            for ip, hosts in ip_map.items():
                table_data.append([
                    ip,
                    ', '.join(hosts)[:60] + ('...' if len(', '.join(hosts)) > 60 else '')
                ])
                
            a_table = Table(table_data, colWidths=[120, 330])
            a_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), BRAND_COLORS['primary']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
            ]))
            elements.append(a_table)
            elements.append(Spacer(1, 15))

        # Other Records
        other_types = ['AAAA', 'MX', 'NS', 'TXT', 'SOA']
        for rtype in other_types:
            if rtype in records and records[rtype]:
                elements.append(Paragraph(f"<b>{rtype} Records</b>", self.styles['TechCat']))
                
                for rec in records[rtype]:
                    elements.append(Paragraph(
                        f"• {rec.get('data', '')}",
                        self.styles['CodeText']
                    ))
                elements.append(Spacer(1, 5))
        
        return elements

    def _create_appendix(self) -> List:
        """Create appendix with CVSS reference"""
        elements = []
        
        elements.append(Paragraph("📚 APPENDIX: CVSS SCORING", self.styles['SectionTitle']))
        
        elements.append(Paragraph(
            "The Common Vulnerability Scoring System (CVSS) provides a standardized way to "
            "assess the severity of security vulnerabilities.",
            self.styles['BodyText']
        ))
        
        cvss_data = [
            ['Score Range', 'Severity', 'Action Required'],
            ['9.0 - 10.0', 'CRITICAL', 'Immediate remediation required'],
            ['7.0 - 8.9', 'HIGH', 'Prioritize within 24-48 hours'],
            ['4.0 - 6.9', 'MEDIUM', 'Schedule for next sprint'],
            ['0.1 - 3.9', 'LOW', 'Address when resources permit'],
            ['0.0', 'NONE', 'Informational only']
        ]
        
        cvss_table = Table(cvss_data, colWidths=[100, 100, 250])
        cvss_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(cvss_table)
        
        elements.append(Spacer(1, 40))
        
        # Footer
        elements.append(Paragraph(
            f"Report generated by <b>WebVulnX</b> | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ParagraphStyle(name='Footer', fontSize=10, textColor=colors.gray, alignment=TA_CENTER)
        ))
        
        elements.append(Spacer(1, 10))
        
        elements.append(Paragraph(
            "🛡️ WebVulnX - Professional Security Assessment",
            ParagraphStyle(name='Brand', fontSize=12, textColor=BRAND_COLORS['primary'], alignment=TA_CENTER, fontName='Helvetica-Bold')
        ))
        
        return elements
    
    def _create_error_pdf(self, error_msg: str) -> bytes:
        """Create a minimal PDF with error message"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        
        story = [
            Spacer(1, 100),
            Paragraph("WebVulnX", self.styles['BrandTitle']),
            Spacer(1, 30),
            Paragraph("Error Generating Report", ParagraphStyle(
                name='Error',
                fontSize=16,
                textColor=colors.red,
                alignment=TA_CENTER
            )),
            Spacer(1, 20),
            Paragraph(f"Error: {error_msg}", self.styles['BodyText']),
            Spacer(1, 20),
            Paragraph("Please check the scan results and try again.", self.styles['BodyText'])
        ]
        
        doc.build(story)
        result = buffer.getvalue()
        buffer.close()
        return result


def generate(scan_results: Dict[str, Any], output_path: str = None) -> bytes:
    """Module-level generate function"""
    try:
        generator = VulnerabilityXPDFReport()
        pdf_bytes = generator.generate(scan_results)
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)
        
        return pdf_bytes
    except Exception as e:
        print(f"PDF Generation Failed: {e}")
        traceback.print_exc()
        # Return error PDF
        generator = VulnerabilityXPDFReport()
        return generator._create_error_pdf(str(e))
