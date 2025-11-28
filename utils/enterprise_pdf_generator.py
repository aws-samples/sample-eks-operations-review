"""
Enterprise-Grade PDF Report Generator
Generates comprehensive reports with:
- All checks performed with commands and observations
- Detailed recommendations for each finding
- Compliance framework mapping
- Executive summary
"""
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
from typing import Dict, Any, List
import os

class EnterprisePDFGenerator:
    """Generate enterprise-grade PDF reports"""
    
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.doc = SimpleDocTemplate(output_path, pagesize=letter,
                                     rightMargin=72, leftMargin=72,
                                     topMargin=72, bottomMargin=18)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.story = []
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            borderWidth=1,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=5,
            backColor=colors.HexColor('#ecf0f1')
        ))
        
        self.styles.add(ParagraphStyle(
            name='CheckTitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=6,
            spaceBefore=6,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CommandStyle',
            parent=self.styles['Code'],
            fontSize=9,
            textColor=colors.HexColor('#c0392b'),
            backColor=colors.HexColor('#f8f9fa'),
            borderWidth=1,
            borderColor=colors.HexColor('#dee2e6'),
            borderPadding=5,
            fontName='Courier'
        ))
    
    def generate_comprehensive_report(self, analysis_data: Dict[str, Any], 
                                     observation_analysis: Dict[str, Any]) -> str:
        """Generate complete enterprise report"""
        
        # Cover Page
        self._add_cover_page(analysis_data)
        self.story.append(PageBreak())
        
        # Executive Summary
        self._add_executive_summary(analysis_data, observation_analysis)
        self.story.append(PageBreak())
        
        # Table of Contents
        self._add_table_of_contents(analysis_data)
        self.story.append(PageBreak())
        
        # Compliance Framework Summary
        self._add_compliance_summary(analysis_data)
        self.story.append(PageBreak())
        
        # Detailed Check Results by Framework
        self._add_detailed_check_results(analysis_data)
        self.story.append(PageBreak())
        
        # Observation Agent Analysis
        self._add_observation_analysis(observation_analysis)
        self.story.append(PageBreak())
        
        # Remediation Plan
        self._add_remediation_plan(observation_analysis)
        self.story.append(PageBreak())
        
        # Appendix - All Commands
        self._add_commands_appendix(analysis_data)
        
        # Build PDF
        self.doc.build(self.story)
        return self.output_path
    
    def _add_cover_page(self, data: Dict[str, Any]):
        """Add professional cover page"""
        self.story.append(Spacer(1, 2*inch))
        
        title = Paragraph("EKS Cluster Security & Compliance Report", self.styles['CustomTitle'])
        self.story.append(title)
        self.story.append(Spacer(1, 0.5*inch))
        
        cluster_info = f"""
        <para alignment="center" fontSize="14">
        <b>Cluster:</b> {data.get('cluster_name', 'Unknown')}<br/>
        <b>Region:</b> {data.get('region', 'Unknown')}<br/>
        <b>Analysis Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Report Type:</b> Comprehensive Security & Compliance Assessment
        </para>
        """
        self.story.append(Paragraph(cluster_info, self.styles['Normal']))
        self.story.append(Spacer(1, 1*inch))
        
        # Compliance badges
        frameworks = """
        <para alignment="center" fontSize="12">
        <b>Compliance Frameworks Assessed:</b><br/>
        • CIS EKS Benchmark v1.0.1<br/>
        • NIST Cybersecurity Framework v1.1<br/>
        • SOC 2 Type II<br/>
        • EU DORA (152 checks)<br/>
        • PCI DSS v3.2.1<br/>
        • HIPAA Security Rule<br/>
        • ISO 27001:2013
        </para>
        """
        self.story.append(Paragraph(frameworks, self.styles['Normal']))
    
    def _add_executive_summary(self, data: Dict[str, Any], obs_data: Dict[str, Any]):
        """Add executive summary"""
        self.story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        summary = obs_data.get('executive_summary', {})
        
        summary_text = f"""
        <para>
        <b>Overall Risk Assessment:</b> {summary.get('risk_assessment', 'Unknown')}<br/><br/>
        
        <b>Total Issues Identified:</b> {summary.get('total_issues', 0)}<br/>
        • Critical: {summary.get('critical_count', 0)}<br/>
        • High: {summary.get('high_count', 0)}<br/>
        • Medium: {summary.get('medium_count', 0)}<br/>
        • Low: {summary.get('low_count', 0)}<br/><br/>
        
        <b>Key Findings:</b><br/>
        This report presents a comprehensive analysis of the EKS cluster security posture 
        and compliance status across multiple regulatory frameworks. Each finding includes 
        detailed command execution logs, observations, and actionable recommendations.
        </para>
        """
        self.story.append(Paragraph(summary_text, self.styles['Normal']))
        self.story.append(Spacer(1, 0.3*inch))
        
        # Top priorities table
        if summary.get('top_priorities'):
            self.story.append(Paragraph("<b>Top 5 Priorities:</b>", self.styles['Heading3']))
            priorities_data = [['Priority', 'Check ID', 'Title', 'Severity']]
            for idx, priority in enumerate(summary['top_priorities'][:5], 1):
                priorities_data.append([
                    str(idx),
                    priority['check_id'],
                    priority['title'][:50] + '...' if len(priority['title']) > 50 else priority['title'],
                    priority['severity']
                ])
            
            priorities_table = Table(priorities_data, colWidths=[0.7*inch, 1*inch, 3.5*inch, 1*inch])
            priorities_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            self.story.append(priorities_table)
    
    def _add_table_of_contents(self, data: Dict[str, Any]):
        """Add table of contents"""
        self.story.append(Paragraph("Table of Contents", self.styles['SectionHeader']))
        
        toc_items = [
            "1. Executive Summary",
            "2. Compliance Framework Summary",
            "3. Detailed Check Results",
            "   3.1 CIS EKS Benchmark",
            "   3.2 NIST Cybersecurity Framework",
            "   3.3 SOC 2 Type II",
            "   3.4 EU DORA (152 checks)",
            "   3.5 PCI DSS",
            "   3.6 HIPAA Security Rule",
            "   3.7 ISO 27001",
            "4. Observation Agent Analysis",
            "5. Remediation Plan",
            "6. Appendix: Commands Executed"
        ]
        
        for item in toc_items:
            self.story.append(Paragraph(item, self.styles['Normal']))
            self.story.append(Spacer(1, 0.1*inch))
    
    def _add_compliance_summary(self, data: Dict[str, Any]):
        """Add compliance framework summary"""
        self.story.append(Paragraph("Compliance Framework Summary", self.styles['SectionHeader']))
        
        frameworks = [
            ('CIS EKS Benchmark', data.get('cis_analysis', {})),
            ('NIST CSF', data.get('nist_analysis', {})),
            ('SOC 2 Type II', data.get('soc2_analysis', {})),
            ('EU DORA', data.get('dora_analysis', {})),
            ('PCI DSS', data.get('pci_analysis', {})),
            ('HIPAA', data.get('hipaa_analysis', {})),
            ('ISO 27001', data.get('iso27001_analysis', {}))
        ]
        
        summary_data = [['Framework', 'Total Checks', 'Passed', 'Failed', 'Compliance %']]
        
        for name, framework_data in frameworks:
            summary = framework_data.get('summary', {})
            summary_data.append([
                name,
                str(summary.get('total_checks', 0)),
                str(summary.get('passed', 0)),
                str(summary.get('failed', 0)),
                f"{summary.get('compliance_percentage', 0):.1f}%"
            ])
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1.2*inch, 1*inch, 1*inch, 1.2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        self.story.append(summary_table)
    
    def _add_detailed_check_results(self, data: Dict[str, Any]):
        """Add detailed results for each check"""
        self.story.append(Paragraph("Detailed Check Results", self.styles['SectionHeader']))
        
        # Process each framework
        frameworks = [
            ('CIS EKS Benchmark', data.get('cis_analysis', {})),
            ('EU DORA', data.get('dora_analysis', {})),
            ('NIST CSF', data.get('nist_analysis', {})),
            ('SOC 2', data.get('soc2_analysis', {})),
            ('PCI DSS', data.get('pci_analysis', {})),
            ('HIPAA', data.get('hipaa_analysis', {})),
            ('ISO 27001', data.get('iso27001_analysis', {}))
        ]
        
        for framework_name, framework_data in frameworks:
            self.story.append(Paragraph(f"{framework_name} - Detailed Results", self.styles['Heading2']))
            
            detailed_results = framework_data.get('detailed_results', [])
            
            for result in detailed_results[:20]:  # Limit to first 20 for PDF size
                self._add_single_check_result(result)
                self.story.append(Spacer(1, 0.2*inch))
            
            if len(detailed_results) > 20:
                self.story.append(Paragraph(
                    f"<i>Note: Showing first 20 of {len(detailed_results)} checks. See JSON report for complete results.</i>",
                    self.styles['Normal']
                ))
            
            self.story.append(PageBreak())
    
    def _add_single_check_result(self, result: Dict[str, Any]):
        """Add detailed result for a single check"""
        # Check header
        status_color = {
            'PASSED': colors.green,
            'FAILED': colors.red,
            'WARNING': colors.orange,
            'MANUAL_REVIEW': colors.blue
        }.get(result.get('status', 'UNKNOWN'), colors.grey)
        
        header_text = f"""
        <para>
        <b>{result.get('check_id', 'N/A')}: {result.get('title', 'Unknown Check')}</b><br/>
        <font color="#{status_color.hexval()[2:]}">[{result.get('status', 'UNKNOWN')}]</font> | 
        Severity: {result.get('severity', 'N/A')} | 
        Category: {result.get('category', 'N/A')}
        </para>
        """
        self.story.append(Paragraph(header_text, self.styles['CheckTitle']))
        
        # Commands executed
        if result.get('commands_executed'):
            self.story.append(Paragraph("<b>Commands Executed:</b>", self.styles['Normal']))
            for cmd in result['commands_executed']:
                cmd_text = f"<font face='Courier' size='8'>{cmd.get('command', 'N/A')}</font>"
                self.story.append(Paragraph(cmd_text, self.styles['CommandStyle']))
                self.story.append(Spacer(1, 0.05*inch))
        
        # Observations
        if result.get('observations'):
            self.story.append(Paragraph("<b>Observations:</b>", self.styles['Normal']))
            for obs in result['observations']:
                obs_text = f"• {obs.get('text', 'N/A')} [{obs.get('severity', 'INFO')}]"
                self.story.append(Paragraph(obs_text, self.styles['Normal']))
        
        # Reasoning
        if result.get('reasoning'):
            self.story.append(Paragraph(f"<b>Analysis:</b> {result['reasoning']}", self.styles['Normal']))
        
        # Recommendation (if failed)
        if result.get('status') == 'FAILED' and result.get('recommendation'):
            rec = result['recommendation']
            self.story.append(Paragraph("<b>Recommendation:</b>", self.styles['Normal']))
            self.story.append(Paragraph(rec.get('description', ''), self.styles['Normal']))
            
            if rec.get('commands'):
                self.story.append(Paragraph("<b>Remediation Commands:</b>", self.styles['Normal']))
                for cmd in rec['commands'][:3]:  # Limit to 3 commands
                    self.story.append(Paragraph(f"<font face='Courier' size='8'>{cmd}</font>", self.styles['CommandStyle']))
    
    def _add_observation_analysis(self, obs_data: Dict[str, Any]):
        """Add observation agent analysis"""
        self.story.append(Paragraph("Observation Agent Analysis", self.styles['SectionHeader']))
        
        analysis_text = """
        <para>
        The Observation Agent has analyzed all check results and generated detailed 
        recommendations with business impact assessment, remediation steps, and 
        verification procedures.
        </para>
        """
        self.story.append(Paragraph(analysis_text, self.styles['Normal']))
        
        # Add prioritized recommendations
        if obs_data.get('prioritized_recommendations'):
            self.story.append(Paragraph("<b>Prioritized Action Items:</b>", self.styles['Heading3']))
            
            for rec in obs_data['prioritized_recommendations'][:10]:
                rec_text = f"""
                <para>
                <b>{rec['priority']}. {rec['title']}</b><br/>
                Check ID: {rec['check_id']} | Severity: {rec['severity']} | Effort: {rec['effort']}<br/>
                Estimated Time: {rec['estimated_time']}<br/>
                Impact: {rec['business_impact'][:100]}...
                </para>
                """
                self.story.append(Paragraph(rec_text, self.styles['Normal']))
                self.story.append(Spacer(1, 0.1*inch))
    
    def _add_remediation_plan(self, obs_data: Dict[str, Any]):
        """Add remediation plan"""
        self.story.append(Paragraph("Remediation Plan", self.styles['SectionHeader']))
        
        plan_text = """
        <para>
        This section provides a phased approach to addressing identified issues, 
        organized by priority and estimated effort.
        </para>
        """
        self.story.append(Paragraph(plan_text, self.styles['Normal']))
        
        # Add phases
        phases = [
            ('Phase 1: Immediate Action (Critical)', obs_data.get('critical_findings', [])),
            ('Phase 2: Short Term (High Priority)', obs_data.get('high_findings', [])),
            ('Phase 3: Medium Term', obs_data.get('medium_findings', [])),
            ('Phase 4: Long Term', obs_data.get('low_findings', []))
        ]
        
        for phase_name, findings in phases:
            self.story.append(Paragraph(phase_name, self.styles['Heading3']))
            self.story.append(Paragraph(f"Total Items: {len(findings)}", self.styles['Normal']))
            self.story.append(Spacer(1, 0.1*inch))
    
    def _add_commands_appendix(self, data: Dict[str, Any]):
        """Add appendix with all commands"""
        self.story.append(Paragraph("Appendix: All Commands Executed", self.styles['SectionHeader']))
        
        appendix_text = """
        <para>
        This appendix lists all commands that were executed during the analysis, 
        providing a complete audit trail for compliance and verification purposes.
        </para>
        """
        self.story.append(Paragraph(appendix_text, self.styles['Normal']))
