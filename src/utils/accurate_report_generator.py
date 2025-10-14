"""
Accurate Report Generator - Uses actual cluster data instead of form inputs
Fixes the N/A metadata issues and endpoint configuration errors
"""

import logging
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

logger = logging.getLogger(__name__)

def _sanitize_log_input(text: str) -> str:
    """Sanitize input for logging to prevent log injection."""
    if not isinstance(text, str):
        return str(text)
    sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
    return sanitized[:200]

class AccurateReportGenerator:
    """
    Generates accurate reports using actual cluster data from AWS APIs
    """
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for the report"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceAfter=6,
            spaceBefore=12,
            textColor=colors.black
        ))
    
    def generate_accurate_report(self, analysis_results: Dict[str, Any], 
                               output_path: str) -> bool:
        """
        Generate accurate PDF report using actual cluster data
        
        Args:
            analysis_results: Results from UnifiedClusterAnalyzer
            output_path: Path to save the PDF report
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            story = []
            
            # Extract data from analysis results
            cluster_metadata = analysis_results.get('cluster_metadata', {})
            consolidated_findings = analysis_results.get('consolidated_findings', {})
            scores = analysis_results.get('scores', {})
            accuracy_validation = analysis_results.get('accuracy_validation', {})
            
            # Title Page
            story.extend(self._create_title_page(cluster_metadata, scores))
            story.append(PageBreak())
            
            # Executive Summary
            story.extend(self._create_executive_summary(cluster_metadata, scores, accuracy_validation))
            story.append(PageBreak())
            
            # Cluster Information (Accurate)
            story.extend(self._create_accurate_cluster_info(cluster_metadata, analysis_results.get('cluster_state', {})))
            story.append(PageBreak())
            
            # Security Analysis
            story.extend(self._create_security_analysis(consolidated_findings, scores))
            story.append(PageBreak())
            
            # Detailed Findings
            story.extend(self._create_detailed_findings(consolidated_findings))
            story.append(PageBreak())
            
            # Recommendations Summary
            story.extend(self._create_recommendations_summary(consolidated_findings))
            
            # Build PDF
            doc.build(story)
            logger.info(f"Accurate report generated successfully: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating accurate report: {_sanitize_log_input(str(e))}")
            return False
    
    def _create_title_page(self, cluster_metadata: Dict[str, Any], 
                          scores: Dict[str, Any]) -> List:
        """Create title page with accurate cluster information"""
        story = []
        
        # Main title
        story.append(Paragraph("EKS Operational Review Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Cluster information table with accurate data
        cluster_data = [
            ['Cluster Name', cluster_metadata.get('cluster_name', 'Unknown')],
            ['Region', cluster_metadata.get('region', 'Unknown')],
            ['Kubernetes Version', cluster_metadata.get('kubernetes_version', 'Unknown')],
            ['Platform Version', cluster_metadata.get('platform_version', 'Unknown')],
            ['Status', cluster_metadata.get('status', 'Unknown')],
            ['Created At', self._format_date(cluster_metadata.get('created_at', 'Unknown'))],
            ['VPC ID', cluster_metadata.get('vpc_id', 'Unknown')],
            ['Security Score', f"{scores.get('security_score', 0)}%"]
        ]
        
        cluster_table = Table(cluster_data, colWidths=[2*inch, 3*inch])
        cluster_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(cluster_table)
        story.append(Spacer(1, 0.5*inch))
        
        # Report generation info
        story.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                              self.styles['Normal']))
        
        return story
    
    def _create_executive_summary(self, cluster_metadata: Dict[str, Any], 
                                scores: Dict[str, Any],
                                accuracy_validation: Dict[str, Any]) -> List:
        """Create executive summary with accurate information"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        # Accurate cluster overview
        overview_text = f"""
        This report provides a comprehensive operational review of the EKS cluster 
        <b>{cluster_metadata.get('cluster_name', 'Unknown')}</b> running Kubernetes version 
        <b>{cluster_metadata.get('kubernetes_version', 'Unknown')}</b> in the 
        <b>{cluster_metadata.get('region', 'Unknown')}</b> region.
        
        The cluster was created on <b>{self._format_date(cluster_metadata.get('created_at', 'Unknown'))}</b> 
        and is currently in <b>{cluster_metadata.get('status', 'Unknown')}</b> status.
        """
        
        story.append(Paragraph(overview_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Security score summary
        security_text = f"""
        <b>Security Analysis Summary:</b><br/>
        Overall Security Score: <b>{scores.get('security_score', 0)}%</b><br/>
        Total Checks Performed: <b>{scores.get('total_checks', 0)}</b><br/>
        Passed Checks: <b>{scores.get('passed_checks', 0)}</b><br/>
        Failed Checks: <b>{scores.get('failed_checks', 0)}</b><br/>
        High Priority Issues: <b>{scores.get('high_priority_issues', 0)}</b><br/>
        Medium Priority Issues: <b>{scores.get('medium_priority_issues', 0)}</b><br/>
        Low Priority Issues: <b>{scores.get('low_priority_issues', 0)}</b>
        """
        
        story.append(Paragraph(security_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Accuracy validation summary
        if accuracy_validation:
            confidence_score = accuracy_validation.get('overall_confidence', 0) * 100
            accuracy_text = f"""
            <b>Report Accuracy Validation:</b><br/>
            Overall Confidence Score: <b>{confidence_score:.1f}%</b><br/>
            Metadata Completeness: <b>{accuracy_validation.get('metadata_accuracy', {}).get('completeness_percentage', 0):.1f}%</b><br/>
            Finding Validation: <b>{accuracy_validation.get('finding_accuracy', {}).get('validated_percentage', 0):.1f}%</b>
            """
            story.append(Paragraph(accuracy_text, self.styles['Normal']))
        
        return story
    
    def _create_accurate_cluster_info(self, cluster_metadata: Dict[str, Any], 
                                    cluster_state: Dict[str, Any]) -> List:
        """Create accurate cluster information section"""
        story = []
        
        story.append(Paragraph("Cluster Configuration", self.styles['SectionHeader']))
        
        # Basic Information
        story.append(Paragraph("Basic Information", self.styles['FindingTitle']))
        
        basic_info = [
            ['Property', 'Value'],
            ['Cluster Name', cluster_metadata.get('cluster_name', 'Unknown')],
            ['Region', cluster_metadata.get('region', 'Unknown')],
            ['Kubernetes Version', cluster_metadata.get('kubernetes_version', 'Unknown')],
            ['Platform Version', cluster_metadata.get('platform_version', 'Unknown')],
            ['Status', cluster_metadata.get('status', 'Unknown')],
            ['Created At', self._format_date(cluster_metadata.get('created_at', 'Unknown'))],
            ['API Endpoint', cluster_metadata.get('endpoint', 'Unknown')]
        ]
        
        basic_table = Table(basic_info, colWidths=[2*inch, 4*inch])
        basic_table.setStyle(self._get_table_style())
        story.append(basic_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Network Configuration (Accurate)
        story.append(Paragraph("Network Configuration", self.styles['FindingTitle']))
        
        endpoint_config = cluster_metadata.get('endpoint_config', {})
        network_info = [
            ['Property', 'Value'],
            ['VPC ID', cluster_metadata.get('vpc_id', 'Unknown')],
            ['Private Endpoint Access', 'Enabled' if endpoint_config.get('private_access') else 'Disabled'],
            ['Public Endpoint Access', 'Enabled' if endpoint_config.get('public_access') else 'Disabled'],
            ['Public Access CIDRs', ', '.join(endpoint_config.get('public_access_cidrs', []))],
            ['Subnet IDs', ', '.join(cluster_metadata.get('subnet_ids', []))[:100] + '...' if len(', '.join(cluster_metadata.get('subnet_ids', []))) > 100 else ', '.join(cluster_metadata.get('subnet_ids', []))],
            ['Security Group IDs', ', '.join(cluster_metadata.get('security_group_ids', []))[:100] + '...' if len(', '.join(cluster_metadata.get('security_group_ids', []))) > 100 else ', '.join(cluster_metadata.get('security_group_ids', []))]
        ]
        
        network_table = Table(network_info, colWidths=[2*inch, 4*inch])
        network_table.setStyle(self._get_table_style())
        story.append(network_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Security Configuration
        story.append(Paragraph("Security Configuration", self.styles['FindingTitle']))
        
        security_state = cluster_state.get('security_state', {})
        secrets_encryption = security_state.get('secrets_encryption', {})
        oidc_provider = security_state.get('oidc_provider', {})
        
        security_info = [
            ['Property', 'Value'],
            ['Secrets Encryption', 'Enabled' if secrets_encryption.get('enabled') else 'Disabled'],
            ['KMS Key ID', secrets_encryption.get('kms_key_id', 'N/A')],
            ['OIDC Provider', 'Configured' if oidc_provider.get('configured') else 'Not Configured'],
            ['OIDC Issuer URL', oidc_provider.get('issuer_url', 'N/A')]
        ]
        
        security_table = Table(security_info, colWidths=[2*inch, 4*inch])
        security_table.setStyle(self._get_table_style())
        story.append(security_table)
        
        return story
    
    def _create_security_analysis(self, consolidated_findings: Dict[str, Any], 
                                scores: Dict[str, Any]) -> List:
        """Create security analysis section"""
        story = []
        
        story.append(Paragraph("Security Analysis", self.styles['SectionHeader']))
        
        # Security score visualization
        score_data = [
            ['Metric', 'Count', 'Percentage'],
            ['Passed Checks', scores.get('passed_checks', 0), f"{(scores.get('passed_checks', 0) / max(scores.get('total_checks', 1), 1)) * 100:.1f}%"],
            ['Failed Checks', scores.get('failed_checks', 0), f"{(scores.get('failed_checks', 0) / max(scores.get('total_checks', 1), 1)) * 100:.1f}%"],
            ['High Priority Issues', scores.get('high_priority_issues', 0), ''],
            ['Medium Priority Issues', scores.get('medium_priority_issues', 0), ''],
            ['Low Priority Issues', scores.get('low_priority_issues', 0), '']
        ]
        
        score_table = Table(score_data, colWidths=[2*inch, 1*inch, 1.5*inch])
        score_table.setStyle(self._get_table_style())
        story.append(score_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Priority breakdown
        priority_text = f"""
        <b>Security Findings Summary:</b><br/>
        The security analysis identified <b>{scores.get('failed_checks', 0)}</b> areas requiring attention 
        out of <b>{scores.get('total_checks', 0)}</b> total checks performed. 
        This results in an overall security score of <b>{scores.get('security_score', 0)}%</b>.
        """
        
        story.append(Paragraph(priority_text, self.styles['Normal']))
        
        return story
    
    def _create_detailed_findings(self, consolidated_findings: Dict[str, Any]) -> List:
        """Create detailed findings section"""
        story = []
        
        story.append(Paragraph("Detailed Security Findings", self.styles['SectionHeader']))
        
        # High Priority Issues
        if consolidated_findings.get('high_priority'):
            story.append(Paragraph("High Priority Issues", self.styles['FindingTitle']))
            for i, finding in enumerate(consolidated_findings['high_priority'], 1):
                story.extend(self._format_finding(finding, i, 'HIGH'))
            story.append(Spacer(1, 0.2*inch))
        
        # Medium Priority Issues
        if consolidated_findings.get('medium_priority'):
            story.append(Paragraph("Medium Priority Issues", self.styles['FindingTitle']))
            for i, finding in enumerate(consolidated_findings['medium_priority'], 1):
                story.extend(self._format_finding(finding, i, 'MEDIUM'))
            story.append(Spacer(1, 0.2*inch))
        
        # Low Priority Issues
        if consolidated_findings.get('low_priority'):
            story.append(Paragraph("Low Priority Issues", self.styles['FindingTitle']))
            for i, finding in enumerate(consolidated_findings['low_priority'], 1):
                story.extend(self._format_finding(finding, i, 'LOW'))
        
        return story
    
    def _create_recommendations_summary(self, consolidated_findings: Dict[str, Any]) -> List:
        """Create recommendations summary"""
        story = []
        
        story.append(Paragraph("Action Items Summary", self.styles['SectionHeader']))
        
        # Create action items table
        action_items = []
        action_items.append(['Priority', 'Category', 'Title', 'Action Required'])
        
        for priority_level, priority_name in [('high_priority', 'High'), ('medium_priority', 'Medium'), ('low_priority', 'Low')]:
            for finding in consolidated_findings.get(priority_level, []):
                action_items.append([
                    priority_name,
                    finding.get('category', 'General'),
                    finding.get('title', 'Unknown'),
                    self._extract_primary_action(finding.get('action_items', []))
                ])
        
        if len(action_items) > 1:  # More than just header
            action_table = Table(action_items, colWidths=[1*inch, 1.5*inch, 2*inch, 2.5*inch])
            action_table.setStyle(self._get_table_style())
            story.append(action_table)
        else:
            story.append(Paragraph("No action items identified. Cluster configuration appears to be optimal.", 
                                 self.styles['Normal']))
        
        return story
    
    def _format_finding(self, finding: Dict[str, Any], index: int, priority: str) -> List:
        """Format individual finding"""
        story = []
        
        # Finding header
        title = f"{index}. {finding.get('title', 'Unknown Issue')} [{priority}]"
        story.append(Paragraph(title, self.styles['FindingTitle']))
        
        # Finding details
        details_text = f"""
        <b>Category:</b> {finding.get('category', 'General')}<br/>
        <b>Description:</b> {finding.get('description', 'No description available')}<br/>
        <b>Current State:</b> {finding.get('current_state', 'Unknown')}<br/>
        <b>Impact:</b> {finding.get('impact', 'No impact specified')}<br/>
        """
        
        story.append(Paragraph(details_text, self.styles['Normal']))
        
        # Action items
        if finding.get('action_items'):
            story.append(Paragraph("<b>Recommended Actions:</b>", self.styles['Normal']))
            if isinstance(finding['action_items'], list):
                for action in finding['action_items']:
                    story.append(Paragraph(f"• {action}", self.styles['Normal']))
            else:
                story.append(Paragraph(f"• {finding['action_items']}", self.styles['Normal']))
        
        story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _get_table_style(self) -> TableStyle:
        """Get standard table style"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ])
    
    def _format_date(self, date_str: str) -> str:
        """Format date string for display"""
        if date_str == 'Unknown' or not date_str:
            return 'Unknown'
        
        try:
            # Try to parse ISO format
            if 'T' in date_str:
                dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
            else:
                return date_str
        except Exception:
            return date_str
    
    def _extract_primary_action(self, action_items: List[str]) -> str:
        """Extract primary action from action items list"""
        if not action_items:
            return "Review configuration"
        
        if isinstance(action_items, list):
            return action_items[0][:50] + "..." if len(action_items[0]) > 50 else action_items[0]
        else:
            return str(action_items)[:50] + "..." if len(str(action_items)) > 50 else str(action_items)
