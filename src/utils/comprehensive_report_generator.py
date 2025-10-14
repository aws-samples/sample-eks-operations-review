import logging
import os
from datetime import datetime
from typing import Dict, List, Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.units import inch

logger = logging.getLogger(__name__)

class ComprehensiveReportGenerator:
    """Generate comprehensive EKS cluster analysis reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()
    
    def _setup_styles(self):
        """Setup custom styles for the report"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#232F3E')
        ))
        
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceBefore=10,
            spaceAfter=10,
            leftIndent=20,
            rightIndent=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='FindingHigh',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.red,
            leftIndent=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='FindingMedium',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.orange,
            leftIndent=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='FindingLow',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=colors.blue,
            leftIndent=20
        ))
    
    def generate_comprehensive_report(self, analysis_results: Dict[str, Any], 
                                    cluster_name: str, output_path: str) -> str:
        """Generate comprehensive PDF report"""
        try:
            # Create the PDF document
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            story = []
            
            # Title page
            story.extend(self._create_title_page(cluster_name, analysis_results))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(analysis_results))
            story.append(PageBreak())
            
            # Cluster overview
            story.extend(self._create_cluster_overview(analysis_results))
            story.append(PageBreak())
            
            # Security analysis
            story.extend(self._create_security_section(analysis_results))
            story.append(PageBreak())
            
            # Workload analysis
            story.extend(self._create_workload_section(analysis_results))
            story.append(PageBreak())
            
            # Cost optimization
            story.extend(self._create_cost_section(analysis_results))
            story.append(PageBreak())
            
            # Performance analysis
            story.extend(self._create_performance_section(analysis_results))
            story.append(PageBreak())
            
            # Reliability analysis
            story.extend(self._create_reliability_section(analysis_results))
            story.append(PageBreak())
            
            # Compliance analysis
            story.extend(self._create_compliance_section(analysis_results))
            story.append(PageBreak())
            
            # Recommendations summary
            story.extend(self._create_recommendations_summary(analysis_results))
            
            # Build the PDF
            doc.build(story)
            
            logger.info(f"Comprehensive report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate comprehensive report: {e}")
            raise
    
    def _create_title_page(self, cluster_name: str, analysis_results: Dict[str, Any]) -> List:
        """Create title page"""
        story = []
        
        # Title
        story.append(Paragraph("EKS Cluster Comprehensive Analysis Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Cluster information
        story.append(Paragraph(f"<b>Cluster Name:</b> {cluster_name}", self.styles['Normal']))
        story.append(Paragraph(f"<b>Analysis Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal']))
        
        # Get cluster metadata
        cluster_metadata = analysis_results.get('cluster_level', {}).get('cluster_metadata', {})
        if cluster_metadata:
            story.append(Paragraph(f"<b>Kubernetes Version:</b> {cluster_metadata.get('version_info', {}).get('current', 'N/A')}", self.styles['Normal']))
            story.append(Paragraph(f"<b>Region:</b> {cluster_metadata.get('cluster', {}).get('region', 'N/A')}", self.styles['Normal']))
            story.append(Paragraph(f"<b>Status:</b> {cluster_metadata.get('cluster', {}).get('status', 'N/A')}", self.styles['Normal']))
        
        story.append(Spacer(1, 1*inch))
        
        # Analysis scope
        story.append(Paragraph("<b>Analysis Scope:</b>", self.styles['Heading2']))
        scope_items = [
            "• Cluster-level configuration and security",
            "• Namespace-level policies and configurations", 
            "• Workload analysis (Deployments, StatefulSets, DaemonSets)",
            "• Security deep dive and compliance",
            "• Cost optimization opportunities",
            "• Performance and reliability assessment",
            "• Add-on analysis and upgrade readiness"
        ]
        
        for item in scope_items:
            story.append(Paragraph(item, self.styles['Normal']))
        
        return story
    
    def _create_executive_summary(self, analysis_results: Dict[str, Any]) -> List:
        """Create executive summary"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        # Get consolidated recommendations
        recommendations = analysis_results.get('consolidated_recommendations', [])
        
        # Count findings by severity
        high_count = len([r for r in recommendations if r.get('severity') == 'High'])
        medium_count = len([r for r in recommendations if r.get('severity') == 'Medium'])
        low_count = len([r for r in recommendations if r.get('severity') == 'Low'])
        
        # Summary statistics
        summary_data = [
            ['Metric', 'Count', 'Status'],
            ['High Priority Findings', str(high_count), 'Requires Immediate Action' if high_count > 0 else 'Good'],
            ['Medium Priority Findings', str(medium_count), 'Should Address Soon' if medium_count > 0 else 'Good'],
            ['Low Priority Findings', str(low_count), 'Consider for Future' if low_count > 0 else 'Good'],
            ['Total Findings', str(len(recommendations)), 'Overall Assessment']
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Key findings summary
        story.append(Paragraph("<b>Key Findings:</b>", self.styles['Heading2']))
        
        if high_count > 0:
            story.append(Paragraph(f"• <b>Critical Issues:</b> {high_count} high-priority findings require immediate attention", 
                                 self.styles['ExecutiveSummary']))
        
        if medium_count > 0:
            story.append(Paragraph(f"• <b>Important Issues:</b> {medium_count} medium-priority findings should be addressed soon", 
                                 self.styles['ExecutiveSummary']))
        
        # Top 3 recommendations
        if recommendations:
            story.append(Paragraph("<b>Top Priority Recommendations:</b>", self.styles['Heading2']))
            for i, rec in enumerate(recommendations[:3], 1):
                story.append(Paragraph(f"{i}. {rec.get('recommendation', 'N/A')}", self.styles['ExecutiveSummary']))
        
        return story
    
    def _create_cluster_overview(self, analysis_results: Dict[str, Any]) -> List:
        """Create cluster overview section"""
        story = []
        
        story.append(Paragraph("Cluster Overview", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        cluster_level = analysis_results.get('cluster_level', {})
        cluster_metadata = cluster_level.get('cluster_metadata', {})
        
        if cluster_metadata:
            # Cluster configuration table
            cluster_info = cluster_metadata.get('cluster', {})
            version_info = cluster_metadata.get('version_info', {})
            networking = cluster_metadata.get('networking', {})
            
            config_data = [
                ['Configuration', 'Value'],
                ['Cluster Name', cluster_info.get('name', 'N/A')],
                ['Kubernetes Version', version_info.get('current', 'N/A')],
                ['Platform Version', cluster_info.get('platform_version', 'N/A')],
                ['Status', cluster_info.get('status', 'N/A')],
                ['Region', cluster_info.get('region', 'N/A')],
                ['VPC ID', networking.get('vpc_id', 'N/A')],
                ['Public Endpoint', 'Enabled' if networking.get('endpoint_access', {}).get('public') else 'Disabled'],
                ['Private Endpoint', 'Enabled' if networking.get('endpoint_access', {}).get('private') else 'Disabled']
            ]
            
            config_table = Table(config_data, colWidths=[2*inch, 3*inch])
            config_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(config_table)
            story.append(Spacer(1, 0.3*inch))
        
        # Node groups information
        nodegroups = cluster_metadata.get('nodegroups', [])
        if nodegroups:
            story.append(Paragraph("<b>Node Groups:</b>", self.styles['Heading2']))
            
            ng_data = [['Name', 'Instance Type', 'Capacity Type', 'Min Size', 'Max Size', 'Desired Size']]
            for ng in nodegroups:
                ng_data.append([
                    ng.get('name', 'N/A'),
                    ng.get('instanceType', 'N/A'),
                    ng.get('capacityType', 'N/A'),
                    str(ng.get('minSize', 'N/A')),
                    str(ng.get('maxSize', 'N/A')),
                    str(ng.get('desiredSize', 'N/A'))
                ])
            
            ng_table = Table(ng_data, colWidths=[1.2*inch, 1*inch, 1*inch, 0.8*inch, 0.8*inch, 0.8*inch])
            ng_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(ng_table)
        
        return story
    
    def _create_security_section(self, analysis_results: Dict[str, Any]) -> List:
        """Create security analysis section"""
        story = []
        
        story.append(Paragraph("Security Analysis", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        security_analysis = analysis_results.get('security_deep_dive', {})
        findings = security_analysis.get('findings', [])
        
        if findings:
            story.append(Paragraph("<b>Security Findings:</b>", self.styles['Heading2']))
            
            for finding in findings:
                severity = finding.get('severity', 'Low')
                style = self.styles[f'Finding{severity}'] if f'Finding{severity}' in self.styles else self.styles['Normal']
                
                story.append(Paragraph(f"<b>[{severity.upper()}]</b> {finding.get('finding', 'N/A')}", style))
                story.append(Paragraph(f"<b>Recommendation:</b> {finding.get('recommendation', 'N/A')}", self.styles['Normal']))
                story.append(Paragraph(f"<b>Impact:</b> {finding.get('impact', 'N/A')}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
        
        # Security metrics
        story.append(Paragraph("<b>Security Metrics:</b>", self.styles['Heading2']))
        
        metrics_data = [
            ['Metric', 'Count'],
            ['Privileged Containers', str(security_analysis.get('privileged_containers_count', 0))],
            ['Root Containers', str(security_analysis.get('root_containers_count', 0))]
        ]
        
        metrics_table = Table(metrics_data, colWidths=[3*inch, 1*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(metrics_table)
        
        return story
    
    def _create_workload_section(self, analysis_results: Dict[str, Any]) -> List:
        """Create workload analysis section"""
        story = []
        
        story.append(Paragraph("Workload Analysis", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        workload_analysis = analysis_results.get('workload_level', {})
        
        # Deployments analysis
        deployments = workload_analysis.get('deployments', [])
        if deployments:
            story.append(Paragraph("<b>Deployment Analysis:</b>", self.styles['Heading2']))
            
            deployment_issues = []
            for deployment in deployments:
                if deployment.get('findings'):
                    deployment_issues.extend(deployment['findings'])
            
            if deployment_issues:
                for issue in deployment_issues[:5]:  # Show top 5 issues
                    severity = issue.get('severity', 'Low')
                    style = self.styles[f'Finding{severity}'] if f'Finding{severity}' in self.styles else self.styles['Normal']
                    
                    story.append(Paragraph(f"<b>[{severity.upper()}]</b> {issue.get('finding', 'N/A')}", style))
                    story.append(Paragraph(f"<b>Recommendation:</b> {issue.get('recommendation', 'N/A')}", self.styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
        
        # Workload summary
        story.append(Paragraph("<b>Workload Summary:</b>", self.styles['Heading2']))
        
        workload_data = [
            ['Resource Type', 'Count'],
            ['Deployments', str(len(deployments))],
            ['DaemonSets', str(len(workload_analysis.get('daemonsets', [])))],
            ['StatefulSets', str(len(workload_analysis.get('statefulsets', [])))],
            ['Services', str(len(workload_analysis.get('services', [])))]
        ]
        
        workload_table = Table(workload_data, colWidths=[3*inch, 1*inch])
        workload_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(workload_table)
        
        return story
    
    def _create_cost_section(self, analysis_results: Dict[str, Any]) -> List:
        """Create cost optimization section"""
        story = []
        
        story.append(Paragraph("Cost Optimization", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        cost_analysis = analysis_results.get('cost_optimization', {})
        findings = cost_analysis.get('findings', [])
        
        if findings:
            story.append(Paragraph("<b>Cost Optimization Opportunities:</b>", self.styles['Heading2']))
            
            for finding in findings:
                story.append(Paragraph(f"• {finding.get('finding', 'N/A')}", self.styles['Normal']))
                story.append(Paragraph(f"  <b>Recommendation:</b> {finding.get('recommendation', 'N/A')}", self.styles['Normal']))
                if finding.get('potential_savings'):
                    story.append(Paragraph(f"  <b>Potential Savings:</b> {finding.get('potential_savings')}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
        
        # Cost estimate
        estimated_cost = cost_analysis.get('estimated_monthly_cost', {})
        if estimated_cost and not estimated_cost.get('error'):
            story.append(Paragraph("<b>Estimated Monthly Cost:</b>", self.styles['Heading2']))
            story.append(Paragraph(f"Total: ${estimated_cost.get('total_monthly_cost', 0):.2f}", self.styles['Normal']))
        
        return story
    
    def _create_performance_section(self, analysis_results: Dict[str, Any]) -> List:
        """Create performance analysis section"""
        story = []
        
        story.append(Paragraph("Performance Analysis", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        performance_analysis = analysis_results.get('performance_analysis', {})
        findings = performance_analysis.get('findings', [])
        
        if findings:
            for finding in findings:
                severity = finding.get('severity', 'Low')
                style = self.styles[f'Finding{severity}'] if f'Finding{severity}' in self.styles else self.styles['Normal']
                
                story.append(Paragraph(f"<b>[{severity.upper()}]</b> {finding.get('finding', 'N/A')}", style))
                story.append(Paragraph(f"<b>Recommendation:</b> {finding.get('recommendation', 'N/A')}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
        
        # Performance metrics
        story.append(Paragraph("<b>Performance Metrics:</b>", self.styles['Heading2']))
        
        perf_data = [
            ['Metric', 'Value'],
            ['HPAs Configured', str(performance_analysis.get('hpa_count', 0))],
            ['Deployments without HPA', str(performance_analysis.get('deployments_without_hpa', 0))]
        ]
        
        perf_table = Table(perf_data, colWidths=[3*inch, 1*inch])
        perf_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(perf_table)
        
        return story
    
    def _create_reliability_section(self, analysis_results: Dict[str, Any]) -> List:
        """Create reliability analysis section"""
        story = []
        
        story.append(Paragraph("Reliability Analysis", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        reliability_analysis = analysis_results.get('reliability_analysis', {})
        findings = reliability_analysis.get('findings', [])
        
        if findings:
            for finding in findings:
                severity = finding.get('severity', 'Low')
                style = self.styles[f'Finding{severity}'] if f'Finding{severity}' in self.styles else self.styles['Normal']
                
                story.append(Paragraph(f"<b>[{severity.upper()}]</b> {finding.get('finding', 'N/A')}", style))
                story.append(Paragraph(f"<b>Recommendation:</b> {finding.get('recommendation', 'N/A')}", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
        
        # Reliability metrics
        story.append(Paragraph("<b>Reliability Metrics:</b>", self.styles['Heading2']))
        
        rel_data = [
            ['Metric', 'Value'],
            ['PDBs Configured', str(reliability_analysis.get('pdb_count', 0))],
            ['Deployments without PDB', str(reliability_analysis.get('deployments_without_pdb', 0))]
        ]
        
        rel_table = Table(rel_data, colWidths=[3*inch, 1*inch])
        rel_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(rel_table)
        
        return story
    
    def _create_compliance_section(self, analysis_results: Dict[str, Any]) -> List:
        """Create compliance analysis section"""
        story = []
        
        story.append(Paragraph("Compliance Analysis", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        # Placeholder for compliance analysis
        story.append(Paragraph("Compliance analysis results would be displayed here based on the selected framework (CIS, NIST, PCI DSS).", self.styles['Normal']))
        
        return story
    
    def _create_recommendations_summary(self, analysis_results: Dict[str, Any]) -> List:
        """Create recommendations summary"""
        story = []
        
        story.append(Paragraph("Recommendations Summary", self.styles['Heading1']))
        story.append(Spacer(1, 0.2*inch))
        
        recommendations = analysis_results.get('consolidated_recommendations', [])
        
        if recommendations:
            # Group by severity
            high_priority = [r for r in recommendations if r.get('severity') == 'High']
            medium_priority = [r for r in recommendations if r.get('severity') == 'Medium']
            low_priority = [r for r in recommendations if r.get('severity') == 'Low']
            
            # High priority recommendations
            if high_priority:
                story.append(Paragraph("<b>High Priority (Immediate Action Required):</b>", self.styles['Heading2']))
                for i, rec in enumerate(high_priority, 1):
                    story.append(Paragraph(f"{i}. {rec.get('recommendation', 'N/A')}", self.styles['FindingHigh']))
                    story.append(Paragraph(f"   Impact: {rec.get('impact', 'N/A')}", self.styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
            
            # Medium priority recommendations
            if medium_priority:
                story.append(Paragraph("<b>Medium Priority (Address Soon):</b>", self.styles['Heading2']))
                for i, rec in enumerate(medium_priority, 1):
                    story.append(Paragraph(f"{i}. {rec.get('recommendation', 'N/A')}", self.styles['FindingMedium']))
                    story.append(Paragraph(f"   Impact: {rec.get('impact', 'N/A')}", self.styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
            
            # Low priority recommendations
            if low_priority:
                story.append(Paragraph("<b>Low Priority (Consider for Future):</b>", self.styles['Heading2']))
                for i, rec in enumerate(low_priority, 1):
                    story.append(Paragraph(f"{i}. {rec.get('recommendation', 'N/A')}", self.styles['FindingLow']))
                    story.append(Paragraph(f"   Impact: {rec.get('impact', 'N/A')}", self.styles['Normal']))
                    story.append(Spacer(1, 0.1*inch))
        
        return story
