"""
Enhanced PDF Report Generator - Comprehensive analysis with detailed findings
"""
import json
import io
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

class PDFGenerator:
    """Generate comprehensive PDF reports for EKS analysis"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=20,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=1  # Center alignment
        )
        self.section_style = ParagraphStyle(
            'SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=15,
            textColor=colors.darkred,
            borderWidth=1,
            borderColor=colors.darkred,
            borderPadding=5
        )
        self.finding_style = ParagraphStyle(
            'FindingHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceAfter=10,
            textColor=colors.darkblue
        )
        
    def generate_report(self, analysis_results: Dict[str, Any], cluster_name: str) -> bytes:
        """Generate comprehensive PDF report and return as bytes"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.8*inch, bottomMargin=0.8*inch)
        story = []
        
        # Title Page
        self._add_title_page(story, cluster_name)
        
        # Executive Summary
        self._add_executive_summary(story, analysis_results, cluster_name)
        
        # Detailed Cluster Information
        self._add_detailed_cluster_info(story, analysis_results)
        
        # Security Analysis with Commands and Evidence
        self._add_comprehensive_security_analysis(story, analysis_results)
        
        # Network Analysis with Detailed Findings
        self._add_detailed_network_analysis(story, analysis_results)
        
        # Node Group Analysis
        self._add_node_group_analysis(story, analysis_results)
        
        # Addon Analysis
        self._add_addon_analysis(story, analysis_results)
        
        # Detailed Recommendations with Justifications
        self._add_detailed_recommendations(story, analysis_results)
        
        # Commands Reference
        self._add_commands_reference(story, cluster_name)
        
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    
    def _add_title_page(self, story, cluster_name):
        """Add professional title page"""
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("EKS CLUSTER SECURITY & OPERATIONS REVIEW", self.title_style))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(f"Cluster: <b>{cluster_name}</b>", self.styles['Heading2']))
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}", self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph("AgentK8s - Comprehensive EKS Analysis Tool", self.styles['Normal']))
        story.append(PageBreak())
    
    def _add_executive_summary(self, story, results, cluster_name):
        """Add executive summary with key findings"""
        story.append(Paragraph("EXECUTIVE SUMMARY", self.section_style))
        
        health = results.get('health_analysis', {})
        security = results.get('security_analysis', {})
        cluster_info = health.get('cluster_info', {})
        
        # Cluster Overview
        story.append(Paragraph("Cluster Overview", self.finding_style))
        overview_data = [
            ['Cluster Name', cluster_name],
            ['Status', cluster_info.get('status', 'Unknown')],
            ['Kubernetes Version', cluster_info.get('version', 'Unknown')],
            ['Platform Version', cluster_info.get('platform_version', 'Unknown')],
            ['Total Nodes', str(health.get('node_analysis', {}).get('total_nodes', 0))],
            ['Analysis Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
        ]
        
        table = Table(overview_data, colWidths=[2.5*inch, 3.5*inch])
        table.setStyle(self._get_table_style())
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Security Summary
        story.append(Paragraph("Security Assessment Summary", self.finding_style))
        
        total_checks = security.get('total_checks', 0)
        passed_checks = security.get('passed_checks', 0)
        failed_checks = security.get('failed_checks', 0)
        
        security_summary = [
            ['Total Security Checks Performed', str(total_checks)],
            ['Checks Passed', f"{passed_checks} ({(passed_checks/total_checks*100):.1f}%)" if total_checks > 0 else "0"],
            ['Checks Failed', f"{failed_checks} ({(failed_checks/total_checks*100):.1f}%)" if total_checks > 0 else "0"],
            ['Critical Issues Found', str(len([c for c in security.get('checks', []) if c.get('severity') == 'HIGH' and c.get('status') == 'FAIL']))],
            ['Recommendations Generated', str(len(security.get('recommendations', [])))]
        ]
        
        table = Table(security_summary, colWidths=[3*inch, 3*inch])
        table.setStyle(self._get_table_style())
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Key Issues Summary
        failed_checks_list = [c for c in security.get('checks', []) if c.get('status') == 'FAIL']
        if failed_checks_list:
            story.append(Paragraph("Critical Issues Requiring Immediate Attention", self.finding_style))
            for i, check in enumerate(failed_checks_list[:5], 1):  # Top 5 issues
                story.append(Paragraph(f"{i}. {check.get('title', 'Unknown Issue')} - {check.get('severity', 'MEDIUM')} Priority", self.styles['Normal']))
            story.append(Spacer(1, 20))
        
        story.append(PageBreak())
    
    def _add_detailed_cluster_info(self, story, results):
        """Add detailed cluster configuration information"""
        story.append(Paragraph("DETAILED CLUSTER CONFIGURATION", self.section_style))
        
        health = results.get('health_analysis', {})
        cluster_info = health.get('cluster_info', {})
        
        if cluster_info:
            story.append(Paragraph("Cluster Configuration Details", self.finding_style))
            story.append(Paragraph("<b>Command Used:</b> <font name='Courier'>aws eks describe-cluster --name [cluster-name]</font>", self.styles['Normal']))
            story.append(Spacer(1, 10))
            
            config_data = [
                ['Property', 'Value', 'Analysis'],
                ['Cluster Name', cluster_info.get('name', 'N/A'), 'Cluster identifier'],
                ['Status', cluster_info.get('status', 'N/A'), 'ACTIVE indicates healthy cluster'],
                ['Kubernetes Version', cluster_info.get('version', 'N/A'), 'Check against latest supported versions'],
                ['Platform Version', cluster_info.get('platform_version', 'N/A'), 'EKS platform version for features'],
                ['API Endpoint', cluster_info.get('endpoint', 'N/A'), 'Cluster API server endpoint'],
                ['Created Date', cluster_info.get('created_at', 'N/A'), 'Cluster age and lifecycle']
            ]
            
            table = Table(config_data, colWidths=[2*inch, 2.5*inch, 2.5*inch])
            table.setStyle(self._get_detailed_table_style())
            story.append(table)
            story.append(Spacer(1, 20))
        
        story.append(PageBreak())
    
    def _add_comprehensive_security_analysis(self, story, results):
        """Add comprehensive security analysis with detailed findings"""
        story.append(Paragraph("COMPREHENSIVE SECURITY ANALYSIS", self.section_style))
        
        security = results.get('security_analysis', {})
        checks = security.get('checks', [])
        
        if checks:
            story.append(Paragraph("Security Checks Performed", self.finding_style))
            story.append(Paragraph("Each security check includes the AWS CLI commands used for verification and detailed analysis of findings.", self.styles['Normal']))
            story.append(Spacer(1, 15))
            
            for check in checks:
                # Check Header
                status_symbol = "✓" if check['status'] == 'PASS' else "✗" if check['status'] == 'FAIL' else "?"
                story.append(Paragraph(f"{status_symbol} {check.get('title', 'Unknown Check')}", self.finding_style))
                
                # Status and Severity
                story.append(Paragraph(f"<b>Status:</b> {check['status']}", self.styles['Normal']))
                if 'severity' in check:
                    story.append(Paragraph(f"<b>Severity:</b> {check['severity']}", self.styles['Normal']))
                
                # Description and Evidence
                story.append(Paragraph(f"<b>Description:</b> {check.get('description', 'No description available')}", self.styles['Normal']))
                
                # Add specific commands and evidence based on check type
                self._add_check_specific_details(story, check)
                
                story.append(Spacer(1, 15))
        
        story.append(PageBreak())
    
    def _add_check_specific_details(self, story, check):
        """Add specific details for each type of security check"""
        check_id = check.get('id', '')
        
        if check_id == 'cluster_encryption':
            story.append(Paragraph("<b>Verification Command:</b>", self.styles['Normal']))
            story.append(Paragraph("<font name='Courier'>aws eks describe-cluster --name [cluster] --query 'cluster.encryptionConfig'</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> No encryption configuration found. Secrets are stored unencrypted in etcd.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Sensitive data like passwords, tokens, and keys are vulnerable if etcd is compromised.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> Encryption at rest is properly configured with KMS key.", self.styles['Normal']))
        
        elif check_id == 'cluster_logging':
            story.append(Paragraph("<b>Verification Command:</b>", self.styles['Normal']))
            story.append(Paragraph("<font name='Courier'>aws eks describe-cluster --name [cluster] --query 'cluster.logging'</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> Control plane logging is not enabled for critical log types.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Limited visibility into API server, audit, authenticator, controller manager, and scheduler activities.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> Control plane logging is properly configured.", self.styles['Normal']))
        
        elif check_id == 'endpoint_access':
            story.append(Paragraph("<b>Verification Command:</b>", self.styles['Normal']))
            story.append(Paragraph("<font name='Courier'>aws eks describe-cluster --name [cluster] --query 'cluster.resourcesVpcConfig'</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> API endpoint is publicly accessible from 0.0.0.0/0 or private access is disabled.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Cluster API server exposed to internet attacks and unauthorized access attempts.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> API endpoint access is properly restricted.", self.styles['Normal']))
        
        story.append(Spacer(1, 10))
    
    def _add_detailed_network_analysis(self, story, results):
        """Add detailed network analysis"""
        story.append(Paragraph("NETWORK CONFIGURATION ANALYSIS", self.section_style))
        
        health = results.get('health_analysis', {})
        network = health.get('network_analysis', {})
        
        if network:
            story.append(Paragraph("Network Security Assessment", self.finding_style))
            story.append(Paragraph("<b>Commands Used:</b>", self.styles['Normal']))
            story.append(Paragraph("<font name='Courier'>aws ec2 describe-vpcs --vpc-ids [vpc-id]</font>", self.styles['Normal']))
            story.append(Paragraph("<font name='Courier'>aws ec2 describe-subnets --subnet-ids [subnet-ids]</font>", self.styles['Normal']))
            story.append(Spacer(1, 10))
            
            # VPC Configuration
            story.append(Paragraph("VPC Configuration", self.finding_style))
            vpc_data = [
                ['Property', 'Value', 'Security Assessment'],
                ['VPC ID', network.get('vpc_id', 'N/A'), 'Network isolation boundary'],
                ['VPC CIDR', network.get('vpc_cidr', 'N/A'), 'IP address space allocation'],
                ['Public Access', str(network.get('endpoint_config', {}).get('public_access', 'N/A')), 'API endpoint accessibility'],
                ['Private Access', str(network.get('endpoint_config', {}).get('private_access', 'N/A')), 'Internal network access']
            ]
            
            table = Table(vpc_data, colWidths=[2*inch, 2*inch, 3*inch])
            table.setStyle(self._get_detailed_table_style())
            story.append(table)
            story.append(Spacer(1, 15))
            
            # Subnet Analysis
            subnets = network.get('subnets', [])
            if subnets:
                story.append(Paragraph("Subnet Configuration Analysis", self.finding_style))
                
                subnet_data = [['Subnet ID', 'CIDR', 'AZ', 'Available IPs', 'Utilization', 'Risk Level']]
                
                for subnet in subnets:
                    utilization = subnet.get('utilization_percent', 0)
                    risk_level = 'HIGH' if utilization > 80 else 'MEDIUM' if utilization > 60 else 'LOW'
                    
                    subnet_data.append([
                        subnet.get('subnet_id', 'N/A')[-12:],  # Last 12 chars
                        subnet.get('cidr', 'N/A'),
                        subnet.get('az', 'N/A'),
                        str(subnet.get('available_ips', 'N/A')),
                        f"{utilization:.1f}%",
                        risk_level
                    ])
                
                table = Table(subnet_data, colWidths=[1.2*inch, 1.2*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch])
                table.setStyle(self._get_detailed_table_style())
                story.append(table)
                story.append(Spacer(1, 15))
            
            # Network Issues
            issues = network.get('issues', [])
            if issues:
                story.append(Paragraph("Network Security Issues Identified", self.finding_style))
                for i, issue in enumerate(issues, 1):
                    story.append(Paragraph(f"{i}. {issue}", self.styles['Normal']))
                story.append(Spacer(1, 15))
        
        story.append(PageBreak())
    
    def _add_node_group_analysis(self, story, results):
        """Add detailed node group analysis"""
        story.append(Paragraph("NODE GROUP ANALYSIS", self.section_style))
        
        health = results.get('health_analysis', {})
        node_analysis = health.get('node_analysis', {})
        
        if node_analysis and 'node_groups' in node_analysis:
            story.append(Paragraph("Node Group Configuration Assessment", self.finding_style))
            story.append(Paragraph("<b>Command Used:</b> <font name='Courier'>aws eks describe-nodegroup --cluster-name [cluster] --nodegroup-name [nodegroup]</font>", self.styles['Normal']))
            story.append(Spacer(1, 10))
            
            node_data = [['Node Group', 'Status', 'Instance Types', 'Desired/Min/Max', 'Security Assessment']]
            
            for ng in node_analysis['node_groups']:
                security_assessment = 'Healthy' if ng['status'] == 'ACTIVE' else f"Issue: {ng['status']}"
                
                node_data.append([
                    ng['name'],
                    ng['status'],
                    ', '.join(ng['instance_types'][:2]),  # First 2 instance types
                    f"{ng['desired_size']}/{ng['min_size']}/{ng['max_size']}",
                    security_assessment
                ])
            
            table = Table(node_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 1*inch, 2*inch])
            table.setStyle(self._get_detailed_table_style())
            story.append(table)
            story.append(Spacer(1, 15))
            
            # Node Group Issues
            issues = node_analysis.get('issues', [])
            if issues:
                story.append(Paragraph("Node Group Issues", self.finding_style))
                for i, issue in enumerate(issues, 1):
                    story.append(Paragraph(f"{i}. {issue}", self.styles['Normal']))
                story.append(Spacer(1, 15))
        
        story.append(PageBreak())
    
    def _add_addon_analysis(self, story, results):
        """Add detailed addon analysis"""
        story.append(Paragraph("EKS ADDON ANALYSIS", self.section_style))
        
        health = results.get('health_analysis', {})
        addon_analysis = health.get('addon_analysis', {})
        
        if addon_analysis:
            story.append(Paragraph("EKS Addon Health Assessment", self.finding_style))
            story.append(Paragraph("<b>Command Used:</b> <font name='Courier'>aws eks describe-addon --cluster-name [cluster] --addon-name [addon]</font>", self.styles['Normal']))
            story.append(Spacer(1, 10))
            
            addon_details = addon_analysis.get('addon_details', [])
            if addon_details:
                addon_data = [['Addon Name', 'Status', 'Version', 'Health Assessment']]
                
                for addon in addon_details:
                    health_status = 'Healthy' if addon['status'] == 'ACTIVE' else f"Degraded: {addon['status']}"
                    
                    addon_data.append([
                        addon['name'],
                        addon['status'],
                        addon['version'],
                        health_status
                    ])
                
                table = Table(addon_data, colWidths=[2*inch, 1.5*inch, 1.5*inch, 2*inch])
                table.setStyle(self._get_detailed_table_style())
                story.append(table)
                story.append(Spacer(1, 15))
            
            # Addon Issues
            issues = addon_analysis.get('issues', [])
            if issues:
                story.append(Paragraph("Addon Issues Requiring Attention", self.finding_style))
                for i, issue in enumerate(issues, 1):
                    story.append(Paragraph(f"{i}. {issue}", self.styles['Normal']))
                story.append(Spacer(1, 15))
        
        story.append(PageBreak())
    
    def _add_detailed_recommendations(self, story, results):
        """Add detailed recommendations with justifications"""
        story.append(Paragraph("DETAILED RECOMMENDATIONS & REMEDIATION", self.section_style))
        
        security = results.get('security_analysis', {})
        recommendations = security.get('recommendations', [])
        
        if recommendations:
            story.append(Paragraph("Priority-Based Remediation Plan", self.finding_style))
            story.append(Paragraph("Each recommendation includes detailed justification, implementation steps, and expected security improvements.", self.styles['Normal']))
            story.append(Spacer(1, 15))
            
            for i, rec in enumerate(recommendations, 1):
                # Recommendation Header
                story.append(Paragraph(f"Recommendation {i}: {rec.get('title', 'Unknown')}", self.finding_style))
                
                # Priority and Impact
                story.append(Paragraph(f"<b>Priority:</b> {rec.get('priority', 'MEDIUM')}", self.styles['Normal']))
                story.append(Paragraph(f"<b>Description:</b> {rec.get('description', 'No description available')}", self.styles['Normal']))
                
                # Detailed Justification
                self._add_recommendation_justification(story, rec)
                
                # Implementation Steps
                if 'aws_cli' in rec:
                    story.append(Paragraph("<b>Implementation Command:</b>", self.styles['Normal']))
                    story.append(Paragraph(f"<font name='Courier'>{rec['aws_cli']}</font>", self.styles['Normal']))
                
                # Verification Steps
                self._add_verification_steps(story, rec)
                
                story.append(Spacer(1, 20))
        else:
            story.append(Paragraph("No Critical Recommendations", self.finding_style))
            story.append(Paragraph("Your cluster configuration meets the basic security requirements. Consider implementing additional hardening measures for production environments.", self.styles['Normal']))
        
        story.append(PageBreak())
    
    def _add_recommendation_justification(self, story, rec):
        """Add detailed justification for each recommendation"""
        title = rec.get('title', '')
        
        if 'Encryption' in title:
            story.append(Paragraph("<b>Security Justification:</b>", self.styles['Normal']))
            story.append(Paragraph("• Protects sensitive data (secrets, configmaps) stored in etcd", self.styles['Normal']))
            story.append(Paragraph("• Prevents data exposure in case of etcd backup compromise", self.styles['Normal']))
            story.append(Paragraph("• Required for compliance with security frameworks (SOC2, PCI DSS)", self.styles['Normal']))
            story.append(Paragraph("<b>Business Impact:</b> Reduces risk of data breach and regulatory violations", self.styles['Normal']))
        
        elif 'Logging' in title:
            story.append(Paragraph("<b>Security Justification:</b>", self.styles['Normal']))
            story.append(Paragraph("• Enables detection of unauthorized API access attempts", self.styles['Normal']))
            story.append(Paragraph("• Provides audit trail for compliance requirements", self.styles['Normal']))
            story.append(Paragraph("• Facilitates incident response and forensic analysis", self.styles['Normal']))
            story.append(Paragraph("<b>Business Impact:</b> Improves security monitoring and compliance posture", self.styles['Normal']))
        
        elif 'Endpoint' in title:
            story.append(Paragraph("<b>Security Justification:</b>", self.styles['Normal']))
            story.append(Paragraph("• Reduces attack surface by limiting API server exposure", self.styles['Normal']))
            story.append(Paragraph("• Prevents unauthorized access from internet-based attacks", self.styles['Normal']))
            story.append(Paragraph("• Implements network-level access controls", self.styles['Normal']))
            story.append(Paragraph("<b>Business Impact:</b> Significantly reduces risk of cluster compromise", self.styles['Normal']))
        
        story.append(Spacer(1, 10))
    
    def _add_verification_steps(self, story, rec):
        """Add verification steps for each recommendation"""
        title = rec.get('title', '')
        
        story.append(Paragraph("<b>Verification Steps:</b>", self.styles['Normal']))
        
        if 'Encryption' in title:
            story.append(Paragraph("1. <font name='Courier'>aws eks describe-cluster --name [cluster] --query 'cluster.encryptionConfig'</font>", self.styles['Normal']))
            story.append(Paragraph("2. Verify KMS key is listed and resources include 'secrets'", self.styles['Normal']))
        
        elif 'Logging' in title:
            story.append(Paragraph("1. <font name='Courier'>aws eks describe-cluster --name [cluster] --query 'cluster.logging'</font>", self.styles['Normal']))
            story.append(Paragraph("2. Verify enabled log types include: api, audit, authenticator, controllerManager, scheduler", self.styles['Normal']))
        
        elif 'Endpoint' in title:
            story.append(Paragraph("1. <font name='Courier'>aws eks describe-cluster --name [cluster] --query 'cluster.resourcesVpcConfig'</font>", self.styles['Normal']))
            story.append(Paragraph("2. Verify endpointPrivateAccess=true and publicAccessCidrs is restricted", self.styles['Normal']))
        
        story.append(Spacer(1, 10))
    
    def _add_commands_reference(self, story, cluster_name):
        """Add comprehensive commands reference"""
        story.append(Paragraph("COMMANDS REFERENCE", self.section_style))
        
        story.append(Paragraph("AWS CLI Commands Used in Analysis", self.finding_style))
        
        commands = [
            ['Analysis Area', 'Command', 'Purpose'],
            ['Cluster Info', f'aws eks describe-cluster --name {cluster_name}', 'Get cluster configuration'],
            ['Node Groups', f'aws eks list-nodegroups --cluster-name {cluster_name}', 'List all node groups'],
            ['Node Group Details', f'aws eks describe-nodegroup --cluster-name {cluster_name} --nodegroup-name [ng]', 'Get node group configuration'],
            ['Addons', f'aws eks list-addons --cluster-name {cluster_name}', 'List EKS addons'],
            ['Addon Details', f'aws eks describe-addon --cluster-name {cluster_name} --addon-name [addon]', 'Get addon status'],
            ['VPC Info', 'aws ec2 describe-vpcs --vpc-ids [vpc-id]', 'Get VPC configuration'],
            ['Subnet Info', 'aws ec2 describe-subnets --subnet-ids [subnet-ids]', 'Get subnet details'],
            ['Security Groups', 'aws ec2 describe-security-groups --group-ids [sg-ids]', 'Get security group rules']
        ]
        
        table = Table(commands, colWidths=[1.5*inch, 3*inch, 2.5*inch])
        table.setStyle(self._get_detailed_table_style())
        story.append(table)
        story.append(Spacer(1, 20))
        
        story.append(Paragraph("Kubectl Commands for Further Analysis", self.finding_style))
        
        kubectl_commands = [
            ['kubectl get nodes -o wide', 'Check node status and details'],
            ['kubectl get pods --all-namespaces', 'List all pods across namespaces'],
            ['kubectl describe node [node-name]', 'Get detailed node information'],
            ['kubectl get networkpolicies --all-namespaces', 'Check network policies'],
            ['kubectl get psp', 'Check pod security policies'],
            ['kubectl auth can-i --list', 'Check current user permissions']
        ]
        
        for cmd, desc in kubectl_commands:
            story.append(Paragraph(f"<font name='Courier'>{cmd}</font>", self.styles['Normal']))
            story.append(Paragraph(f"Purpose: {desc}", self.styles['Normal']))
            story.append(Spacer(1, 5))
    
    def _get_table_style(self):
        """Get standard table style"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9)
        ])
    
    def _get_detailed_table_style(self):
        """Get detailed table style with alternating rows"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ])
