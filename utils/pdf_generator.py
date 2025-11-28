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
            textColor=colors.darkblue,
            borderWidth=1,
            borderColor=colors.darkblue,
            borderPadding=5
        )
        self.finding_style = ParagraphStyle(
            'FindingHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceAfter=10,
            textColor=colors.darkblue
        )
        # Add consistent normal style with proper color
        self.normal_style = ParagraphStyle(
            'CustomNormal',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.black,
            spaceAfter=6
        )
        # Add table cell style for consistent formatting
        self.table_cell_style = ParagraphStyle(
            'TableCell',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.black,
            spaceAfter=3,
            leftIndent=2,
            rightIndent=2
        )
        # Add table header style
        self.table_header_style = ParagraphStyle(
            'TableHeader',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            spaceAfter=3,
            leftIndent=2,
            rightIndent=2,
            fontName='Helvetica-Bold'
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
        
        # HardenEKS Analysis Section
        self._add_hardeneks_analysis_section(story, analysis_results)
        
        # DORA Compliance Analysis Section
        self._add_dora_compliance_analysis_section(story, analysis_results)
        
        # Detailed Check Results Section
        self._add_detailed_check_results_section(story, analysis_results)
        
        # Comprehensive Compliance Analysis
        self._add_comprehensive_compliance_analysis(story, analysis_results)
        
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
        
        # Get actual cluster name from results if available
        actual_cluster_name = cluster_info.get('name') or results.get('cluster_name') or cluster_name
        
        # Cluster Overview
        story.append(Paragraph("Cluster Overview", self.finding_style))
        overview_data = [
            ['Cluster Name', actual_cluster_name],
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
        """Add specific details for each type of security check with standardized format"""
        check_id = check.get('id', '')
        check_title = check.get('title', '').lower()
        
        # Always add verification command, finding, risk, and documentation for ALL checks
        story.append(Paragraph("<b>Verification Command:</b>", self.styles['Normal']))
        
        if check_id == 'cluster_encryption' or 'encryption' in check_title:
            story.append(Paragraph("<font name='Courier'>aws eks describe-cluster --name [cluster] --query 'cluster.encryptionConfig'</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> No encryption configuration found. Secrets are stored unencrypted in etcd.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Sensitive data like passwords, tokens, and keys are vulnerable if etcd is compromised.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> Encryption at rest is properly configured with KMS key.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> N/A - Configuration meets security requirements.", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b> https://docs.aws.amazon.com/eks/latest/userguide/encryption-at-rest.html", self.styles['Normal']))
        
        elif check_id == 'cluster_logging' or 'logging' in check_title:
            story.append(Paragraph("<font name='Courier'>aws eks describe-cluster --name [cluster] --query 'cluster.logging'</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> Control plane logging is not enabled for critical log types.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Limited visibility into API server, audit, authenticator, controller manager, and scheduler activities.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> Control plane logging is properly configured.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> N/A - Comprehensive logging enabled for monitoring and compliance.", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b> https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html", self.styles['Normal']))
        
        elif check_id == 'endpoint_access' or 'endpoint' in check_title or 'api' in check_title:
            story.append(Paragraph("<font name='Courier'>aws eks describe-cluster --name [cluster] --query 'cluster.resourcesVpcConfig'</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> API endpoint is publicly accessible from 0.0.0.0/0 or private access is disabled.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Cluster API server exposed to internet attacks and unauthorized access attempts.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> API endpoint access is properly restricted.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> N/A - Network access controls properly configured.", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b> https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html", self.styles['Normal']))
        
        elif 'network' in check_title or 'vpc' in check_title or 'security group' in check_title:
            story.append(Paragraph("<font name='Courier'>aws ec2 describe-security-groups --group-ids [sg-ids]</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> Network security configuration has vulnerabilities or missing controls.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Potential for unauthorized network access, lateral movement, or data exfiltration.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> Network security controls are properly configured.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> N/A - Network segmentation and access controls meet requirements.", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b> https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html", self.styles['Normal']))
        
        elif 'iam' in check_title or 'rbac' in check_title or 'role' in check_title or 'policy' in check_title:
            story.append(Paragraph("<font name='Courier'>aws iam get-role --role-name [role-name]</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> IAM or RBAC configuration does not follow least-privilege principles.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Excessive permissions may allow privilege escalation or unauthorized resource access.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> IAM and RBAC configurations follow security best practices.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> N/A - Access controls properly implement least-privilege model.", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b> https://docs.aws.amazon.com/eks/latest/userguide/security-iam.html", self.styles['Normal']))
        
        elif 'node' in check_title or 'instance' in check_title:
            story.append(Paragraph("<font name='Courier'>aws eks describe-nodegroup --cluster-name [cluster] --nodegroup-name [ng]</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> Node group configuration has security vulnerabilities or misconfigurations.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Compromised nodes could affect cluster integrity and workload security.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> Node group security configuration meets requirements.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> N/A - Node security controls properly configured.", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b> https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html", self.styles['Normal']))
        
        elif 'pod' in check_title or 'container' in check_title or 'security context' in check_title:
            story.append(Paragraph("<font name='Courier'>kubectl get pods -o yaml | grep securityContext</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> Pod security policies or security contexts are not properly configured.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Containers may run with excessive privileges, increasing attack surface.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> Pod security policies and contexts are properly configured.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> N/A - Container security controls properly restrict privileges.", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b> https://kubernetes.io/docs/concepts/security/pod-security-standards/", self.styles['Normal']))
        
        elif 'addon' in check_title or 'cni' in check_title:
            story.append(Paragraph("<font name='Courier'>aws eks describe-addon --cluster-name [cluster] --addon-name [addon]</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph("<b>Finding:</b> EKS addons are outdated, misconfigured, or not properly secured.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Vulnerable addons may provide attack vectors or degrade cluster functionality.", self.styles['Normal']))
            else:
                story.append(Paragraph("<b>Finding:</b> EKS addons are up-to-date and properly configured.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> N/A - Addons meet security and operational requirements.", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b> https://docs.aws.amazon.com/eks/latest/userguide/eks-add-ons.html", self.styles['Normal']))
        
        else:
            # Generic check handling with appropriate command based on check type
            story.append(Paragraph("<font name='Courier'>aws eks describe-cluster --name [cluster]</font>", self.styles['Normal']))
            if check['status'] == 'FAIL':
                story.append(Paragraph(f"<b>Finding:</b> {check.get('title', 'Security check')} failed validation against best practices.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> Configuration does not meet security requirements, potentially exposing cluster to threats.", self.styles['Normal']))
            else:
                story.append(Paragraph(f"<b>Finding:</b> {check.get('title', 'Security check')} meets security requirements.", self.styles['Normal']))
                story.append(Paragraph("<b>Risk:</b> N/A - Configuration follows security best practices.", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b> https://docs.aws.amazon.com/eks/latest/userguide/security.html", self.styles['Normal']))
        
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
            
            # Network Issues with Recommendations
            issues = network.get('issues', [])
            if issues:
                story.append(Paragraph("Network Security Issues Identified", self.finding_style))
                for i, issue in enumerate(issues, 1):
                    story.append(Paragraph(f"{i}. {issue}", self.styles['Normal']))
                
                # Add recommendations for network issues
                story.append(Spacer(1, 10))
                story.append(Paragraph("Recommended Actions:", self.styles['Normal']))
                
                for issue in issues:
                    if "API endpoint accessible from anywhere" in issue:
                        story.append(Paragraph("• Restrict API endpoint access: aws eks update-cluster-config --name [cluster] --resources-vpc-config endpointPrivateAccess=true,publicAccessCidrs=[\"YOUR_IP/32\"]", self.styles['Normal']))
                        story.append(Paragraph("📖 Reference: https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html", self.styles['Normal']))
                    elif "Private endpoint access disabled" in issue:
                        story.append(Paragraph("• Enable private endpoint access: aws eks update-cluster-config --name [cluster] --resources-vpc-config endpointPrivateAccess=true", self.styles['Normal']))
                        story.append(Paragraph("📖 Reference: https://docs.aws.amazon.com/eks/latest/userguide/private-clusters.html", self.styles['Normal']))
                    elif "utilization" in issue:
                        story.append(Paragraph("• Monitor subnet utilization and consider expanding CIDR blocks or adding subnets", self.styles['Normal']))
                        story.append(Paragraph("📖 Reference: https://docs.aws.amazon.com/vpc/latest/userguide/subnet-sizing.html", self.styles['Normal']))
                
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
                
                # Fix instance types formatting - handle both string and list formats
                instance_types = ng.get('instance_types', [])
                if isinstance(instance_types, str):
                    instance_types = [instance_types]
                elif isinstance(instance_types, list):
                    instance_types = [str(itype) for itype in instance_types if itype]
                else:
                    instance_types = ['Unknown']
                
                formatted_instance_types = ', '.join(instance_types[:2]) if instance_types else 'N/A'
                
                node_data.append([
                    ng['name'],
                    ng['status'],
                    formatted_instance_types,
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
    
    def _add_hardeneks_analysis_section(self, story, results):
        """Add comprehensive HardenEKS analysis section"""
        story.append(Paragraph("HARDENEKS SECURITY ANALYSIS", self.section_style))
        
        # Check multiple possible locations for HardenEKS data
        hardeneks = results.get('hardeneks_analysis', {})
        
        # Check if it's nested in security analysis (enhanced analyzer path)
        if not hardeneks:
            security_analysis = results.get('security_analysis', {})
            hardeneks = security_analysis.get('hardeneks_analysis', {})
        
        if hardeneks:
            # HardenEKS Summary
            story.append(Paragraph("HardenEKS Security Posture Assessment", self.finding_style))
            story.append(Paragraph("Comprehensive analysis based on AWS EKS Security Best Practices and HardenEKS recommendations.", self.styles['Normal']))
            story.append(Spacer(1, 10))
            
            hardeneks_score = hardeneks.get('hardeneks_score', {})
            
            # Overall Score Summary with detailed explanations
            score_data = [
                ['Metric', 'Value', 'Assessment'],
                ['Overall HardenEKS Score', f"{hardeneks_score.get('overall_score', 0):.1f}/100", hardeneks_score.get('security_posture', 'Unknown')],
                ['Security Grade', hardeneks_score.get('grade', 'F'), 'Letter grade: A(90-100%), B(80-89%), C(70-79%), D(60-69%), F(<60%)'],
                ['Total Checks Performed', str(hardeneks.get('total_checks', 0)), 'See COMMANDS REFERENCE section for complete list'],
                ['Checks Passed', str(hardeneks.get('passed_checks', 0)), 'Configurations meeting security standards'],
                ['Checks Failed', str(hardeneks.get('failed_checks', 0)), 'Critical vulnerabilities requiring immediate action'],
                ['Checks with Warnings', str(hardeneks.get('warning_checks', 0)), 'Configurations needing manual verification']
            ]
            
            table = Table(score_data, colWidths=[2.5*inch, 1.5*inch, 3*inch])
            table.setStyle(self._get_detailed_table_style())
            story.append(table)
            story.append(Spacer(1, 20))
            
            # Category Analysis
            story.append(Paragraph("HardenEKS Category Analysis", self.finding_style))
            category_scores = hardeneks_score.get('category_scores', {})
            
            if category_scores:
                cat_data = [['Category', 'Score', 'Status', 'Passed/Total', 'Key Issues']]
                
                for category, cat_info in category_scores.items():
                    score = cat_info.get('score', 0)
                    status = cat_info.get('status', 'Unknown')
                    passed = cat_info.get('passed', 0)
                    total = cat_info.get('total_checks', 0)
                    
                    # Get key issues for this category
                    checks = cat_info.get('checks', [])
                    failed_checks = [c for c in checks if c.get('status') == 'FAIL']
                    key_issues = ', '.join([c['title'][:30] + '...' if len(c['title']) > 30 else c['title'] for c in failed_checks[:2]])
                    
                    cat_data.append([
                        category.replace('_', ' ').title(),
                        f"{score:.1f}%",
                        status,
                        f"{passed}/{total}",
                        key_issues or 'No critical issues'
                    ])
                
                table = Table(cat_data, colWidths=[1.5*inch, 0.8*inch, 1*inch, 0.8*inch, 2.9*inch])
                table.setStyle(self._get_detailed_table_style())
                story.append(table)
                story.append(Spacer(1, 20))
            
            # Top HardenEKS Recommendations
            recommendations = hardeneks.get('recommendations', [])
            if recommendations:
                story.append(Paragraph("Priority HardenEKS Recommendations", self.finding_style))
                
                for i, rec in enumerate(recommendations[:5], 1):  # Top 5 recommendations
                    story.append(Paragraph(f"{i}. <b>{rec.get('title', 'Unknown')}</b> - {rec.get('priority', 'MEDIUM')} Priority", self.styles['Normal']))
                    story.append(Paragraph(f"   Category: {rec.get('category', 'General')}", self.styles['Normal']))
                    story.append(Paragraph(f"   Description: {rec.get('description', 'No description available')}", self.styles['Normal']))
                    story.append(Spacer(1, 10))
        else:
            story.append(Paragraph("HardenEKS analysis not available in this report.", self.styles['Normal']))
        
        story.append(PageBreak())
    
    def _add_dora_compliance_analysis_section(self, story, results):
        """Add comprehensive DORA compliance analysis section"""
        story.append(Paragraph("EU DORA COMPLIANCE ANALYSIS", self.section_style))
        
        # Check multiple possible locations for DORA data
        dora_analysis = results.get('dora_analysis', {})
        
        # Check if it's nested in security analysis (enhanced analyzer path)
        if not dora_analysis:
            security_analysis = results.get('security_analysis', {})
            dora_analysis = security_analysis.get('dora_analysis', {})
        
        if dora_analysis:
            # DORA Summary
            story.append(Paragraph("EU DORA Digital Operational Resilience Assessment", self.finding_style))
            story.append(Paragraph("Comprehensive analysis based on EU Regulation 2022/2554 for digital operational resilience in financial services and critical infrastructure.", self.styles['Normal']))
            story.append(Spacer(1, 10))
            
            # DORA Overview Table
            dora_overview = [
                ['DORA Assessment Metric', 'Value', 'Compliance Status'],
                ['DORA Version', dora_analysis.get('dora_version', 'Unknown'), 'Current EU regulation'],
                ['Assessment Date', dora_analysis.get('assessment_date', 'Unknown'), 'Regulatory compliance timestamp'],
                ['Target Environment', dora_analysis.get('target_environment', 'Amazon EKS'), 'Cloud infrastructure assessment'],
                ['Regulatory Framework', 'EU Regulation 2022/2554', 'Digital Operational Resilience Act'],
                ['Total Compliance Checks', str(dora_analysis.get('total_compliance_checks', 0)), '152 comprehensive DORA checks']
            ]
            
            table = Table(dora_overview, colWidths=[2.5*inch, 2*inch, 2.5*inch])
            table.setStyle(self._get_detailed_table_style())
            story.append(table)
            story.append(Spacer(1, 20))
            
            # DORA Compliance Score
            dora_compliance = dora_analysis.get('dora_compliance_score', {})
            
            if dora_compliance:
                story.append(Paragraph("DORA Compliance Posture", self.finding_style))
                
                compliance_data = [
                    ['Compliance Metric', 'Score/Status', 'Risk Assessment', 'Regulatory Impact'],
                    ['Overall DORA Score', f"{dora_compliance.get('overall_score', 0):.1f}%", dora_compliance.get('risk_level', 'Unknown'), dora_compliance.get('compliance_status', 'Unknown')],
                    ['Checks Passed', str(dora_compliance.get('passed_checks', 0)), 'Compliant controls', 'Meets regulatory requirements'],
                    ['Checks Failed', str(dora_compliance.get('failed_checks', 0)), 'Non-compliant controls', 'Regulatory violations'],
                    ['Critical Issues', str(dora_compliance.get('critical_issues', 0)), 'P0 severity failures', 'Immediate action required'],
                    ['Action Required', 'Yes' if dora_compliance.get('immediate_action_required', False) else 'No', 'Compliance status', 'Regulatory deadline compliance']
                ]
                
                table = Table(compliance_data, colWidths=[1.8*inch, 1.2*inch, 1.5*inch, 2.5*inch])
                table.setStyle(self._get_detailed_table_style())
                story.append(table)
                story.append(Spacer(1, 20))
            
            # DORA Priority Breakdown
            priority_breakdown = dora_analysis.get('priority_breakdown', {})
            
            if priority_breakdown:
                story.append(Paragraph("DORA Priority Risk Analysis", self.finding_style))
                
                priority_data = [['Priority Level', 'Total Checks', 'Passed', 'Failed', 'Compliance %', 'Risk Level']]
                
                for priority, data in priority_breakdown.items():
                    priority_data.append([
                        priority,
                        str(data.get('total', 0)),
                        str(data.get('passed', 0)),
                        str(data.get('failed', 0)),
                        f"{data.get('compliance_percentage', 0):.1f}%",
                        data.get('risk_level', 'Unknown')
                    ])
                
                table = Table(priority_data, colWidths=[1.2*inch, 1*inch, 0.8*inch, 0.8*inch, 1*inch, 1.2*inch])
                table.setStyle(self._get_detailed_table_style())
                story.append(table)
                story.append(Spacer(1, 20))
            
            # DORA Category Analysis
            checks_by_category = dora_analysis.get('checks_by_category', {})
            
            if checks_by_category:
                story.append(Paragraph("DORA Component Category Analysis", self.finding_style))
                
                for category_name, category_checks in checks_by_category.items():
                    if category_checks:
                        story.append(Paragraph(f"{category_name.replace('_', ' ').title()} ({len(category_checks)} checks)", self.styles['Normal']))
                        
                        # Show top failed checks for each category
                        failed_checks = [c for c in category_checks if c.get('status') == 'FAILED']
                        if failed_checks:
                            story.append(Paragraph(f"Critical Issues in {category_name.replace('_', ' ').title()}:", self.styles['Normal']))
                            for i, check in enumerate(failed_checks[:3], 1):  # Top 3 failed checks
                                story.append(Paragraph(f"  {i}. Check #{check.get('check_id', 'N/A')}: {check.get('title', 'Unknown')}", self.styles['Normal']))
                                story.append(Paragraph(f"     Status: {check.get('status', 'Unknown')} | Severity: {check.get('severity', 'Unknown')}", self.styles['Normal']))
                                story.append(Paragraph(f"     Finding: {check.get('finding', 'No details available')}", self.styles['Normal']))
                                if check.get('command_used'):
                                    story.append(Paragraph(f"     Command: <font name='Courier'>{check.get('command_used')}</font>", self.styles['Normal']))
                                if check.get('guidance'):
                                    story.append(Paragraph(f"     Remediation: <font name='Courier'>{check.get('guidance')}</font>", self.styles['Normal']))
                                story.append(Spacer(1, 8))
                        story.append(Spacer(1, 10))
            
            # Critical DORA Findings
            critical_findings = dora_analysis.get('critical_findings', [])
            
            if critical_findings:
                story.append(Paragraph("Critical DORA Compliance Violations", self.finding_style))
                story.append(Paragraph("The following P0 severity issues require immediate remediation to meet DORA regulatory requirements:", self.styles['Normal']))
                story.append(Spacer(1, 10))
                
                critical_data = [['Check ID', 'Component', 'Issue', 'Business Impact', 'Required Action']]
                
                for finding in critical_findings[:10]:  # Top 10 critical findings
                    business_impact = finding.get('business_impact', 'Unknown business impact')
                    if len(business_impact) > 60:
                        business_impact = business_impact[:57] + '...'
                    
                    remediation = finding.get('remediation', 'No remediation specified')
                    if len(remediation) > 50:
                        remediation = remediation[:47] + '...'
                    
                    critical_data.append([
                        finding.get('check_id', 'N/A'),
                        finding.get('component', 'Unknown'),
                        finding.get('title', 'Unknown issue')[:30] + ('...' if len(finding.get('title', '')) > 30 else ''),
                        business_impact,
                        remediation
                    ])
                
                table = Table(critical_data, colWidths=[0.8*inch, 1.2*inch, 1.5*inch, 2*inch, 1.5*inch])
                table.setStyle(self._get_detailed_table_style())
                story.append(table)
                story.append(Spacer(1, 20))
            
            # DORA Recommendations
            dora_recommendations = dora_analysis.get('recommendations', [])
            
            if dora_recommendations:
                story.append(Paragraph("DORA Compliance Recommendations", self.finding_style))
                
                for i, rec in enumerate(dora_recommendations[:5], 1):  # Top 5 DORA recommendations
                    story.append(Paragraph(f"{i}. <b>{rec.get('title', 'Unknown Recommendation')}</b> - {rec.get('priority', 'MEDIUM')} Priority", self.styles['Normal']))
                    story.append(Paragraph(f"   Category: {rec.get('category', 'General DORA Compliance')}", self.styles['Normal']))
                    story.append(Paragraph(f"   Description: {rec.get('description', 'No description available')}", self.styles['Normal']))
                    
                    # Add DORA-specific details
                    dora_articles = rec.get('dora_articles', [])
                    if dora_articles:
                        story.append(Paragraph(f"   DORA Articles: {', '.join(dora_articles)}", self.styles['Normal']))
                    
                    timeline = rec.get('implementation_timeline', '')
                    if timeline:
                        story.append(Paragraph(f"   Implementation Timeline: {timeline}", self.styles['Normal']))
                    
                    story.append(Spacer(1, 10))
            
        else:
            story.append(Paragraph("DORA compliance analysis not available in this report.", self.styles['Normal']))
            story.append(Paragraph("To enable DORA compliance assessment, ensure the DORA analyzer is properly configured and integrated with the analysis pipeline.", self.styles['Normal']))
        
        story.append(PageBreak())
    
    def _add_comprehensive_compliance_analysis(self, story, results):
        """Add comprehensive compliance framework analysis section"""
        story.append(Paragraph("COMPLIANCE FRAMEWORK ANALYSIS", self.section_style))
        
        # Check if we have compliance analysis results
        compliance = results.get('compliance_analysis', {})
        
        if compliance:
            story.append(Paragraph("Multi-Framework Compliance Assessment", self.finding_style))
            story.append(Paragraph("Analysis against major security and compliance frameworks including CIS, NIST, PCI DSS, SOC2, HIPAA, and ISO 27001.", self.styles['Normal']))
            story.append(Spacer(1, 15))
            
            # Overall Compliance Posture
            overall_compliance = compliance.get('overall_compliance_posture', {})
            
            if overall_compliance:
                story.append(Paragraph("Overall Compliance Posture", self.finding_style))
                
                posture_data = [
                    ['Metric', 'Value', 'Assessment'],
                    ['Overall Compliance Score', f"{overall_compliance.get('overall_compliance_score', 0):.1f}%", overall_compliance.get('compliance_posture', 'Unknown')],
                    ['Frameworks Analyzed', str(overall_compliance.get('compliance_summary', {}).get('total_frameworks_analyzed', 0)), 'Comprehensive coverage'],
                    ['Frameworks with Good Compliance', str(overall_compliance.get('compliance_summary', {}).get('frameworks_with_good_compliance', 0)), '≥80% compliance rate'],
                    ['Frameworks Needing Attention', str(overall_compliance.get('compliance_summary', {}).get('frameworks_needing_attention', 0)), '<80% compliance rate']
                ]
                
                table = Table(posture_data, colWidths=[2.5*inch, 1.5*inch, 3*inch])
                table.setStyle(self._get_detailed_table_style())
                story.append(table)
                story.append(Spacer(1, 20))
            
            # Framework-by-Framework Analysis
            frameworks = compliance.get('compliance_frameworks', {})
            
            for framework_id, framework_data in frameworks.items():
                story.append(Paragraph(f"{framework_data.get('framework_name', framework_id)} Compliance", self.finding_style))
                
                framework_summary = [
                    ['Framework Version', framework_data.get('version', 'Unknown')],
                    ['Compliance Percentage', f"{framework_data.get('compliance_percentage', 0):.1f}%"],
                    ['Compliance Level', framework_data.get('compliance_level', 'Unknown')],
                    ['Total Controls', str(framework_data.get('total_controls', 0))],
                    ['Compliant Controls', str(framework_data.get('compliant_controls', 0))],
                    ['Non-Compliant Controls', str(framework_data.get('non_compliant_controls', 0))]
                ]
                
                table = Table(framework_summary, colWidths=[2.5*inch, 3.5*inch])
                table.setStyle(self._get_table_style())
                story.append(table)
                story.append(Spacer(1, 15))
                
                # Critical Findings for this Framework
                critical_findings = framework_data.get('critical_findings', [])
                if critical_findings:
                    story.append(Paragraph(f"Critical Findings - {framework_data.get('framework_name', framework_id)}", self.styles['Normal']))
                    for finding in critical_findings[:3]:  # Top 3 critical findings
                        control_id = finding.get('control_id', finding.get('control', 'N/A'))
                        story.append(Paragraph(f"• Control {control_id}: {finding.get('title', 'Unknown')}", self.styles['Normal']))
                    story.append(Spacer(1, 10))
            
            # Top Compliance Gaps
            top_gaps = overall_compliance.get('top_compliance_gaps', [])
            if top_gaps:
                story.append(Paragraph("Top Compliance Gaps Across All Frameworks", self.finding_style))
                
                gap_data = [['Framework', 'Control', 'Issue', 'Severity', 'Remediation']]
                
                for gap in top_gaps[:10]:  # Top 10 gaps
                    remediation = gap.get('remediation', '')
                    # Truncate long remediation text
                    if len(remediation) > 50:
                        remediation = remediation[:47] + '...'
                    
                    gap_data.append([
                        gap.get('framework', 'N/A')[:15],  # Truncate framework name
                        gap.get('control', 'N/A'),
                        gap.get('title', 'Unknown')[:25] + ('...' if len(gap.get('title', '')) > 25 else ''),
                        gap.get('severity', 'MEDIUM'),
                        remediation
                    ])
                
                table = Table(gap_data, colWidths=[1.2*inch, 0.8*inch, 1.8*inch, 0.7*inch, 2.5*inch])
                table.setStyle(self._get_detailed_table_style())
                story.append(table)
                story.append(Spacer(1, 20))
        
        else:
            # Add basic compliance note if comprehensive compliance analysis is not available
            story.append(Paragraph("Basic Compliance Considerations", self.finding_style))
            
            # Check if we have hardeneks compliance summary
            hardeneks = results.get('hardeneks_analysis', {})
            compliance_summary = hardeneks.get('compliance_summary', {})
            
            if compliance_summary:
                story.append(Paragraph("The following compliance frameworks have been assessed based on HardenEKS analysis:", self.styles['Normal']))
                story.append(Spacer(1, 10))
                
                comp_data = [['Framework', 'Version', 'Compliance %', 'Status']]
                
                for framework_id, framework_info in compliance_summary.items():
                    comp_data.append([
                        framework_info.get('framework_name', framework_id),
                        framework_info.get('version', 'Unknown'),
                        f"{framework_info.get('compliance_percentage', 0):.1f}%",
                        framework_info.get('status', 'Unknown')
                    ])
                
                table = Table(comp_data, colWidths=[2.5*inch, 1*inch, 1.5*inch, 2*inch])
                table.setStyle(self._get_detailed_table_style())
                story.append(table)
                story.append(Spacer(1, 15))
            else:
                story.append(Paragraph("Comprehensive compliance analysis requires additional configuration. Current analysis covers basic security controls.", self.styles['Normal']))
            
            # Add DORA Metrics Assessment
            self._add_dora_metrics_assessment(story, results)
        
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
        """Add detailed justification for each recommendation with AWS documentation links"""
        title = rec.get('title', '')
        
        if 'Encryption' in title:
            story.append(Paragraph("<b>Security Justification:</b>", self.styles['Normal']))
            story.append(Paragraph("• Protects sensitive data (secrets, configmaps) stored in etcd", self.styles['Normal']))
            story.append(Paragraph("• Prevents data exposure in case of etcd backup compromise", self.styles['Normal']))
            story.append(Paragraph("• Required for compliance with security frameworks (SOC2, PCI DSS)", self.styles['Normal']))
            story.append(Paragraph("<b>Business Impact:</b> Reduces risk of data breach and regulatory violations", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b>", self.styles['Normal']))
            story.append(Paragraph("📖 Envelope encryption: https://docs.aws.amazon.com/eks/latest/userguide/encryption-at-rest.html", self.styles['Normal']))
            story.append(Paragraph("📖 KMS key management: https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html", self.styles['Normal']))
            story.append(Paragraph("<b>Implementation Guide:</b>", self.styles['Normal']))
            story.append(Paragraph("1. Create or identify a KMS key in the same region as your cluster", self.styles['Normal']))
            story.append(Paragraph("2. Ensure the EKS service role has permissions to use the KMS key", self.styles['Normal']))
            story.append(Paragraph("3. Update cluster configuration to enable envelope encryption", self.styles['Normal']))
            story.append(Paragraph("4. Verify encryption is working by checking cluster configuration", self.styles['Normal']))
        
        elif 'Logging' in title:
            story.append(Paragraph("<b>Security Justification:</b>", self.styles['Normal']))
            story.append(Paragraph("• Enables detection of unauthorized API access attempts", self.styles['Normal']))
            story.append(Paragraph("• Provides audit trail for compliance requirements", self.styles['Normal']))
            story.append(Paragraph("• Facilitates incident response and forensic analysis", self.styles['Normal']))
            story.append(Paragraph("<b>Business Impact:</b> Improves security monitoring and compliance posture", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b>", self.styles['Normal']))
            story.append(Paragraph("📖 Control plane logging: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html", self.styles['Normal']))
            story.append(Paragraph("📖 CloudWatch integration: https://docs.aws.amazon.com/eks/latest/userguide/monitor-control-plane.html", self.styles['Normal']))
            story.append(Paragraph("<b>Implementation Guide:</b>", self.styles['Normal']))
            story.append(Paragraph("1. Enable all log types: api, audit, authenticator, controllerManager, scheduler", self.styles['Normal']))
            story.append(Paragraph("2. Configure CloudWatch log retention policy (recommend 90+ days)", self.styles['Normal']))
            story.append(Paragraph("3. Set up CloudWatch alarms for suspicious activities", self.styles['Normal']))
            story.append(Paragraph("4. Integrate with SIEM tools for advanced threat detection", self.styles['Normal']))
        
        elif 'Endpoint' in title:
            story.append(Paragraph("<b>Security Justification:</b>", self.styles['Normal']))
            story.append(Paragraph("• Reduces attack surface by limiting API server exposure", self.styles['Normal']))
            story.append(Paragraph("• Prevents unauthorized access from internet-based attacks", self.styles['Normal']))
            story.append(Paragraph("• Implements network-level access controls", self.styles['Normal']))
            story.append(Paragraph("<b>Business Impact:</b> Significantly reduces risk of cluster compromise", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b>", self.styles['Normal']))
            story.append(Paragraph("📖 API endpoint access: https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html", self.styles['Normal']))
            story.append(Paragraph("📖 Private clusters: https://docs.aws.amazon.com/eks/latest/userguide/private-clusters.html", self.styles['Normal']))
            story.append(Paragraph("<b>Implementation Guide:</b>", self.styles['Normal']))
            story.append(Paragraph("1. Enable private endpoint access for internal communication", self.styles['Normal']))
            story.append(Paragraph("2. Restrict public access to specific IP ranges or disable completely", self.styles['Normal']))
            story.append(Paragraph("3. Use VPN or bastion hosts for administrative access", self.styles['Normal']))
            story.append(Paragraph("4. Configure security groups to further restrict access", self.styles['Normal']))
        
        elif 'Network' in title:
            story.append(Paragraph("<b>Security Justification:</b>", self.styles['Normal']))
            story.append(Paragraph("• Implements network segmentation and micro-segmentation", self.styles['Normal']))
            story.append(Paragraph("• Prevents lateral movement in case of pod compromise", self.styles['Normal']))
            story.append(Paragraph("• Enforces least-privilege network access", self.styles['Normal']))
            story.append(Paragraph("<b>AWS Documentation:</b>", self.styles['Normal']))
            story.append(Paragraph("📖 Network policies: https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html", self.styles['Normal']))
            story.append(Paragraph("📖 Security groups for pods: https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html", self.styles['Normal']))
            story.append(Paragraph("<b>Implementation Guide:</b>", self.styles['Normal']))
            story.append(Paragraph("1. Install AWS VPC CNI with network policy support", self.styles['Normal']))
            story.append(Paragraph("2. Define default-deny network policies for all namespaces", self.styles['Normal']))
            story.append(Paragraph("3. Create specific allow rules for required communications", self.styles['Normal']))
            story.append(Paragraph("4. Test connectivity after implementing policies", self.styles['Normal']))
        
        else:
            # Generic recommendation with general AWS best practices
            story.append(Paragraph("<b>AWS Best Practices:</b>", self.styles['Normal']))
            story.append(Paragraph("📖 EKS Best Practices Guide: https://aws.github.io/aws-eks-best-practices/", self.styles['Normal']))
            story.append(Paragraph("📖 Security best practices: https://docs.aws.amazon.com/eks/latest/userguide/security.html", self.styles['Normal']))
            story.append(Paragraph("📖 Well-Architected Framework: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/", self.styles['Normal']))
        
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
        
        # Create table data with Paragraph objects for proper text wrapping
        commands_data = []
        # Header row
        commands_data.append([
            Paragraph('<b>Analysis Area</b>', self.table_header_style),
            Paragraph('<b>Command</b>', self.table_header_style),
            Paragraph('<b>Purpose</b>', self.table_header_style)
        ])
        
        # Data rows with wrapped text
        command_entries = [
            ['Cluster Info', f'aws eks describe-cluster --name {cluster_name}', 'Get cluster configuration'],
            ['Node Groups', f'aws eks list-nodegroups --cluster-name {cluster_name}', 'List all node groups'],
            ['Node Group Details', f'aws eks describe-nodegroup --cluster-name {cluster_name} --nodegroup-name [ng]', 'Get node group configuration'],
            ['Addons', f'aws eks list-addons --cluster-name {cluster_name}', 'List EKS addons'],
            ['Addon Details', f'aws eks describe-addon --cluster-name {cluster_name} --addon-name [addon]', 'Get addon status'],
            ['VPC Info', 'aws ec2 describe-vpcs --vpc-ids [vpc-id]', 'Get VPC configuration'],
            ['Subnet Info', 'aws ec2 describe-subnets --subnet-ids [subnet-ids]', 'Get subnet details'],
            ['Security Groups', 'aws ec2 describe-security-groups --group-ids [sg-ids]', 'Get security group rules']
        ]
        
        for area, command, purpose in command_entries:
            commands_data.append([
                Paragraph(area, self.table_cell_style),
                Paragraph(f'<font name="Courier" size="9">{command}</font>', self.table_cell_style),
                Paragraph(purpose, self.table_cell_style)
            ])
        
        table = Table(commands_data, colWidths=[1.3*inch, 3.2*inch, 2.5*inch])
        table.setStyle(self._get_detailed_table_style())
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Add HardenEKS Security Checks Reference
        story.append(Paragraph("HardenEKS Security Checks Reference", self.finding_style))
        story.append(Paragraph("Complete list of 39 security checks performed during HardenEKS analysis:", self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        # HardenEKS checks by category with Paragraph objects
        hardeneks_data = []
        # Header row
        hardeneks_data.append([
            Paragraph('<b>Category</b>', self.table_header_style),
            Paragraph('<b>Check Name</b>', self.table_header_style),
            Paragraph('<b>Command/Method</b>', self.table_header_style),
            Paragraph('<b>AWS Documentation</b>', self.table_header_style)
        ])
        
        # Data rows
        hardeneks_entries = [
            ['IAM & Access', 'EKS Cluster Service Role', 'aws iam get-role --role-name [role]', 'https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html'],
            ['IAM & Access', 'Node Group Instance Profile', 'aws iam get-instance-profile --instance-profile-name [profile]', 'https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html'],
            ['IAM & Access', 'IRSA Configuration', 'aws eks describe-cluster --name [cluster] --query cluster.identity.oidc', 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html'],
            ['IAM & Access', 'RBAC Configuration', 'kubectl get clusterrolebindings', 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/'],
            ['IAM & Access', 'AWS Auth ConfigMap', 'kubectl get configmap aws-auth -n kube-system', 'https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html'],
            ['Pod Security', 'Pod Security Standards', 'kubectl get pss --all-namespaces', 'https://kubernetes.io/docs/concepts/security/pod-security-standards/'],
            ['Pod Security', 'Security Context', 'kubectl get pods -o yaml | grep securityContext', 'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/'],
            ['Pod Security', 'Resource Limits', 'kubectl describe limitrange --all-namespaces', 'https://kubernetes.io/docs/concepts/policy/limit-range/'],
            ['Pod Security', 'Admission Controllers', 'kubectl get validatingwebhookconfigurations', 'https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/'],
            ['Pod Security', 'Privileged Containers', 'kubectl get pods -o jsonpath="{..securityContext.privileged}"', 'https://kubernetes.io/docs/concepts/security/pod-security-standards/'],
            ['Network Security', 'API Server Endpoint', 'aws eks describe-cluster --name [cluster] --query cluster.resourcesVpcConfig', 'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html'],
            ['Network Security', 'Security Groups', 'aws ec2 describe-security-groups --group-ids [sg-ids]', 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html'],
            ['Network Security', 'Network Policies', 'kubectl get networkpolicies --all-namespaces', 'https://kubernetes.io/docs/concepts/services-networking/network-policies/'],
            ['Network Security', 'VPC Configuration', 'aws ec2 describe-vpcs --vpc-ids [vpc-id]', 'https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html'],
            ['Encryption', 'Secrets Encryption', 'aws eks describe-cluster --name [cluster] --query cluster.encryptionConfig', 'https://docs.aws.amazon.com/eks/latest/userguide/encryption-at-rest.html'],
            ['Encryption', 'Transit Encryption', 'kubectl get services -o yaml | grep annotations', 'https://docs.aws.amazon.com/eks/latest/userguide/alb-ingress.html'],
            ['Logging & Monitoring', 'Control Plane Logs', 'aws eks describe-cluster --name [cluster] --query cluster.logging', 'https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html'],
            ['Logging & Monitoring', 'CloudTrail Logging', 'aws cloudtrail describe-trails', 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/'],
            ['Logging & Monitoring', 'GuardDuty Integration', 'aws guardduty list-detectors', 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_cloudwatch.html']
        ]
        
        for category, check_name, command, docs in hardeneks_entries:
            hardeneks_data.append([
                Paragraph(category, self.table_cell_style),
                Paragraph(check_name, self.table_cell_style),
                Paragraph(f'<font name="Courier" size="9">{command}</font>', self.table_cell_style),
                Paragraph(f'<font size="9">{docs}</font>', self.table_cell_style)
            ])
        
        table = Table(hardeneks_data, colWidths=[1.1*inch, 1.6*inch, 2.1*inch, 2.2*inch])
        table.setStyle(self._get_detailed_table_style())
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Compliance Framework Checks Reference
        story.append(Paragraph("Compliance Framework Checks Reference", self.finding_style))
        story.append(Paragraph("Security and compliance frameworks assessed with their control mappings:", self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Create compliance table with Paragraph objects
        compliance_data = []
        # Header row
        compliance_data.append([
            Paragraph('<b>Framework</b>', self.table_header_style),
            Paragraph('<b>Version</b>', self.table_header_style),
            Paragraph('<b>Total Controls</b>', self.table_header_style),
            Paragraph('<b>Key Assessment Areas</b>', self.table_header_style),
            Paragraph('<b>Documentation</b>', self.table_header_style)
        ])
        
        # Data rows
        compliance_entries = [
            ['CIS EKS Benchmark', 'v1.0.1', '17 controls', 'Control Plane, Node Security, Policies', 'https://www.cisecurity.org/benchmark/kubernetes'],
            ['NIST CSF', 'v1.1', '20 controls', 'Identify, Protect, Detect, Respond, Recover', 'https://www.nist.gov/cyberframework'],
            ['SOC 2 Type II', '2017', '12 controls', 'Security, Availability, Confidentiality', 'https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html'],
            ['EU DORA', '2024', '10 controls', 'ICT Risk, Incident Management, Resilience Testing', 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554'],
            ['PCI DSS', 'v3.2.1', '8 controls', 'Network Security, Encryption, Access Control', 'https://www.pcisecuritystandards.org/'],
            ['HIPAA Security Rule', '2013', '6 controls', 'Administrative, Physical, Technical Safeguards', 'https://www.hhs.gov/hipaa/for-professionals/security/'],
            ['ISO 27001', '2013', '4 controls', 'Access Control, Cryptography', 'https://www.iso.org/isoiec-27001-information-security.html']
        ]
        
        for framework, version, controls, areas, docs in compliance_entries:
            compliance_data.append([
                Paragraph(framework, self.table_cell_style),
                Paragraph(version, self.table_cell_style),
                Paragraph(controls, self.table_cell_style),
                Paragraph(areas, self.table_cell_style),
                Paragraph(f'<font size="9">{docs}</font>', self.table_cell_style)
            ])
        
        table = Table(compliance_data, colWidths=[1.2*inch, 0.6*inch, 0.8*inch, 1.7*inch, 2.7*inch])
        table.setStyle(self._get_detailed_table_style())
        story.append(table)
        story.append(Spacer(1, 20))
        
        # Security Grade Reference
        story.append(Paragraph("Security Grade Reference", self.finding_style))
        story.append(Paragraph("Understanding security grades and compliance percentages:", self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Create grade reference table with Paragraph objects
        grade_data = []
        # Header row
        grade_data.append([
            Paragraph('<b>Grade</b>', self.table_header_style),
            Paragraph('<b>Percentage Range</b>', self.table_header_style),
            Paragraph('<b>Security Posture</b>', self.table_header_style),
            Paragraph('<b>Description</b>', self.table_header_style),
            Paragraph('<b>Recommended Actions</b>', self.table_header_style)
        ])
        
        # Data rows
        grade_entries = [
            ['A', '90-100%', 'EXCELLENT', 'Exceptional security posture meeting all best practices', 'Maintain current standards, regular reviews'],
            ['B', '80-89%', 'GOOD', 'Strong security with minor gaps', 'Address remaining issues, enhance monitoring'],
            ['C', '70-79%', 'SATISFACTORY', 'Adequate security with some concerns', 'Prioritize medium-risk issues, improve policies'],
            ['D', '60-69%', 'NEEDS_IMPROVEMENT', 'Below-average security requiring attention', 'Implement security improvements immediately'],
            ['F', '<60%', 'CRITICAL', 'Poor security posture with significant risks', 'Emergency remediation required, comprehensive review']
        ]
        
        for grade, range_val, posture, description, actions in grade_entries:
            grade_data.append([
                Paragraph(f'<b>{grade}</b>', self.table_cell_style),
                Paragraph(range_val, self.table_cell_style),
                Paragraph(posture, self.table_cell_style),
                Paragraph(description, self.table_cell_style),
                Paragraph(actions, self.table_cell_style)
            ])
        
        table = Table(grade_data, colWidths=[0.5*inch, 1*inch, 1.1*inch, 2.2*inch, 2.2*inch])
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
    
    def _add_detailed_check_results_section(self, story, results):
        """Add comprehensive table of all checks performed with results and recommendations"""
        story.append(Paragraph("DETAILED CHECK RESULTS", self.section_style))
        story.append(Paragraph("Complete listing of all security, compliance, and operational checks performed during analysis.", self.styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Collect all checks from different sources
        all_checks = []
        
        # Basic Security Checks
        security_analysis = results.get('security_analysis', {})
        basic_checks = security_analysis.get('checks', [])
        for check in basic_checks:
            all_checks.append({
                'source': 'Basic Security',
                'check_id': check.get('id', 'N/A'),
                'title': check.get('title', 'Unknown Check'),
                'status': check.get('status', 'Unknown'),
                'severity': check.get('severity', 'N/A'),
                'description': check.get('description', 'No description available'),
                'finding': check.get('finding', check.get('description', 'No finding details')),
                'recommendation': check.get('recommendation', 'See recommendations section'),
                'command': check.get('command_used', 'aws eks describe-cluster --name [cluster]'),
                'category': 'Security'
            })
        
        # HardenEKS checks
        hardeneks_analysis = results.get('hardeneks_analysis', {})
        if not hardeneks_analysis:
            hardeneks_analysis = security_analysis.get('hardeneks_analysis', {})
        
        hardeneks_checks = hardeneks_analysis.get('checks', [])
        for check in hardeneks_checks:
            all_checks.append({
                'source': 'HardenEKS',
                'check_id': check.get('check_id', check.get('id', 'N/A')),
                'title': check.get('title', check.get('name', 'Unknown Check')),
                'status': check.get('status', 'Unknown'),
                'severity': check.get('severity', check.get('priority', 'N/A')),
                'description': check.get('description', 'No description available'),
                'finding': check.get('finding', check.get('result', 'No finding details')),
                'recommendation': check.get('recommendation', check.get('remediation', 'No recommendation')),
                'command': check.get('command_used', check.get('check_command', 'N/A')),
                'category': check.get('category', 'HardenEKS')
            })
        
        # DORA Compliance checks
        dora_analysis = results.get('dora_analysis', {})
        if not dora_analysis:
            dora_analysis = security_analysis.get('dora_analysis', {})
        
        dora_checks = dora_analysis.get('checks', [])
        for check in dora_checks:
            all_checks.append({
                'source': 'DORA Compliance',
                'check_id': check.get('check_id', 'N/A'),
                'title': check.get('title', 'Unknown Check'),
                'status': check.get('status', 'Unknown'),
                'severity': check.get('severity', 'N/A'),
                'description': check.get('description', 'No description available'),
                'finding': check.get('finding', 'No finding details'),
                'recommendation': check.get('recommendation', check.get('guidance', 'No recommendation')),
                'command': check.get('command_used', 'N/A'),
                'category': 'DORA Compliance'
            })
        
        # Sort checks by status (FAIL first, then WARN, then PASS)
        status_order = {'FAIL': 1, 'FAILED': 1, 'WARNING': 2, 'WARN': 2, 'PASS': 3, 'PASSED': 3}
        all_checks.sort(key=lambda x: status_order.get(x['status'].upper(), 4))
        
        if all_checks:
            # Summary table first
            story.append(Paragraph("Check Results Summary", self.finding_style))
            
            # Count results by status and source
            status_counts = {'PASS': 0, 'FAIL': 0, 'WARNING': 0}
            source_counts = {}
            
            for check in all_checks:
                status = check['status'].upper()
                if status in ['PASSED', 'PASS']:
                    status_counts['PASS'] += 1
                elif status in ['FAILED', 'FAIL']:
                    status_counts['FAIL'] += 1
                elif status in ['WARNING', 'WARN']:
                    status_counts['WARNING'] += 1
                
                source = check['source']
                source_counts[source] = source_counts.get(source, 0) + 1
            
            summary_data = [
                ['Metric', 'Count', 'Percentage'],
                ['Total Checks', str(len(all_checks)), '100%'],
                ['Passed Checks', str(status_counts['PASS']), f"{(status_counts['PASS']/len(all_checks)*100):.1f}%"],
                ['Failed Checks', str(status_counts['FAIL']), f"{(status_counts['FAIL']/len(all_checks)*100):.1f}%"],
                ['Warning Checks', str(status_counts['WARNING']), f"{(status_counts['WARNING']/len(all_checks)*100):.1f}%"]
            ]
            
            table = Table(summary_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
            table.setStyle(self._get_detailed_table_style())
            story.append(table)
            story.append(Spacer(1, 20))
            
            # Source breakdown
            story.append(Paragraph("Checks by Source", self.finding_style))
            source_data = [['Source', 'Count', 'Percentage']]
            for source, count in source_counts.items():
                source_data.append([source, str(count), f"{(count/len(all_checks)*100):.1f}%"])
            
            table = Table(source_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
            table.setStyle(self._get_detailed_table_style())
            story.append(table)
            story.append(Spacer(1, 20))
            
            # Detailed check results table
            story.append(Paragraph("Complete Check Results", self.finding_style))
            story.append(Paragraph("The following table contains all checks performed. For Excel export with full details and filtering capabilities, use the Reports tab in the application.", self.styles['Normal']))
            story.append(Spacer(1, 10))
            
            # Create paginated tables to avoid PDF page issues
            page_size = 15  # Number of checks per page
            for page_start in range(0, len(all_checks), page_size):
                page_checks = all_checks[page_start:page_start + page_size]
                
                if page_start > 0:
                    story.append(PageBreak())
                    story.append(Paragraph("Detailed Check Results (continued)", self.finding_style))
                    story.append(Spacer(1, 10))
                
                # Create table with Paragraph objects for text wrapping
                check_data = []
                check_data.append([
                    Paragraph('<b>ID</b>', self.table_header_style),
                    Paragraph('<b>Check Name</b>', self.table_header_style),
                    Paragraph('<b>Status</b>', self.table_header_style),
                    Paragraph('<b>Severity</b>', self.table_header_style),
                    Paragraph('<b>Source</b>', self.table_header_style),
                    Paragraph('<b>Finding</b>', self.table_header_style)
                ])
                
                for check in page_checks:
                    # Truncate long text for table display
                    finding = check['finding'][:80] + '...' if len(check['finding']) > 80 else check['finding']
                    title = check['title'][:40] + '...' if len(check['title']) > 40 else check['title']
                    
                    # Color code status
                    status_color = colors.red if check['status'].upper() in ['FAIL', 'FAILED'] else \
                                  colors.orange if check['status'].upper() in ['WARN', 'WARNING'] else colors.green
                    
                    check_data.append([
                        Paragraph(check['check_id'], self.table_cell_style),
                        Paragraph(title, self.table_cell_style),
                        Paragraph(f'<font color="{status_color.hexval()}">{check["status"]}</font>', self.table_cell_style),
                        Paragraph(check['severity'], self.table_cell_style),
                        Paragraph(check['source'], self.table_cell_style),
                        Paragraph(finding, self.table_cell_style)
                    ])
                
                table = Table(check_data, colWidths=[0.8*inch, 2*inch, 0.8*inch, 0.8*inch, 1.2*inch, 2.4*inch])
                table.setStyle(self._get_detailed_table_style())
                story.append(table)
                story.append(Spacer(1, 15))
            
            # Failed checks details
            failed_checks = [c for c in all_checks if c['status'].upper() in ['FAIL', 'FAILED']]
            if failed_checks:
                story.append(PageBreak())
                story.append(Paragraph("Failed Checks - Detailed Analysis", self.finding_style))
                story.append(Paragraph("The following checks failed and require immediate attention:", self.styles['Normal']))
                story.append(Spacer(1, 15))
                
                for i, check in enumerate(failed_checks[:10], 1):  # Top 10 failed checks
                    story.append(Paragraph(f"❌ {i}. {check['title']} (ID: {check['check_id']})", self.finding_style))
                    story.append(Paragraph(f"<b>Source:</b> {check['source']} | <b>Severity:</b> {check['severity']}", self.styles['Normal']))
                    story.append(Paragraph(f"<b>Description:</b> {check['description']}", self.styles['Normal']))
                    story.append(Paragraph(f"<b>Finding:</b> {check['finding']}", self.styles['Normal']))
                    story.append(Paragraph(f"<b>Recommendation:</b> {check['recommendation']}", self.styles['Normal']))
                    if check['command'] != 'N/A':
                        story.append(Paragraph(f"<b>Verification Command:</b> <font name='Courier'>{check['command']}</font>", self.styles['Normal']))
                    story.append(Spacer(1, 15))
        else:
            story.append(Paragraph("No detailed check results available. This may indicate an issue with the analysis process.", self.styles['Normal']))
        
        story.append(PageBreak())
    
    def _add_dora_metrics_assessment(self, story, results):
        """Add EU DORA (European Union's Digital Operational Resilience Act) metrics to PDF"""
        story.append(Spacer(1, 20))
        story.append(Paragraph("EU DORA (European Union's Digital Operational Resilience Act) Metrics", self.finding_style))
        story.append(Paragraph("Analysis of digital operational resilience based on EU financial regulation requirements for ICT risk management, incident handling, and operational resilience testing.", self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Calculate DORA metrics based on available data
        health = results.get('health_analysis', {})
        security = results.get('security_analysis', {})
        
        # Assess automation capabilities
        auto_scaling = self._assess_auto_scaling_pdf(results)
        automation_level = self._assess_automation_level_pdf(results)
        monitoring_setup = self._assess_monitoring_setup_pdf(results)
        
        # Calculate security score
        security_score = 0
        if security.get('total_checks', 0) > 0:
            security_score = (security.get('passed_checks', 0) / security.get('total_checks', 1)) * 100
        
        # Calculate overall DORA score
        dora_score = self._calculate_dora_score_pdf(auto_scaling, automation_level, security_score, monitoring_setup)
        
        # DORA Metrics Table
        dora_data = [
            ['DORA Metric', 'Assessment', 'Score/Status', 'Recommendation'],
            ['Deployment Frequency', 'Auto-scaling Capability', 'High' if auto_scaling else 'Medium', 'Enable Cluster Autoscaler and HPA'],
            ['Lead Time for Changes', 'Automation Level', automation_level, 'Implement Infrastructure as Code'],
            ['Change Failure Rate', 'Security Compliance', f"{security_score:.1f}%", 'Improve security posture'],
            ['Recovery Time', 'Monitoring Setup', 'Configured' if monitoring_setup else 'Basic', 'Enable comprehensive logging'],
            ['Overall DORA Score', 'Performance Category', f"{dora_score:.1f}%", self._get_dora_category(dora_score)]
        ]
        
        table = Table(dora_data, colWidths=[1.8*inch, 1.5*inch, 1.2*inch, 2.5*inch])
        table.setStyle(self._get_detailed_table_style())
        story.append(table)
        story.append(Spacer(1, 15))
        
        # Performance Category Assessment
        category = self._get_dora_category(dora_score)
        story.append(Paragraph(f"DORA Performance Category: <b>{category}</b>", self.styles['Normal']))
        
        if category == "Elite Performer":
            story.append(Paragraph("🏆 Your EKS cluster demonstrates elite DevOps performance characteristics with high automation, strong security, and comprehensive monitoring.", self.styles['Normal']))
        elif category == "High Performer":
            story.append(Paragraph("📈 Your EKS cluster shows good DevOps practices with room for optimization in automation and monitoring.", self.styles['Normal']))
        elif category == "Medium Performer":
            story.append(Paragraph("⚠️ Your EKS cluster has basic DevOps capabilities but needs improvement in key areas like automation and security.", self.styles['Normal']))
        else:
            story.append(Paragraph("🔴 Your EKS cluster requires significant improvements in DevOps practices, automation, and security.", self.styles['Normal']))
        
        # DORA Improvement Recommendations
        story.append(Spacer(1, 10))
        story.append(Paragraph("DORA Improvement Recommendations:", self.styles['Normal']))
        
        recommendations = []
        if not auto_scaling:
            recommendations.append("• Enable Cluster Autoscaler and Horizontal Pod Autoscaler for better deployment frequency")
        if automation_level == "Low":
            recommendations.append("• Implement Infrastructure as Code (Terraform/CloudFormation) for consistent deployments")
        if security_score < 80:
            recommendations.append("• Improve security posture to reduce change failure rate")
        if not monitoring_setup:
            recommendations.append("• Enable comprehensive logging and monitoring for faster recovery times")
        
        if recommendations:
            for rec in recommendations:
                story.append(Paragraph(rec, self.styles['Normal']))
        else:
            story.append(Paragraph("🎉 Your cluster demonstrates excellent DORA practices!", self.styles['Normal']))
        
        story.append(Spacer(1, 10))
        story.append(Paragraph("📖 Reference: https://www.devops-research.com/research.html", self.styles['Normal']))
    
    def _assess_auto_scaling_pdf(self, results: Dict[str, Any]) -> bool:
        """Assess if auto-scaling is properly configured for PDF"""
        health = results.get('health_analysis', {})
        node_analysis = health.get('node_analysis', {})
        node_groups = node_analysis.get('node_groups', [])
        
        for ng in node_groups:
            min_size = ng.get('min_size', 0)
            max_size = ng.get('max_size', 0)
            desired_size = ng.get('desired_size', 0)
            
            if max_size > min_size and desired_size < max_size:
                return True
        return False
    
    def _assess_automation_level_pdf(self, results: Dict[str, Any]) -> str:
        """Assess the level of automation for PDF"""
        health = results.get('health_analysis', {})
        node_analysis = health.get('node_analysis', {})
        addon_analysis = health.get('addon_analysis', {})
        
        total_node_groups = node_analysis.get('total_node_groups', 0)
        total_addons = addon_analysis.get('total_addons', 0)
        
        if total_addons >= 3 and total_node_groups > 0:
            return "High"
        elif total_addons >= 1 or total_node_groups > 0:
            return "Medium"
        else:
            return "Low"
    
    def _assess_monitoring_setup_pdf(self, results: Dict[str, Any]) -> bool:
        """Assess if comprehensive monitoring is setup for PDF"""
        security = results.get('security_analysis', {})
        
        for check in security.get('checks', []):
            if check.get('id') == 'cluster_logging' and check.get('status') == 'PASS':
                return True
        return False
    
    def _calculate_dora_score_pdf(self, auto_scaling: bool, automation_level: str, security_score: float, monitoring_setup: bool) -> float:
        """Calculate overall DORA performance score for PDF"""
        score = 0
        
        if auto_scaling:
            score += 25
        
        if automation_level == "High":
            score += 25
        elif automation_level == "Medium":
            score += 15
        
        score += (security_score * 0.30)
        
        if monitoring_setup:
            score += 20
        
        return min(score, 100)
    
    def _get_dora_category(self, score: float) -> str:
        """Get DORA performance category based on score"""
        if score >= 80:
            return "Elite Performer"
        elif score >= 60:
            return "High Performer"
        elif score >= 40:
            return "Medium Performer"
        else:
            return "Low Performer"
    
    def _get_table_style(self):
        """Get standard table style with text wrapping"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('WORDWRAP', (0, 0), (-1, -1), 'CJK'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.beige, colors.lightgrey])
        ])
    
    def _get_detailed_table_style(self):
        """Get detailed table style with text wrapping and improved spacing"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('WORDWRAP', (0, 0), (-1, -1), 'CJK'),
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.darkblue)
        ])
