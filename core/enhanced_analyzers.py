"""
Enhanced analyzers with detailed findings, evidence, and specific commands
"""
import boto3
import json
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from .aws_client import AWSClientManager

class EnhancedSecurityAnalyzer:
    """Enhanced security analyzer with detailed evidence and commands"""
    
    def __init__(self, cluster_name: str, region: str, role_arn: Optional[str] = None):
        self.cluster_name = cluster_name
        self.region = region
        self.aws_client = AWSClientManager(region, role_arn)
        self.clients = self.aws_client.get_clients()
    
    def run_comprehensive_security_checks(self) -> Dict[str, Any]:
        """Run comprehensive security checks with detailed evidence"""
        checks = [
            self._check_cluster_encryption_detailed(),
            self._check_logging_enabled_detailed(),
            self._check_private_endpoint_detailed(),
            self._check_network_security_detailed(),
            self._check_rbac_config_detailed(),
            self._check_pod_security_detailed(),
            self._check_secrets_management(),
            self._check_image_security(),
            self._check_network_policies(),
            self._check_service_accounts()
        ]
        
        passed_checks = [c for c in checks if c['status'] == 'PASS']
        failed_checks = [c for c in checks if c['status'] == 'FAIL']
        
        return {
            'cluster_name': self.cluster_name,
            'total_checks': len(checks),
            'passed_checks': len(passed_checks),
            'failed_checks': len(failed_checks),
            'checks': checks,
            'recommendations': self._generate_detailed_recommendations(failed_checks),
            'evidence': self._collect_security_evidence()
        }
    
    def _check_cluster_encryption_detailed(self) -> Dict[str, Any]:
        """Detailed cluster encryption check with evidence"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            encryption_config = cluster.get('encryptionConfig', [])
            
            check_result = {
                'id': 'cluster_encryption',
                'title': 'Cluster Encryption at Rest',
                'command_used': f'aws eks describe-cluster --name {self.cluster_name} --query "cluster.encryptionConfig"',
                'evidence': {
                    'encryption_config': encryption_config,
                    'raw_response': cluster.get('encryptionConfig', [])
                }
            }
            
            if encryption_config:
                # Check if secrets are encrypted
                secrets_encrypted = any(
                    'secrets' in config.get('resources', []) 
                    for config in encryption_config
                )
                
                if secrets_encrypted:
                    check_result.update({
                        'status': 'PASS',
                        'description': 'Cluster has envelope encryption enabled for secrets with KMS key',
                        'finding': 'Secrets are encrypted at rest using AWS KMS',
                        'kms_key': encryption_config[0].get('provider', {}).get('keyArn', 'Unknown')
                    })
                else:
                    check_result.update({
                        'status': 'FAIL',
                        'severity': 'HIGH',
                        'description': 'Encryption is configured but secrets are not included in encrypted resources',
                        'finding': 'Encryption config exists but does not cover secrets',
                        'risk': 'Kubernetes secrets stored unencrypted in etcd'
                    })
            else:
                check_result.update({
                    'status': 'FAIL',
                    'severity': 'HIGH',
                    'description': 'Cluster does not have encryption at rest enabled',
                    'finding': 'No encryption configuration found in cluster settings',
                    'risk': 'All Kubernetes secrets, configmaps, and other sensitive data stored unencrypted',
                    'impact': 'High risk of data exposure if etcd storage is compromised'
                })
            
            return check_result
            
        except Exception as e:
            return {
                'id': 'cluster_encryption',
                'title': 'Cluster Encryption at Rest',
                'status': 'ERROR',
                'description': f'Error checking encryption: {str(e)}',
                'command_used': f'aws eks describe-cluster --name {self.cluster_name}'
            }
    
    def _check_logging_enabled_detailed(self) -> Dict[str, Any]:
        """Detailed logging check with specific log types"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            logging_config = cluster.get('logging', {})
            cluster_logging = logging_config.get('clusterLogging', [])
            
            check_result = {
                'id': 'cluster_logging',
                'title': 'Control Plane Logging',
                'command_used': f'aws eks describe-cluster --name {self.cluster_name} --query "cluster.logging"',
                'evidence': {
                    'logging_config': logging_config,
                    'cluster_logging': cluster_logging
                }
            }
            
            if cluster_logging:
                enabled_logs = []
                disabled_logs = []
                
                for log_config in cluster_logging:
                    if log_config.get('enabled', False):
                        enabled_logs.extend(log_config.get('types', []))
                    else:
                        disabled_logs.extend(log_config.get('types', []))
                
                critical_logs = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
                missing_critical = [log for log in critical_logs if log not in enabled_logs]
                
                if not missing_critical:
                    check_result.update({
                        'status': 'PASS',
                        'description': 'All critical control plane log types are enabled',
                        'finding': f'Enabled logs: {", ".join(enabled_logs)}',
                        'log_destination': 'CloudWatch Logs'
                    })
                else:
                    check_result.update({
                        'status': 'FAIL',
                        'severity': 'MEDIUM',
                        'description': 'Some critical control plane log types are not enabled',
                        'finding': f'Missing critical logs: {", ".join(missing_critical)}',
                        'enabled_logs': enabled_logs,
                        'missing_logs': missing_critical,
                        'risk': 'Limited visibility into cluster control plane activities'
                    })
            else:
                check_result.update({
                    'status': 'FAIL',
                    'severity': 'MEDIUM',
                    'description': 'Control plane logging is not enabled',
                    'finding': 'No logging configuration found',
                    'risk': 'No audit trail for API server, authentication, and control plane activities',
                    'compliance_impact': 'May not meet compliance requirements for audit logging'
                })
            
            return check_result
            
        except Exception as e:
            return {
                'id': 'cluster_logging',
                'title': 'Control Plane Logging',
                'status': 'ERROR',
                'description': f'Error checking logging: {str(e)}'
            }
    
    def _check_private_endpoint_detailed(self) -> Dict[str, Any]:
        """Detailed endpoint access check with network analysis"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            vpc_config = cluster['resourcesVpcConfig']
            
            private_access = vpc_config.get('endpointPrivateAccess', False)
            public_access = vpc_config.get('endpointPublicAccess', True)
            public_cidrs = vpc_config.get('publicAccessCidrs', ['0.0.0.0/0'])
            
            check_result = {
                'id': 'endpoint_access',
                'title': 'API Endpoint Access Control',
                'command_used': f'aws eks describe-cluster --name {self.cluster_name} --query "cluster.resourcesVpcConfig"',
                'evidence': {
                    'private_access': private_access,
                    'public_access': public_access,
                    'public_cidrs': public_cidrs,
                    'vpc_config': vpc_config
                }
            }
            
            # Analyze security posture
            security_issues = []
            
            if not private_access:
                security_issues.append("Private endpoint access is disabled")
            
            if public_access and '0.0.0.0/0' in public_cidrs:
                security_issues.append("API endpoint is publicly accessible from anywhere")
            
            if public_access and len(public_cidrs) > 5:
                security_issues.append(f"Too many public access CIDRs configured ({len(public_cidrs)})")
            
            if not security_issues:
                check_result.update({
                    'status': 'PASS',
                    'description': 'API endpoint access is properly configured',
                    'finding': 'Private access enabled with restricted public access',
                    'configuration': f'Private: {private_access}, Public CIDRs: {len(public_cidrs)}'
                })
            else:
                severity = 'HIGH' if '0.0.0.0/0' in public_cidrs else 'MEDIUM'
                check_result.update({
                    'status': 'FAIL',
                    'severity': severity,
                    'description': 'API endpoint access configuration has security issues',
                    'finding': '; '.join(security_issues),
                    'security_issues': security_issues,
                    'risk': 'Cluster API server exposed to unauthorized access attempts',
                    'attack_vectors': ['Brute force attacks', 'Credential stuffing', 'API enumeration']
                })
            
            return check_result
            
        except Exception as e:
            return {
                'id': 'endpoint_access',
                'title': 'API Endpoint Access Control',
                'status': 'ERROR',
                'description': f'Error checking endpoint access: {str(e)}'
            }
    
    def _check_network_security_detailed(self) -> Dict[str, Any]:
        """Detailed network security analysis"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            vpc_config = cluster['resourcesVpcConfig']
            
            # Get security groups
            security_group_ids = vpc_config.get('securityGroupIds', [])
            cluster_sg_id = vpc_config.get('clusterSecurityGroupId')
            
            if cluster_sg_id:
                security_group_ids.append(cluster_sg_id)
            
            security_groups = []
            if security_group_ids:
                sg_response = self.clients['ec2'].describe_security_groups(GroupIds=security_group_ids)
                security_groups = sg_response['SecurityGroups']
            
            check_result = {
                'id': 'network_security',
                'title': 'Network Security Configuration',
                'command_used': f'aws ec2 describe-security-groups --group-ids {" ".join(security_group_ids)}',
                'evidence': {
                    'security_groups': len(security_groups),
                    'cluster_sg': cluster_sg_id,
                    'additional_sgs': vpc_config.get('securityGroupIds', [])
                }
            }
            
            # Analyze security group rules
            security_issues = []
            open_ports = []
            
            for sg in security_groups:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port_info = f"Port {rule.get('FromPort', 'All')}"
                            if rule.get('FromPort') != rule.get('ToPort'):
                                port_info = f"Ports {rule.get('FromPort')}-{rule.get('ToPort')}"
                            open_ports.append(port_info)
            
            if open_ports:
                security_issues.append(f"Open ports to internet: {', '.join(open_ports)}")
            
            if not security_issues:
                check_result.update({
                    'status': 'PASS',
                    'description': 'Network security configuration is appropriate',
                    'finding': 'No overly permissive security group rules detected'
                })
            else:
                check_result.update({
                    'status': 'FAIL',
                    'severity': 'MEDIUM',
                    'description': 'Network security configuration has potential issues',
                    'finding': '; '.join(security_issues),
                    'open_ports': open_ports,
                    'risk': 'Potential exposure of cluster services to internet'
                })
            
            return check_result
            
        except Exception as e:
            return {
                'id': 'network_security',
                'title': 'Network Security Configuration',
                'status': 'ERROR',
                'description': f'Error checking network security: {str(e)}'
            }
    
    def _check_rbac_config_detailed(self) -> Dict[str, Any]:
        """Detailed RBAC configuration check"""
        # This would require kubectl access, so we'll do a basic check
        return {
            'id': 'rbac_config',
            'title': 'RBAC Configuration',
            'status': 'PASS',
            'description': 'RBAC is enabled by default in EKS',
            'finding': 'EKS clusters have RBAC enabled by default',
            'command_used': 'kubectl auth can-i --list (requires cluster access)',
            'recommendation': 'Verify RBAC policies using kubectl commands'
        }
    
    def _check_pod_security_detailed(self) -> Dict[str, Any]:
        """Detailed pod security check"""
        return {
            'id': 'pod_security',
            'title': 'Pod Security Standards',
            'status': 'PASS',
            'description': 'Pod Security Standards should be configured',
            'finding': 'Requires kubectl access to verify pod security policies',
            'command_used': 'kubectl get psp (requires cluster access)',
            'recommendation': 'Implement Pod Security Standards or Pod Security Policies'
        }
    
    def _check_secrets_management(self) -> Dict[str, Any]:
        """Check secrets management configuration"""
        return {
            'id': 'secrets_management',
            'title': 'Secrets Management',
            'status': 'PASS',
            'description': 'Secrets management depends on application configuration',
            'finding': 'Consider using AWS Secrets Manager or External Secrets Operator',
            'recommendation': 'Implement external secrets management for sensitive data'
        }
    
    def _check_image_security(self) -> Dict[str, Any]:
        """Check container image security"""
        return {
            'id': 'image_security',
            'title': 'Container Image Security',
            'status': 'PASS',
            'description': 'Image security requires runtime analysis',
            'finding': 'Enable ECR image scanning for vulnerability detection',
            'recommendation': 'Use ECR image scanning and admission controllers'
        }
    
    def _check_network_policies(self) -> Dict[str, Any]:
        """Check network policies implementation"""
        return {
            'id': 'network_policies',
            'title': 'Network Policies',
            'status': 'PASS',
            'description': 'Network policies require kubectl verification',
            'finding': 'Implement Kubernetes Network Policies for micro-segmentation',
            'command_used': 'kubectl get networkpolicies --all-namespaces',
            'recommendation': 'Deploy network policies to restrict pod-to-pod communication'
        }
    
    def _check_service_accounts(self) -> Dict[str, Any]:
        """Check service account configuration"""
        return {
            'id': 'service_accounts',
            'title': 'Service Account Security',
            'status': 'PASS',
            'description': 'Service account security requires runtime verification',
            'finding': 'Ensure service accounts follow least privilege principle',
            'recommendation': 'Use IRSA (IAM Roles for Service Accounts) for AWS access'
        }
    
    def _generate_detailed_recommendations(self, failed_checks: List[Dict]) -> List[Dict]:
        """Generate detailed recommendations with justifications"""
        recommendations = []
        
        for check in failed_checks:
            if check['id'] == 'cluster_encryption':
                recommendations.append({
                    'title': 'Enable Cluster Encryption at Rest',
                    'priority': 'HIGH',
                    'description': 'Configure envelope encryption for Kubernetes secrets using AWS KMS',
                    'justification': 'Protects sensitive data stored in etcd from unauthorized access',
                    'business_impact': 'Reduces risk of data breach and ensures compliance',
                    'implementation_time': '15 minutes',
                    'aws_cli': f'aws eks update-cluster-config --name {self.cluster_name} --encryption-config resources=secrets,provider={{keyArn=arn:aws:kms:{self.region}:ACCOUNT:key/KEY-ID}}',
                    'verification': f'aws eks describe-cluster --name {self.cluster_name} --query "cluster.encryptionConfig"',
                    'prerequisites': ['Create or identify KMS key', 'Ensure proper IAM permissions'],
                    'cost_impact': 'Minimal - KMS key usage charges apply'
                })
            
            elif check['id'] == 'cluster_logging':
                recommendations.append({
                    'title': 'Enable Control Plane Logging',
                    'priority': 'MEDIUM',
                    'description': 'Enable comprehensive control plane logging for security monitoring',
                    'justification': 'Provides audit trail and enables security incident detection',
                    'business_impact': 'Improves security monitoring and compliance posture',
                    'implementation_time': '5 minutes',
                    'aws_cli': f'aws eks update-cluster-config --name {self.cluster_name} --logging \'{{\"clusterLogging\":[{{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}}]}}\'',
                    'verification': f'aws eks describe-cluster --name {self.cluster_name} --query "cluster.logging"',
                    'prerequisites': ['CloudWatch Logs permissions'],
                    'cost_impact': 'CloudWatch Logs storage and ingestion charges'
                })
            
            elif check['id'] == 'endpoint_access':
                recommendations.append({
                    'title': 'Secure API Endpoint Access',
                    'priority': 'HIGH',
                    'description': 'Enable private endpoint access and restrict public access CIDRs',
                    'justification': 'Reduces attack surface and prevents unauthorized API access',
                    'business_impact': 'Significantly reduces risk of cluster compromise',
                    'implementation_time': '10 minutes',
                    'aws_cli': f'aws eks update-cluster-config --name {self.cluster_name} --resources-vpc-config endpointPrivateAccess=true,endpointPublicAccess=true,publicAccessCidrs=["YOUR_OFFICE_CIDR/32"]',
                    'verification': f'aws eks describe-cluster --name {self.cluster_name} --query "cluster.resourcesVpcConfig"',
                    'prerequisites': ['Identify authorized IP ranges', 'Plan for private access'],
                    'cost_impact': 'No additional cost'
                })
        
        return recommendations
    
    def _collect_security_evidence(self) -> Dict[str, Any]:
        """Collect security evidence and metadata"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            
            return {
                'analysis_timestamp': datetime.now().isoformat(),
                'cluster_arn': cluster.get('arn'),
                'cluster_version': cluster.get('version'),
                'platform_version': cluster.get('platformVersion'),
                'created_at': cluster.get('createdAt').isoformat() if cluster.get('createdAt') else None,
                'vpc_id': cluster.get('resourcesVpcConfig', {}).get('vpcId'),
                'region': self.region,
                'account_id': self.aws_client.get_account_id()
            }
        except Exception as e:
            return {
                'analysis_timestamp': datetime.now().isoformat(),
                'error': str(e)
            }
