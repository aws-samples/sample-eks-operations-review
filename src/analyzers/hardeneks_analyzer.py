import logging
import re
from typing import Dict, List, Any
from .cluster_state_analyzer import ClusterStateAnalyzer

logger = logging.getLogger(__name__)

def _sanitize_log_input(text: str) -> str:
    """Sanitize input for logging to prevent log injection."""
    if not isinstance(text, str):
        return str(text)
    # Remove newlines and control characters
    sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
    return sanitized[:200]  # Limit length

class HardenEKSAnalyzer:
    def __init__(self, aws_access_key: str = None, aws_secret_key: str = None, region: str = None):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.region = region
        self.state_analyzer = None
    def analyze_cluster(self, cluster_name: str) -> Dict[str, Any]:
        """Analyze cluster for HardenEKS compliance using actual cluster state.
        
        Args:
            cluster_name: Name of the EKS cluster to analyze
            
        Returns:
            Dict containing analysis results with cluster-specific findings
        """
        if not self.aws_access_key or not self.aws_secret_key or not self.region:
            raise ValueError("AWS credentials and region must be provided")
            
        try:
            # Initialize state analyzer
            self.state_analyzer = ClusterStateAnalyzer(
                self.aws_access_key, self.aws_secret_key, self.region, cluster_name
            )
            
            # Get actual cluster state
            cluster_state = self.state_analyzer.get_comprehensive_cluster_state()
            
            # Analyze based on real cluster state
            high_priority = []
            medium_priority = []
            low_priority = []
            passed_checks = []
            failed_checks = []
        
            # Check IRSA implementation
            irsa_result = self._check_irsa_implementation(cluster_state)
            if irsa_result['passed']:
                passed_checks.append({'check': 'IRSA Implementation', 'status': 'PASSED', 'details': irsa_result['details']})
            else:
                failed_checks.append({'check': 'IRSA Implementation', 'status': 'FAILED', 'details': irsa_result['details']})
                high_priority.append({
                    'category': 'IAM',
                    'title': 'Implement IAM Roles for Service Accounts (IRSA)',
                    'description': f'IRSA not properly configured. {irsa_result["details"]}',
                    'impact': 'Pods using node IAM role with excessive permissions',
                    'priority': 'High',
                    'current_state': irsa_result['current_state'],
                    'action_items': irsa_result['action_items'],
                    'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html'
                })
        
            # Check secrets encryption
            encryption_result = self._check_secrets_encryption(cluster_state)
            if encryption_result['passed']:
                passed_checks.append({'check': 'Secrets Encryption', 'status': 'PASSED', 'details': encryption_result['details']})
            else:
                failed_checks.append({'check': 'Secrets Encryption', 'status': 'FAILED', 'details': encryption_result['details']})
                high_priority.append({
                    'category': 'Data Security',
                    'title': 'Enable Secrets Encryption',
                    'description': f'Kubernetes secrets not encrypted at rest. {encryption_result["details"]}',
                    'impact': 'Sensitive data vulnerable to unauthorized access',
                    'priority': 'High',
                    'current_state': encryption_result['current_state'],
                    'action_items': encryption_result['action_items'],
                    'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/enable-secrets-encryption.html'
                })
            
            # Check audit logging
            audit_result = self._check_audit_logging(cluster_state)
            if audit_result['passed']:
                passed_checks.append({'check': 'Audit Logging', 'status': 'PASSED', 'details': audit_result['details']})
            else:
                failed_checks.append({'check': 'Audit Logging', 'status': 'FAILED', 'details': audit_result['details']})
                high_priority.append({
                    'category': 'Detective Controls',
                    'title': 'Enable Audit Logging',
                    'description': f'Kubernetes audit logging not enabled. {audit_result["details"]}',
                    'impact': 'Limited visibility into cluster activities',
                    'priority': 'High',
                    'current_state': audit_result['current_state'],
                    'action_items': audit_result['action_items'],
                    'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html'
                })
            
            # Check private subnets
            subnet_result = self._check_private_subnets(cluster_state)
            if subnet_result['passed']:
                passed_checks.append({'check': 'Private Subnets', 'status': 'PASSED', 'details': subnet_result['details']})
            else:
                failed_checks.append({'check': 'Private Subnets', 'status': 'FAILED', 'details': subnet_result['details']})
                high_priority.append({
                    'category': 'Infrastructure Security',
                    'title': 'Deploy Nodes in Private Subnets',
                    'description': f'Nodes not properly deployed in private subnets. {subnet_result["details"]}',
                    'impact': 'Increased exposure to external threats',
                    'priority': 'High',
                    'current_state': subnet_result['current_state'],
                    'action_items': subnet_result['action_items'],
                    'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html'
                })
            
            # Check endpoint access
            endpoint_result = self._check_endpoint_access(cluster_state)
            if not endpoint_result['passed']:
                medium_priority.append({
                    'category': 'Network Security',
                    'title': 'Optimize Cluster Endpoint Access',
                    'description': f'Cluster endpoint access not optimally configured. {endpoint_result["details"]}',
                    'impact': 'Potential security risks or accessibility issues',
                    'priority': 'Medium',
                    'current_state': endpoint_result['current_state'],
                    'action_items': endpoint_result['action_items'],
                    'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html'
                })
            else:
                passed_checks.append({'check': 'Endpoint Access', 'status': 'PASSED', 'details': endpoint_result['details']})
            
            # Check addon versions
            addon_results = self._check_addon_versions(cluster_state)
            for addon_result in addon_results:
                if not addon_result['passed']:
                    medium_priority.append({
                        'category': 'Addons',
                        'title': f'Update {addon_result["addon_name"]} Addon',
                        'description': f'{addon_result["details"]}',
                        'impact': 'Missing security patches and performance improvements',
                        'priority': 'Medium',
                        'current_state': addon_result['current_state'],
                        'action_items': addon_result['action_items'],
                        'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/managing-add-ons.html'
                    })
                else:
                    passed_checks.append({'check': f'{addon_result["addon_name"]} Version', 'status': 'PASSED', 'details': addon_result['details']})
        
            # Calculate HardenEKS score
            total_checks = len(passed_checks) + len(failed_checks)
            hardeneks_score = int((len(passed_checks) / total_checks) * 100) if total_checks > 0 else 0
            
            return {
                'high_priority': high_priority,
                'medium_priority': medium_priority,
                'low_priority': low_priority,
                'passed_checks': passed_checks,
                'failed_checks': failed_checks,
                'hardeneks_score': hardeneks_score,
                'cluster_state': cluster_state
            }
        
        except Exception as e:
            logger.warning(f"Error during cluster analysis: {_sanitize_log_input(str(e))}")
            raise
    
    def _check_irsa_implementation(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """Check if IRSA is properly implemented using actual cluster state."""
        try:
            security_state = cluster_state['security_state']
            iam_state = cluster_state['iam_state']
            
            oidc_configured = security_state['oidc_provider']['configured']
            irsa_roles_count = iam_state['irsa_roles_count']
            addon_irsa_count = iam_state.get('addon_irsa_count', 0)
            custom_irsa_count = iam_state.get('custom_irsa_count', 0)
            
            # IRSA is considered properly configured if:
            # 1. OIDC provider exists
            # 2. At least some addons are using IRSA (which is default for managed addons)
            if oidc_configured and addon_irsa_count > 0:
                details = f'OIDC provider configured with {irsa_roles_count} IRSA roles ({addon_irsa_count} addon roles'
                if custom_irsa_count > 0:
                    details += f', {custom_irsa_count} custom roles'
                details += ')'
                
                return {
                    'passed': True,
                    'details': details,
                    'current_state': f'OIDC Provider: ✓, IRSA Roles: {irsa_roles_count} (Addon: {addon_irsa_count}, Custom: {custom_irsa_count})',
                    'action_items': ['Consider creating additional IRSA roles for workloads that need AWS access'] if custom_irsa_count == 0 else []
                }
            else:
                action_items = []
                if not oidc_configured:
                    action_items.append('Create IAM OIDC provider for the cluster')
                if irsa_roles_count == 0:
                    action_items.extend([
                        'Create IAM roles for service accounts',
                        'Associate IAM roles with Kubernetes service accounts',
                        'Configure pods to use service accounts with IAM roles'
                    ])
                
                return {
                    'passed': False,
                    'details': f'OIDC Provider: {"✓" if oidc_configured else "✗"}, IRSA Roles: {irsa_roles_count}',
                    'current_state': f'OIDC Provider: {"Configured" if oidc_configured else "Not Configured"}, IRSA Roles: {irsa_roles_count}',
                    'action_items': action_items
                }
        except Exception as e:
            logger.error(f"Error checking IRSA: {e}")
            return {
                'passed': False,
                'details': 'Error checking IRSA configuration',
                'current_state': 'Unknown',
                'action_items': ['Verify cluster access and permissions']
            }
    
    def _check_secrets_encryption(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """Check if secrets encryption is enabled using actual cluster state."""
        try:
            security_state = cluster_state['security_state']
            encryption_enabled = security_state['secrets_encryption']['enabled']
            kms_key_id = security_state['secrets_encryption']['kms_key_id']
            
            if encryption_enabled:
                return {
                    'passed': True,
                    'details': f'Secrets encryption enabled with KMS key: {kms_key_id or "Default"}',
                    'current_state': f'Encryption: ✓, KMS Key: {kms_key_id or "Default"}',
                    'action_items': []
                }
            else:
                return {
                    'passed': False,
                    'details': 'Secrets encryption not enabled',
                    'current_state': 'Encryption: ✗',
                    'action_items': [
                        'Enable envelope encryption using AWS KMS',
                        'Create dedicated KMS key for secrets',
                        'Enable automatic key rotation',
                        'Consider using external secrets management'
                    ]
                }
        except Exception as e:
            logger.error(f"Error checking secrets encryption: {e}")
            return {
                'passed': False,
                'details': 'Error checking secrets encryption',
                'current_state': 'Unknown',
                'action_items': ['Verify cluster access and permissions']
            }
    
    def _check_audit_logging(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """Check if audit logging is enabled using actual cluster state."""
        try:
            logging_state = cluster_state['logging_state']
            audit_enabled = logging_state['audit_logging_enabled']
            enabled_logs = logging_state['enabled_log_types']
            disabled_logs = logging_state['disabled_log_types']
            
            if audit_enabled:
                return {
                    'passed': True,
                    'details': f'Audit logging enabled. Active logs: {", ".join(enabled_logs)}',
                    'current_state': f'Audit Logging: ✓, Enabled Types: {", ".join(enabled_logs)}',
                    'action_items': []
                }
            else:
                return {
                    'passed': False,
                    'details': f'Audit logging disabled. Missing logs: {", ".join(disabled_logs)}',
                    'current_state': f'Audit Logging: ✗, Disabled Types: {", ".join(disabled_logs)}',
                    'action_items': [
                        'Enable Kubernetes audit logging',
                        'Configure appropriate log retention',
                        'Set up log analysis and monitoring',
                        'Implement automated alerting for suspicious activities'
                    ]
                }
        except Exception as e:
            logger.error(f"Error checking audit logging: {e}")
            return {
                'passed': False,
                'details': 'Error checking audit logging',
                'current_state': 'Unknown',
                'action_items': ['Verify cluster access and permissions']
            }
    
    def _check_private_subnets(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """Check if nodes are deployed in private subnets using actual cluster state."""
        try:
            nodegroups_state = cluster_state['nodegroups_state']
            nodegroups = nodegroups_state['nodegroups']
            
            # If no managed node groups, check if cluster might be using Fargate or self-managed nodes
            if not nodegroups:
                # Check if cluster has Fargate profiles
                try:
                    fargate_profiles = self.state_analyzer.eks.list_fargate_profiles(clusterName=self.state_analyzer.cluster_name)['fargateProfileNames']
                    if fargate_profiles:
                        return {
                            'passed': True,
                            'details': f'Using Fargate profiles: {", ".join(fargate_profiles)}',
                            'current_state': f'Fargate Profiles: {len(fargate_profiles)}',
                            'action_items': []
                        }
                except Exception as e:
                    logger.warning(f"Could not check Fargate profiles: {e}")
                    # Continue to check for self-managed nodes
                
                # No managed node groups or Fargate - could be self-managed or empty cluster
                return {
                    'passed': False,
                    'details': 'No managed node groups or Fargate profiles found',
                    'current_state': 'Node Groups: 0, Fargate Profiles: 0',
                    'action_items': [
                        'Create managed node groups in private subnets, or',
                        'Set up Fargate profiles for serverless compute, or', 
                        'Verify self-managed nodes are in private subnets'
                    ]
                }
            
            private_nodegroups = 0
            total_nodegroups = len(nodegroups)
            nodegroup_details = []
            
            for ng in nodegroups:
                private_ratio = ng['private_subnets_count'] / ng['total_subnets_count']
                if private_ratio >= 0.5:  # At least 50% private subnets
                    private_nodegroups += 1
                    nodegroup_details.append(f"{ng['name']}: ✓ ({ng['private_subnets_count']}/{ng['total_subnets_count']} private)")
                else:
                    nodegroup_details.append(f"{ng['name']}: ✗ ({ng['private_subnets_count']}/{ng['total_subnets_count']} private)")
            
            if private_nodegroups == total_nodegroups:
                return {
                    'passed': True,
                    'details': f'All {total_nodegroups} node groups properly deployed in private subnets',
                    'current_state': '\n'.join(nodegroup_details),
                    'action_items': []
                }
            else:
                return {
                    'passed': False,
                    'details': f'{private_nodegroups}/{total_nodegroups} node groups in private subnets',
                    'current_state': '\n'.join(nodegroup_details),
                    'action_items': [
                        'Move node groups to private subnets',
                        'Configure NAT gateways for outbound traffic',
                        'Use VPC endpoints for AWS services',
                        'Update security groups for private subnet access'
                    ]
                }
        except Exception as e:
            logger.error(f"Error checking private subnets: {e}")
            return {
                'passed': False,
                'details': 'Error checking private subnet configuration',
                'current_state': 'Unknown',
                'action_items': ['Verify cluster access and permissions']
            }
    
    def _check_endpoint_access(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """Check cluster endpoint access configuration."""
        try:
            security_state = cluster_state['security_state']
            endpoint_access = security_state['endpoint_access']
            
            public_access = endpoint_access['public']
            private_access = endpoint_access['private']
            public_cidrs = endpoint_access['public_cidrs']
            
            # Ideal: private access enabled, public access restricted or disabled
            if private_access and (not public_access or (public_access and public_cidrs != ['0.0.0.0/0'])):
                return {
                    'passed': True,
                    'details': f'Optimal endpoint configuration: Private={private_access}, Public={public_access}',
                    'current_state': f'Private Access: ✓, Public Access: {"Restricted" if public_access else "Disabled"}',
                    'action_items': []
                }
            else:
                issues = []
                if not private_access:
                    issues.append('Private access disabled')
                if public_access and public_cidrs == ['0.0.0.0/0']:
                    issues.append('Public access unrestricted (0.0.0.0/0)')
                
                return {
                    'passed': False,
                    'details': f'Endpoint access issues: {", ".join(issues)}',
                    'current_state': f'Private: {private_access}, Public: {public_access}, CIDRs: {public_cidrs}',
                    'action_items': [
                        'Enable private endpoint access',
                        'Restrict public access to specific CIDRs',
                        'Consider disabling public access if not needed',
                        'Configure VPC endpoints for AWS services'
                    ]
                }
        except Exception as e:
            logger.error(f"Error checking endpoint access: {e}")
            return {
                'passed': False,
                'details': 'Error checking endpoint access',
                'current_state': 'Unknown',
                'action_items': ['Verify cluster access and permissions']
            }
    
    def _check_addon_versions(self, cluster_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if addons are up to date."""
        try:
            addons_state = cluster_state['addons_state']
            addons = addons_state['addons']
            
            results = []
            for addon in addons:
                if addon['needs_update']:
                    results.append({
                        'passed': False,
                        'addon_name': addon['name'],
                        'details': f'Version {addon["version"]} available, latest is {addon["latest_version"]}',
                        'current_state': f'Current: {addon["version"]}, Latest: {addon["latest_version"]}',
                        'action_items': [
                            f'Update {addon["name"]} to version {addon["latest_version"]}',
                            'Test addon update in non-production environment',
                            'Review changelog for breaking changes',
                            'Schedule maintenance window for update'
                        ]
                    })
                else:
                    results.append({
                        'passed': True,
                        'addon_name': addon['name'],
                        'details': f'Version {addon["version"]} is up to date',
                        'current_state': f'Current: {addon["version"]} (Latest)',
                        'action_items': []
                    })
            
            return results
        except Exception as e:
            logger.warning(f"Error checking addon versions: {e}")
            return [{
                'passed': False,
                'addon_name': 'Unknown',
                'details': 'Error checking addon versions',
                'current_state': 'Unknown',
                'action_items': ['Verify cluster access and permissions']
            }]
