import logging
import re
from typing import Dict, List, Any
from .cluster_state_analyzer import ClusterStateAnalyzer

logger = logging.getLogger(__name__)

def _sanitize_log_input(text: str) -> str:
    """Sanitize input for logging to prevent log injection."""
    if not isinstance(text, str):
        return str(text)
    sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
    return sanitized[:200]

class AccurateClusterAnalyzer:
    """Provides accurate, cluster-specific recommendations based on actual AWS API data"""
    
    def __init__(self, aws_access_key: str = None, aws_secret_key: str = None, region: str = None):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.region = region
        self.state_analyzer = None

    def analyze_cluster(self, cluster_name: str) -> Dict[str, Any]:
        """Analyze cluster and provide only accurate, cluster-specific recommendations."""
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
            
            # Only check things that can be definitively determined from cluster state
            
            # 1. Secrets Encryption - definitive check
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
            
            # 2. Audit Logging - definitive check
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
            
            # 3. Endpoint Access - definitive check
            endpoint_result = self._check_endpoint_access(cluster_state)
            if endpoint_result['passed']:
                passed_checks.append({'check': 'Endpoint Access', 'status': 'PASSED', 'details': endpoint_result['details']})
            else:
                failed_checks.append({'check': 'Endpoint Access', 'status': 'FAILED', 'details': endpoint_result['details']})
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
            
            # 4. Addon Versions - definitive check
            addon_results = self._check_addon_versions(cluster_state)
            for addon_result in addon_results:
                if addon_result['needs_update']:
                    failed_checks.append({'check': f'{addon_result["addon_name"]} Version', 'status': 'FAILED', 'details': addon_result['details']})
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
            
            # 5. IRSA Implementation - check if properly configured
            irsa_result = self._check_irsa_implementation(cluster_state)
            if irsa_result['passed']:
                passed_checks.append({'check': 'IRSA Implementation', 'status': 'PASSED', 'details': irsa_result['details']})
            else:
                failed_checks.append({'check': 'IRSA Implementation', 'status': 'FAILED', 'details': irsa_result['details']})
                if irsa_result['severity'] == 'high':
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
                else:
                    medium_priority.append({
                        'category': 'IAM',
                        'title': 'Enhance IRSA Implementation',
                        'description': f'IRSA could be improved. {irsa_result["details"]}',
                        'impact': 'Better security through more granular IAM permissions',
                        'priority': 'Medium',
                        'current_state': irsa_result['current_state'],
                        'action_items': irsa_result['action_items'],
                        'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html'
                    })
            
            # 6. Node Groups Analysis - only if managed node groups exist
            nodegroup_result = self._check_nodegroups(cluster_state)
            if nodegroup_result['has_findings']:
                if nodegroup_result['passed']:
                    passed_checks.append({'check': 'Node Groups Configuration', 'status': 'PASSED', 'details': nodegroup_result['details']})
                else:
                    failed_checks.append({'check': 'Node Groups Configuration', 'status': 'FAILED', 'details': nodegroup_result['details']})
                    medium_priority.append({
                        'category': 'Infrastructure Security',
                        'title': 'Optimize Node Groups Configuration',
                        'description': f'{nodegroup_result["details"]}',
                        'impact': nodegroup_result['impact'],
                        'priority': 'Medium',
                        'current_state': nodegroup_result['current_state'],
                        'action_items': nodegroup_result['action_items'],
                        'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html'
                    })
            
            # Calculate security score
            total_checks = len(passed_checks) + len(failed_checks)
            security_score = int((len(passed_checks) / total_checks) * 100) if total_checks > 0 else 0
            
            return {
                'high_priority': high_priority,
                'medium_priority': medium_priority,
                'low_priority': low_priority,
                'passed_checks': passed_checks,
                'failed_checks': failed_checks,
                'security_score': security_score,
                'cluster_state': cluster_state,
                'analysis_summary': {
                    'total_checks': total_checks,
                    'passed': len(passed_checks),
                    'failed': len(failed_checks),
                    'high_priority_issues': len(high_priority),
                    'medium_priority_issues': len(medium_priority),
                    'cluster_version': cluster_state['cluster_info']['version'],
                    'region': self.region
                }
            }
        
        except Exception as e:
            logger.warning(f"Error during cluster analysis: {_sanitize_log_input(str(e))}")
            raise

    def _check_secrets_encryption(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """Check if secrets encryption is enabled."""
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
                        'Enable automatic key rotation'
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
        """Check if audit logging is enabled."""
        try:
            logging_state = cluster_state['logging_state']
            audit_enabled = logging_state['audit_logging_enabled']
            enabled_logs = logging_state['enabled_log_types']
            disabled_logs = logging_state['disabled_log_types']
            
            if audit_enabled and len(enabled_logs) >= 3:  # At least 3 log types enabled
                return {
                    'passed': True,
                    'details': f'Comprehensive logging enabled. Active logs: {", ".join(enabled_logs)}',
                    'current_state': f'Audit Logging: ✓, Enabled Types: {", ".join(enabled_logs)}',
                    'action_items': []
                }
            elif audit_enabled:
                return {
                    'passed': False,
                    'details': f'Partial logging enabled. Missing: {", ".join(disabled_logs)}',
                    'current_state': f'Audit Logging: Partial, Missing Types: {", ".join(disabled_logs)}',
                    'action_items': [
                        f'Enable missing log types: {", ".join(disabled_logs)}',
                        'Configure appropriate log retention',
                        'Set up log analysis and monitoring'
                    ]
                }
            else:
                return {
                    'passed': False,
                    'details': 'Audit logging completely disabled',
                    'current_state': f'Audit Logging: ✗, All Types Disabled',
                    'action_items': [
                        'Enable Kubernetes audit logging',
                        'Enable API server logging',
                        'Configure appropriate log retention',
                        'Set up log analysis and monitoring'
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

    def _check_endpoint_access(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """Check cluster endpoint access configuration."""
        try:
            security_state = cluster_state['security_state']
            endpoint_access = security_state['endpoint_access']
            
            public_access = endpoint_access['public']
            private_access = endpoint_access['private']
            public_cidrs = endpoint_access['public_cidrs']
            
            # Optimal: private access enabled, public access restricted or disabled
            if private_access and (not public_access or (public_access and public_cidrs != ['0.0.0.0/0'])):
                return {
                    'passed': True,
                    'details': f'Optimal endpoint configuration: Private access enabled, public access {"restricted" if public_access else "disabled"}',
                    'current_state': f'Private Access: ✓, Public Access: {"Restricted" if public_access else "Disabled"}',
                    'action_items': []
                }
            else:
                issues = []
                action_items = []
                
                if not private_access:
                    issues.append('Private access disabled')
                    action_items.append('Enable private endpoint access')
                    
                if public_access and public_cidrs == ['0.0.0.0/0']:
                    issues.append('Public access unrestricted (0.0.0.0/0)')
                    action_items.extend([
                        'Restrict public access to specific CIDRs',
                        'Consider disabling public access if not needed'
                    ])
                
                return {
                    'passed': False,
                    'details': f'Endpoint access issues: {", ".join(issues)}',
                    'current_state': f'Private: {private_access}, Public: {public_access}, CIDRs: {public_cidrs}',
                    'action_items': action_items
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
        """Check if addons need updates."""
        try:
            addons_state = cluster_state['addons_state']
            addons = addons_state['addons']
            
            results = []
            for addon in addons:
                results.append({
                    'addon_name': addon['name'],
                    'needs_update': addon['needs_update'],
                    'details': f'Version {addon["version"]} {"needs update to" if addon["needs_update"] else "is current, latest is"} {addon["latest_version"]}',
                    'current_state': f'Current: {addon["version"]}, Latest: {addon["latest_version"]}',
                    'action_items': [
                        f'Update {addon["name"]} to version {addon["latest_version"]}',
                        'Test addon update in non-production environment',
                        'Review changelog for breaking changes',
                        'Schedule maintenance window for update'
                    ] if addon['needs_update'] else []
                })
            
            return results
        except Exception as e:
            logger.error(f"Error checking addon versions: {e}")
            return []

    def _check_irsa_implementation(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """Check IRSA implementation status."""
        try:
            security_state = cluster_state['security_state']
            iam_state = cluster_state['iam_state']
            
            oidc_configured = security_state['oidc_provider']['configured']
            irsa_roles_count = iam_state['irsa_roles_count']
            addon_irsa_count = iam_state.get('addon_irsa_count', 0)
            custom_irsa_count = iam_state.get('custom_irsa_count', 0)
            
            if not oidc_configured:
                return {
                    'passed': False,
                    'severity': 'high',
                    'details': 'OIDC provider not configured',
                    'current_state': 'OIDC Provider: ✗, IRSA Roles: 0',
                    'action_items': [
                        'Create IAM OIDC provider for the cluster',
                        'Create IAM roles for service accounts',
                        'Configure pods to use service accounts with IAM roles'
                    ]
                }
            elif addon_irsa_count > 0 and custom_irsa_count == 0:
                return {
                    'passed': False,
                    'severity': 'medium',
                    'details': f'OIDC configured with {addon_irsa_count} addon IRSA roles, but no custom IRSA roles for workloads',
                    'current_state': f'OIDC Provider: ✓, Addon IRSA: {addon_irsa_count}, Custom IRSA: 0',
                    'action_items': [
                        'Create IRSA roles for workloads that need AWS access',
                        'Replace node IAM roles with workload-specific IRSA roles',
                        'Implement least privilege access for workloads'
                    ]
                }
            elif irsa_roles_count > 0:
                return {
                    'passed': True,
                    'details': f'IRSA properly configured with {irsa_roles_count} roles ({addon_irsa_count} addon, {custom_irsa_count} custom)',
                    'current_state': f'OIDC Provider: ✓, Total IRSA: {irsa_roles_count} (Addon: {addon_irsa_count}, Custom: {custom_irsa_count})',
                    'action_items': []
                }
            else:
                return {
                    'passed': False,
                    'severity': 'high',
                    'details': 'OIDC provider configured but no IRSA roles found',
                    'current_state': 'OIDC Provider: ✓, IRSA Roles: 0',
                    'action_items': [
                        'Create IAM roles for service accounts',
                        'Associate IAM roles with Kubernetes service accounts',
                        'Configure pods to use service accounts with IAM roles'
                    ]
                }
        except Exception as e:
            logger.error(f"Error checking IRSA: {e}")
            return {
                'passed': False,
                'severity': 'high',
                'details': 'Error checking IRSA configuration',
                'current_state': 'Unknown',
                'action_items': ['Verify cluster access and permissions']
            }

    def _check_nodegroups(self, cluster_state: Dict[str, Any]) -> Dict[str, Any]:
        """Check node groups configuration if they exist."""
        try:
            nodegroups_state = cluster_state['nodegroups_state']
            nodegroups = nodegroups_state['nodegroups']
            
            # Check if cluster has Fargate profiles
            fargate_profiles = []
            try:
                fargate_profiles = self.state_analyzer.eks.list_fargate_profiles(clusterName=self.state_analyzer.cluster_name)['fargateProfileNames']
            except Exception as e:
                logger.warning(f"Could not retrieve Fargate profiles: {e}")
                fargate_profiles = []
            
            if not nodegroups and not fargate_profiles:
                # No managed resources found - could be self-managed or empty cluster
                return {
                    'has_findings': False,
                    'details': 'No managed node groups or Fargate profiles detected',
                    'current_state': 'Managed Node Groups: 0, Fargate Profiles: 0'
                }
            elif fargate_profiles and not nodegroups:
                # Using Fargate only - this is valid
                return {
                    'has_findings': True,
                    'passed': True,
                    'details': f'Using serverless compute with {len(fargate_profiles)} Fargate profiles',
                    'current_state': f'Fargate Profiles: {len(fargate_profiles)}',
                    'action_items': []
                }
            elif nodegroups:
                # Analyze managed node groups
                issues = []
                recommendations = []
                
                public_nodegroups = 0
                spot_nodegroups = 0
                
                for ng in nodegroups:
                    private_ratio = ng['private_subnets_count'] / ng['total_subnets_count']
                    if private_ratio < 0.5:
                        public_nodegroups += 1
                        issues.append(f"{ng['name']}: nodes in public subnets")
                        
                    if ng['capacity_type'] == 'SPOT':
                        spot_nodegroups += 1
                
                if public_nodegroups > 0:
                    recommendations.extend([
                        'Move node groups to private subnets',
                        'Configure NAT gateways for outbound traffic'
                    ])
                
                if spot_nodegroups == 0 and len(nodegroups) > 0:
                    recommendations.append('Consider using Spot instances for cost optimization')
                
                if issues:
                    return {
                        'has_findings': True,
                        'passed': False,
                        'details': f'Node group issues found: {"; ".join(issues)}',
                        'current_state': f'Total Node Groups: {len(nodegroups)}, Public: {public_nodegroups}, Spot: {spot_nodegroups}',
                        'impact': 'Increased security risk and potentially higher costs',
                        'action_items': recommendations
                    }
                else:
                    return {
                        'has_findings': True,
                        'passed': True,
                        'details': f'All {len(nodegroups)} node groups properly configured',
                        'current_state': f'Total Node Groups: {len(nodegroups)}, All in private subnets, Spot: {spot_nodegroups}',
                        'action_items': recommendations if recommendations else []
                    }
            
            return {
                'has_findings': False,
                'details': 'No node group analysis needed',
                'current_state': 'Mixed compute configuration'
            }
            
        except Exception as e:
            logger.error(f"Error checking node groups: {e}")
            return {
                'has_findings': False,
                'details': 'Error checking node groups',
                'current_state': 'Unknown'
            }
