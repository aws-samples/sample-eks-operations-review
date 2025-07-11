import logging
import re
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

def _sanitize_log_input(text: str) -> str:
    """Sanitize input for logging to prevent log injection."""
    if not isinstance(text, str):
        return str(text)
    # Remove newlines and control characters
    sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
    return sanitized[:200]  # Limit length

class HardenEKSAnalyzer:
    def analyze_cluster(self, cluster_details: Dict[str, Any], inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze cluster for HardenEKS compliance using actual cluster data.
        
        Args:
            cluster_details: Cluster configuration and status
            inputs: User-provided configuration inputs
            
        Returns:
            Dict containing analysis results
            
        Raises:
            ValueError: If inputs are invalid
        """
        # Validate inputs
        if not isinstance(cluster_details, dict):
            raise ValueError("cluster_details must be a dictionary")
        if not isinstance(inputs, dict):
            raise ValueError("inputs must be a dictionary")
            
        try:
            # Create recommendations based on cluster analysis
            high_priority = []
            medium_priority = []
            low_priority = []
            passed_checks = []
            failed_checks = []
        
            # Check for IRSA implementation with error handling
            try:
                if self._check_irsa_implementation(cluster_details, inputs):
                    passed_checks.append({'check': 'IRSA Implementation', 'status': 'PASSED'})
                else:
                    failed_checks.append({'check': 'IRSA Implementation', 'status': 'FAILED'})
                    high_priority.append({
                        'category': 'IAM',
                        'title': 'Implement IAM Roles for Service Accounts (IRSA)',
                        'description': 'IRSA allows you to associate an IAM role with a Kubernetes service account',
                        'impact': 'Without IRSA, pods may use the node IAM role which violates least privilege',
                        'priority': 'High',
                        'action_items': [
                            'Create an IAM OIDC provider for your cluster',
                            'Create IAM roles with appropriate permissions',
                            'Associate IAM roles with Kubernetes service accounts',
                            'Configure pods to use service accounts with IAM roles'
                        ],
                        'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html'
                    })
            except Exception as e:
                logger.error(f"Error checking IRSA implementation: {_sanitize_log_input(str(e))}")
                failed_checks.append({'check': 'IRSA Implementation', 'status': 'ERROR'})
        
            # Check for Pod Security Standards with error handling
            try:
                if self._check_pod_security_standards(cluster_details, inputs):
                    passed_checks.append({'check': 'Pod Security Standards', 'status': 'PASSED'})
                else:
                    failed_checks.append({'check': 'Pod Security Standards', 'status': 'FAILED'})
                    high_priority.append({
                        'category': 'Pod Security',
                        'title': 'Implement Pod Security Standards',
                        'description': 'Pod Security Standards not enforced in the cluster',
                        'impact': 'Pods may run with excessive privileges',
                        'priority': 'High',
                        'action_items': [
                            'Enable Pod Security Admission controller',
                            'Define namespace-level Pod Security Standards',
                            'Apply appropriate security contexts to pods',
                            'Monitor for policy violations'
                        ],
                        'reference': 'https://kubernetes.io/docs/concepts/security/pod-security-standards/'
                    })
            except Exception as e:
                logger.error(f"Error checking Pod Security Standards: {_sanitize_log_input(str(e))}")
                failed_checks.append({'check': 'Pod Security Standards', 'status': 'ERROR'})
            
            # Check for Network Policies with error handling
            try:
                if self._check_network_policies(cluster_details, inputs):
                    passed_checks.append({'check': 'Network Policies', 'status': 'PASSED'})
                else:
                    failed_checks.append({'check': 'Network Policies', 'status': 'FAILED'})
                    high_priority.append({
                        'category': 'Network Security',
                        'title': 'Implement Network Policies',
                        'description': 'Network policies not implemented in the cluster',
                        'impact': 'Unrestricted pod-to-pod communication',
                        'priority': 'High',
                        'action_items': [
                            'Install a network policy provider (e.g., Calico)',
                            'Define default deny policies',
                            'Create application-specific network policies',
                            'Monitor policy violations'
                        ],
                        'reference': 'https://kubernetes.io/docs/concepts/services-networking/network-policies/'
                    })
            except Exception as e:
                logger.error(f"Error checking Network Policies: {_sanitize_log_input(str(e))}")
                failed_checks.append({'check': 'Network Policies', 'status': 'ERROR'})
            
            # Check for Audit Logging with error handling
            try:
                if self._check_audit_logging(cluster_details, inputs):
                    passed_checks.append({'check': 'Audit Logging', 'status': 'PASSED'})
                else:
                    failed_checks.append({'check': 'Audit Logging', 'status': 'FAILED'})
                    high_priority.append({
                        'category': 'Detective Controls',
                        'title': 'Enable Audit Logging',
                        'description': 'Kubernetes audit logging not enabled',
                        'impact': 'Limited visibility into cluster activities',
                        'priority': 'High',
                        'action_items': [
                            'Enable Kubernetes audit logging',
                            'Configure appropriate log retention',
                            'Set up log analysis',
                            'Implement automated alerting for suspicious activities'
                        ],
                        'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html'
                    })
            except Exception as e:
                logger.error(f"Error checking Audit Logging: {_sanitize_log_input(str(e))}")
                failed_checks.append({'check': 'Audit Logging', 'status': 'ERROR'})
            
            # Check for Private Subnets with error handling
            try:
                if self._check_private_subnets(cluster_details, inputs):
                    passed_checks.append({'check': 'Nodes in Private Subnets', 'status': 'PASSED'})
                else:
                    failed_checks.append({'check': 'Nodes in Private Subnets', 'status': 'FAILED'})
                    high_priority.append({
                        'category': 'Infrastructure Security',
                        'title': 'Deploy Nodes in Private Subnets',
                        'description': 'Nodes not deployed in private subnets',
                        'impact': 'Increased exposure to external threats',
                        'priority': 'High',
                        'action_items': [
                            'Move nodes to private subnets',
                            'Configure NAT gateways for outbound traffic',
                            'Use VPC endpoints for AWS services',
                            'Implement proper security groups'
                        ],
                        'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html'
                    })
            except Exception as e:
                logger.error(f"Error checking Private Subnets: {_sanitize_log_input(str(e))}")
                failed_checks.append({'check': 'Nodes in Private Subnets', 'status': 'ERROR'})
            
            # Check for Secrets Encryption with error handling
            try:
                if self._check_secrets_encryption(cluster_details, inputs):
                    passed_checks.append({'check': 'Secrets Encryption', 'status': 'PASSED'})
                else:
                    failed_checks.append({'check': 'Secrets Encryption', 'status': 'FAILED'})
                    high_priority.append({
                        'category': 'Data Security',
                        'title': 'Enable Secrets Encryption',
                        'description': 'Kubernetes secrets not encrypted at rest',
                        'impact': 'Sensitive data vulnerable to unauthorized access',
                        'priority': 'High',
                        'action_items': [
                            'Enable envelope encryption using KMS',
                            'Create dedicated KMS key for secrets',
                            'Enable automatic key rotation',
                            'Consider using external secrets management'
                        ],
                        'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/enable-secrets-encryption.html'
                    })
            except Exception as e:
                logger.error(f"Error checking Secrets Encryption: {_sanitize_log_input(str(e))}")
                failed_checks.append({'check': 'Secrets Encryption', 'status': 'ERROR'})
        
            # Calculate HardenEKS score based on passed checks
            total_checks = len(passed_checks) + len(failed_checks)
            hardeneks_score = int((len(passed_checks) / total_checks) * 100) if total_checks > 0 else 0
            
            return {
                'high_priority': high_priority,
                'medium_priority': medium_priority,
                'low_priority': low_priority,
                'passed_checks': passed_checks,
                'failed_checks': failed_checks,
                'hardeneks_score': hardeneks_score
            }
        
        except Exception as e:
            logger.error(f"Error during cluster analysis: {_sanitize_log_input(str(e))}")
            # Return safe default values on error
            return {
                'high_priority': [],
                'medium_priority': [],
                'low_priority': [],
                'passed_checks': [],
                'failed_checks': [{'check': 'Analysis Error', 'status': 'FAILED'}],
                'hardeneks_score': 0
            }
    
    def _check_irsa_implementation(self, cluster_details: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
        """Check if IRSA is implemented using both cluster data and user inputs."""
        try:
            # Check cluster details for OIDC provider
            cluster_identity = cluster_details.get('cluster', {}).get('identity', {})
            if cluster_identity.get('oidc'):
                return True
                
            # Check security configuration
            security_config = cluster_details.get('security', {}).get('iam', {})
            if security_config.get('oidc_provider'):
                return True
                
            # Check user inputs as fallback
            security_inputs = inputs.get('Security', {}) or inputs.get('🔐 Security', {})
            if isinstance(security_inputs, dict):
                for field, value in security_inputs.items():
                    if isinstance(value, str):
                        value_lower = value.lower()
                        if ('irsa' in value_lower or 'iam roles for service accounts' in value_lower):
                            if any(keyword in value_lower for keyword in ['enabled', 'implemented', 'configured']):
                                return True
        except Exception as e:
            logger.error(f"Error checking IRSA implementation: {_sanitize_log_input(str(e))}")
        return False
    
    def _check_pod_security_standards(self, cluster_details: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
        """Check if Pod Security Standards are implemented using cluster data and inputs."""
        try:
            # Check cluster version for PSS availability
            cluster_version = cluster_details.get('cluster', {}).get('version', '1.0')
            if cluster_version >= '1.25':
                # Check security configuration
                pod_security = cluster_details.get('security', {}).get('pod_security', {})
                if pod_security.get('pod_security_standards', {}).get('available'):
                    return True
                    
            # Check user inputs as fallback
            security_inputs = inputs.get('Security', {}) or inputs.get('🔐 Security', {})
            if isinstance(security_inputs, dict):
                for field, value in security_inputs.items():
                    if isinstance(value, str):
                        value_lower = value.lower()
                        if ('pod security' in value_lower or 'pss' in value_lower):
                            if any(keyword in value_lower for keyword in ['enabled', 'implemented', 'configured']):
                                return True
        except Exception as e:
            logger.error(f"Error checking Pod Security Standards: {_sanitize_log_input(str(e))}")
        return False
    
    def _check_network_policies(self, cluster_details: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
        """Check if Network Policies are implemented using cluster data and inputs."""
        try:
            # Check cluster networking configuration
            networking_config = cluster_details.get('networking', {})
            if networking_config.get('network_policies'):
                return True
                
            # Check security configuration for network policies
            security_config = cluster_details.get('security', {}).get('network_policies', {})
            if security_config.get('calico_installed') or security_config.get('vpc_cni_policy_support'):
                return True
                
            # Check user inputs as fallback
            security_inputs = inputs.get('Security', {}) or inputs.get('🔐 Security', {})
            if isinstance(security_inputs, dict):
                for field, value in security_inputs.items():
                    if isinstance(value, str) and 'network polic' in value.lower():
                        if any(keyword in value.lower() for keyword in ['enabled', 'implemented', 'configured']):
                            return True
        except Exception as e:
            logger.error(f"Error checking network policies: {_sanitize_log_input(str(e))}")
        return False
    
    def _check_audit_logging(self, cluster_details: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
        """Check if Audit Logging is enabled using cluster data and inputs."""
        try:
            # Check cluster logging configuration
            cluster_logging = cluster_details.get('cluster', {}).get('logging', {})
            if cluster_logging.get('clusterLogging'):
                for log_config in cluster_logging['clusterLogging']:
                    if log_config.get('enabled') and 'audit' in log_config.get('types', []):
                        return True
                        
            # Check security audit configuration
            audit_config = cluster_details.get('security', {}).get('audit_logging', {})
            if audit_config.get('enabled'):
                return True
                
            # Check user inputs as fallback
            security_inputs = inputs.get('Security', {}) or inputs.get('🔐 Security', {})
            if isinstance(security_inputs, dict):
                for field, value in security_inputs.items():
                    if isinstance(value, str) and 'audit log' in value.lower():
                        if any(keyword in value.lower() for keyword in ['enabled', 'implemented', 'configured']):
                            return True
        except Exception as e:
            logger.error(f"Error checking audit logging: {_sanitize_log_input(str(e))}")
        return False
    
    def _check_private_subnets(self, cluster_details: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
        """Check if Private Subnets are used using cluster data and inputs."""
        try:
            # Check networking configuration for private subnets
            networking_config = cluster_details.get('networking', {})
            subnets = networking_config.get('subnets', [])
            
            # Check if any subnets are private (no direct internet gateway route)
            for subnet in subnets:
                if not subnet.get('MapPublicIpOnLaunch', True):  # Private subnets don't auto-assign public IPs
                    return True
                    
            # Check endpoint access configuration
            endpoint_access = networking_config.get('endpoint_access', {})
            if endpoint_access.get('private') and not endpoint_access.get('public'):
                return True
                
            # Check user inputs as fallback
            security_inputs = inputs.get('Security', {}) or inputs.get('🔐 Security', {})
            if isinstance(security_inputs, dict):
                for field, value in security_inputs.items():
                    if isinstance(value, str):
                        value_lower = value.lower()
                        if ('private subnet' in value_lower or 'private network' in value_lower):
                            if any(keyword in value_lower for keyword in ['enabled', 'implemented', 'configured']):
                                return True
        except Exception as e:
            logger.error(f"Error checking private subnets: {_sanitize_log_input(str(e))}")
        return False
    
    def _check_secrets_encryption(self, cluster_details: Dict[str, Any], inputs: Dict[str, Any]) -> bool:
        """Check if Secrets Encryption is enabled using cluster data and inputs."""
        try:
            # Check cluster encryption configuration
            cluster_config = cluster_details.get('cluster', {})
            if cluster_config.get('encryptionConfig'):
                return True
                
            # Check security encryption configuration
            encryption_config = cluster_details.get('security', {}).get('encryption', {})
            if encryption_config.get('secrets'):
                return True
                
            # Check user inputs as fallback
            security_inputs = inputs.get('Security', {}) or inputs.get('🔐 Security', {})
            if isinstance(security_inputs, dict):
                for field, value in security_inputs.items():
                    if isinstance(value, str):
                        value_lower = value.lower()
                        if ('secret' in value_lower and 'encrypt' in value_lower):
                            if any(keyword in value_lower for keyword in ['enabled', 'implemented', 'configured']):
                                return True
        except Exception as e:
            logger.error(f"Error checking secrets encryption: {_sanitize_log_input(str(e))}")
        return False