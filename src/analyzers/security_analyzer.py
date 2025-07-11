import logging

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self):
        self.security_checks = {
            'iam': self._check_iam,
            'encryption': self._check_encryption,
            'network': self._check_network,
            'pod_security': self._check_pod_security
        }

    def analyze_security(self, cluster_details, inputs):
        """Analyze cluster security configuration"""
        security_results = {
            'status': {},
            'recommendations': [],
            'high_priority_issues': [],
            'medium_priority_issues': [],
            'low_priority_issues': []
        }

        for check_name, check_func in self.security_checks.items():
            try:
                result = check_func(cluster_details, inputs)
                security_results['status'][check_name] = result['status']
                if result.get('recommendation'):
                    security_results['recommendations'].append(result['recommendation'])
                
                if result.get('priority') == 'high':
                    security_results['high_priority_issues'].append(result)
                elif result.get('priority') == 'medium':
                    security_results['medium_priority_issues'].append(result)
                else:
                    security_results['low_priority_issues'].append(result)
                    
            except Exception as e:
                logger.error(f"Error in security check {check_name}: {e}")
                security_results['status'][check_name] = 'Error'

        return security_results

    def _check_iam(self, cluster_details, inputs):
        """Check IAM configurations"""
        security_info = inputs.get('🔐 Security', {}).get('IAM Configuration', '')
        
        result = {
            'status': 'Unknown',
            'priority': 'high',
            'category': 'IAM'
        }

        if 'irsa' in security_info.lower():
            result['status'] = 'Compliant'
        else:
            result['status'] = 'Non-compliant'
            result['recommendation'] = 'Implement IAM Roles for Service Accounts (IRSA)'

        return result

    def _check_encryption(self, cluster_details, inputs):
        """Check encryption configurations"""
        security_info = inputs.get('🔐 Security', {}).get('Secret Management', '')
        
        result = {
            'status': 'Unknown',
            'priority': 'high',
            'category': 'Encryption'
        }

        if 'encryption' in security_info.lower() and 'enabled' in security_info.lower():
            result['status'] = 'Compliant'
        else:
            result['status'] = 'Non-compliant'
            result['recommendation'] = 'Enable encryption at rest for sensitive data'

        return result

    def _check_network(self, cluster_details, inputs):
        """Check network security configurations"""
        security_info = inputs.get('🔐 Security', {}).get('Network Policies', '')
        
        result = {
            'status': 'Unknown',
            'priority': 'high',
            'category': 'Network'
        }

        if 'network policies' in security_info.lower() and 'implemented' in security_info.lower():
            result['status'] = 'Compliant'
        else:
            result['status'] = 'Non-compliant'
            result['recommendation'] = 'Implement network policies for pod-to-pod communication'

        return result

    def _check_pod_security(self, cluster_details, inputs):
        """Check pod security configurations"""
        security_info = inputs.get('🔐 Security', {}).get('Network Policies', '')
        
        result = {
            'status': 'Unknown',
            'priority': 'high',
            'category': 'Pod Security'
        }

        if 'pod security' in security_info.lower() and 'enabled' in security_info.lower():
            result['status'] = 'Compliant'
        else:
            result['status'] = 'Non-compliant'
            result['recommendation'] = 'Enable pod security policies'

        return result
