import logging
import json
import os
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class ComplianceManager:
    """
    Manages compliance framework validation for EKS clusters
    """
    
    def __init__(self):
        """Initialize the compliance manager"""
        self.frameworks = self._load_compliance_frameworks()
    
    def _load_compliance_frameworks(self) -> Dict[str, Any]:
        """
        Load compliance frameworks from JSON files
        
        Returns:
            Dictionary of compliance frameworks
        """
        frameworks = {}
        framework_dir = os.path.join(os.path.dirname(__file__), 'frameworks')
        
        # Create frameworks directory if it doesn't exist
        if not os.path.exists(framework_dir):
            os.makedirs(framework_dir)
            self._create_default_frameworks(framework_dir)
        
        # Load frameworks from files
        for filename in os.listdir(framework_dir):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join(framework_dir, filename), 'r', encoding='utf-8') as file:
                        framework = json.load(file)
                        framework_id = os.path.splitext(filename)[0]
                        frameworks[framework_id] = framework
                except Exception as e:
                    logger.error(f"Error loading framework {filename}: {e}")
        
        return frameworks
    
    def _create_default_frameworks(self, framework_dir: str):
        """
        Create default compliance frameworks
        
        Args:
            framework_dir: Directory to store frameworks
        """
        # CIS Benchmarks for EKS
        cis_framework = {
            'name': 'CIS Amazon EKS Benchmark',
            'version': '1.0.1',
            'description': 'Center for Internet Security (CIS) Benchmarks for Amazon EKS',
            'controls': [
                {
                    'id': 'CIS-EKS-1.1',
                    'title': 'Restrict Access to the EKS Control Plane Endpoint',
                    'description': 'Ensure that the EKS cluster control plane endpoint is not publicly accessible',
                    'severity': 'HIGH',
                    'checks': [
                        {
                            'check_id': 'Public API Endpoint',
                            'expected_result': 'FAILED'
                        }
                    ]
                },
                {
                    'id': 'CIS-EKS-1.2',
                    'title': 'Enable EKS Control Plane Audit Logging',
                    'description': 'Ensure that EKS control plane audit logging is enabled',
                    'severity': 'MEDIUM',
                    'checks': [
                        {
                            'check_id': 'Audit Logging',
                            'expected_result': 'PASSED'
                        }
                    ]
                },
                {
                    'id': 'CIS-EKS-2.1',
                    'title': 'Enable Envelope Encryption for Kubernetes Secrets',
                    'description': 'Ensure that envelope encryption is enabled for Kubernetes secrets',
                    'severity': 'HIGH',
                    'checks': [
                        {
                            'check_id': 'Secrets Encryption',
                            'expected_result': 'PASSED'
                        }
                    ]
                },
                {
                    'id': 'CIS-EKS-3.1',
                    'title': 'Use IAM Roles for Service Accounts',
                    'description': 'Ensure that IAM roles are used for service accounts',
                    'severity': 'HIGH',
                    'checks': [
                        {
                            'check_id': 'IRSA Implementation',
                            'expected_result': 'PASSED'
                        }
                    ]
                },
                {
                    'id': 'CIS-EKS-5.1',
                    'title': 'Implement Network Policies',
                    'description': 'Ensure that network policies are implemented',
                    'severity': 'MEDIUM',
                    'checks': [
                        {
                            'check_id': 'Network Policies',
                            'expected_result': 'PASSED'
                        }
                    ]
                }
            ]
        }
        
        # NIST SP 800-53 for EKS
        nist_framework = {
            'name': 'NIST SP 800-53 for EKS',
            'version': '1.0.0',
            'description': 'NIST Special Publication 800-53 controls for Amazon EKS',
            'controls': [
                {
                    'id': 'AC-3',
                    'title': 'Access Enforcement',
                    'description': 'Enforce approved authorizations for logical access to information and system resources',
                    'severity': 'HIGH',
                    'checks': [
                        {
                            'check_id': 'IRSA Implementation',
                            'expected_result': 'PASSED'
                        },
                        {
                            'check_id': 'Network Policies',
                            'expected_result': 'PASSED'
                        }
                    ]
                },
                {
                    'id': 'AU-2',
                    'title': 'Audit Events',
                    'description': 'Identify the events that the system is capable of auditing',
                    'severity': 'MEDIUM',
                    'checks': [
                        {
                            'check_id': 'Audit Logging',
                            'expected_result': 'PASSED'
                        }
                    ]
                },
                {
                    'id': 'SC-8',
                    'title': 'Transmission Confidentiality and Integrity',
                    'description': 'Protect the confidentiality and integrity of transmitted information',
                    'severity': 'HIGH',
                    'checks': [
                        {
                            'check_id': 'Public API Endpoint',
                            'expected_result': 'FAILED'
                        }
                    ]
                },
                {
                    'id': 'SC-28',
                    'title': 'Protection of Information at Rest',
                    'description': 'Protect the confidentiality and integrity of information at rest',
                    'severity': 'HIGH',
                    'checks': [
                        {
                            'check_id': 'Secrets Encryption',
                            'expected_result': 'PASSED'
                        },
                        {
                            'check_id': 'EBS Encryption',
                            'expected_result': 'PASSED'
                        }
                    ]
                }
            ]
        }
        
        # PCI DSS for EKS
        pci_framework = {
            'name': 'PCI DSS for EKS',
            'version': '3.2.1',
            'description': 'Payment Card Industry Data Security Standard for Amazon EKS',
            'controls': [
                {
                    'id': 'PCI-DSS-1.3',
                    'title': 'Prohibit Direct Public Access',
                    'description': 'Prohibit direct public access between the Internet and any system component in the cardholder data environment',
                    'severity': 'HIGH',
                    'checks': [
                        {
                            'check_id': 'Public API Endpoint',
                            'expected_result': 'FAILED'
                        },
                        {
                            'check_id': 'Nodes in Private Subnets',
                            'expected_result': 'PASSED'
                        }
                    ]
                },
                {
                    'id': 'PCI-DSS-3.4',
                    'title': 'Render PAN Unreadable',
                    'description': 'Render PAN unreadable anywhere it is stored',
                    'severity': 'HIGH',
                    'checks': [
                        {
                            'check_id': 'Secrets Encryption',
                            'expected_result': 'PASSED'
                        },
                        {
                            'check_id': 'EBS Encryption',
                            'expected_result': 'PASSED'
                        }
                    ]
                },
                {
                    'id': 'PCI-DSS-7.1',
                    'title': 'Limit Access to System Components',
                    'description': 'Limit access to system components and cardholder data to only those individuals whose job requires such access',
                    'severity': 'HIGH',
                    'checks': [
                        {
                            'check_id': 'IRSA Implementation',
                            'expected_result': 'PASSED'
                        },
                        {
                            'check_id': 'Network Policies',
                            'expected_result': 'PASSED'
                        }
                    ]
                },
                {
                    'id': 'PCI-DSS-10.1',
                    'title': 'Implement Audit Trails',
                    'description': 'Implement audit trails to link all access to system components to each individual user',
                    'severity': 'MEDIUM',
                    'checks': [
                        {
                            'check_id': 'Audit Logging',
                            'expected_result': 'PASSED'
                        }
                    ]
                }
            ]
        }
        
        # Write frameworks to files
        with open(os.path.join(framework_dir, 'cis.json'), 'w', encoding='utf-8') as file:
            json.dump(cis_framework, file, indent=2)
        
        with open(os.path.join(framework_dir, 'nist.json'), 'w', encoding='utf-8') as file:
            json.dump(nist_framework, file, indent=2)
        
        with open(os.path.join(framework_dir, 'pci.json'), 'w', encoding='utf-8') as file:
            json.dump(pci_framework, file, indent=2)
    
    def get_available_frameworks(self) -> List[Dict[str, Any]]:
        """
        Get available compliance frameworks
        
        Returns:
            List of available compliance frameworks
        """
        return [
            {
                'id': framework_id,
                'name': framework.get('name', 'Unknown'),
                'version': framework.get('version', 'Unknown'),
                'description': framework.get('description', '')
            }
            for framework_id, framework in self.frameworks.items()
        ]
    
    def validate_compliance(self, framework_id: str, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate compliance against a specific framework
        
        Args:
            framework_id: ID of the compliance framework
            analysis_results: Analysis results from HardenEKS analyzer
            
        Returns:
            Compliance validation results
        """
        if framework_id not in self.frameworks:
            return {
                'success': False,
                'message': f"Compliance framework {framework_id} not found"
            }
        
        framework = self.frameworks[framework_id]
        
        # Create a map of check results
        check_results = {}
        for check in analysis_results.get('passed_checks', []):
            check_results[check['check']] = 'PASSED'
        
        for check in analysis_results.get('failed_checks', []):
            check_results[check['check']] = 'FAILED'
        
        # Add a default check for Public API Endpoint
        if 'Public API Endpoint' not in check_results:
            check_results['Public API Endpoint'] = 'FAILED'
            
        # Add a default check for EBS Encryption
        if 'EBS Encryption' not in check_results:
            check_results['EBS Encryption'] = 'FAILED'
        
        # Validate controls
        controls = framework.get('controls', [])
        compliant_controls = []
        non_compliant_controls = []
        
        for control in controls:
            control_checks = control.get('checks', [])
            control_compliant = True
            
            for check in control_checks:
                check_id = check.get('check_id')
                expected_result = check.get('expected_result')
                actual_result = check_results.get(check_id)
                
                if actual_result != expected_result:
                    control_compliant = False
                    break
            
            if control_compliant:
                compliant_controls.append(control)
            else:
                non_compliant_controls.append(control)
        
        # Calculate compliance score
        total_controls = len(controls)
        compliant_count = len(compliant_controls)
        compliance_score = int((compliant_count / total_controls) * 100) if total_controls > 0 else 0
        
        return {
            'success': True,
            'framework': {
                'id': framework_id,
                'name': framework.get('name', 'Unknown'),
                'version': framework.get('version', 'Unknown'),
                'description': framework.get('description', '')
            },
            'compliance_score': compliance_score,
            'compliant_controls': compliant_controls,
            'non_compliant_controls': non_compliant_controls,
            'total_controls': total_controls,
            'compliant_count': compliant_count,
            'non_compliant_count': len(non_compliant_controls)
        }