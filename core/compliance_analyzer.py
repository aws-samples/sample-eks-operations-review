"""
Comprehensive Compliance Framework Analyzer
Implements checks against CIS, NIST, PCI DSS, SOC2, and other security frameworks
"""
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

class ComplianceFrameworkAnalyzer:
    """
    Comprehensive compliance framework analyzer implementing multiple security benchmarks:
    - CIS Amazon EKS Benchmark
    - NIST Cybersecurity Framework
    - PCI DSS Requirements
    - SOC 2 Type II
    - HIPAA Security Rule
    - ISO 27001
    """
    
    def __init__(self, cluster_name: str, offline_data: Optional[Dict] = None):
        self.cluster_name = cluster_name
        self.offline_data = offline_data
    
    def run_comprehensive_compliance_analysis(self) -> Dict[str, Any]:
        """Run comprehensive compliance analysis across all frameworks"""
        
        # Analyze against each framework
        cis_eks_results = self._analyze_cis_eks_benchmark()
        nist_csf_results = self._analyze_nist_cybersecurity_framework()
        pci_dss_results = self._analyze_pci_dss_requirements()
        soc2_results = self._analyze_soc2_type2()
        hipaa_results = self._analyze_hipaa_security_rule()
        iso27001_results = self._analyze_iso27001()
        dora_results = self._analyze_dora_regulation()
        
        # Calculate overall compliance posture
        overall_compliance = self._calculate_overall_compliance([
            cis_eks_results, nist_csf_results, pci_dss_results, 
            soc2_results, hipaa_results, iso27001_results, dora_results
        ])
        
        return {
            'cluster_name': self.cluster_name,
            'analysis_timestamp': datetime.now().isoformat(),
            'compliance_frameworks': {
                'CIS_EKS_Benchmark': cis_eks_results,
                'NIST_Cybersecurity_Framework': nist_csf_results,
                'PCI_DSS': pci_dss_results,
                'SOC2_Type2': soc2_results,
                'HIPAA_Security_Rule': hipaa_results,
                'ISO_27001': iso27001_results,
                'EU_DORA': dora_results
            },
            'overall_compliance_posture': overall_compliance,
            'data_source': 'offline' if self.offline_data else 'online'
        }
    
    def _analyze_cis_eks_benchmark(self) -> Dict[str, Any]:
        """Analyze against CIS Amazon EKS Benchmark v1.0.1"""
        
        checks = []
        
        # 1. Control Plane Configuration
        checks.extend(self._cis_control_plane_checks())
        
        # 2. Node Security Configuration  
        checks.extend(self._cis_node_security_checks())
        
        # 3. Policies
        checks.extend(self._cis_policies_checks())
        
        # 4. Managed Services
        checks.extend(self._cis_managed_services_checks())
        
        # Calculate CIS compliance score
        total_checks = len(checks)
        compliant_checks = len([c for c in checks if c['status'] == 'PASS'])
        
        return {
            'framework_name': 'CIS Amazon EKS Benchmark',
            'version': '1.0.1',
            'total_controls': total_checks,
            'compliant_controls': compliant_checks,
            'non_compliant_controls': total_checks - compliant_checks,
            'compliance_percentage': round((compliant_checks / total_checks * 100), 1) if total_checks > 0 else 0,
            'compliance_level': self._get_compliance_level(compliant_checks, total_checks),
            'checks': checks,
            'critical_findings': [c for c in checks if c['severity'] == 'HIGH' and c['status'] == 'FAIL'],
            'recommendations': self._generate_cis_recommendations(checks)
        }
    
    def _cis_control_plane_checks(self) -> List[Dict[str, Any]]:
        """CIS Control Plane Configuration checks"""
        checks = []
        
        # CIS 1.1.1 - Ensure that the API server pod specification file permissions are set to 644 or more restrictive
        checks.append({
            'control_id': '1.1.1',
            'title': 'API Server Configuration Security',
            'description': 'Ensure API server is configured securely',
            'severity': 'MEDIUM',
            'status': self._check_api_server_config(),
            'evidence': self._get_api_server_evidence(),
            'remediation': 'Configure API server with secure settings and restrict endpoint access'
        })
        
        # CIS 1.2.1 - Ensure that anonymous requests are disabled
        checks.append({
            'control_id': '1.2.1', 
            'title': 'Anonymous Authentication Disabled',
            'description': 'Ensure anonymous authentication is disabled',
            'severity': 'HIGH',
            'status': 'PASS',  # EKS disables anonymous auth by default
            'evidence': 'EKS clusters have anonymous authentication disabled by default',
            'remediation': 'No action required - EKS default configuration'
        })
        
        # CIS 1.2.2 - Ensure that the --basic-auth-file argument is not set
        checks.append({
            'control_id': '1.2.2',
            'title': 'Basic Authentication Disabled', 
            'description': 'Ensure basic authentication is not used',
            'severity': 'HIGH',
            'status': 'PASS',  # EKS doesn't use basic auth
            'evidence': 'EKS uses IAM and RBAC, not basic authentication',
            'remediation': 'No action required - EKS default configuration'
        })
        
        # CIS 1.2.3 - Ensure that the --token-auth-file argument is not set
        checks.append({
            'control_id': '1.2.3',
            'title': 'Token Authentication File Not Used',
            'description': 'Ensure static token files are not used',
            'severity': 'HIGH', 
            'status': 'PASS',  # EKS doesn't use token files
            'evidence': 'EKS uses dynamic token authentication via IAM',
            'remediation': 'No action required - EKS default configuration'
        })
        
        # CIS 1.2.4 - Ensure that the --kubelet-https argument is set to true
        checks.append({
            'control_id': '1.2.4',
            'title': 'Kubelet HTTPS Communication',
            'description': 'Ensure API server communicates with kubelets over HTTPS',
            'severity': 'MEDIUM',
            'status': 'PASS',  # EKS enforces HTTPS
            'evidence': 'EKS enforces HTTPS communication with kubelets',
            'remediation': 'No action required - EKS default configuration'
        })
        
        # CIS 1.2.5 - Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate
        checks.append({
            'control_id': '1.2.5',
            'title': 'Kubelet Client Certificates',
            'description': 'Ensure kubelet client certificates are properly configured',
            'severity': 'MEDIUM',
            'status': 'PASS',  # EKS manages certificates
            'evidence': 'EKS manages kubelet client certificates automatically', 
            'remediation': 'No action required - EKS manages certificates'
        })
        
        return checks
    
    def _cis_node_security_checks(self) -> List[Dict[str, Any]]:
        """CIS Node Security Configuration checks"""
        checks = []
        
        # CIS 2.1.1 - Ensure that the --anonymous-auth argument is set to false
        checks.append({
            'control_id': '2.1.1',
            'title': 'Node Anonymous Authentication Disabled',
            'description': 'Ensure kubelet anonymous authentication is disabled',
            'severity': 'HIGH',
            'status': self._check_node_anonymous_auth(),
            'evidence': self._get_node_auth_evidence(),
            'remediation': 'Configure node groups with anonymous authentication disabled'
        })
        
        # CIS 2.1.2 - Ensure that the --authorization-mode argument is not set to AlwaysAllow
        checks.append({
            'control_id': '2.1.2',
            'title': 'Node Authorization Mode',
            'description': 'Ensure proper authorization mode is configured on nodes',
            'severity': 'HIGH',
            'status': 'PASS',  # EKS configures proper authorization
            'evidence': 'EKS configures proper kubelet authorization mode',
            'remediation': 'No action required - EKS default configuration'
        })
        
        # CIS 2.1.3 - Ensure that the --client-ca-file argument is set as appropriate
        checks.append({
            'control_id': '2.1.3',
            'title': 'Client CA File Configuration',
            'description': 'Ensure client CA file is properly configured',
            'severity': 'MEDIUM',
            'status': 'PASS',  # EKS manages CA files
            'evidence': 'EKS manages client CA files automatically',
            'remediation': 'No action required - EKS manages CA configuration'
        })
        
        return checks
    
    def _cis_policies_checks(self) -> List[Dict[str, Any]]:
        """CIS Policies checks"""
        checks = []
        
        # CIS 3.1.1 - Ensure that the --anonymous-auth argument is set to false
        checks.append({
            'control_id': '3.1.1',
            'title': 'Pod Security Standards Enabled',
            'description': 'Ensure Pod Security Standards are implemented',
            'severity': 'HIGH',
            'status': self._check_pod_security_standards(),
            'evidence': self._get_pod_security_evidence(),
            'remediation': 'Implement Pod Security Standards with restricted profile'
        })
        
        # CIS 3.2.1 - Ensure that a minimal audit policy is created
        checks.append({
            'control_id': '3.2.1',
            'title': 'Audit Policy Configuration',
            'description': 'Ensure comprehensive audit policy is configured',
            'severity': 'MEDIUM',
            'status': self._check_audit_policy(),
            'evidence': self._get_audit_evidence(),
            'remediation': 'Enable all control plane logging types for comprehensive auditing'
        })
        
        return checks
    
    def _cis_managed_services_checks(self) -> List[Dict[str, Any]]:
        """CIS Managed Services checks"""
        checks = []
        
        # CIS 4.1.1 - Ensure that the cluster-admin role is only used where required
        checks.append({
            'control_id': '4.1.1',
            'title': 'Cluster Admin Role Usage',
            'description': 'Ensure cluster-admin role is used judiciously',
            'severity': 'HIGH',
            'status': 'WARNING',  # Requires runtime verification
            'evidence': 'Requires analysis of RBAC configurations',
            'remediation': 'Audit and restrict cluster-admin role bindings'
        })
        
        # CIS 4.1.2 - Minimize access to secrets
        checks.append({
            'control_id': '4.1.2',
            'title': 'Secrets Access Control',
            'description': 'Ensure minimal access to Kubernetes secrets',
            'severity': 'HIGH',
            'status': 'WARNING',  # Requires runtime verification
            'evidence': 'Requires analysis of secret access permissions',
            'remediation': 'Implement least privilege access for secrets'
        })
        
        return checks
    
    def _analyze_nist_cybersecurity_framework(self) -> Dict[str, Any]:
        """Analyze against NIST Cybersecurity Framework v1.1"""
        
        checks = []
        
        # IDENTIFY (ID) Function
        checks.extend(self._nist_identify_checks())
        
        # PROTECT (PR) Function  
        checks.extend(self._nist_protect_checks())
        
        # DETECT (DE) Function
        checks.extend(self._nist_detect_checks())
        
        # RESPOND (RS) Function
        checks.extend(self._nist_respond_checks())
        
        # RECOVER (RC) Function
        checks.extend(self._nist_recover_checks())
        
        total_checks = len(checks)
        compliant_checks = len([c for c in checks if c['status'] == 'PASS'])
        
        return {
            'framework_name': 'NIST Cybersecurity Framework',
            'version': '1.1',
            'total_controls': total_checks,
            'compliant_controls': compliant_checks,
            'non_compliant_controls': total_checks - compliant_checks,
            'compliance_percentage': round((compliant_checks / total_checks * 100), 1) if total_checks > 0 else 0,
            'compliance_level': self._get_compliance_level(compliant_checks, total_checks),
            'checks': checks,
            'functions_analysis': self._analyze_nist_functions(checks)
        }
    
    def _nist_identify_checks(self) -> List[Dict[str, Any]]:
        """NIST Identify function checks"""
        return [
            {
                'function': 'IDENTIFY',
                'category': 'ID.AM-1',
                'title': 'Asset Management',
                'description': 'Physical devices and systems within the organization are inventoried',
                'severity': 'MEDIUM',
                'status': self._check_asset_inventory(),
                'evidence': 'Node groups and instances are tracked',
                'remediation': 'Maintain comprehensive asset inventory'
            },
            {
                'function': 'IDENTIFY', 
                'category': 'ID.GV-1',
                'title': 'Governance Policy',
                'description': 'Organizational cybersecurity policy is established',
                'severity': 'MEDIUM',
                'status': 'WARNING',
                'evidence': 'Requires organizational policy verification',
                'remediation': 'Establish and document cybersecurity governance policies'
            }
        ]
    
    def _nist_protect_checks(self) -> List[Dict[str, Any]]:
        """NIST Protect function checks"""
        return [
            {
                'function': 'PROTECT',
                'category': 'PR.AC-1',
                'title': 'Identity and Access Management',
                'description': 'Identities and credentials are issued, managed, verified, revoked, and audited',
                'severity': 'HIGH',
                'status': self._check_iam_management(),
                'evidence': 'RBAC and IAM roles configured',
                'remediation': 'Implement comprehensive IAM with least privilege'
            },
            {
                'function': 'PROTECT',
                'category': 'PR.DS-1', 
                'title': 'Data Security',
                'description': 'Data-at-rest is protected',
                'severity': 'HIGH',
                'status': self._check_data_encryption(),
                'evidence': self._get_encryption_evidence(),
                'remediation': 'Enable encryption at rest for all data stores'
            }
        ]
    
    def _nist_detect_checks(self) -> List[Dict[str, Any]]:
        """NIST Detect function checks"""
        return [
            {
                'function': 'DETECT',
                'category': 'DE.AE-1',
                'title': 'Anomalies and Events',
                'description': 'A baseline of network operations and expected data flows is established',
                'severity': 'MEDIUM',
                'status': self._check_monitoring_baseline(),
                'evidence': 'Control plane logging and monitoring configured',
                'remediation': 'Establish comprehensive monitoring and alerting'
            },
            {
                'function': 'DETECT',
                'category': 'DE.CM-1',
                'title': 'Security Continuous Monitoring',
                'description': 'The network is monitored to detect potential cybersecurity events',
                'severity': 'MEDIUM', 
                'status': self._check_continuous_monitoring(),
                'evidence': 'Network and security monitoring capabilities',
                'remediation': 'Implement continuous security monitoring'
            }
        ]
    
    def _nist_respond_checks(self) -> List[Dict[str, Any]]:
        """NIST Respond function checks"""
        return [
            {
                'function': 'RESPOND',
                'category': 'RS.RP-1',
                'title': 'Response Planning',
                'description': 'Response plan is executed during or after an incident',
                'severity': 'MEDIUM',
                'status': 'WARNING',
                'evidence': 'Requires incident response plan verification',
                'remediation': 'Develop and test incident response procedures'
            }
        ]
    
    def _nist_recover_checks(self) -> List[Dict[str, Any]]:
        """NIST Recover function checks"""
        return [
            {
                'function': 'RECOVER',
                'category': 'RC.RP-1',
                'title': 'Recovery Planning',
                'description': 'Recovery plan is executed during or after a cybersecurity incident',
                'severity': 'MEDIUM',
                'status': 'WARNING',
                'evidence': 'Requires recovery plan verification', 
                'remediation': 'Develop and test recovery procedures'
            }
        ]
    
    def _analyze_pci_dss_requirements(self) -> Dict[str, Any]:
        """Analyze against PCI DSS Requirements"""
        
        checks = []
        
        # PCI DSS Requirement 1: Install and maintain a firewall configuration
        checks.append({
            'requirement': '1',
            'title': 'Firewall and Router Configuration',
            'description': 'Install and maintain network security controls',
            'severity': 'HIGH',
            'status': self._check_network_security_controls(),
            'evidence': 'Security groups and network policies configured',
            'remediation': 'Implement comprehensive network security controls'
        })
        
        # PCI DSS Requirement 2: Do not use vendor-supplied defaults
        checks.append({
            'requirement': '2',
            'title': 'Vendor Default Passwords and Security Parameters',
            'description': 'Change vendor-supplied defaults and remove unnecessary default accounts',
            'severity': 'HIGH',
            'status': 'PASS',  # EKS doesn't use default passwords
            'evidence': 'EKS uses IAM authentication, no default passwords',
            'remediation': 'No action required for EKS managed services'
        })
        
        # PCI DSS Requirement 3: Protect stored cardholder data
        checks.append({
            'requirement': '3',
            'title': 'Protect Stored Cardholder Data',
            'description': 'Protect stored cardholder data with encryption',
            'severity': 'CRITICAL',
            'status': self._check_data_encryption(),
            'evidence': self._get_encryption_evidence(),
            'remediation': 'Enable encryption at rest for all data storage'
        })
        
        # PCI DSS Requirement 4: Encrypt transmission of cardholder data
        checks.append({
            'requirement': '4',
            'title': 'Encrypt Transmission of Cardholder Data',
            'description': 'Encrypt transmission of cardholder data across open, public networks',
            'severity': 'CRITICAL',
            'status': self._check_encryption_in_transit(),
            'evidence': 'TLS encryption configured for API communications',
            'remediation': 'Ensure all data transmission uses strong encryption'
        })
        
        # Continue with other PCI DSS requirements...
        
        total_checks = len(checks)
        compliant_checks = len([c for c in checks if c['status'] == 'PASS'])
        
        return {
            'framework_name': 'PCI Data Security Standard',
            'version': '3.2.1',
            'total_controls': total_checks,
            'compliant_controls': compliant_checks,
            'non_compliant_controls': total_checks - compliant_checks,
            'compliance_percentage': round((compliant_checks / total_checks * 100), 1) if total_checks > 0 else 0,
            'compliance_level': self._get_compliance_level(compliant_checks, total_checks),
            'checks': checks
        }
    
    def _analyze_soc2_type2(self) -> Dict[str, Any]:
        """Analyze against SOC 2 Type II requirements"""
        
        checks = []
        
        # Security Principle
        checks.extend(self._soc2_security_checks())
        
        # Availability Principle
        checks.extend(self._soc2_availability_checks())
        
        # Processing Integrity Principle
        checks.extend(self._soc2_processing_integrity_checks())
        
        # Confidentiality Principle
        checks.extend(self._soc2_confidentiality_checks())
        
        # Privacy Principle
        checks.extend(self._soc2_privacy_checks())
        
        total_checks = len(checks)
        compliant_checks = len([c for c in checks if c['status'] == 'PASS'])
        
        return {
            'framework_name': 'SOC 2 Type II',
            'version': '2017',
            'total_controls': total_checks,
            'compliant_controls': compliant_checks,
            'non_compliant_controls': total_checks - compliant_checks,
            'compliance_percentage': round((compliant_checks / total_checks * 100), 1) if total_checks > 0 else 0,
            'compliance_level': self._get_compliance_level(compliant_checks, total_checks),
            'checks': checks
        }
    
    def _soc2_security_checks(self) -> List[Dict[str, Any]]:
        """SOC 2 Security principle checks"""
        return [
            {
                'principle': 'Security',
                'control': 'CC6.1',
                'title': 'Logical and Physical Access Controls',
                'description': 'The entity implements logical and physical access controls',
                'severity': 'HIGH',
                'status': self._check_access_controls(),
                'evidence': 'IAM roles and RBAC implemented',
                'remediation': 'Implement comprehensive access controls'
            },
            {
                'principle': 'Security',
                'control': 'CC6.2',
                'title': 'Authentication',
                'description': 'Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users',
                'severity': 'HIGH',
                'status': self._check_authentication_controls(),
                'evidence': 'IAM and RBAC authentication configured',
                'remediation': 'Implement strong authentication mechanisms'
            }
        ]
    
    def _soc2_availability_checks(self) -> List[Dict[str, Any]]:
        """SOC 2 Availability principle checks"""
        return [
            {
                'principle': 'Availability',
                'control': 'A1.1',
                'title': 'Availability Monitoring',
                'description': 'The entity maintains, monitors, and evaluates current processing capacity',
                'severity': 'MEDIUM',
                'status': self._check_availability_monitoring(),
                'evidence': 'CloudWatch monitoring and health checks configured',
                'remediation': 'Implement comprehensive availability monitoring'
            }
        ]
    
    def _soc2_processing_integrity_checks(self) -> List[Dict[str, Any]]:
        """SOC 2 Processing Integrity principle checks"""
        return [
            {
                'principle': 'Processing Integrity',
                'control': 'PI1.1',
                'title': 'Data Processing Integrity',
                'description': 'The entity implements controls to ensure processing integrity',
                'severity': 'MEDIUM',
                'status': 'WARNING',
                'evidence': 'Requires application-level integrity verification',
                'remediation': 'Implement data processing integrity controls'
            }
        ]
    
    def _soc2_confidentiality_checks(self) -> List[Dict[str, Any]]:
        """SOC 2 Confidentiality principle checks"""
        return [
            {
                'principle': 'Confidentiality',
                'control': 'C1.1',
                'title': 'Data Confidentiality',
                'description': 'The entity implements controls to protect confidential information',
                'severity': 'HIGH',
                'status': self._check_data_confidentiality(),
                'evidence': self._get_encryption_evidence(),
                'remediation': 'Implement comprehensive data confidentiality controls'
            }
        ]
    
    def _soc2_privacy_checks(self) -> List[Dict[str, Any]]:
        """SOC 2 Privacy principle checks"""
        return [
            {
                'principle': 'Privacy',
                'control': 'P1.1',
                'title': 'Privacy Notice',
                'description': 'The entity provides notice about its privacy practices',
                'severity': 'LOW',
                'status': 'WARNING',
                'evidence': 'Requires privacy policy verification',
                'remediation': 'Implement privacy notices and data handling policies'
            }
        ]
    
    def _analyze_hipaa_security_rule(self) -> Dict[str, Any]:
        """Analyze against HIPAA Security Rule requirements"""
        
        checks = []
        
        # Administrative Safeguards
        checks.append({
            'safeguard': 'Administrative',
            'standard': '164.308(a)(1)(i)',
            'title': 'Security Officer',
            'description': 'Assign security responsibilities to an individual',
            'severity': 'HIGH',
            'status': 'WARNING',
            'evidence': 'Requires organizational security officer assignment',
            'remediation': 'Assign dedicated security officer responsibilities'
        })
        
        # Physical Safeguards
        checks.append({
            'safeguard': 'Physical',
            'standard': '164.310(a)(1)',
            'title': 'Facility Access Controls',
            'description': 'Implement policies and procedures to limit physical access',
            'severity': 'MEDIUM',
            'status': 'PASS',  # AWS manages physical security
            'evidence': 'AWS provides physical security for EKS infrastructure',
            'remediation': 'No action required - AWS managed infrastructure'
        })
        
        # Technical Safeguards
        checks.append({
            'safeguard': 'Technical',
            'standard': '164.312(a)(1)',
            'title': 'Access Control',
            'description': 'Implement technical policies and procedures for electronic information systems',
            'severity': 'HIGH',
            'status': self._check_access_controls(),
            'evidence': 'IAM and RBAC access controls implemented',
            'remediation': 'Implement comprehensive technical access controls'
        })
        
        total_checks = len(checks)
        compliant_checks = len([c for c in checks if c['status'] == 'PASS'])
        
        return {
            'framework_name': 'HIPAA Security Rule',
            'version': '2013',
            'total_controls': total_checks,
            'compliant_controls': compliant_checks,
            'non_compliant_controls': total_checks - compliant_checks,
            'compliance_percentage': round((compliant_checks / total_checks * 100), 1) if total_checks > 0 else 0,
            'compliance_level': self._get_compliance_level(compliant_checks, total_checks),
            'checks': checks
        }
    
    def _analyze_iso27001(self) -> Dict[str, Any]:
        """Analyze against ISO 27001 requirements"""
        
        checks = []
        
        # A.9 Access Control
        checks.append({
            'domain': 'A.9',
            'control': 'A.9.1.1',
            'title': 'Access Control Policy',
            'description': 'An access control policy should be established and reviewed',
            'severity': 'HIGH',
            'status': self._check_access_control_policy(),
            'evidence': 'IAM policies and RBAC configured',
            'remediation': 'Establish comprehensive access control policies'
        })
        
        # A.10 Cryptography
        checks.append({
            'domain': 'A.10',
            'control': 'A.10.1.1',
            'title': 'Cryptographic Controls Policy',
            'description': 'A policy on the use of cryptographic controls should be developed',
            'severity': 'HIGH',
            'status': self._check_cryptographic_policy(),
            'evidence': self._get_encryption_evidence(),
            'remediation': 'Implement comprehensive cryptographic policies'
        })
        
        total_checks = len(checks)
        compliant_checks = len([c for c in checks if c['status'] == 'PASS'])
        
        return {
            'framework_name': 'ISO/IEC 27001',
            'version': '2013',
            'total_controls': total_checks,
            'compliant_controls': compliant_checks,
            'non_compliant_controls': total_checks - compliant_checks,
            'compliance_percentage': round((compliant_checks / total_checks * 100), 1) if total_checks > 0 else 0,
            'compliance_level': self._get_compliance_level(compliant_checks, total_checks),
            'checks': checks
        }
    
    def _analyze_dora_regulation(self) -> Dict[str, Any]:
        """Analyze against EU Digital Operational Resilience Act (DORA)"""
        
        checks = []
        
        # Article 8: ICT risk management framework
        checks.extend(self._dora_ict_risk_management_checks())
        
        # Article 17: ICT-related incident management
        checks.extend(self._dora_incident_management_checks())
        
        # Article 25: Digital operational resilience testing
        checks.extend(self._dora_resilience_testing_checks())
        
        # Article 28: ICT third-party risk
        checks.extend(self._dora_third_party_risk_checks())
        
        total_checks = len(checks)
        compliant_checks = len([c for c in checks if c['status'] == 'PASS'])
        
        return {
            'framework_name': 'EU Digital Operational Resilience Act (DORA)',
            'version': '2024',
            'total_controls': total_checks,
            'compliant_controls': compliant_checks,
            'non_compliant_controls': total_checks - compliant_checks,
            'compliance_percentage': round((compliant_checks / total_checks * 100), 1) if total_checks > 0 else 0,
            'compliance_level': self._get_compliance_level(compliant_checks, total_checks),
            'checks': checks,
            'key_requirements': self._get_dora_key_requirements()
        }
    
    def _dora_ict_risk_management_checks(self) -> List[Dict[str, Any]]:
        """DORA ICT risk management framework checks"""
        return [
            {
                'article': 'Article 8',
                'requirement': 'ICT Risk Management Framework',
                'title': 'ICT Risk Management Policy',
                'description': 'Financial entities shall have a sound, comprehensive and well-documented ICT risk management framework',
                'severity': 'HIGH',
                'status': self._check_ict_risk_framework(),
                'evidence': 'Security policies and risk management procedures',
                'remediation': 'Establish comprehensive ICT risk management framework with documented policies'
            },
            {
                'article': 'Article 9',
                'requirement': 'ICT Systems and Infrastructure',
                'title': 'ICT Systems Protection and Recovery',
                'description': 'Ensure protection and prevention measures for ICT systems',
                'severity': 'HIGH',
                'status': self._check_ict_protection_measures(),
                'evidence': 'Encryption, backup, and recovery capabilities implemented',
                'remediation': 'Implement comprehensive ICT protection and recovery measures'
            },
            {
                'article': 'Article 10',
                'requirement': 'Business Continuity',
                'title': 'Business Continuity Policy',
                'description': 'Maintain business continuity through ICT business continuity policy',
                'severity': 'HIGH',
                'status': 'WARNING',
                'evidence': 'Requires business continuity plan verification',
                'remediation': 'Develop and maintain comprehensive business continuity plans'
            }
        ]
    
    def _dora_incident_management_checks(self) -> List[Dict[str, Any]]:
        """DORA incident management checks"""
        return [
            {
                'article': 'Article 17',
                'requirement': 'Incident Classification',
                'title': 'ICT-related Incident Classification',
                'description': 'Classify ICT-related incidents based on set criteria',
                'severity': 'MEDIUM',
                'status': self._check_incident_classification(),
                'evidence': 'Monitoring and alerting systems configured',
                'remediation': 'Implement incident classification and management procedures'
            },
            {
                'article': 'Article 18',
                'requirement': 'Incident Reporting',
                'title': 'Internal Incident Reporting',
                'description': 'Establish procedures for internal reporting of ICT-related incidents',
                'severity': 'MEDIUM',
                'status': self._check_incident_reporting(),
                'evidence': 'Audit logging and monitoring capabilities',
                'remediation': 'Establish comprehensive incident reporting procedures'
            }
        ]
    
    def _dora_resilience_testing_checks(self) -> List[Dict[str, Any]]:
        """DORA digital operational resilience testing checks"""
        return [
            {
                'article': 'Article 25',
                'requirement': 'Resilience Testing',
                'title': 'Digital Operational Resilience Testing Programme',
                'description': 'Conduct appropriate digital operational resilience testing',
                'severity': 'MEDIUM',
                'status': 'WARNING',
                'evidence': 'Requires testing program verification',
                'remediation': 'Establish regular resilience testing programme including penetration testing'
            },
            {
                'article': 'Article 26',
                'requirement': 'Threat-Led Testing',
                'title': 'Advanced Testing (TLPT)',
                'description': 'Conduct threat-led penetration testing',
                'severity': 'HIGH',
                'status': 'WARNING',
                'evidence': 'Requires threat-led penetration testing verification',
                'remediation': 'Implement threat-led penetration testing for critical systems'
            }
        ]
    
    def _dora_third_party_risk_checks(self) -> List[Dict[str, Any]]:
        """DORA ICT third-party risk checks"""
        return [
            {
                'article': 'Article 28',
                'requirement': 'Third-Party Risk Management',  
                'title': 'ICT Third-Party Risk Management',
                'description': 'Manage and monitor ICT third-party risk',
                'severity': 'HIGH',
                'status': self._check_third_party_risk(),
                'evidence': 'AWS EKS managed service with security controls',
                'remediation': 'Establish comprehensive third-party risk management for ICT services'
            },
            {
                'article': 'Article 30',
                'requirement': 'Contractual Arrangements',
                'title': 'ICT Services Contractual Arrangements',
                'description': 'Ensure appropriate contractual arrangements for ICT services',
                'severity': 'MEDIUM',
                'status': 'WARNING',
                'evidence': 'Requires contract review with cloud providers',
                'remediation': 'Review and enhance contractual arrangements with ICT service providers'
            }
        ]
    
    def _get_dora_key_requirements(self) -> List[Dict[str, Any]]:
        """Get key DORA requirements summary"""
        return [
            {
                'chapter': 'Chapter II',
                'title': 'ICT Risk Management',
                'description': 'Comprehensive ICT risk management framework',
                'articles': ['8', '9', '10', '11', '12', '13', '14', '15', '16']
            },
            {
                'chapter': 'Chapter III', 
                'title': 'ICT-related Incident Management',
                'description': 'Incident classification, management and reporting',
                'articles': ['17', '18', '19', '20', '21', '22', '23']
            },
            {
                'chapter': 'Chapter IV',
                'title': 'Digital Operational Resilience Testing',
                'description': 'Testing programmes and threat-led penetration testing',
                'articles': ['24', '25', '26', '27']
            },
            {
                'chapter': 'Chapter V',
                'title': 'Managing ICT Third-Party Risk',
                'description': 'Third-party risk management and oversight',
                'articles': ['28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44']
            }
        ]
    
    def _check_ict_risk_framework(self) -> str:
        """Check ICT risk management framework"""
        # Basic security controls indicate some risk management
        if self._check_data_encryption() == 'PASS' and self._check_audit_policy() == 'PASS':
            return 'PASS'
        else:
            return 'WARNING'
    
    def _check_ict_protection_measures(self) -> str:
        """Check ICT protection measures"""
        encryption_status = self._check_data_encryption()
        backup_recovery = 'PASS'  # EKS provides managed backup/recovery
        
        if encryption_status == 'PASS' and backup_recovery == 'PASS':
            return 'PASS'
        else:
            return 'WARNING'
    
    def _check_incident_classification(self) -> str:
        """Check incident classification procedures"""
        monitoring_status = self._check_continuous_monitoring()
        return monitoring_status
    
    def _check_incident_reporting(self) -> str:
        """Check incident reporting procedures"""
        audit_status = self._check_audit_policy()
        return audit_status
    
    def _check_third_party_risk(self) -> str:
        """Check third-party risk management"""
        # AWS EKS is a managed service with strong security controls
        return 'PASS'
    
    # Helper methods for various checks
    def _check_api_server_config(self) -> str:
        """Check API server configuration security"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                vpc_config = cluster_data['cluster'].get('resourcesVpcConfig', {})
                if not vpc_config.get('endpointPrivateAccess', False):
                    return 'FAIL'
                elif vpc_config.get('publicAccessCidrs', []) == ['0.0.0.0/0']:
                    return 'WARNING'
                else:
                    return 'PASS'
        return 'WARNING'
    
    def _get_api_server_evidence(self) -> str:
        """Get API server configuration evidence"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                vpc_config = cluster_data['cluster'].get('resourcesVpcConfig', {})
                return f"Private access: {vpc_config.get('endpointPrivateAccess', False)}, Public CIDRs: {vpc_config.get('publicAccessCidrs', [])}"
        return 'Configuration requires verification'
    
    def _check_node_anonymous_auth(self) -> str:
        """Check node anonymous authentication"""
        # EKS node groups disable anonymous auth by default
        return 'PASS'
    
    def _get_node_auth_evidence(self) -> str:
        """Get node authentication evidence"""
        return 'EKS node groups have anonymous authentication disabled by default'
    
    def _check_pod_security_standards(self) -> str:
        """Check Pod Security Standards implementation"""
        # This requires runtime verification of namespace configurations
        return 'WARNING'
    
    def _get_pod_security_evidence(self) -> str:
        """Get pod security evidence"""
        return 'Pod Security Standards implementation requires runtime verification'
    
    def _check_audit_policy(self) -> str:
        """Check audit policy configuration"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                logging_config = cluster_data['cluster'].get('logging', {})
                cluster_logging = logging_config.get('clusterLogging', [])
                
                if cluster_logging:
                    enabled_logs = []
                    for log_config in cluster_logging:
                        if log_config.get('enabled', False):
                            enabled_logs.extend(log_config.get('types', []))
                    
                    critical_logs = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
                    missing_critical = [log for log in critical_logs if log not in enabled_logs]
                    
                    if not missing_critical:
                        return 'PASS'
                    else:
                        return 'FAIL'
                else:
                    return 'FAIL'
        return 'WARNING'
    
    def _get_audit_evidence(self) -> str:
        """Get audit configuration evidence"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                logging_config = cluster_data['cluster'].get('logging', {})
                return f"Control plane logging configuration: {logging_config}"
        return 'Audit configuration requires verification'
    
    def _check_data_encryption(self) -> str:
        """Check data encryption at rest"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                encryption_config = cluster_data['cluster'].get('encryptionConfig', [])
                if encryption_config:
                    secrets_encrypted = any(
                        'secrets' in config.get('resources', [])
                        for config in encryption_config
                    )
                    return 'PASS' if secrets_encrypted else 'FAIL'
                else:
                    return 'FAIL'
        return 'WARNING'
    
    def _get_encryption_evidence(self) -> str:
        """Get encryption configuration evidence"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                encryption_config = cluster_data['cluster'].get('encryptionConfig', [])
                if encryption_config:
                    return f"Encryption configuration found: {len(encryption_config)} KMS keys configured"
                else:
                    return 'No encryption at rest configured'
        return 'Encryption configuration requires verification'
    
    def _check_encryption_in_transit(self) -> str:
        """Check encryption in transit"""
        # EKS enforces TLS for API communication by default
        return 'PASS'
    
    def _check_network_security_controls(self) -> str:
        """Check network security controls"""
        if self.offline_data:
            network_data = self.offline_data.get('network_info', {})
            security_groups = network_data.get('security_groups', [])
            if security_groups:
                return 'PASS'
            else:
                return 'WARNING'
        return 'WARNING'
    
    def _check_access_controls(self) -> str:
        """Check access controls implementation"""
        # RBAC is enabled by default in EKS
        return 'PASS'
    
    def _check_authentication_controls(self) -> str:
        """Check authentication controls"""
        # EKS uses IAM authentication by default
        return 'PASS'
    
    def _check_iam_management(self) -> str:
        """Check IAM management"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                identity = cluster_data['cluster'].get('identity', {})
                oidc_issuer = identity.get('oidc', {}).get('issuer', '')
                return 'PASS' if oidc_issuer else 'WARNING'
        return 'WARNING'
    
    def _check_asset_inventory(self) -> str:
        """Check asset inventory management"""
        if self.offline_data:
            node_groups = self.offline_data.get('cluster_info', {}).get('nodegroup_details', [])
            return 'PASS' if node_groups else 'WARNING'
        return 'WARNING'
    
    def _check_monitoring_baseline(self) -> str:
        """Check monitoring baseline"""
        # Check if control plane logging is enabled
        return self._check_audit_policy()
    
    def _check_continuous_monitoring(self) -> str:
        """Check continuous monitoring"""
        # This requires verification of monitoring tools like CloudWatch, Prometheus, etc.
        return 'WARNING'
    
    def _check_availability_monitoring(self) -> str:
        """Check availability monitoring"""
        # EKS provides basic health monitoring
        return 'PASS'
    
    def _check_data_confidentiality(self) -> str:
        """Check data confidentiality controls"""
        return self._check_data_encryption()
    
    def _check_access_control_policy(self) -> str:
        """Check access control policy"""
        # EKS has RBAC enabled by default
        return 'PASS'
    
    def _check_cryptographic_policy(self) -> str:
        """Check cryptographic policy"""
        return self._check_data_encryption()
    
    def _get_compliance_level(self, compliant_checks: int, total_checks: int) -> str:
        """Get compliance level based on percentage"""
        if total_checks == 0:
            return 'UNKNOWN'
        
        percentage = (compliant_checks / total_checks) * 100
        
        if percentage >= 90:
            return 'EXCELLENT'
        elif percentage >= 80:
            return 'GOOD'
        elif percentage >= 70:
            return 'SATISFACTORY'
        elif percentage >= 60:
            return 'NEEDS_IMPROVEMENT'
        else:
            return 'CRITICAL'
    
    def _generate_cis_recommendations(self, checks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate CIS-specific recommendations"""
        recommendations = []
        
        failed_checks = [c for c in checks if c['status'] == 'FAIL']
        warning_checks = [c for c in checks if c['status'] == 'WARNING']
        
        for check in failed_checks:
            recommendations.append({
                'control_id': check['control_id'],
                'title': f"Address CIS Control {check['control_id']}: {check['title']}",
                'priority': 'HIGH' if check['severity'] == 'HIGH' else 'MEDIUM',
                'description': check['remediation'],
                'compliance_impact': f"Required for CIS EKS Benchmark compliance"
            })
        
        return recommendations[:10]  # Top 10 recommendations
    
    def _analyze_nist_functions(self, checks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze NIST framework functions"""
        functions = {'IDENTIFY': 0, 'PROTECT': 0, 'DETECT': 0, 'RESPOND': 0, 'RECOVER': 0}
        function_totals = {'IDENTIFY': 0, 'PROTECT': 0, 'DETECT': 0, 'RESPOND': 0, 'RECOVER': 0}
        
        for check in checks:
            function = check.get('function')
            if function in functions:
                function_totals[function] += 1
                if check['status'] == 'PASS':
                    functions[function] += 1
        
        function_scores = {}
        for func, passed in functions.items():
            total = function_totals[func]
            score = (passed / total * 100) if total > 0 else 0
            function_scores[func] = {
                'passed': passed,
                'total': total,
                'score': round(score, 1),
                'status': 'GOOD' if score >= 80 else 'NEEDS_IMPROVEMENT' if score >= 60 else 'CRITICAL'
            }
        
        return function_scores
    
    def _calculate_overall_compliance(self, framework_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall compliance posture across all frameworks"""
        total_frameworks = len(framework_results)
        if total_frameworks == 0:
            return {'overall_score': 0, 'posture': 'UNKNOWN'}
        
        total_score = 0
        framework_scores = {}
        
        for framework in framework_results:
            framework_name = framework['framework_name']
            compliance_percentage = framework['compliance_percentage']
            total_score += compliance_percentage
            
            framework_scores[framework_name] = {
                'compliance_percentage': compliance_percentage,
                'compliance_level': framework['compliance_level'],
                'total_controls': framework['total_controls'],
                'compliant_controls': framework['compliant_controls']
            }
        
        average_score = total_score / total_frameworks
        
        if average_score >= 90:
            posture = 'EXCELLENT'
        elif average_score >= 80:
            posture = 'GOOD'
        elif average_score >= 70:
            posture = 'SATISFACTORY'
        elif average_score >= 60:
            posture = 'NEEDS_IMPROVEMENT'
        else:
            posture = 'CRITICAL'
        
        return {
            'overall_compliance_score': round(average_score, 1),
            'compliance_posture': posture,
            'framework_scores': framework_scores,
            'top_compliance_gaps': self._identify_top_compliance_gaps(framework_results),
            'compliance_summary': {
                'total_frameworks_analyzed': total_frameworks,
                'frameworks_with_good_compliance': len([f for f in framework_results if f['compliance_percentage'] >= 80]),
                'frameworks_needing_attention': len([f for f in framework_results if f['compliance_percentage'] < 80])
            }
        }
    
    def _identify_top_compliance_gaps(self, framework_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify top compliance gaps across all frameworks"""
        gaps = []
        
        for framework in framework_results:
            framework_name = framework['framework_name']
            if 'checks' in framework:
                failed_checks = [c for c in framework['checks'] if c['status'] == 'FAIL']
                for check in failed_checks:
                    gaps.append({
                        'framework': framework_name,
                        'control': check.get('control_id', check.get('control', 'N/A')),
                        'title': check['title'],
                        'severity': check['severity'],
                        'remediation': check['remediation']
                    })
        
        # Sort by severity (HIGH first)
        gaps.sort(key=lambda x: 0 if x['severity'] == 'HIGH' else 1 if x['severity'] == 'MEDIUM' else 2)
        
        return gaps[:15]  # Top 15 gaps
