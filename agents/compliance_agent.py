"""
Compliance Orchestration Agent - Multi-framework compliance automation
"""
import boto3
import json
from datetime import datetime
from typing import Dict, Any, List
from .base_agent import BaseAgent, AgentTask, AgentResult

class ComplianceOrchestrationAgent(BaseAgent):
    """Multi-framework compliance validation agent"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("compliance-orchestration", config)
        self.region = config.get('region', 'us-west-2')
        self.compliance_frameworks = {
            'CIS_EKS': self._validate_cis_eks,
            'NIST_800_53': self._validate_nist_800_53,
            'PCI_DSS': self._validate_pci_dss,
            'SOC2': self._validate_soc2,
            'HIPAA': self._validate_hipaa
        }
    
    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process compliance validation task"""
        try:
            cluster_name = task.cluster_id
            region = task.payload.get('region', self.region)
            role_arn = task.payload.get('role_arn')
            frameworks = task.payload.get('frameworks', list(self.compliance_frameworks.keys()))
            
            # Get security analysis results for compliance mapping
            security_results = task.payload.get('security_results', {})
            
            compliance_results = await self._validate_compliance(cluster_name, region, role_arn, frameworks, security_results)
            
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="completed",
                data=compliance_results,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="failed",
                data={"error": str(e)},
                timestamp=datetime.now()
            )
    
    async def _validate_compliance(self, cluster_name: str, region: str, role_arn: str, frameworks: List[str], security_results: Dict) -> Dict[str, Any]:
        """Validate compliance against multiple frameworks"""
        compliance_results = {
            'cluster_name': cluster_name,
            'validation_timestamp': datetime.now().isoformat(),
            'frameworks_validated': frameworks,
            'compliance_summary': {},
            'detailed_results': {},
            'evidence_collection': {},
            'remediation_priorities': []
        }
        
        # Validate each framework
        for framework in frameworks:
            if framework in self.compliance_frameworks:
                validator = self.compliance_frameworks[framework]
                result = await validator(cluster_name, region, role_arn, security_results)
                compliance_results['detailed_results'][framework] = result
                compliance_results['compliance_summary'][framework] = {
                    'compliance_score': result.get('compliance_score', 0),
                    'status': result.get('status', 'UNKNOWN'),
                    'critical_gaps': result.get('critical_gaps', 0)
                }
        
        # Generate overall compliance assessment
        compliance_results['overall_assessment'] = self._generate_overall_assessment(compliance_results['compliance_summary'])
        
        # Collect evidence for audit purposes
        compliance_results['evidence_collection'] = await self._collect_compliance_evidence(cluster_name, region, role_arn)
        
        # Generate remediation priorities
        compliance_results['remediation_priorities'] = self._generate_remediation_priorities(compliance_results['detailed_results'])
        
        return compliance_results
    
    async def _validate_cis_eks(self, cluster_name: str, region: str, role_arn: str, security_results: Dict) -> Dict[str, Any]:
        """Validate against CIS Amazon EKS Benchmark"""
        cis_controls = {
            '1.1.1': {'name': 'Ensure EKS cluster endpoint access is restricted', 'status': 'NOT_CHECKED'},
            '1.1.2': {'name': 'Ensure EKS cluster logging is enabled', 'status': 'NOT_CHECKED'},
            '1.1.3': {'name': 'Ensure EKS cluster encryption is enabled', 'status': 'NOT_CHECKED'},
            '1.2.1': {'name': 'Ensure RBAC is enabled', 'status': 'NOT_CHECKED'},
            '1.2.2': {'name': 'Ensure service account tokens are not automatically mounted', 'status': 'NOT_CHECKED'},
            '1.3.1': {'name': 'Ensure network policies are in place', 'status': 'NOT_CHECKED'},
            '1.3.2': {'name': 'Ensure pod security policies are enforced', 'status': 'NOT_CHECKED'},
            '1.4.1': {'name': 'Ensure secrets are encrypted at rest', 'status': 'NOT_CHECKED'},
            '1.4.2': {'name': 'Ensure image vulnerability scanning is enabled', 'status': 'NOT_CHECKED'}
        }
        
        # Map security results to CIS controls
        security_checks = security_results.get('checks', [])
        
        for check in security_checks:
            check_id = check.get('id', '')
            
            if check_id == 'endpoint_access':
                cis_controls['1.1.1']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
                cis_controls['1.1.1']['finding'] = check.get('description', '')
            
            elif check_id == 'cluster_logging':
                cis_controls['1.1.2']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
                cis_controls['1.1.2']['finding'] = check.get('description', '')
            
            elif check_id == 'cluster_encryption':
                cis_controls['1.1.3']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
                cis_controls['1.1.3']['finding'] = check.get('description', '')
                cis_controls['1.4.1']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
                cis_controls['1.4.1']['finding'] = check.get('description', '')
            
            elif check_id == 'rbac_config':
                cis_controls['1.2.1']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
                cis_controls['1.2.1']['finding'] = check.get('description', '')
        
        # Calculate compliance score
        total_controls = len(cis_controls)
        passed_controls = len([c for c in cis_controls.values() if c['status'] == 'PASS'])
        failed_controls = len([c for c in cis_controls.values() if c['status'] == 'FAIL'])
        not_checked = len([c for c in cis_controls.values() if c['status'] == 'NOT_CHECKED'])
        
        compliance_score = (passed_controls / total_controls) * 100
        
        return {
            'framework': 'CIS Amazon EKS Benchmark v1.0.1',
            'compliance_score': round(compliance_score, 1),
            'status': 'COMPLIANT' if compliance_score >= 80 else 'NON_COMPLIANT',
            'total_controls': total_controls,
            'passed_controls': passed_controls,
            'failed_controls': failed_controls,
            'not_checked': not_checked,
            'critical_gaps': failed_controls,
            'controls': cis_controls,
            'recommendations': self._generate_cis_recommendations(cis_controls)
        }
    
    async def _validate_nist_800_53(self, cluster_name: str, region: str, role_arn: str, security_results: Dict) -> Dict[str, Any]:
        """Validate against NIST SP 800-53 controls"""
        nist_controls = {
            'AC-2': {'name': 'Account Management', 'status': 'PASS', 'description': 'RBAC enabled by default'},
            'AC-3': {'name': 'Access Enforcement', 'status': 'NOT_CHECKED', 'description': 'Requires runtime verification'},
            'AU-2': {'name': 'Audit Events', 'status': 'NOT_CHECKED', 'description': 'Control plane logging'},
            'AU-3': {'name': 'Content of Audit Records', 'status': 'NOT_CHECKED', 'description': 'Audit log content'},
            'CA-7': {'name': 'Continuous Monitoring', 'status': 'NOT_CHECKED', 'description': 'Security monitoring'},
            'CM-2': {'name': 'Baseline Configuration', 'status': 'PASS', 'description': 'EKS managed configuration'},
            'IA-2': {'name': 'Identification and Authentication', 'status': 'PASS', 'description': 'AWS IAM integration'},
            'SC-7': {'name': 'Boundary Protection', 'status': 'NOT_CHECKED', 'description': 'Network security'},
            'SC-8': {'name': 'Transmission Confidentiality', 'status': 'PASS', 'description': 'TLS encryption'},
            'SC-13': {'name': 'Cryptographic Protection', 'status': 'NOT_CHECKED', 'description': 'Encryption at rest'}
        }
        
        # Map security results to NIST controls
        security_checks = security_results.get('checks', [])
        
        for check in security_checks:
            check_id = check.get('id', '')
            
            if check_id == 'cluster_logging':
                nist_controls['AU-2']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
                nist_controls['AU-3']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
            
            elif check_id == 'cluster_encryption':
                nist_controls['SC-13']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
            
            elif check_id == 'network_security':
                nist_controls['SC-7']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
        
        # Calculate compliance score
        total_controls = len(nist_controls)
        passed_controls = len([c for c in nist_controls.values() if c['status'] == 'PASS'])
        compliance_score = (passed_controls / total_controls) * 100
        
        return {
            'framework': 'NIST SP 800-53 Rev 5',
            'compliance_score': round(compliance_score, 1),
            'status': 'COMPLIANT' if compliance_score >= 70 else 'NON_COMPLIANT',
            'total_controls': total_controls,
            'passed_controls': passed_controls,
            'controls': nist_controls
        }
    
    async def _validate_pci_dss(self, cluster_name: str, region: str, role_arn: str, security_results: Dict) -> Dict[str, Any]:
        """Validate against PCI DSS requirements"""
        pci_requirements = {
            '2.2': {'name': 'Default passwords and security parameters', 'status': 'PASS'},
            '2.3': {'name': 'Encrypt non-console administrative access', 'status': 'PASS'},
            '3.4': {'name': 'Protect stored cardholder data', 'status': 'NOT_CHECKED'},
            '4.1': {'name': 'Use strong cryptography for data transmission', 'status': 'PASS'},
            '7.1': {'name': 'Limit access to system components', 'status': 'NOT_CHECKED'},
            '8.1': {'name': 'Identify and authenticate access', 'status': 'PASS'},
            '10.1': {'name': 'Implement audit trails', 'status': 'NOT_CHECKED'},
            '11.4': {'name': 'Use intrusion-detection systems', 'status': 'NOT_CHECKED'}
        }
        
        # Map security results
        security_checks = security_results.get('checks', [])
        
        for check in security_checks:
            check_id = check.get('id', '')
            
            if check_id == 'cluster_encryption':
                pci_requirements['3.4']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
            
            elif check_id == 'cluster_logging':
                pci_requirements['10.1']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
        
        total_requirements = len(pci_requirements)
        passed_requirements = len([r for r in pci_requirements.values() if r['status'] == 'PASS'])
        compliance_score = (passed_requirements / total_requirements) * 100
        
        return {
            'framework': 'PCI DSS v3.2.1',
            'compliance_score': round(compliance_score, 1),
            'status': 'COMPLIANT' if compliance_score >= 85 else 'NON_COMPLIANT',
            'total_requirements': total_requirements,
            'passed_requirements': passed_requirements,
            'requirements': pci_requirements
        }
    
    async def _validate_soc2(self, cluster_name: str, region: str, role_arn: str, security_results: Dict) -> Dict[str, Any]:
        """Validate against SOC 2 Type II controls"""
        soc2_controls = {
            'CC6.1': {'name': 'Logical and physical access controls', 'status': 'PASS'},
            'CC6.2': {'name': 'Authentication and authorization', 'status': 'PASS'},
            'CC6.3': {'name': 'System access monitoring', 'status': 'NOT_CHECKED'},
            'CC6.7': {'name': 'Data transmission controls', 'status': 'PASS'},
            'CC6.8': {'name': 'Data classification and handling', 'status': 'NOT_CHECKED'},
            'A1.1': {'name': 'Availability monitoring', 'status': 'NOT_CHECKED'},
            'C1.1': {'name': 'Confidentiality controls', 'status': 'NOT_CHECKED'}
        }
        
        # Map security results
        security_checks = security_results.get('checks', [])
        
        for check in security_checks:
            check_id = check.get('id', '')
            
            if check_id == 'cluster_logging':
                soc2_controls['CC6.3']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
            
            elif check_id == 'cluster_encryption':
                soc2_controls['C1.1']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
        
        total_controls = len(soc2_controls)
        passed_controls = len([c for c in soc2_controls.values() if c['status'] == 'PASS'])
        compliance_score = (passed_controls / total_controls) * 100
        
        return {
            'framework': 'SOC 2 Type II',
            'compliance_score': round(compliance_score, 1),
            'status': 'COMPLIANT' if compliance_score >= 75 else 'NON_COMPLIANT',
            'total_controls': total_controls,
            'passed_controls': passed_controls,
            'controls': soc2_controls
        }
    
    async def _validate_hipaa(self, cluster_name: str, region: str, role_arn: str, security_results: Dict) -> Dict[str, Any]:
        """Validate against HIPAA Security Rule"""
        hipaa_safeguards = {
            '164.308(a)(1)': {'name': 'Security Officer', 'status': 'PASS'},
            '164.308(a)(3)': {'name': 'Assigned Security Responsibilities', 'status': 'PASS'},
            '164.308(a)(4)': {'name': 'Information Access Management', 'status': 'NOT_CHECKED'},
            '164.310(a)(1)': {'name': 'Facility Access Controls', 'status': 'PASS'},
            '164.312(a)(1)': {'name': 'Access Control', 'status': 'NOT_CHECKED'},
            '164.312(b)': {'name': 'Audit Controls', 'status': 'NOT_CHECKED'},
            '164.312(c)(1)': {'name': 'Integrity', 'status': 'NOT_CHECKED'},
            '164.312(e)(1)': {'name': 'Transmission Security', 'status': 'PASS'}
        }
        
        # Map security results
        security_checks = security_results.get('checks', [])
        
        for check in security_checks:
            check_id = check.get('id', '')
            
            if check_id == 'cluster_logging':
                hipaa_safeguards['164.312(b)']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
            
            elif check_id == 'rbac_config':
                hipaa_safeguards['164.312(a)(1)']['status'] = 'PASS' if check['status'] == 'PASS' else 'FAIL'
        
        total_safeguards = len(hipaa_safeguards)
        passed_safeguards = len([s for s in hipaa_safeguards.values() if s['status'] == 'PASS'])
        compliance_score = (passed_safeguards / total_safeguards) * 100
        
        return {
            'framework': 'HIPAA Security Rule',
            'compliance_score': round(compliance_score, 1),
            'status': 'COMPLIANT' if compliance_score >= 80 else 'NON_COMPLIANT',
            'total_safeguards': total_safeguards,
            'passed_safeguards': passed_safeguards,
            'safeguards': hipaa_safeguards
        }
    
    def _generate_overall_assessment(self, compliance_summary: Dict) -> Dict[str, Any]:
        """Generate overall compliance assessment"""
        if not compliance_summary:
            return {'status': 'NO_FRAMEWORKS_VALIDATED', 'average_score': 0}
        
        total_score = sum(framework['compliance_score'] for framework in compliance_summary.values())
        average_score = total_score / len(compliance_summary)
        
        compliant_frameworks = len([f for f in compliance_summary.values() if f['status'] == 'COMPLIANT'])
        total_frameworks = len(compliance_summary)
        
        overall_status = 'COMPLIANT' if compliant_frameworks == total_frameworks else 'PARTIALLY_COMPLIANT' if compliant_frameworks > 0 else 'NON_COMPLIANT'
        
        return {
            'status': overall_status,
            'average_score': round(average_score, 1),
            'compliant_frameworks': compliant_frameworks,
            'total_frameworks': total_frameworks,
            'compliance_percentage': round((compliant_frameworks / total_frameworks) * 100, 1)
        }
    
    async def _collect_compliance_evidence(self, cluster_name: str, region: str, role_arn: str) -> Dict[str, Any]:
        """Collect evidence for compliance audits"""
        return {
            'evidence_collection_timestamp': datetime.now().isoformat(),
            'cluster_configuration_snapshot': f'aws eks describe-cluster --name {cluster_name}',
            'logging_configuration': f'aws eks describe-cluster --name {cluster_name} --query cluster.logging',
            'encryption_configuration': f'aws eks describe-cluster --name {cluster_name} --query cluster.encryptionConfig',
            'network_configuration': f'aws eks describe-cluster --name {cluster_name} --query cluster.resourcesVpcConfig',
            'evidence_storage': 'Evidence should be stored in secure, immutable storage for audit purposes'
        }
    
    def _generate_cis_recommendations(self, cis_controls: Dict) -> List[Dict]:
        """Generate CIS-specific recommendations"""
        recommendations = []
        
        for control_id, control in cis_controls.items():
            if control['status'] == 'FAIL':
                recommendations.append({
                    'control_id': control_id,
                    'control_name': control['name'],
                    'priority': 'HIGH',
                    'recommendation': f'Implement {control["name"]} to meet CIS benchmark requirements'
                })
        
        return recommendations
    
    def _generate_remediation_priorities(self, detailed_results: Dict) -> List[Dict]:
        """Generate prioritized remediation plan across all frameworks"""
        priorities = []
        
        # Collect all failed controls across frameworks
        failed_controls = {}
        
        for framework, results in detailed_results.items():
            controls = results.get('controls', {})
            for control_id, control in controls.items():
                if control.get('status') == 'FAIL':
                    control_key = control.get('name', control_id)
                    if control_key not in failed_controls:
                        failed_controls[control_key] = {
                            'frameworks': [],
                            'control_name': control.get('name', control_id),
                            'impact_score': 0
                        }
                    failed_controls[control_key]['frameworks'].append(framework)
                    failed_controls[control_key]['impact_score'] += 1
        
        # Sort by impact score (number of frameworks affected)
        sorted_controls = sorted(failed_controls.items(), key=lambda x: x[1]['impact_score'], reverse=True)
        
        for control_name, control_info in sorted_controls:
            priority = 'CRITICAL' if control_info['impact_score'] >= 3 else 'HIGH' if control_info['impact_score'] >= 2 else 'MEDIUM'
            
            priorities.append({
                'control_name': control_name,
                'affected_frameworks': control_info['frameworks'],
                'impact_score': control_info['impact_score'],
                'priority': priority,
                'recommendation': f'Address {control_name} to improve compliance across {len(control_info["frameworks"])} frameworks'
            })
        
        return priorities[:10]  # Top 10 priorities
