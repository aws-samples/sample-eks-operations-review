"""
Security Intelligence Agent - Advanced threat detection and security analysis
"""
import boto3
import json
from datetime import datetime
from typing import Dict, Any
from .base_agent import BaseAgent, AgentTask, AgentResult
from core.enhanced_analyzers import EnhancedSecurityAnalyzer

class SecurityIntelligenceAgent(BaseAgent):
    """Advanced security analysis agent"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("security-intelligence", config)
        self.region = config.get('region', 'us-west-2')
    
    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process security analysis task"""
        try:
            cluster_name = task.cluster_id
            region = task.payload.get('region', self.region)
            role_arn = task.payload.get('role_arn')
            
            # Use enhanced security analyzer
            analyzer = EnhancedSecurityAnalyzer(cluster_name, region, role_arn)
            security_results = analyzer.run_comprehensive_security_checks()
            
            # Add agent-specific enhancements
            enhanced_results = await self._enhance_security_analysis(security_results, cluster_name, region, role_arn)
            
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="completed",
                data=enhanced_results,
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
    
    async def _enhance_security_analysis(self, base_results: Dict[str, Any], cluster_name: str, region: str, role_arn: str = None) -> Dict[str, Any]:
        """Enhance security analysis with additional intelligence"""
        enhanced = base_results.copy()
        
        # Add threat intelligence
        enhanced['threat_intelligence'] = await self._analyze_threat_landscape(cluster_name, region, role_arn)
        
        # Add security posture scoring
        enhanced['security_posture'] = self._calculate_security_posture(base_results)
        
        # Add compliance mapping
        enhanced['compliance_mapping'] = self._map_to_compliance_frameworks(base_results)
        
        return enhanced
    
    async def _analyze_threat_landscape(self, cluster_name: str, region: str, role_arn: str = None) -> Dict[str, Any]:
        """Analyze threat landscape using AWS Security Hub and GuardDuty"""
        try:
            if role_arn:
                from core.aws_client import AWSClientManager
                aws_client = AWSClientManager(region, role_arn)
                clients = aws_client.get_clients()
            else:
                clients = {
                    'securityhub': boto3.client('securityhub', region_name=region),
                    'guardduty': boto3.client('guardduty', region_name=region)
                }
            
            threat_analysis = {
                'security_hub_findings': [],
                'guardduty_findings': [],
                'threat_level': 'LOW',
                'active_threats': 0
            }
            
            # Get Security Hub findings (if available)
            try:
                findings = clients['securityhub'].get_findings(
                    Filters={
                        'ResourceId': [{'Value': cluster_name, 'Comparison': 'CONTAINS'}]
                    },
                    MaxResults=50
                )
                threat_analysis['security_hub_findings'] = len(findings.get('Findings', []))
                
                # Analyze severity
                critical_findings = [f for f in findings.get('Findings', []) if f.get('Severity', {}).get('Label') == 'CRITICAL']
                if critical_findings:
                    threat_analysis['threat_level'] = 'CRITICAL'
                    threat_analysis['active_threats'] = len(critical_findings)
                
            except Exception as e:
                threat_analysis['security_hub_error'] = str(e)
            
            # Get GuardDuty findings (if available)
            try:
                detectors = clients['guardduty'].list_detectors()
                if detectors.get('DetectorIds'):
                    detector_id = detectors['DetectorIds'][0]
                    findings = clients['guardduty'].list_findings(DetectorId=detector_id, MaxResults=50)
                    threat_analysis['guardduty_findings'] = len(findings.get('FindingIds', []))
            except Exception as e:
                threat_analysis['guardduty_error'] = str(e)
            
            return threat_analysis
            
        except Exception as e:
            return {'error': str(e), 'threat_level': 'UNKNOWN'}
    
    def _calculate_security_posture(self, security_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive security posture"""
        checks = security_results.get('checks', [])
        total_checks = len(checks)
        passed_checks = len([c for c in checks if c['status'] == 'PASS'])
        failed_checks = len([c for c in checks if c['status'] == 'FAIL'])
        
        # Calculate weighted score based on severity
        severity_weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        total_weight = 0
        failed_weight = 0
        
        for check in checks:
            weight = severity_weights.get(check.get('severity', 'MEDIUM'), 2)
            total_weight += weight
            if check['status'] == 'FAIL':
                failed_weight += weight
        
        weighted_score = ((total_weight - failed_weight) / total_weight * 100) if total_weight > 0 else 0
        
        # Determine security posture level
        if weighted_score >= 90:
            posture_level = 'EXCELLENT'
        elif weighted_score >= 75:
            posture_level = 'GOOD'
        elif weighted_score >= 60:
            posture_level = 'FAIR'
        elif weighted_score >= 40:
            posture_level = 'POOR'
        else:
            posture_level = 'CRITICAL'
        
        return {
            'weighted_score': round(weighted_score, 1),
            'posture_level': posture_level,
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'failed_checks': failed_checks,
            'critical_issues': len([c for c in checks if c.get('severity') == 'HIGH' and c['status'] == 'FAIL'])
        }
    
    def _map_to_compliance_frameworks(self, security_results: Dict[str, Any]) -> Dict[str, Any]:
        """Map security findings to compliance frameworks"""
        checks = security_results.get('checks', [])
        
        # Compliance framework mappings
        compliance_mapping = {
            'CIS_EKS': {
                'total_controls': 25,
                'applicable_checks': [],
                'compliant_checks': [],
                'non_compliant_checks': []
            },
            'NIST_800_53': {
                'total_controls': 18,
                'applicable_checks': [],
                'compliant_checks': [],
                'non_compliant_checks': []
            },
            'PCI_DSS': {
                'total_controls': 12,
                'applicable_checks': [],
                'compliant_checks': [],
                'non_compliant_checks': []
            }
        }
        
        # Map checks to frameworks (simplified mapping)
        framework_check_mapping = {
            'cluster_encryption': ['CIS_EKS', 'NIST_800_53', 'PCI_DSS'],
            'cluster_logging': ['CIS_EKS', 'NIST_800_53'],
            'endpoint_access': ['CIS_EKS', 'NIST_800_53', 'PCI_DSS'],
            'network_security': ['CIS_EKS', 'NIST_800_53'],
            'rbac_config': ['CIS_EKS', 'NIST_800_53']
        }
        
        for check in checks:
            check_id = check.get('id', '')
            frameworks = framework_check_mapping.get(check_id, [])
            
            for framework in frameworks:
                if framework in compliance_mapping:
                    compliance_mapping[framework]['applicable_checks'].append(check_id)
                    if check['status'] == 'PASS':
                        compliance_mapping[framework]['compliant_checks'].append(check_id)
                    else:
                        compliance_mapping[framework]['non_compliant_checks'].append(check_id)
        
        # Calculate compliance scores
        for framework, data in compliance_mapping.items():
            applicable = len(data['applicable_checks'])
            compliant = len(data['compliant_checks'])
            data['compliance_score'] = (compliant / applicable * 100) if applicable > 0 else 0
            data['compliance_level'] = 'COMPLIANT' if data['compliance_score'] >= 80 else 'NON_COMPLIANT'
        
        return compliance_mapping
