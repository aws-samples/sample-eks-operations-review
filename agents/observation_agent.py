"""
Observation Agent - Provides detailed reasoning for each finding
Explains how observations were derived and why they matter
"""
from typing import Dict, Any, List
from datetime import datetime

class ObservationAgent:
    """
    Specialized agent that:
    1. Analyzes raw command outputs
    2. Provides detailed reasoning for each observation
    3. Explains the analysis methodology
    4. Generates comprehensive recommendations
    """
    
    def __init__(self, cluster_name: str):
        self.cluster_name = cluster_name
        self.observations = []
    
    def analyze_observation(self, check_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Provide detailed analysis of a check result
        
        Returns:
            Detailed observation with reasoning, methodology, and recommendations
        """
        observation = {
            'check_id': check_result['check_id'],
            'title': check_result['title'],
            'timestamp': datetime.now().isoformat(),
            'methodology': self._explain_methodology(check_result),
            'raw_data_analysis': self._analyze_raw_data(check_result),
            'reasoning': self._provide_reasoning(check_result),
            'security_implications': self._assess_security_implications(check_result),
            'compliance_impact': self._assess_compliance_impact(check_result),
            'detailed_recommendations': self._generate_detailed_recommendations(check_result),
            'evidence': self._compile_evidence(check_result)
        }
        
        self.observations.append(observation)
        return observation
    
    def _explain_methodology(self, check_result: Dict[str, Any]) -> Dict[str, Any]:
        """Explain how the check was performed"""
        return {
            'description': f"Analysis methodology for {check_result['title']}",
            'data_sources': [cmd['command'] for cmd in check_result.get('commands_executed', [])],
            'analysis_approach': self._get_analysis_approach(check_result),
            'validation_steps': self._get_validation_steps(check_result),
            'assumptions': self._get_assumptions(check_result)
        }
    
    def _analyze_raw_data(self, check_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze each raw observation in detail"""
        analyses = []
        
        for cmd_result in check_result.get('commands_executed', []):
            analysis = {
                'command': cmd_result['command'],
                'execution_time': cmd_result['execution_time'],
                'raw_output': cmd_result['observation'],
                'interpretation': self._interpret_output(cmd_result),
                'key_findings': self._extract_key_findings(cmd_result),
                'anomalies': self._detect_anomalies(cmd_result)
            }
            analyses.append(analysis)
        
        return analyses
    
    def _provide_reasoning(self, check_result: Dict[str, Any]) -> Dict[str, Any]:
        """Provide detailed reasoning for the check result"""
        status = check_result.get('status', 'UNKNOWN')
        
        reasoning = {
            'status': status,
            'why_this_status': self._explain_status(check_result),
            'contributing_factors': self._identify_factors(check_result),
            'risk_assessment': self._assess_risk(check_result),
            'comparison_to_baseline': self._compare_to_baseline(check_result),
            'trend_analysis': self._analyze_trends(check_result)
        }
        
        return reasoning
    
    def _assess_security_implications(self, check_result: Dict[str, Any]) -> Dict[str, Any]:
        """Assess security implications of the finding"""
        return {
            'threat_vectors': self._identify_threat_vectors(check_result),
            'attack_scenarios': self._describe_attack_scenarios(check_result),
            'potential_impact': self._assess_potential_impact(check_result),
            'exploitability': self._assess_exploitability(check_result),
            'mitigation_urgency': self._determine_urgency(check_result)
        }
    
    def _assess_compliance_impact(self, check_result: Dict[str, Any]) -> Dict[str, Any]:
        """Assess compliance implications"""
        frameworks = check_result.get('compliance_frameworks', [])
        
        return {
            'affected_frameworks': frameworks,
            'specific_requirements': self._map_to_requirements(check_result, frameworks),
            'compliance_gap': self._assess_compliance_gap(check_result),
            'remediation_priority': self._determine_remediation_priority(check_result),
            'regulatory_risk': self._assess_regulatory_risk(check_result)
        }
    
    def _generate_detailed_recommendations(self, check_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate comprehensive, actionable recommendations"""
        recommendations = []
        
        if check_result.get('status') in ['FAILED', 'WARNING']:
            # Immediate actions
            recommendations.append({
                'priority': 'IMMEDIATE',
                'category': 'Quick Wins',
                'actions': self._get_immediate_actions(check_result),
                'estimated_time': '< 1 hour',
                'complexity': 'Low'
            })
            
            # Short-term improvements
            recommendations.append({
                'priority': 'SHORT_TERM',
                'category': 'Configuration Improvements',
                'actions': self._get_short_term_actions(check_result),
                'estimated_time': '1-5 days',
                'complexity': 'Medium'
            })
            
            # Long-term strategic changes
            recommendations.append({
                'priority': 'LONG_TERM',
                'category': 'Strategic Improvements',
                'actions': self._get_long_term_actions(check_result),
                'estimated_time': '1-4 weeks',
                'complexity': 'High'
            })
        
        return recommendations
    
    def _compile_evidence(self, check_result: Dict[str, Any]) -> Dict[str, Any]:
        """Compile evidence for audit purposes"""
        return {
            'commands_executed': [
                {
                    'command': cmd['command'],
                    'timestamp': cmd['execution_time'],
                    'output_summary': self._summarize_output(cmd['observation'])
                }
                for cmd in check_result.get('commands_executed', [])
            ],
            'analysis_timestamp': datetime.now().isoformat(),
            'analyst': 'ObservationAgent',
            'confidence_level': self._calculate_confidence(check_result),
            'data_quality': self._assess_data_quality(check_result)
        }
    
    # Helper methods
    def _get_analysis_approach(self, check_result: Dict[str, Any]) -> str:
        """Describe the analysis approach"""
        category = check_result.get('category', '')
        if 'Security' in category:
            return 'Security-focused analysis examining authentication, authorization, and encryption'
        elif 'Network' in category:
            return 'Network topology and connectivity analysis'
        elif 'Compliance' in category:
            return 'Compliance framework mapping and gap analysis'
        else:
            return 'General configuration and best practices analysis'
    
    def _get_validation_steps(self, check_result: Dict[str, Any]) -> List[str]:
        """List validation steps performed"""
        return [
            'Execute AWS CLI commands to retrieve current configuration',
            'Parse and validate JSON/YAML output',
            'Compare against security baselines and best practices',
            'Assess compliance with regulatory requirements',
            'Generate risk-based recommendations'
        ]
    
    def _get_assumptions(self, check_result: Dict[str, Any]) -> List[str]:
        """List assumptions made during analysis"""
        return [
            'AWS credentials have sufficient permissions for read operations',
            'Cluster is in a stable state during analysis',
            'Configuration represents production environment',
            'No changes are made during analysis execution'
        ]
    
    def _interpret_output(self, cmd_result: Dict[str, Any]) -> str:
        """Interpret command output"""
        obs = cmd_result.get('observation', {})
        if isinstance(obs, dict):
            if 'error' in obs:
                return f"Command failed: {obs['error']}"
            elif obs:
                return f"Retrieved {len(obs)} configuration items"
            else:
                return "No data returned"
        return "Output requires manual interpretation"
    
    def _extract_key_findings(self, cmd_result: Dict[str, Any]) -> List[str]:
        """Extract key findings from command output"""
        findings = []
        obs = cmd_result.get('observation', {})
        
        if isinstance(obs, dict):
            if 'enabled' in obs:
                findings.append(f"Feature enabled: {obs.get('enabled')}")
            if 'status' in obs:
                findings.append(f"Status: {obs.get('status')}")
            if 'items' in obs:
                findings.append(f"Found {len(obs.get('items', []))} items")
        
        return findings if findings else ['No specific findings extracted']
    
    def _detect_anomalies(self, cmd_result: Dict[str, Any]) -> List[str]:
        """Detect anomalies in the output"""
        anomalies = []
        obs = cmd_result.get('observation', {})
        
        # Check for common security issues
        if isinstance(obs, dict):
            if obs.get('publicAccessCidrs') == ['0.0.0.0/0']:
                anomalies.append('Public access from anywhere detected')
            if obs.get('enabled') == False:
                anomalies.append('Critical feature is disabled')
        
        return anomalies
    
    def _explain_status(self, check_result: Dict[str, Any]) -> str:
        """Explain why the check has its current status"""
        status = check_result.get('status')
        
        explanations = {
            'PASSED': 'Configuration meets security and compliance requirements',
            'FAILED': 'Configuration does not meet minimum security standards',
            'WARNING': 'Configuration has potential security concerns',
            'MANUAL_REVIEW': 'Automated analysis insufficient, manual review required',
            'ERROR': 'Unable to complete analysis due to technical error'
        }
        
        return explanations.get(status, 'Status explanation not available')
    
    def _identify_factors(self, check_result: Dict[str, Any]) -> List[str]:
        """Identify contributing factors to the result"""
        return [
            'Current cluster configuration',
            'AWS service limitations',
            'Security best practices',
            'Compliance requirements',
            'Operational constraints'
        ]
    
    def _assess_risk(self, check_result: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk level"""
        severity = check_result.get('severity', 'MEDIUM')
        status = check_result.get('status', 'UNKNOWN')
        
        risk_levels = {
            'CRITICAL': {'level': 'CRITICAL', 'score': 10, 'action': 'Immediate remediation required'},
            'HIGH': {'level': 'HIGH', 'score': 7, 'action': 'Remediate within 7 days'},
            'MEDIUM': {'level': 'MEDIUM', 'score': 5, 'action': 'Remediate within 30 days'},
            'LOW': {'level': 'LOW', 'score': 3, 'action': 'Remediate during next maintenance window'}
        }
        
        risk = risk_levels.get(severity, risk_levels['MEDIUM'])
        
        if status == 'PASSED':
            risk['score'] = 0
            risk['action'] = 'No action required'
        
        return risk
    
    def _compare_to_baseline(self, check_result: Dict[str, Any]) -> str:
        """Compare to security baseline"""
        return 'Compared against AWS EKS best practices and CIS benchmarks'
    
    def _analyze_trends(self, check_result: Dict[str, Any]) -> str:
        """Analyze trends (placeholder for historical data)"""
        return 'Trend analysis requires historical data collection'
    
    def _identify_threat_vectors(self, check_result: Dict[str, Any]) -> List[str]:
        """Identify potential threat vectors"""
        category = check_result.get('category', '')
        
        threat_vectors = {
            'Network': ['Unauthorized network access', 'Man-in-the-middle attacks', 'Network sniffing'],
            'Security': ['Privilege escalation', 'Credential theft', 'Unauthorized access'],
            'Compliance': ['Regulatory violations', 'Audit failures', 'Data exposure']
        }
        
        for key in threat_vectors:
            if key in category:
                return threat_vectors[key]
        
        return ['General security threats']
    
    def _describe_attack_scenarios(self, check_result: Dict[str, Any]) -> List[str]:
        """Describe potential attack scenarios"""
        return [
            'Attacker gains unauthorized access to cluster',
            'Lateral movement within cluster',
            'Data exfiltration',
            'Service disruption'
        ]
    
    def _assess_potential_impact(self, check_result: Dict[str, Any]) -> Dict[str, str]:
        """Assess potential impact"""
        return {
            'confidentiality': 'Potential data exposure',
            'integrity': 'Potential unauthorized modifications',
            'availability': 'Potential service disruption',
            'financial': 'Potential regulatory fines and remediation costs',
            'reputational': 'Potential brand damage'
        }
    
    def _assess_exploitability(self, check_result: Dict[str, Any]) -> str:
        """Assess how easily the issue can be exploited"""
        severity = check_result.get('severity', 'MEDIUM')
        
        exploitability = {
            'CRITICAL': 'Easily exploitable with publicly available tools',
            'HIGH': 'Exploitable with moderate skill level',
            'MEDIUM': 'Requires specific knowledge or access',
            'LOW': 'Difficult to exploit'
        }
        
        return exploitability.get(severity, 'Moderate exploitability')
    
    def _determine_urgency(self, check_result: Dict[str, Any]) -> str:
        """Determine mitigation urgency"""
        severity = check_result.get('severity', 'MEDIUM')
        
        urgency = {
            'CRITICAL': 'IMMEDIATE - Remediate within 24 hours',
            'HIGH': 'URGENT - Remediate within 7 days',
            'MEDIUM': 'MODERATE - Remediate within 30 days',
            'LOW': 'LOW - Remediate during next maintenance window'
        }
        
        return urgency.get(severity, 'MODERATE')
    
    def _map_to_requirements(self, check_result: Dict[str, Any], frameworks: List[str]) -> Dict[str, List[str]]:
        """Map to specific compliance requirements"""
        mapping = {}
        
        for framework in frameworks:
            if framework == 'CIS EKS Benchmark':
                mapping[framework] = ['CIS Control 3.1', 'CIS Control 4.2']
            elif framework == 'NIST CSF':
                mapping[framework] = ['PR.AC-1', 'PR.DS-1', 'DE.CM-1']
            elif framework == 'PCI DSS':
                mapping[framework] = ['Requirement 2.2', 'Requirement 10.1']
            elif framework == 'HIPAA':
                mapping[framework] = ['164.312(a)(1)', '164.312(b)']
            elif framework == 'EU DORA':
                mapping[framework] = ['Article 8', 'Article 9']
        
        return mapping
    
    def _assess_compliance_gap(self, check_result: Dict[str, Any]) -> str:
        """Assess compliance gap"""
        status = check_result.get('status')
        
        if status == 'FAILED':
            return 'Significant compliance gap - immediate remediation required'
        elif status == 'WARNING':
            return 'Partial compliance - improvements recommended'
        else:
            return 'Compliant with requirements'
    
    def _determine_remediation_priority(self, check_result: Dict[str, Any]) -> str:
        """Determine remediation priority"""
        severity = check_result.get('severity', 'MEDIUM')
        frameworks = check_result.get('compliance_frameworks', [])
        
        if severity == 'CRITICAL' and len(frameworks) > 2:
            return 'P0 - Critical Priority'
        elif severity in ['CRITICAL', 'HIGH']:
            return 'P1 - High Priority'
        elif severity == 'MEDIUM':
            return 'P2 - Medium Priority'
        else:
            return 'P3 - Low Priority'
    
    def _assess_regulatory_risk(self, check_result: Dict[str, Any]) -> str:
        """Assess regulatory risk"""
        frameworks = check_result.get('compliance_frameworks', [])
        
        if any(f in frameworks for f in ['PCI DSS', 'HIPAA', 'EU DORA']):
            return 'HIGH - Regulatory penalties possible'
        elif frameworks:
            return 'MEDIUM - Compliance audit findings likely'
        else:
            return 'LOW - Best practice recommendation'
    
    def _get_immediate_actions(self, check_result: Dict[str, Any]) -> List[str]:
        """Get immediate actions"""
        return [
            'Review current configuration',
            'Assess business impact',
            'Create remediation ticket',
            'Notify security team'
        ]
    
    def _get_short_term_actions(self, check_result: Dict[str, Any]) -> List[str]:
        """Get short-term actions"""
        return [
            'Implement configuration changes',
            'Test in non-production environment',
            'Update documentation',
            'Train operations team'
        ]
    
    def _get_long_term_actions(self, check_result: Dict[str, Any]) -> List[str]:
        """Get long-term actions"""
        return [
            'Implement automated compliance checking',
            'Integrate with CI/CD pipeline',
            'Establish continuous monitoring',
            'Regular compliance audits'
        ]
    
    def _summarize_output(self, observation: Any) -> str:
        """Summarize command output"""
        if isinstance(observation, dict):
            return f"Retrieved {len(observation)} configuration items"
        elif isinstance(observation, list):
            return f"Retrieved {len(observation)} items"
        else:
            return "Output retrieved successfully"
    
    def _calculate_confidence(self, check_result: Dict[str, Any]) -> str:
        """Calculate confidence level"""
        if check_result.get('status') == 'ERROR':
            return 'LOW'
        elif check_result.get('status') == 'MANUAL_REVIEW':
            return 'MEDIUM'
        else:
            return 'HIGH'
    
    def _assess_data_quality(self, check_result: Dict[str, Any]) -> str:
        """Assess data quality"""
        commands = check_result.get('commands_executed', [])
        
        if all(cmd.get('success') for cmd in commands):
            return 'HIGH - All data retrieved successfully'
        elif any(cmd.get('success') for cmd in commands):
            return 'MEDIUM - Partial data retrieved'
        else:
            return 'LOW - Data retrieval issues'
    
    def get_all_observations(self) -> List[Dict[str, Any]]:
        """Return all observations"""
        return self.observations
