"""
Enhanced Observation Agent - Provides detailed recommendations for all findings
Analyzes check results and generates comprehensive, actionable recommendations
"""
from typing import Dict, Any, List
from datetime import datetime

class EnhancedObservationAgent:
    """
    Analyzes all check results and provides:
    - Detailed reasoning for each observation
    - Specific commands that were run
    - Comprehensive recommendations
    - Business impact analysis
    - Step-by-step remediation
    """
    
    def __init__(self):
        self.observations = []
        self.recommendations = []
    
    def analyze_check_results(self, all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze all check results and generate detailed recommendations"""
        
        critical_findings = []
        high_findings = []
        medium_findings = []
        low_findings = []
        
        for result in all_results:
            if result['status'] == 'FAILED':
                finding = self._create_detailed_finding(result)
                
                if result['severity'] in ['P0', 'CRITICAL']:
                    critical_findings.append(finding)
                elif result['severity'] in ['P1', 'HIGH']:
                    high_findings.append(finding)
                elif result['severity'] in ['P2', 'MEDIUM']:
                    medium_findings.append(finding)
                else:
                    low_findings.append(finding)
        
        return {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_findings': len(critical_findings) + len(high_findings) + len(medium_findings) + len(low_findings),
            'critical_findings': critical_findings,
            'high_findings': high_findings,
            'medium_findings': medium_findings,
            'low_findings': low_findings,
            'executive_summary': self._generate_executive_summary(
                critical_findings, high_findings, medium_findings, low_findings
            ),
            'prioritized_recommendations': self._prioritize_recommendations(
                critical_findings, high_findings, medium_findings, low_findings
            )
        }
    
    def _create_detailed_finding(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Create detailed finding with full context"""
        return {
            'check_id': result['check_id'],
            'title': result['title'],
            'category': result['category'],
            'severity': result['severity'],
            'status': result['status'],
            
            # What was checked
            'commands_executed': result.get('commands_executed', []),
            
            # What was found
            'observations': result.get('observations', []),
            
            # Why it matters
            'reasoning': result.get('reasoning', ''),
            'business_impact': result.get('recommendation', {}).get('business_impact', ''),
            
            # How to fix it
            'recommendation': {
                'description': result.get('recommendation', {}).get('description', ''),
                'steps': result.get('recommendation', {}).get('steps', []),
                'commands': result.get('recommendation', {}).get('commands', []),
                'verification': result.get('recommendation', {}).get('verification', []),
                'effort': result.get('recommendation', {}).get('effort', 'Unknown'),
                'risk': result.get('recommendation', {}).get('risk', ''),
                'documentation_links': result.get('recommendation', {}).get('documentation_links', [])
            },
            
            # Compliance context
            'compliance_frameworks': result.get('compliance_frameworks', []),
            'dora_article': result.get('dora_article', ''),
            
            # Audit trail
            'timestamp': result.get('timestamp', ''),
            'raw_data': result.get('raw_data', {})
        }
    
    def _generate_executive_summary(self, critical, high, medium, low) -> Dict[str, Any]:
        """Generate executive summary of findings"""
        total = len(critical) + len(high) + len(medium) + len(low)
        
        summary = {
            'total_issues': total,
            'critical_count': len(critical),
            'high_count': len(high),
            'medium_count': len(medium),
            'low_count': len(low),
            'risk_assessment': self._assess_overall_risk(critical, high, medium, low),
            'top_priorities': []
        }
        
        # Identify top 5 priorities
        all_findings = critical + high + medium + low
        summary['top_priorities'] = [
            {
                'check_id': f['check_id'],
                'title': f['title'],
                'severity': f['severity'],
                'business_impact': f['business_impact']
            }
            for f in all_findings[:5]
        ]
        
        return summary
    
    def _assess_overall_risk(self, critical, high, medium, low) -> str:
        """Assess overall risk level"""
        if len(critical) > 10:
            return 'CRITICAL - Immediate action required'
        elif len(critical) > 0 or len(high) > 20:
            return 'HIGH - Action required within 30 days'
        elif len(high) > 0 or len(medium) > 30:
            return 'MEDIUM - Action required within 90 days'
        else:
            return 'LOW - Monitor and plan remediation'
    
    def _prioritize_recommendations(self, critical, high, medium, low) -> List[Dict[str, Any]]:
        """Create prioritized list of recommendations"""
        all_findings = critical + high + medium + low
        
        prioritized = []
        for idx, finding in enumerate(all_findings, 1):
            prioritized.append({
                'priority': idx,
                'check_id': finding['check_id'],
                'title': finding['title'],
                'severity': finding['severity'],
                'effort': finding['recommendation']['effort'],
                'business_impact': finding['business_impact'],
                'quick_fix': finding['recommendation']['commands'][:2] if finding['recommendation']['commands'] else [],
                'estimated_time': self._estimate_remediation_time(finding['recommendation']['effort'])
            })
        
        return prioritized
    
    def _estimate_remediation_time(self, effort: str) -> str:
        """Estimate time to remediate"""
        effort_map = {
            'Low': '1-2 hours',
            'Medium': '4-8 hours',
            'High': '1-3 days',
            'Very High': '1-2 weeks'
        }
        return effort_map.get(effort, 'Unknown')
    
    def generate_remediation_plan(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive remediation plan"""
        return {
            'plan_created': datetime.now().isoformat(),
            'total_items': findings['total_findings'],
            
            'phase_1_immediate': {
                'description': 'Critical issues requiring immediate attention',
                'items': findings['critical_findings'],
                'estimated_duration': f"{len(findings['critical_findings']) * 2} hours"
            },
            
            'phase_2_short_term': {
                'description': 'High priority issues to address within 30 days',
                'items': findings['high_findings'],
                'estimated_duration': f"{len(findings['high_findings'])} days"
            },
            
            'phase_3_medium_term': {
                'description': 'Medium priority issues to address within 90 days',
                'items': findings['medium_findings'],
                'estimated_duration': f"{len(findings['medium_findings']) // 2} weeks"
            },
            
            'phase_4_long_term': {
                'description': 'Low priority issues for continuous improvement',
                'items': findings['low_findings'],
                'estimated_duration': 'Ongoing'
            }
        }
