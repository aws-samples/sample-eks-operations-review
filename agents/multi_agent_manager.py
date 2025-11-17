"""
Multi-Agent Manager - Orchestrates all agents for comprehensive analysis
"""
import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List
from .security_agent import SecurityIntelligenceAgent
from .performance_agent import PerformanceOptimizationAgent
from .compliance_agent import ComplianceOrchestrationAgent
from .base_agent import AgentTask

class MultiAgentManager:
    """Manages and orchestrates multiple agents for comprehensive EKS analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.agents = {}
        self._initialize_agents()
    
    def _initialize_agents(self):
        """Initialize all agents"""
        from .operational_agent import OperationalIntelligenceAgent
        from .workload_agent import WorkloadAnalysisAgent
        from .infrastructure_agent import InfrastructureAgent
        
        self.agents = {
            'security': SecurityIntelligenceAgent(self.config),
            'performance': PerformanceOptimizationAgent(self.config),
            'compliance': ComplianceOrchestrationAgent(self.config),
            'operational': OperationalIntelligenceAgent(self.config),
            'workload': WorkloadAnalysisAgent(self.config),
            'infrastructure': InfrastructureAgent(self.config)
        }
    
    async def run_comprehensive_analysis(self, cluster_name: str, region: str, role_arn: str = None) -> Dict[str, Any]:
        """Run comprehensive multi-agent analysis"""
        analysis_start = datetime.now()
        
        # Prepare analysis results container
        comprehensive_results = {
            'cluster_name': cluster_name,
            'analysis_timestamp': analysis_start.isoformat(),
            'agents_used': list(self.agents.keys()),
            'agent_results': {},
            'cross_agent_insights': {},
            'unified_recommendations': [],
            'executive_summary': {}
        }
        
        try:
            # Run security analysis first (other agents may need its results)
            security_results = await self.agents['security'].analyze_cluster(cluster_name, region, role_arn)
            comprehensive_results['agent_results']['security'] = security_results
            
            # Run all other agents in parallel
            performance_task = self.agents['performance'].analyze_cluster(cluster_name, region, role_arn)
            operational_task = self.agents['operational'].analyze_cluster(cluster_name, region, role_arn)
            workload_task = self.agents['workload'].analyze_cluster(cluster_name, region, role_arn)
            infrastructure_task = self.agents['infrastructure'].analyze_cluster(cluster_name, region, role_arn)
            
            # Pass security results to compliance agent for better mapping
            compliance_task = self._run_compliance_with_security_context(cluster_name, region, role_arn, security_results)
            
            # Wait for parallel tasks to complete
            performance_results, operational_results, workload_results, infrastructure_results, compliance_results = await asyncio.gather(
                performance_task, operational_task, workload_task, infrastructure_task, compliance_task
            )
            
            comprehensive_results['agent_results']['performance'] = performance_results
            comprehensive_results['agent_results']['operational'] = operational_results
            comprehensive_results['agent_results']['workload'] = workload_results
            comprehensive_results['agent_results']['infrastructure'] = infrastructure_results
            comprehensive_results['agent_results']['compliance'] = compliance_results
            
            # Generate cross-agent insights
            comprehensive_results['cross_agent_insights'] = self._generate_cross_agent_insights(comprehensive_results['agent_results'])
            
            # Generate unified recommendations
            comprehensive_results['unified_recommendations'] = self._generate_unified_recommendations(comprehensive_results['agent_results'])
            
            # Generate executive summary
            comprehensive_results['executive_summary'] = self._generate_executive_summary(comprehensive_results)
            
            # Calculate total analysis time
            analysis_end = datetime.now()
            comprehensive_results['analysis_duration_seconds'] = (analysis_end - analysis_start).total_seconds()
            
            return comprehensive_results
            
        except Exception as e:
            comprehensive_results['error'] = str(e)
            comprehensive_results['status'] = 'failed'
            return comprehensive_results
    
    async def _run_compliance_with_security_context(self, cluster_name: str, region: str, role_arn: str, security_results: Dict) -> Dict[str, Any]:
        """Run compliance analysis with security context"""
        # Create a task with security results as context
        task = AgentTask(
            task_id=f"compliance-{datetime.now().timestamp()}",
            agent_id="compliance-orchestration",
            task_type="compliance_validation",
            cluster_id=cluster_name,
            payload={
                "region": region,
                "role_arn": role_arn,
                "security_results": security_results,
                "frameworks": ["CIS_EKS", "NIST_800_53", "PCI_DSS", "SOC2"]
            }
        )
        
        result = await self.agents['compliance'].process_task(task)
        return result.data
    
    def _generate_cross_agent_insights(self, agent_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate insights by correlating data across agents"""
        insights = {
            'security_performance_correlation': {},
            'compliance_security_gaps': {},
            'cost_security_tradeoffs': {},
            'risk_assessment': {}
        }
        
        security_data = agent_results.get('security', {})
        performance_data = agent_results.get('performance', {})
        compliance_data = agent_results.get('compliance', {})
        
        # Security-Performance Correlation
        security_posture = security_data.get('security_posture', {})
        resource_efficiency = performance_data.get('resource_utilization', {}).get('resource_efficiency', {})
        
        insights['security_performance_correlation'] = {
            'security_score': security_posture.get('weighted_score', 0),
            'performance_efficiency': resource_efficiency.get('efficiency_score', 0),
            'correlation_analysis': self._analyze_security_performance_correlation(security_posture, resource_efficiency)
        }
        
        # Compliance-Security Gap Analysis
        compliance_summary = compliance_data.get('compliance_summary', {})
        security_checks = security_data.get('checks', [])
        
        insights['compliance_security_gaps'] = {
            'frameworks_analyzed': len(compliance_summary),
            'security_checks_mapped': len(security_checks),
            'gap_analysis': self._analyze_compliance_security_gaps(compliance_summary, security_checks)
        }
        
        # Cost-Security Tradeoffs
        cost_optimization = performance_data.get('cost_optimization', {})
        security_recommendations = security_data.get('recommendations', [])
        
        insights['cost_security_tradeoffs'] = self._analyze_cost_security_tradeoffs(cost_optimization, security_recommendations)
        
        # Overall Risk Assessment
        insights['risk_assessment'] = self._calculate_overall_risk(security_data, performance_data, compliance_data)
        
        return insights
    
    def _analyze_security_performance_correlation(self, security_posture: Dict, resource_efficiency: Dict) -> Dict[str, Any]:
        """Analyze correlation between security and performance"""
        security_score = security_posture.get('weighted_score', 0)
        efficiency_score = resource_efficiency.get('efficiency_score', 0)
        
        # Simple correlation analysis
        if security_score > 80 and efficiency_score > 80:
            correlation = 'OPTIMAL'
            insight = 'Cluster has both strong security posture and good performance efficiency'
        elif security_score > 80 and efficiency_score < 60:
            correlation = 'SECURITY_FOCUSED'
            insight = 'Strong security but performance optimization needed'
        elif security_score < 60 and efficiency_score > 80:
            correlation = 'PERFORMANCE_FOCUSED'
            insight = 'Good performance but security improvements required'
        else:
            correlation = 'NEEDS_IMPROVEMENT'
            insight = 'Both security and performance need attention'
        
        return {
            'correlation_type': correlation,
            'insight': insight,
            'security_score': security_score,
            'efficiency_score': efficiency_score
        }
    
    def _analyze_compliance_security_gaps(self, compliance_summary: Dict, security_checks: List) -> Dict[str, Any]:
        """Analyze gaps between compliance requirements and security implementation"""
        total_frameworks = len(compliance_summary)
        compliant_frameworks = len([f for f in compliance_summary.values() if f.get('status') == 'COMPLIANT'])
        
        failed_security_checks = [c for c in security_checks if c.get('status') == 'FAIL']
        critical_security_issues = [c for c in failed_security_checks if c.get('severity') == 'HIGH']
        
        gap_severity = 'CRITICAL' if len(critical_security_issues) > 3 else 'HIGH' if len(critical_security_issues) > 1 else 'MEDIUM'
        
        return {
            'compliance_rate': (compliant_frameworks / total_frameworks * 100) if total_frameworks > 0 else 0,
            'security_gaps': len(failed_security_checks),
            'critical_gaps': len(critical_security_issues),
            'gap_severity': gap_severity,
            'primary_gaps': [c.get('title', 'Unknown') for c in critical_security_issues[:3]]
        }
    
    def _analyze_cost_security_tradeoffs(self, cost_optimization: Dict, security_recommendations: List) -> Dict[str, Any]:
        """Analyze tradeoffs between cost optimization and security"""
        spot_opportunities = cost_optimization.get('spot_instance_opportunities', [])
        security_recs = len(security_recommendations)
        
        # Analyze potential conflicts
        conflicts = []
        if spot_opportunities and security_recs > 0:
            conflicts.append("Spot instances may impact security monitoring continuity")
        
        return {
            'cost_savings_opportunities': len(spot_opportunities),
            'security_improvements_needed': security_recs,
            'potential_conflicts': conflicts,
            'recommendation': 'Balance cost optimization with security requirements'
        }
    
    def _calculate_overall_risk(self, security_data: Dict, performance_data: Dict, compliance_data: Dict) -> Dict[str, Any]:
        """Calculate overall cluster risk assessment"""
        # Security risk factors
        security_posture = security_data.get('security_posture', {})
        critical_security_issues = security_posture.get('critical_issues', 0)
        
        # Performance risk factors
        resource_efficiency = performance_data.get('resource_utilization', {}).get('resource_efficiency', {})
        efficiency_level = resource_efficiency.get('efficiency_level', 'UNKNOWN')
        
        # Compliance risk factors
        compliance_summary = compliance_data.get('overall_assessment', {})
        compliance_status = compliance_summary.get('status', 'UNKNOWN')
        
        # Calculate risk score (0-100, higher is more risky)
        risk_score = 0
        
        # Security risk (40% weight)
        if critical_security_issues >= 3:
            risk_score += 40
        elif critical_security_issues >= 1:
            risk_score += 25
        else:
            risk_score += 10
        
        # Performance risk (30% weight)
        if efficiency_level == 'POOR':
            risk_score += 30
        elif efficiency_level == 'FAIR':
            risk_score += 20
        else:
            risk_score += 5
        
        # Compliance risk (30% weight)
        if compliance_status == 'NON_COMPLIANT':
            risk_score += 30
        elif compliance_status == 'PARTIALLY_COMPLIANT':
            risk_score += 15
        else:
            risk_score += 5
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 30:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'overall_risk_score': risk_score,
            'risk_level': risk_level,
            'primary_risk_factors': self._identify_primary_risk_factors(critical_security_issues, efficiency_level, compliance_status),
            'risk_mitigation_priority': 'IMMEDIATE' if risk_level == 'CRITICAL' else 'HIGH' if risk_level == 'HIGH' else 'MEDIUM'
        }
    
    def _identify_primary_risk_factors(self, security_issues: int, efficiency_level: str, compliance_status: str) -> List[str]:
        """Identify primary risk factors"""
        factors = []
        
        if security_issues >= 3:
            factors.append("Multiple critical security vulnerabilities")
        elif security_issues >= 1:
            factors.append("Critical security issues present")
        
        if efficiency_level == 'POOR':
            factors.append("Poor resource utilization efficiency")
        
        if compliance_status == 'NON_COMPLIANT':
            factors.append("Non-compliant with regulatory frameworks")
        elif compliance_status == 'PARTIALLY_COMPLIANT':
            factors.append("Partial compliance with regulatory frameworks")
        
        return factors
    
    def _generate_unified_recommendations(self, agent_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate unified recommendations across all agents"""
        unified_recommendations = []
        
        # Collect recommendations from all agents
        security_recs = agent_results.get('security', {}).get('recommendations', [])
        performance_recs = agent_results.get('performance', {}).get('performance_recommendations', [])
        compliance_recs = agent_results.get('compliance', {}).get('remediation_priorities', [])
        
        # Prioritize and merge recommendations
        all_recommendations = []
        
        # Add security recommendations with high priority
        for rec in security_recs:
            all_recommendations.append({
                'source': 'Security Agent',
                'category': 'Security',
                'title': rec.get('title', 'Security Recommendation'),
                'priority': rec.get('priority', 'HIGH'),
                'description': rec.get('description', ''),
                'implementation_time': rec.get('implementation_time', 'Unknown'),
                'business_impact': rec.get('business_impact', 'Security improvement')
            })
        
        # Add performance recommendations
        for rec in performance_recs:
            all_recommendations.append({
                'source': 'Performance Agent',
                'category': rec.get('category', 'Performance'),
                'title': rec.get('title', 'Performance Recommendation'),
                'priority': rec.get('priority', 'MEDIUM'),
                'description': rec.get('description', ''),
                'expected_benefit': rec.get('expected_benefit', 'Performance improvement')
            })
        
        # Add compliance recommendations
        for rec in compliance_recs[:5]:  # Top 5 compliance priorities
            all_recommendations.append({
                'source': 'Compliance Agent',
                'category': 'Compliance',
                'title': rec.get('control_name', 'Compliance Recommendation'),
                'priority': rec.get('priority', 'MEDIUM'),
                'description': rec.get('recommendation', ''),
                'affected_frameworks': rec.get('affected_frameworks', [])
            })
        
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_recommendations = sorted(all_recommendations, key=lambda x: priority_order.get(x['priority'], 3))
        
        return sorted_recommendations[:15]  # Top 15 recommendations
    
    def _generate_executive_summary(self, comprehensive_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of the comprehensive analysis"""
        agent_results = comprehensive_results.get('agent_results', {})
        cross_agent_insights = comprehensive_results.get('cross_agent_insights', {})
        
        # Security summary
        security_data = agent_results.get('security', {})
        security_posture = security_data.get('security_posture', {})
        
        # Performance summary
        performance_data = agent_results.get('performance', {})
        resource_efficiency = performance_data.get('resource_utilization', {}).get('resource_efficiency', {})
        
        # Compliance summary
        compliance_data = agent_results.get('compliance', {})
        overall_compliance = compliance_data.get('overall_assessment', {})
        
        # Risk assessment
        risk_assessment = cross_agent_insights.get('risk_assessment', {})
        
        return {
            'cluster_name': comprehensive_results.get('cluster_name'),
            'analysis_date': comprehensive_results.get('analysis_timestamp'),
            'overall_health': self._determine_overall_health(security_posture, resource_efficiency, overall_compliance),
            'key_metrics': {
                'security_posture': security_posture.get('posture_level', 'UNKNOWN'),
                'performance_efficiency': resource_efficiency.get('efficiency_level', 'UNKNOWN'),
                'compliance_status': overall_compliance.get('status', 'UNKNOWN'),
                'overall_risk': risk_assessment.get('risk_level', 'UNKNOWN')
            },
            'critical_issues': self._extract_critical_issues(agent_results),
            'top_recommendations': comprehensive_results.get('unified_recommendations', [])[:5],
            'analysis_coverage': {
                'agents_executed': len(agent_results),
                'security_checks': len(security_data.get('checks', [])),
                'performance_metrics': len(performance_data.get('resource_utilization', {}).get('node_group_utilization', [])),
                'compliance_frameworks': len(compliance_data.get('frameworks_validated', []))
            }
        }
    
    def _determine_overall_health(self, security_posture: Dict, resource_efficiency: Dict, compliance: Dict) -> str:
        """Determine overall cluster health"""
        security_level = security_posture.get('posture_level', 'UNKNOWN')
        efficiency_level = resource_efficiency.get('efficiency_level', 'UNKNOWN')
        compliance_status = compliance.get('status', 'UNKNOWN')
        
        # Simple health determination logic
        if security_level == 'EXCELLENT' and efficiency_level in ['EXCELLENT', 'GOOD'] and compliance_status == 'COMPLIANT':
            return 'EXCELLENT'
        elif security_level in ['EXCELLENT', 'GOOD'] and efficiency_level != 'POOR' and compliance_status != 'NON_COMPLIANT':
            return 'GOOD'
        elif security_level == 'CRITICAL' or compliance_status == 'NON_COMPLIANT':
            return 'POOR'
        else:
            return 'FAIR'
    
    def _extract_critical_issues(self, agent_results: Dict) -> List[str]:
        """Extract critical issues from all agents"""
        critical_issues = []
        
        # Security critical issues
        security_data = agent_results.get('security', {})
        security_checks = security_data.get('checks', [])
        for check in security_checks:
            if check.get('severity') == 'HIGH' and check.get('status') == 'FAIL':
                critical_issues.append(f"Security: {check.get('title', 'Unknown issue')}")
        
        # Performance critical issues
        performance_data = agent_results.get('performance', {})
        performance_recs = performance_data.get('performance_recommendations', [])
        for rec in performance_recs:
            if rec.get('priority') == 'HIGH':
                critical_issues.append(f"Performance: {rec.get('title', 'Unknown issue')}")
        
        # Compliance critical issues
        compliance_data = agent_results.get('compliance', {})
        remediation_priorities = compliance_data.get('remediation_priorities', [])
        for priority in remediation_priorities:
            if priority.get('priority') == 'CRITICAL':
                critical_issues.append(f"Compliance: {priority.get('control_name', 'Unknown issue')}")
        
        return critical_issues[:10]  # Top 10 critical issues
