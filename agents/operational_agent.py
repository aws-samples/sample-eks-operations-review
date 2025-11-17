"""
Operational Intelligence Agent - Predictive failure analysis and incident response
"""
import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List
from .base_agent import BaseAgent, AgentTask, AgentResult

class OperationalIntelligenceAgent(BaseAgent):
    """Operational intelligence and predictive analysis agent"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("operational-intelligence", config)
        self.region = config.get('region', 'us-west-2')
    
    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process operational intelligence task"""
        try:
            cluster_name = task.cluster_id
            region = task.payload.get('region', self.region)
            role_arn = task.payload.get('role_arn')
            
            # Initialize AWS clients
            if role_arn:
                from core.aws_client import AWSClientManager
                aws_client = AWSClientManager(region, role_arn)
                clients = aws_client.get_clients()
            else:
                clients = {
                    'eks': boto3.client('eks', region_name=region),
                    'cloudwatch': boto3.client('cloudwatch', region_name=region),
                    'logs': boto3.client('logs', region_name=region),
                    'ssm': boto3.client('ssm', region_name=region)
                }
            
            # Perform operational intelligence analysis
            operational_results = await self._analyze_operational_intelligence(cluster_name, clients)
            
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="completed",
                data=operational_results,
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
    
    async def _analyze_operational_intelligence(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Comprehensive operational intelligence analysis"""
        analysis = {
            'cluster_name': cluster_name,
            'analysis_timestamp': datetime.now().isoformat(),
            'failure_prediction': await self._predict_failures(cluster_name, clients),
            'sla_slo_monitoring': await self._monitor_sla_slo(cluster_name, clients),
            'incident_response': await self._analyze_incident_response(cluster_name, clients),
            'operational_health': await self._assess_operational_health(cluster_name, clients),
            'recommendations': []
        }
        
        # Generate operational recommendations
        analysis['recommendations'] = self._generate_operational_recommendations(analysis)
        
        return analysis
    
    async def _predict_failures(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Predict potential failures using historical data and patterns"""
        try:
            # Get historical metrics for the past 7 days
            end_time = datetime.now()
            start_time = end_time - timedelta(days=7)
            
            failure_prediction = {
                'risk_score': 0.0,
                'risk_level': 'LOW',
                'predicted_failures': [],
                'risk_factors': [],
                'confidence': 0.0
            }
            
            # Analyze cluster health trends
            cluster_health = await self._analyze_cluster_health_trends(cluster_name, clients, start_time, end_time)
            
            # Analyze node health patterns
            node_health = await self._analyze_node_health_patterns(cluster_name, clients, start_time, end_time)
            
            # Calculate risk score based on multiple factors
            risk_factors = []
            risk_score = 0.0
            
            # Factor 1: Cluster stability
            if cluster_health.get('stability_score', 100) < 80:
                risk_score += 0.3
                risk_factors.append("Cluster stability issues detected")
            
            # Factor 2: Node health
            if node_health.get('unhealthy_nodes', 0) > 0:
                risk_score += 0.2
                risk_factors.append(f"{node_health['unhealthy_nodes']} unhealthy nodes detected")
            
            # Factor 3: Resource exhaustion
            if cluster_health.get('resource_exhaustion_risk', False):
                risk_score += 0.4
                risk_factors.append("Resource exhaustion risk identified")
            
            # Factor 4: Error rate trends
            if cluster_health.get('error_rate_increasing', False):
                risk_score += 0.1
                risk_factors.append("Increasing error rates detected")
            
            # Determine risk level
            if risk_score >= 0.7:
                risk_level = 'CRITICAL'
                predicted_failures = ['Cluster instability', 'Service degradation']
            elif risk_score >= 0.4:
                risk_level = 'HIGH'
                predicted_failures = ['Performance degradation', 'Resource exhaustion']
            elif risk_score >= 0.2:
                risk_level = 'MEDIUM'
                predicted_failures = ['Minor service disruptions']
            else:
                risk_level = 'LOW'
                predicted_failures = []
            
            failure_prediction.update({
                'risk_score': round(risk_score, 2),
                'risk_level': risk_level,
                'predicted_failures': predicted_failures,
                'risk_factors': risk_factors,
                'confidence': min(0.8, risk_score + 0.2)  # Confidence based on risk score
            })
            
            return failure_prediction
            
        except Exception as e:
            return {'error': str(e), 'risk_level': 'UNKNOWN'}
    
    async def _analyze_cluster_health_trends(self, cluster_name: str, clients: Dict, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Analyze cluster health trends over time"""
        try:
            # Get cluster status history (simplified)
            cluster_info = clients['eks'].describe_cluster(name=cluster_name)['cluster']
            
            health_trends = {
                'current_status': cluster_info['status'],
                'stability_score': 100,  # Default to stable
                'resource_exhaustion_risk': False,
                'error_rate_increasing': False
            }
            
            # Check for recent issues in CloudWatch logs
            try:
                log_groups = clients['logs'].describe_log_groups(
                    logGroupNamePrefix=f'/aws/eks/{cluster_name}'
                )
                
                if log_groups.get('logGroups'):
                    # Check for error patterns in recent logs
                    for log_group in log_groups['logGroups'][:3]:  # Check first 3 log groups
                        try:
                            events = clients['logs'].filter_log_events(
                                logGroupName=log_group['logGroupName'],
                                startTime=int((end_time - timedelta(hours=24)).timestamp() * 1000),
                                endTime=int(end_time.timestamp() * 1000),
                                filterPattern='ERROR'
                            )
                            
                            if len(events.get('events', [])) > 100:  # High error count
                                health_trends['error_rate_increasing'] = True
                                health_trends['stability_score'] -= 20
                                
                        except Exception:
                            continue  # Skip if log group access fails
                            
            except Exception:
                pass  # Skip if CloudWatch Logs access fails
            
            return health_trends
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_node_health_patterns(self, cluster_name: str, clients: Dict, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Analyze node health patterns"""
        try:
            node_groups = clients['eks'].list_nodegroups(clusterName=cluster_name)['nodegroups']
            
            node_health = {
                'total_node_groups': len(node_groups),
                'healthy_node_groups': 0,
                'unhealthy_nodes': 0,
                'scaling_issues': []
            }
            
            for ng_name in node_groups:
                try:
                    ng_info = clients['eks'].describe_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=ng_name
                    )['nodegroup']
                    
                    if ng_info['status'] == 'ACTIVE':
                        node_health['healthy_node_groups'] += 1
                    else:
                        node_health['unhealthy_nodes'] += 1
                        node_health['scaling_issues'].append(f"Node group {ng_name} is {ng_info['status']}")
                        
                except Exception:
                    node_health['unhealthy_nodes'] += 1
            
            return node_health
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _monitor_sla_slo(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Monitor SLA/SLO metrics"""
        try:
            sla_monitoring = {
                'availability_sla': {
                    'target': 99.9,
                    'current': 99.5,  # Placeholder - would calculate from actual metrics
                    'status': 'AT_RISK'
                },
                'response_time_slo': {
                    'target_ms': 200,
                    'current_ms': 150,  # Placeholder
                    'status': 'MEETING'
                },
                'error_rate_slo': {
                    'target_percent': 0.1,
                    'current_percent': 0.05,  # Placeholder
                    'status': 'MEETING'
                },
                'overall_sla_status': 'AT_RISK'
            }
            
            # In a real implementation, this would:
            # 1. Query CloudWatch metrics for actual availability
            # 2. Calculate response times from application metrics
            # 3. Analyze error rates from logs and metrics
            # 4. Compare against defined SLA/SLO targets
            
            return sla_monitoring
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_incident_response(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze incident response capabilities"""
        try:
            incident_response = {
                'automated_responses': [],
                'runbooks_available': [],
                'escalation_paths': [],
                'response_readiness': 'BASIC'
            }
            
            # Check for Systems Manager automation documents
            try:
                automation_docs = clients['ssm'].describe_automation_executions(
                    Filters=[
                        {
                            'Key': 'DocumentNamePrefix',
                            'Values': ['EKS-', 'Kubernetes-']
                        }
                    ],
                    MaxResults=10
                )
                
                incident_response['automated_responses'] = [
                    doc['DocumentName'] for doc in automation_docs.get('AutomationExecutions', [])
                ]
                
                if len(incident_response['automated_responses']) > 0:
                    incident_response['response_readiness'] = 'ADVANCED'
                    
            except Exception:
                pass  # Skip if SSM access fails
            
            # Check for common runbooks (placeholder)
            common_runbooks = [
                'Pod restart procedures',
                'Node replacement procedures',
                'Service recovery procedures'
            ]
            incident_response['runbooks_available'] = common_runbooks
            
            return incident_response
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _assess_operational_health(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Assess overall operational health"""
        try:
            operational_health = {
                'health_score': 85,  # Placeholder
                'health_level': 'GOOD',
                'key_metrics': {
                    'uptime_percentage': 99.5,
                    'mean_time_to_recovery': 15,  # minutes
                    'incident_frequency': 2,  # per month
                    'automation_coverage': 60  # percentage
                },
                'improvement_areas': []
            }
            
            # Analyze key operational metrics
            if operational_health['key_metrics']['uptime_percentage'] < 99.0:
                operational_health['improvement_areas'].append('Improve system availability')
                operational_health['health_score'] -= 10
            
            if operational_health['key_metrics']['mean_time_to_recovery'] > 30:
                operational_health['improvement_areas'].append('Reduce recovery time')
                operational_health['health_score'] -= 5
            
            if operational_health['key_metrics']['automation_coverage'] < 70:
                operational_health['improvement_areas'].append('Increase automation coverage')
                operational_health['health_score'] -= 5
            
            # Determine health level
            if operational_health['health_score'] >= 90:
                operational_health['health_level'] = 'EXCELLENT'
            elif operational_health['health_score'] >= 75:
                operational_health['health_level'] = 'GOOD'
            elif operational_health['health_score'] >= 60:
                operational_health['health_level'] = 'FAIR'
            else:
                operational_health['health_level'] = 'POOR'
            
            return operational_health
            
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_operational_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate operational intelligence recommendations"""
        recommendations = []
        
        # Failure prediction recommendations
        failure_prediction = analysis.get('failure_prediction', {})
        risk_level = failure_prediction.get('risk_level', 'LOW')
        
        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.append({
                'category': 'Failure Prevention',
                'title': 'Implement Proactive Monitoring',
                'priority': 'HIGH',
                'description': f'Risk level is {risk_level} - implement proactive monitoring and alerting',
                'implementation': 'Set up CloudWatch alarms and automated responses',
                'expected_benefit': 'Prevent service disruptions and reduce MTTR'
            })
        
        # SLA/SLO recommendations
        sla_monitoring = analysis.get('sla_slo_monitoring', {})
        availability_sla = sla_monitoring.get('availability_sla', {})
        
        if availability_sla.get('status') == 'AT_RISK':
            recommendations.append({
                'category': 'SLA Management',
                'title': 'Improve Availability SLA',
                'priority': 'HIGH',
                'description': f'Current availability {availability_sla.get("current", 0)}% is below target {availability_sla.get("target", 99.9)}%',
                'implementation': 'Implement multi-AZ deployment and improve monitoring',
                'expected_benefit': 'Meet availability SLA targets'
            })
        
        # Operational health recommendations
        operational_health = analysis.get('operational_health', {})
        improvement_areas = operational_health.get('improvement_areas', [])
        
        for area in improvement_areas:
            recommendations.append({
                'category': 'Operational Excellence',
                'title': area,
                'priority': 'MEDIUM',
                'description': f'Improvement needed in: {area}',
                'implementation': 'Implement operational best practices and automation',
                'expected_benefit': 'Improved operational efficiency and reliability'
            })
        
        return recommendations
