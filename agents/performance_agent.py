"""
Performance Optimization Agent - Resource analysis and optimization recommendations
"""
import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List
from .base_agent import BaseAgent, AgentTask, AgentResult

class PerformanceOptimizationAgent(BaseAgent):
    """Performance analysis and optimization agent"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("performance-optimization", config)
        self.region = config.get('region', 'us-west-2')
    
    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process performance analysis task"""
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
                    'ec2': boto3.client('ec2', region_name=region),
                    'compute_optimizer': boto3.client('compute-optimizer', region_name=region)
                }
            
            # Perform comprehensive performance analysis
            performance_results = await self._analyze_cluster_performance(cluster_name, clients)
            
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="completed",
                data=performance_results,
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
    
    async def _analyze_cluster_performance(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Comprehensive cluster performance analysis"""
        analysis = {
            'cluster_name': cluster_name,
            'analysis_timestamp': datetime.now().isoformat(),
            'resource_utilization': await self._analyze_resource_utilization(cluster_name, clients),
            'cost_optimization': await self._analyze_cost_optimization(cluster_name, clients),
            'scaling_analysis': await self._analyze_scaling_patterns(cluster_name, clients),
            'performance_recommendations': []
        }
        
        # Generate performance recommendations
        analysis['performance_recommendations'] = self._generate_performance_recommendations(analysis)
        
        return analysis
    
    async def _analyze_resource_utilization(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze resource utilization patterns"""
        try:
            # Get cluster information
            cluster = clients['eks'].describe_cluster(name=cluster_name)['cluster']
            node_groups = clients['eks'].list_nodegroups(clusterName=cluster_name)['nodegroups']
            
            utilization_analysis = {
                'cluster_metrics': {},
                'node_group_utilization': [],
                'resource_efficiency': {},
                'bottlenecks': []
            }
            
            # Analyze each node group
            for ng_name in node_groups:
                ng_info = clients['eks'].describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=ng_name
                )['nodegroup']
                
                # Get CloudWatch metrics for the past 7 days
                end_time = datetime.now()
                start_time = end_time - timedelta(days=7)
                
                ng_utilization = {
                    'node_group_name': ng_name,
                    'instance_types': ng_info['instanceTypes'],
                    'current_capacity': ng_info['scalingConfig']['desiredSize'],
                    'cpu_utilization': await self._get_cpu_utilization(cluster_name, ng_name, clients, start_time, end_time),
                    'memory_utilization': await self._get_memory_utilization(cluster_name, ng_name, clients, start_time, end_time),
                    'network_utilization': await self._get_network_utilization(cluster_name, ng_name, clients, start_time, end_time)
                }
                
                utilization_analysis['node_group_utilization'].append(ng_utilization)
            
            # Calculate overall resource efficiency
            utilization_analysis['resource_efficiency'] = self._calculate_resource_efficiency(utilization_analysis['node_group_utilization'])
            
            return utilization_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _get_cpu_utilization(self, cluster_name: str, node_group: str, clients: Dict, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get CPU utilization metrics"""
        try:
            response = clients['cloudwatch'].get_metric_statistics(
                Namespace='AWS/EKS',
                MetricName='cluster_cpu_utilization',
                Dimensions=[
                    {'Name': 'ClusterName', 'Value': cluster_name}
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,  # 1 hour
                Statistics=['Average', 'Maximum']
            )
            
            datapoints = response.get('Datapoints', [])
            if datapoints:
                avg_cpu = sum(dp['Average'] for dp in datapoints) / len(datapoints)
                max_cpu = max(dp['Maximum'] for dp in datapoints)
                
                return {
                    'average_cpu_percent': round(avg_cpu, 2),
                    'peak_cpu_percent': round(max_cpu, 2),
                    'data_points': len(datapoints),
                    'utilization_level': 'HIGH' if avg_cpu > 70 else 'MEDIUM' if avg_cpu > 40 else 'LOW'
                }
            else:
                return {'average_cpu_percent': 0, 'peak_cpu_percent': 0, 'utilization_level': 'UNKNOWN'}
                
        except Exception as e:
            return {'error': str(e), 'utilization_level': 'UNKNOWN'}
    
    async def _get_memory_utilization(self, cluster_name: str, node_group: str, clients: Dict, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get memory utilization metrics"""
        try:
            response = clients['cloudwatch'].get_metric_statistics(
                Namespace='AWS/EKS',
                MetricName='cluster_memory_utilization',
                Dimensions=[
                    {'Name': 'ClusterName', 'Value': cluster_name}
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Average', 'Maximum']
            )
            
            datapoints = response.get('Datapoints', [])
            if datapoints:
                avg_memory = sum(dp['Average'] for dp in datapoints) / len(datapoints)
                max_memory = max(dp['Maximum'] for dp in datapoints)
                
                return {
                    'average_memory_percent': round(avg_memory, 2),
                    'peak_memory_percent': round(max_memory, 2),
                    'utilization_level': 'HIGH' if avg_memory > 80 else 'MEDIUM' if avg_memory > 50 else 'LOW'
                }
            else:
                return {'average_memory_percent': 0, 'peak_memory_percent': 0, 'utilization_level': 'UNKNOWN'}
                
        except Exception as e:
            return {'error': str(e), 'utilization_level': 'UNKNOWN'}
    
    async def _get_network_utilization(self, cluster_name: str, node_group: str, clients: Dict, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get network utilization metrics"""
        return {
            'network_in_bytes': 0,
            'network_out_bytes': 0,
            'utilization_level': 'UNKNOWN',
            'note': 'Network metrics require additional monitoring setup'
        }
    
    def _calculate_resource_efficiency(self, node_group_utilization: List[Dict]) -> Dict[str, Any]:
        """Calculate overall resource efficiency"""
        if not node_group_utilization:
            return {'efficiency_score': 0, 'efficiency_level': 'UNKNOWN'}
        
        total_cpu = 0
        total_memory = 0
        node_groups = 0
        
        for ng in node_group_utilization:
            cpu_util = ng.get('cpu_utilization', {}).get('average_cpu_percent', 0)
            memory_util = ng.get('memory_utilization', {}).get('average_memory_percent', 0)
            
            if cpu_util > 0 or memory_util > 0:
                total_cpu += cpu_util
                total_memory += memory_util
                node_groups += 1
        
        if node_groups > 0:
            avg_cpu = total_cpu / node_groups
            avg_memory = total_memory / node_groups
            
            # Calculate efficiency score (optimal range is 50-70%)
            cpu_efficiency = 100 - abs(avg_cpu - 60)  # 60% is optimal
            memory_efficiency = 100 - abs(avg_memory - 65)  # 65% is optimal
            
            efficiency_score = (cpu_efficiency + memory_efficiency) / 2
            
            if efficiency_score >= 80:
                efficiency_level = 'EXCELLENT'
            elif efficiency_score >= 60:
                efficiency_level = 'GOOD'
            elif efficiency_score >= 40:
                efficiency_level = 'FAIR'
            else:
                efficiency_level = 'POOR'
            
            return {
                'efficiency_score': round(efficiency_score, 1),
                'efficiency_level': efficiency_level,
                'average_cpu_utilization': round(avg_cpu, 1),
                'average_memory_utilization': round(avg_memory, 1)
            }
        
        return {'efficiency_score': 0, 'efficiency_level': 'UNKNOWN'}
    
    async def _analyze_cost_optimization(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze cost optimization opportunities"""
        try:
            cost_analysis = {
                'spot_instance_opportunities': [],
                'right_sizing_recommendations': [],
                'reserved_instance_recommendations': [],
                'estimated_savings': 0
            }
            
            # Get node groups for cost analysis
            node_groups = clients['eks'].list_nodegroups(clusterName=cluster_name)['nodegroups']
            
            for ng_name in node_groups:
                ng_info = clients['eks'].describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=ng_name
                )['nodegroup']
                
                # Check if using Spot instances
                capacity_type = ng_info.get('capacityType', 'ON_DEMAND')
                if capacity_type == 'ON_DEMAND':
                    cost_analysis['spot_instance_opportunities'].append({
                        'node_group': ng_name,
                        'current_type': 'ON_DEMAND',
                        'recommendation': 'Consider using SPOT instances for non-critical workloads',
                        'potential_savings': '60-70%'
                    })
                
                # Analyze instance types for right-sizing
                instance_types = ng_info['instanceTypes']
                for instance_type in instance_types:
                    if 'xlarge' in instance_type or 'large' in instance_type:
                        cost_analysis['right_sizing_recommendations'].append({
                            'node_group': ng_name,
                            'current_instance': instance_type,
                            'recommendation': 'Analyze actual resource usage to determine if smaller instances are sufficient',
                            'analysis_required': 'Review CPU and memory utilization patterns'
                        })
            
            return cost_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_scaling_patterns(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze auto-scaling patterns and recommendations"""
        try:
            scaling_analysis = {
                'auto_scaling_groups': [],
                'scaling_recommendations': [],
                'capacity_planning': {}
            }
            
            # Get node groups and their scaling configuration
            node_groups = clients['eks'].list_nodegroups(clusterName=cluster_name)['nodegroups']
            
            for ng_name in node_groups:
                ng_info = clients['eks'].describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=ng_name
                )['nodegroup']
                
                scaling_config = ng_info['scalingConfig']
                
                asg_info = {
                    'node_group': ng_name,
                    'min_size': scaling_config['minSize'],
                    'max_size': scaling_config['maxSize'],
                    'desired_size': scaling_config['desiredSize'],
                    'scaling_efficiency': 'GOOD'
                }
                
                # Analyze scaling configuration
                if scaling_config['minSize'] == scaling_config['maxSize']:
                    scaling_analysis['scaling_recommendations'].append({
                        'node_group': ng_name,
                        'issue': 'No auto-scaling configured',
                        'recommendation': 'Enable auto-scaling by setting different min and max sizes',
                        'priority': 'MEDIUM'
                    })
                    asg_info['scaling_efficiency'] = 'POOR'
                
                if scaling_config['maxSize'] - scaling_config['minSize'] < 2:
                    scaling_analysis['scaling_recommendations'].append({
                        'node_group': ng_name,
                        'issue': 'Limited scaling range',
                        'recommendation': 'Increase max size to allow for better scaling flexibility',
                        'priority': 'LOW'
                    })
                
                scaling_analysis['auto_scaling_groups'].append(asg_info)
            
            return scaling_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_performance_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate performance optimization recommendations"""
        recommendations = []
        
        # Resource utilization recommendations
        resource_util = analysis.get('resource_utilization', {})
        efficiency = resource_util.get('resource_efficiency', {})
        
        if efficiency.get('efficiency_level') == 'POOR':
            recommendations.append({
                'category': 'Resource Optimization',
                'title': 'Optimize Resource Utilization',
                'priority': 'HIGH',
                'description': 'Cluster resource utilization is suboptimal',
                'recommendation': 'Review and adjust instance types and scaling policies',
                'expected_benefit': 'Improved performance and cost efficiency'
            })
        
        # Cost optimization recommendations
        cost_analysis = analysis.get('cost_optimization', {})
        spot_opportunities = cost_analysis.get('spot_instance_opportunities', [])
        
        if spot_opportunities:
            recommendations.append({
                'category': 'Cost Optimization',
                'title': 'Implement Spot Instances',
                'priority': 'MEDIUM',
                'description': f'{len(spot_opportunities)} node groups can benefit from Spot instances',
                'recommendation': 'Migrate non-critical workloads to Spot instances',
                'expected_benefit': '60-70% cost reduction for applicable workloads'
            })
        
        # Scaling recommendations
        scaling_analysis = analysis.get('scaling_analysis', {})
        scaling_recs = scaling_analysis.get('scaling_recommendations', [])
        
        for scaling_rec in scaling_recs:
            recommendations.append({
                'category': 'Auto-scaling',
                'title': f"Optimize {scaling_rec['node_group']} Scaling",
                'priority': scaling_rec['priority'],
                'description': scaling_rec['issue'],
                'recommendation': scaling_rec['recommendation'],
                'expected_benefit': 'Better resource allocation and cost control'
            })
        
        return recommendations
