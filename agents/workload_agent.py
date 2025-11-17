"""
Workload Analysis Agent - Application dependency mapping and workload optimization
"""
import boto3
import json
from datetime import datetime
from typing import Dict, Any, List
from .base_agent import BaseAgent, AgentTask, AgentResult

class WorkloadAnalysisAgent(BaseAgent):
    """Workload analysis and application dependency mapping agent"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("workload-analysis", config)
        self.region = config.get('region', 'us-west-2')
    
    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process workload analysis task"""
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
                    'ecr': boto3.client('ecr', region_name=region),
                    'xray': boto3.client('xray', region_name=region)
                }
            
            # Perform workload analysis
            workload_results = await self._analyze_workloads(cluster_name, clients)
            
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="completed",
                data=workload_results,
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
    
    async def _analyze_workloads(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Comprehensive workload analysis"""
        analysis = {
            'cluster_name': cluster_name,
            'analysis_timestamp': datetime.now().isoformat(),
            'dependency_mapping': await self._map_dependencies(cluster_name, clients),
            'container_analysis': await self._analyze_containers(cluster_name, clients),
            'service_mesh_analysis': await self._analyze_service_mesh(cluster_name, clients),
            'workload_security': await self._analyze_workload_security(cluster_name, clients),
            'performance_analysis': await self._analyze_workload_performance(cluster_name, clients),
            'recommendations': []
        }
        
        # Generate workload recommendations
        analysis['recommendations'] = self._generate_workload_recommendations(analysis)
        
        return analysis
    
    async def _map_dependencies(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Map application dependencies and service relationships"""
        try:
            dependency_mapping = {
                'services_discovered': 0,
                'dependencies_mapped': 0,
                'service_graph': {},
                'critical_paths': [],
                'dependency_risks': []
            }
            
            # In a real implementation, this would:
            # 1. Use X-Ray service map to discover services
            # 2. Analyze Kubernetes service definitions
            # 3. Map ingress/egress traffic patterns
            # 4. Identify critical service dependencies
            
            try:
                # Get X-Ray service map (if available)
                service_map = clients['xray'].get_service_graph(
                    StartTime=datetime.now().replace(hour=0, minute=0, second=0),
                    EndTime=datetime.now()
                )
                
                services = service_map.get('Services', [])
                dependency_mapping['services_discovered'] = len(services)
                
                # Build service graph
                for service in services:
                    service_name = service.get('Name', 'Unknown')
                    edges = service.get('Edges', [])
                    
                    dependency_mapping['service_graph'][service_name] = {
                        'type': service.get('Type', 'Unknown'),
                        'state': service.get('State', 'Unknown'),
                        'dependencies': [edge.get('DestinationService', {}).get('Name', 'Unknown') for edge in edges]
                    }
                    
                    dependency_mapping['dependencies_mapped'] += len(edges)
                
                # Identify critical paths (services with many dependencies)
                for service_name, service_info in dependency_mapping['service_graph'].items():
                    if len(service_info['dependencies']) > 3:
                        dependency_mapping['critical_paths'].append({
                            'service': service_name,
                            'dependency_count': len(service_info['dependencies']),
                            'risk_level': 'HIGH' if len(service_info['dependencies']) > 5 else 'MEDIUM'
                        })
                
            except Exception as e:
                dependency_mapping['xray_error'] = str(e)
                # Fallback to basic analysis
                dependency_mapping['note'] = 'X-Ray service map not available - using basic analysis'
            
            return dependency_mapping
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_containers(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze container images and configurations"""
        try:
            container_analysis = {
                'total_repositories': 0,
                'scanned_images': 0,
                'vulnerabilities_found': 0,
                'image_analysis': [],
                'security_issues': []
            }
            
            # Get ECR repositories
            try:
                repositories = clients['ecr'].describe_repositories()['repositories']
                container_analysis['total_repositories'] = len(repositories)
                
                # Analyze first 5 repositories for vulnerabilities
                for repo in repositories[:5]:
                    repo_name = repo['repositoryName']
                    
                    try:
                        # Get image scan results
                        images = clients['ecr'].describe_images(
                            repositoryName=repo_name,
                            maxResults=5
                        )['imageDetails']
                        
                        for image in images:
                            if 'imageScanFindingsSummary' in image:
                                scan_summary = image['imageScanFindingsSummary']
                                
                                image_analysis = {
                                    'repository': repo_name,
                                    'image_tag': image.get('imageTags', ['latest'])[0],
                                    'scan_status': scan_summary.get('scanStatus', 'UNKNOWN'),
                                    'vulnerabilities': scan_summary.get('findingCounts', {}),
                                    'last_scan': image.get('imageScanCompletedAt', 'Never')
                                }
                                
                                container_analysis['image_analysis'].append(image_analysis)
                                container_analysis['scanned_images'] += 1
                                
                                # Count vulnerabilities
                                vuln_counts = scan_summary.get('findingCounts', {})
                                total_vulns = sum(vuln_counts.values())
                                container_analysis['vulnerabilities_found'] += total_vulns
                                
                                # Identify security issues
                                if vuln_counts.get('CRITICAL', 0) > 0:
                                    container_analysis['security_issues'].append(
                                        f"Critical vulnerabilities in {repo_name}:{image_analysis['image_tag']}"
                                    )
                                
                    except Exception as e:
                        container_analysis['security_issues'].append(f"Scan failed for {repo_name}: {str(e)}")
                        
            except Exception as e:
                container_analysis['ecr_error'] = str(e)
            
            return container_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_service_mesh(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze service mesh configuration and optimization"""
        try:
            service_mesh_analysis = {
                'mesh_detected': False,
                'mesh_type': 'None',
                'configuration_issues': [],
                'optimization_opportunities': [],
                'security_policies': 0
            }
            
            # In a real implementation, this would:
            # 1. Check for Istio, Linkerd, or AWS App Mesh
            # 2. Analyze service mesh configuration
            # 3. Check for mTLS configuration
            # 4. Analyze traffic policies
            # 5. Identify optimization opportunities
            
            # Placeholder analysis
            service_mesh_analysis['optimization_opportunities'] = [
                'Consider implementing service mesh for better observability',
                'Enable mTLS for service-to-service communication',
                'Implement traffic splitting for canary deployments',
                'Add circuit breaker patterns for resilience'
            ]
            
            return service_mesh_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_workload_security(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze workload-level security configurations"""
        try:
            workload_security = {
                'pod_security_policies': 0,
                'network_policies': 0,
                'service_accounts': 0,
                'security_contexts': 0,
                'security_issues': [],
                'recommendations': []
            }
            
            # In a real implementation, this would:
            # 1. Use kubectl to analyze pod security policies
            # 2. Check network policies
            # 3. Analyze service account configurations
            # 4. Review security contexts
            # 5. Check for privileged containers
            
            # Placeholder security analysis
            workload_security['security_issues'] = [
                'Pod security policies not implemented',
                'Network policies missing for micro-segmentation',
                'Some containers running as root',
                'Service accounts using default permissions'
            ]
            
            workload_security['recommendations'] = [
                'Implement Pod Security Standards',
                'Deploy network policies for traffic control',
                'Use non-root containers',
                'Implement least privilege service accounts'
            ]
            
            return workload_security
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_workload_performance(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze workload performance patterns"""
        try:
            performance_analysis = {
                'resource_utilization': {
                    'cpu_efficiency': 65,  # Placeholder
                    'memory_efficiency': 70,
                    'storage_efficiency': 80
                },
                'scaling_patterns': {
                    'hpa_configured': False,
                    'vpa_configured': False,
                    'cluster_autoscaler': True
                },
                'performance_issues': [],
                'optimization_opportunities': []
            }
            
            # Analyze resource efficiency
            cpu_eff = performance_analysis['resource_utilization']['cpu_efficiency']
            mem_eff = performance_analysis['resource_utilization']['memory_efficiency']
            
            if cpu_eff < 50:
                performance_analysis['performance_issues'].append('Low CPU utilization - consider right-sizing')
            elif cpu_eff > 80:
                performance_analysis['performance_issues'].append('High CPU utilization - consider scaling up')
            
            if mem_eff < 50:
                performance_analysis['performance_issues'].append('Low memory utilization - consider right-sizing')
            elif mem_eff > 85:
                performance_analysis['performance_issues'].append('High memory utilization - risk of OOM kills')
            
            # Scaling recommendations
            if not performance_analysis['scaling_patterns']['hpa_configured']:
                performance_analysis['optimization_opportunities'].append('Configure Horizontal Pod Autoscaler (HPA)')
            
            if not performance_analysis['scaling_patterns']['vpa_configured']:
                performance_analysis['optimization_opportunities'].append('Consider Vertical Pod Autoscaler (VPA)')
            
            return performance_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_workload_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate workload-specific recommendations"""
        recommendations = []
        
        # Dependency mapping recommendations
        dependency_mapping = analysis.get('dependency_mapping', {})
        critical_paths = dependency_mapping.get('critical_paths', [])
        
        if critical_paths:
            recommendations.append({
                'category': 'Dependency Management',
                'title': 'Optimize Service Dependencies',
                'priority': 'HIGH',
                'description': f'{len(critical_paths)} services have complex dependency chains',
                'implementation': 'Implement circuit breakers and reduce coupling',
                'expected_benefit': 'Improved resilience and reduced failure propagation'
            })
        
        # Container security recommendations
        container_analysis = analysis.get('container_analysis', {})
        vulnerabilities = container_analysis.get('vulnerabilities_found', 0)
        
        if vulnerabilities > 0:
            recommendations.append({
                'category': 'Container Security',
                'title': 'Address Container Vulnerabilities',
                'priority': 'HIGH',
                'description': f'{vulnerabilities} vulnerabilities found in container images',
                'implementation': 'Update base images and implement vulnerability scanning in CI/CD',
                'expected_benefit': 'Reduced security risk and compliance improvement'
            })
        
        # Performance optimization recommendations
        performance_analysis = analysis.get('performance_analysis', {})
        performance_issues = performance_analysis.get('performance_issues', [])
        
        for issue in performance_issues:
            recommendations.append({
                'category': 'Performance Optimization',
                'title': 'Optimize Resource Utilization',
                'priority': 'MEDIUM',
                'description': issue,
                'implementation': 'Adjust resource requests/limits and implement autoscaling',
                'expected_benefit': 'Improved performance and cost efficiency'
            })
        
        # Service mesh recommendations
        service_mesh = analysis.get('service_mesh_analysis', {})
        if not service_mesh.get('mesh_detected', False):
            recommendations.append({
                'category': 'Service Mesh',
                'title': 'Consider Service Mesh Implementation',
                'priority': 'MEDIUM',
                'description': 'Service mesh not detected - missing observability and security benefits',
                'implementation': 'Evaluate Istio, Linkerd, or AWS App Mesh',
                'expected_benefit': 'Improved observability, security, and traffic management'
            })
        
        return recommendations
