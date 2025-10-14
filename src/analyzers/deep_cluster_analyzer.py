import logging
import boto3
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from kubernetes import client, config
from ..utils.kubernetes_client import KubernetesClient
from ..utils.aws_utils import AWSUtils

logger = logging.getLogger(__name__)

class DeepClusterAnalyzer:
    """Comprehensive EKS cluster analyzer that goes deep into cluster, namespace, and workload levels"""
    
    def __init__(self, aws_access_key: str, aws_secret_key: str, region: str, cluster_name: str):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.region = region
        self.cluster_name = cluster_name
        
        # Initialize clients
        self.aws_utils = AWSUtils(aws_access_key, aws_secret_key, region, cluster_name)
        self.k8s_client = KubernetesClient(cluster_name, region)
        
        # Initialize additional AWS clients for deeper analysis
        self.cloudwatch = boto3.client('cloudwatch', 
                                     aws_access_key_id=aws_access_key,
                                     aws_secret_access_key=aws_secret_key,
                                     region_name=region)
        self.pricing = boto3.client('pricing',
                                  aws_access_key_id=aws_access_key,
                                  aws_secret_access_key=aws_secret_key,
                                  region_name='us-east-1')  # Pricing API only in us-east-1
        
    def analyze_comprehensive(self) -> Dict[str, Any]:
        """Perform comprehensive cluster analysis"""
        try:
            # Initialize Kubernetes client
            if not self.k8s_client.initialize():
                raise Exception("Failed to initialize Kubernetes client")
            
            analysis_results = {
                'cluster_level': self._analyze_cluster_level(),
                'namespace_level': self._analyze_namespace_level(),
                'workload_level': self._analyze_workload_level(),
                'security_deep_dive': self._analyze_security_deep_dive(),
                'cost_optimization': self._analyze_cost_optimization(),
                'performance_analysis': self._analyze_performance(),
                'reliability_analysis': self._analyze_reliability(),
                'compliance_analysis': self._analyze_compliance(),
                'addon_analysis': self._analyze_addons(),
                'upgrade_analysis': self._analyze_upgrade_readiness()
            }
            
            # Generate consolidated recommendations
            analysis_results['consolidated_recommendations'] = self._generate_consolidated_recommendations(analysis_results)
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Comprehensive analysis failed: {e}")
            raise
    
    def _analyze_cluster_level(self) -> Dict[str, Any]:
        """Analyze cluster-level configurations and settings"""
        cluster_details = self.aws_utils.get_cluster_details()
        
        findings = []
        recommendations = []
        
        # Analyze cluster version
        current_version = cluster_details.get('version_info', {}).get('current', '')
        latest_version = self._get_latest_k8s_version()
        
        if self._compare_versions(current_version, latest_version) < 0:
            findings.append({
                'category': 'Cluster Version',
                'severity': 'Medium',
                'finding': f'Cluster running Kubernetes {current_version}, latest is {latest_version}',
                'recommendation': f'Plan upgrade to Kubernetes {latest_version}',
                'impact': 'Missing security patches and new features'
            })
        
        # Analyze control plane logging
        logging_config = cluster_details.get('cluster', {}).get('logging', {})
        enabled_logs = logging_config.get('clusterLogging', [])
        
        required_logs = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
        missing_logs = [log for log in required_logs if not any(l.get('types', []) and log in l['types'] for l in enabled_logs if l.get('enabled'))]
        
        if missing_logs:
            findings.append({
                'category': 'Control Plane Logging',
                'severity': 'High',
                'finding': f'Missing control plane logs: {", ".join(missing_logs)}',
                'recommendation': 'Enable all control plane logging types',
                'impact': 'Limited visibility into cluster operations and security events'
            })
        
        # Analyze endpoint configuration
        networking = cluster_details.get('networking', {})
        endpoint_access = networking.get('endpoint_access', {})
        
        if endpoint_access.get('public', True) and not endpoint_access.get('private', False):
            findings.append({
                'category': 'API Endpoint Security',
                'severity': 'High',
                'finding': 'API server endpoint is public-only',
                'recommendation': 'Enable private endpoint access and restrict public access',
                'impact': 'API server accessible from internet increases attack surface'
            })
        
        return {
            'findings': findings,
            'recommendations': recommendations,
            'cluster_metadata': cluster_details
        }
    
    def _analyze_namespace_level(self) -> Dict[str, Any]:
        """Analyze each namespace for security and best practices"""
        namespaces = self.k8s_client.get_all_namespaces()
        namespace_analysis = []
        
        for ns in namespaces:
            ns_name = ns['name']
            
            # Skip system namespaces for some checks
            if ns_name.startswith('kube-'):
                continue
                
            ns_findings = []
            
            # Check for network policies
            network_policies = self.k8s_client.get_all_network_policies(ns_name)
            if not network_policies:
                ns_findings.append({
                    'category': 'Network Security',
                    'severity': 'Medium',
                    'finding': f'No network policies found in namespace {ns_name}',
                    'recommendation': 'Implement network policies to control pod-to-pod communication',
                    'impact': 'Unrestricted network access between pods'
                })
            
            # Check for resource quotas
            resource_quotas = self.k8s_client.get_resource_quotas(ns_name)
            if not resource_quotas:
                ns_findings.append({
                    'category': 'Resource Management',
                    'severity': 'Medium',
                    'finding': f'No resource quotas defined for namespace {ns_name}',
                    'recommendation': 'Define resource quotas to prevent resource exhaustion',
                    'impact': 'Risk of resource exhaustion affecting other workloads'
                })
            
            # Check for limit ranges
            limit_ranges = self.k8s_client.get_limit_ranges(ns_name)
            if not limit_ranges:
                ns_findings.append({
                    'category': 'Resource Management',
                    'severity': 'Low',
                    'finding': f'No limit ranges defined for namespace {ns_name}',
                    'recommendation': 'Define limit ranges to set default resource limits',
                    'impact': 'Pods may consume excessive resources'
                })
            
            # Check for pod security standards
            pss_labels = ns.get('labels', {})
            if not any(label.startswith('pod-security.kubernetes.io/') for label in pss_labels):
                ns_findings.append({
                    'category': 'Pod Security',
                    'severity': 'High',
                    'finding': f'Pod Security Standards not configured for namespace {ns_name}',
                    'recommendation': 'Configure Pod Security Standards with appropriate enforcement level',
                    'impact': 'Pods may run with excessive privileges'
                })
            
            namespace_analysis.append({
                'namespace': ns_name,
                'findings': ns_findings,
                'metadata': ns
            })
        
        return {
            'namespace_count': len(namespaces),
            'analyzed_namespaces': namespace_analysis,
            'summary': self._summarize_namespace_findings(namespace_analysis)
        }
    
    def _analyze_workload_level(self) -> Dict[str, Any]:
        """Analyze individual workloads (deployments, pods, etc.)"""
        workload_analysis = {
            'deployments': self._analyze_deployments(),
            'daemonsets': self._analyze_daemonsets(),
            'statefulsets': self._analyze_statefulsets(),
            'pods': self._analyze_pods(),
            'services': self._analyze_services()
        }
        
        return workload_analysis
    
    def _analyze_deployments(self) -> List[Dict[str, Any]]:
        """Analyze deployment configurations"""
        deployments = self.k8s_client.get_all_deployments()
        deployment_analysis = []
        
        for deployment in deployments:
            findings = []
            
            # Check resource requests/limits
            containers = deployment.get('containers', [])
            for container in containers:
                resources = container.get('resources', {})
                requests = resources.get('requests', {})
                limits = resources.get('limits', {})
                
                if not requests.get('cpu') or not requests.get('memory'):
                    findings.append({
                        'category': 'Resource Management',
                        'severity': 'Medium',
                        'finding': f'Container {container["name"]} missing resource requests',
                        'recommendation': 'Define CPU and memory requests for all containers',
                        'impact': 'Poor scheduling decisions and resource contention'
                    })
                
                if not limits.get('cpu') or not limits.get('memory'):
                    findings.append({
                        'category': 'Resource Management',
                        'severity': 'Medium',
                        'finding': f'Container {container["name"]} missing resource limits',
                        'recommendation': 'Define CPU and memory limits for all containers',
                        'impact': 'Risk of resource exhaustion'
                    })
            
            # Check replica count
            replicas = deployment.get('replicas', 1)
            if replicas < 2:
                findings.append({
                    'category': 'High Availability',
                    'severity': 'Medium',
                    'finding': f'Deployment {deployment["name"]} has only {replicas} replica(s)',
                    'recommendation': 'Use multiple replicas for high availability',
                    'impact': 'Single point of failure'
                })
            
            deployment_analysis.append({
                'name': deployment['name'],
                'namespace': deployment['namespace'],
                'findings': findings,
                'metadata': deployment
            })
        
        return deployment_analysis
    
    def _analyze_security_deep_dive(self) -> Dict[str, Any]:
        """Deep dive security analysis"""
        security_findings = []
        
        # Check for privileged containers
        pods = self.k8s_client.get_all_pods()
        privileged_pods = []
        
        for pod in pods:
            containers = pod.get('containers', [])
            for container in containers:
                security_context = container.get('security_context', {})
                if security_context.get('privileged', False):
                    privileged_pods.append({
                        'pod': pod['name'],
                        'namespace': pod['namespace'],
                        'container': container['name']
                    })
        
        if privileged_pods:
            security_findings.append({
                'category': 'Container Security',
                'severity': 'High',
                'finding': f'Found {len(privileged_pods)} privileged containers',
                'recommendation': 'Remove privileged access from containers unless absolutely necessary',
                'impact': 'Containers have full access to host resources',
                'details': privileged_pods
            })
        
        # Check for containers running as root
        root_containers = []
        for pod in pods:
            containers = pod.get('containers', [])
            for container in containers:
                security_context = container.get('security_context', {})
                if security_context.get('run_as_user') == 0 or not security_context.get('run_as_user'):
                    root_containers.append({
                        'pod': pod['name'],
                        'namespace': pod['namespace'],
                        'container': container['name']
                    })
        
        if root_containers:
            security_findings.append({
                'category': 'Container Security',
                'severity': 'Medium',
                'finding': f'Found {len(root_containers)} containers potentially running as root',
                'recommendation': 'Configure containers to run as non-root user',
                'impact': 'Increased attack surface if container is compromised',
                'details': root_containers[:10]  # Limit details for readability
            })
        
        return {
            'findings': security_findings,
            'privileged_containers_count': len(privileged_pods),
            'root_containers_count': len(root_containers)
        }
    
    def _analyze_cost_optimization(self) -> Dict[str, Any]:
        """Analyze cost optimization opportunities"""
        cost_findings = []
        
        # Get node group information
        cluster_details = self.aws_utils.get_cluster_details()
        nodegroups = cluster_details.get('nodegroups', [])
        
        for ng in nodegroups:
            # Check for spot instances usage
            capacity_type = ng.get('capacityType', 'ON_DEMAND')
            if capacity_type == 'ON_DEMAND':
                cost_findings.append({
                    'category': 'Cost Optimization',
                    'severity': 'Low',
                    'finding': f'Node group {ng["name"]} using On-Demand instances',
                    'recommendation': 'Consider using Spot instances for non-critical workloads',
                    'impact': 'Higher compute costs',
                    'potential_savings': '60-90% cost reduction for suitable workloads'
                })
            
            # Check instance types
            instance_type = ng.get('instanceType', '')
            if instance_type.startswith('m5.') or instance_type.startswith('c5.'):
                cost_findings.append({
                    'category': 'Cost Optimization',
                    'severity': 'Low',
                    'finding': f'Node group {ng["name"]} using older generation instances ({instance_type})',
                    'recommendation': 'Consider upgrading to newer generation instances (m6i, c6i)',
                    'impact': 'Higher costs and lower performance',
                    'potential_savings': '10-20% cost reduction with better performance'
                })
        
        # Analyze resource utilization
        utilization_analysis = self._analyze_resource_utilization()
        
        return {
            'findings': cost_findings,
            'utilization_analysis': utilization_analysis,
            'estimated_monthly_cost': self._estimate_monthly_cost(nodegroups)
        }
    
    def _analyze_performance(self) -> Dict[str, Any]:
        """Analyze cluster performance"""
        performance_findings = []
        
        # Check for HPA configuration
        hpas = self.k8s_client.get_horizontal_pod_autoscalers()
        deployments = self.k8s_client.get_all_deployments()
        
        deployments_without_hpa = []
        for deployment in deployments:
            has_hpa = any(hpa['target_ref']['name'] == deployment['name'] 
                         for hpa in hpas 
                         if hpa['target_ref']['kind'] == 'Deployment')
            if not has_hpa:
                deployments_without_hpa.append(deployment['name'])
        
        if deployments_without_hpa:
            performance_findings.append({
                'category': 'Auto Scaling',
                'severity': 'Medium',
                'finding': f'{len(deployments_without_hpa)} deployments without HPA',
                'recommendation': 'Configure Horizontal Pod Autoscaler for scalable workloads',
                'impact': 'Manual scaling required, potential performance issues under load'
            })
        
        return {
            'findings': performance_findings,
            'hpa_count': len(hpas),
            'deployments_without_hpa': len(deployments_without_hpa)
        }
    
    def _analyze_reliability(self) -> Dict[str, Any]:
        """Analyze cluster reliability"""
        reliability_findings = []
        
        # Check for pod disruption budgets
        pdbs = self.k8s_client.get_pod_disruption_budgets()
        deployments = self.k8s_client.get_all_deployments()
        
        deployments_without_pdb = []
        for deployment in deployments:
            if deployment.get('replicas', 1) > 1:  # Only check multi-replica deployments
                has_pdb = any(pdb['selector'] and 
                            self._selector_matches(pdb['selector'], deployment.get('labels', {}))
                            for pdb in pdbs)
                if not has_pdb:
                    deployments_without_pdb.append(deployment['name'])
        
        if deployments_without_pdb:
            reliability_findings.append({
                'category': 'High Availability',
                'severity': 'Medium',
                'finding': f'{len(deployments_without_pdb)} multi-replica deployments without PDB',
                'recommendation': 'Configure Pod Disruption Budgets for critical workloads',
                'impact': 'Risk of service disruption during node maintenance'
            })
        
        return {
            'findings': reliability_findings,
            'pdb_count': len(pdbs),
            'deployments_without_pdb': len(deployments_without_pdb)
        }
    
    def _analyze_addons(self) -> Dict[str, Any]:
        """Analyze EKS addons and recommend improvements"""
        cluster_details = self.aws_utils.get_cluster_details()
        addons = cluster_details.get('addons', [])
        
        addon_findings = []
        
        # Check for essential addons
        essential_addons = ['vpc-cni', 'coredns', 'kube-proxy']
        installed_addons = [addon['name'] for addon in addons]
        
        missing_addons = [addon for addon in essential_addons if addon not in installed_addons]
        if missing_addons:
            addon_findings.append({
                'category': 'Addon Management',
                'severity': 'High',
                'finding': f'Missing essential addons: {", ".join(missing_addons)}',
                'recommendation': 'Install missing essential EKS addons',
                'impact': 'Core cluster functionality may be impaired'
            })
        
        # Check addon versions
        for addon in addons:
            if addon.get('status') != 'ACTIVE':
                addon_findings.append({
                    'category': 'Addon Management',
                    'severity': 'Medium',
                    'finding': f'Addon {addon["name"]} is not active (status: {addon.get("status")})',
                    'recommendation': f'Investigate and fix addon {addon["name"]}',
                    'impact': 'Addon functionality may be impaired'
                })
        
        return {
            'findings': addon_findings,
            'installed_addons': installed_addons,
            'addon_count': len(addons)
        }
    
    def _analyze_upgrade_readiness(self) -> Dict[str, Any]:
        """Analyze cluster upgrade readiness"""
        upgrade_findings = []
        
        cluster_details = self.aws_utils.get_cluster_details()
        current_version = cluster_details.get('version_info', {}).get('current', '')
        
        # Check for deprecated API versions
        deprecated_apis = self._check_deprecated_apis()
        if deprecated_apis:
            upgrade_findings.append({
                'category': 'Upgrade Readiness',
                'severity': 'High',
                'finding': f'Found {len(deprecated_apis)} resources using deprecated APIs',
                'recommendation': 'Update resources to use supported API versions before upgrading',
                'impact': 'Cluster upgrade may fail or resources may become inaccessible',
                'details': deprecated_apis[:5]  # Show first 5
            })
        
        return {
            'findings': upgrade_findings,
            'current_version': current_version,
            'deprecated_api_count': len(deprecated_apis) if deprecated_apis else 0
        }
    
    def _generate_consolidated_recommendations(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate consolidated, prioritized recommendations"""
        all_findings = []
        
        # Collect all findings from different analysis areas
        for area, results in analysis_results.items():
            if isinstance(results, dict) and 'findings' in results:
                for finding in results['findings']:
                    finding['analysis_area'] = area
                    all_findings.append(finding)
        
        # Sort by severity (High -> Medium -> Low)
        severity_order = {'High': 0, 'Medium': 1, 'Low': 2}
        all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'Low'), 2))
        
        return all_findings
    
    # Helper methods
    def _get_latest_k8s_version(self) -> str:
        """Get latest supported Kubernetes version"""
        # This should be dynamically fetched from EKS API
        return "1.29"
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare two version strings"""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            for i in range(max(len(v1_parts), len(v2_parts))):
                v1 = v1_parts[i] if i < len(v1_parts) else 0
                v2 = v2_parts[i] if i < len(v2_parts) else 0
                if v1 < v2:
                    return -1
                if v1 > v2:
                    return 1
            return 0
        except Exception:
            return 0
    
    def _summarize_namespace_findings(self, namespace_analysis: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize findings across all namespaces"""
        total_findings = sum(len(ns['findings']) for ns in namespace_analysis)
        high_severity = sum(1 for ns in namespace_analysis 
                          for finding in ns['findings'] 
                          if finding.get('severity') == 'High')
        
        return {
            'total_findings': total_findings,
            'high_severity_count': high_severity,
            'namespaces_with_issues': len([ns for ns in namespace_analysis if ns['findings']])
        }
    
    def _analyze_resource_utilization(self) -> Dict[str, Any]:
        """Analyze resource utilization using CloudWatch metrics"""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=7)
            
            # Get CPU utilization
            cpu_metrics = self.cloudwatch.get_metric_statistics(
                Namespace='AWS/EKS',
                MetricName='cluster_cpu_utilization',
                Dimensions=[{'Name': 'ClusterName', 'Value': self.cluster_name}],
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Average']
            )
            
            avg_cpu = sum(point['Average'] for point in cpu_metrics['Datapoints']) / len(cpu_metrics['Datapoints']) if cpu_metrics['Datapoints'] else 0
            
            return {
                'average_cpu_utilization': avg_cpu,
                'recommendation': 'Low' if avg_cpu < 30 else 'Optimal' if avg_cpu < 70 else 'High'
            }
        except Exception as e:
            logger.warning(f"Failed to get utilization metrics: {e}")
            return {'error': 'Unable to retrieve utilization data'}
    
    def _estimate_monthly_cost(self, nodegroups: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Estimate monthly cost for the cluster"""
        try:
            total_cost = 0
            cost_breakdown = []
            
            for ng in nodegroups:
                instance_type = ng.get('instanceType', 'm5.large')
                desired_capacity = ng.get('desiredSize', 1)
                
                # This is a simplified cost calculation
                # In production, you'd use the Pricing API
                instance_costs = {
                    'm5.large': 0.096,
                    'm5.xlarge': 0.192,
                    'c5.large': 0.085,
                    'c5.xlarge': 0.17
                }
                
                hourly_cost = instance_costs.get(instance_type, 0.1) * desired_capacity
                monthly_cost = hourly_cost * 24 * 30
                total_cost += monthly_cost
                
                cost_breakdown.append({
                    'nodegroup': ng['name'],
                    'instance_type': instance_type,
                    'count': desired_capacity,
                    'monthly_cost': monthly_cost
                })
            
            return {
                'total_monthly_cost': total_cost,
                'breakdown': cost_breakdown
            }
        except Exception as e:
            logger.warning(f"Failed to estimate costs: {e}")
            return {'error': 'Unable to estimate costs'}
    
    def _check_deprecated_apis(self) -> List[Dict[str, Any]]:
        """Check for deprecated API versions"""
        # This would require checking all resources in the cluster
        # For now, return empty list
        return []
    
    def _selector_matches(self, selector: Dict[str, Any], labels: Dict[str, str]) -> bool:
        """Check if a selector matches given labels"""
        if not selector or not labels:
            return False
        
        match_labels = selector.get('matchLabels', {})
        for key, value in match_labels.items():
            if labels.get(key) != value:
                return False
        
        return True
