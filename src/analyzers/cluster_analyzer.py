import logging
from typing import Dict, List, Any
from src.utils.kubernetes_client import KubernetesClient

logger = logging.getLogger(__name__)

class ClusterAnalyzer:
    """
    Comprehensive analyzer for EKS clusters using direct Kubernetes API access
    """
    
    def __init__(self, cluster_name=None, region=None):
        """
        Initialize the cluster analyzer
        
        Args:
            cluster_name: Name of the EKS cluster
            region: AWS region where the cluster is located
        """
        self.cluster_name = cluster_name
        self.region = region
        self.k8s_client = KubernetesClient(cluster_name, region)
        self.initialized = False
    
    def initialize(self):
        """Initialize the analyzer with Kubernetes client"""
        try:
            self.initialized = self.k8s_client.initialize()
            return self.initialized
        except Exception as e:
            logger.error(f"Failed to initialize cluster analyzer: {e}")
            return False
    
    def analyze_cluster(self) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of the cluster
        
        Returns:
            Dict containing analysis results
        """
        if not self.initialized:
            raise Exception("Cluster analyzer not initialized")
        
        try:
            results = {
                'high_priority': [],
                'medium_priority': [],
                'low_priority': [],
                'passed_checks': [],
                'failed_checks': [],
                'cluster_info': {}
            }
            
            # Get basic cluster information
            results['cluster_info'] = self._get_cluster_info()
            
            # Analyze workloads
            workload_results = self._analyze_workloads()
            results['high_priority'].extend(workload_results.get('high_priority', []))
            results['medium_priority'].extend(workload_results.get('medium_priority', []))
            results['low_priority'].extend(workload_results.get('low_priority', []))
            results['passed_checks'].extend(workload_results.get('passed_checks', []))
            results['failed_checks'].extend(workload_results.get('failed_checks', []))
            
            # Analyze security
            security_results = self._analyze_security()
            results['high_priority'].extend(security_results.get('high_priority', []))
            results['medium_priority'].extend(security_results.get('medium_priority', []))
            results['low_priority'].extend(security_results.get('low_priority', []))
            results['passed_checks'].extend(security_results.get('passed_checks', []))
            results['failed_checks'].extend(security_results.get('failed_checks', []))
            
            # Analyze networking
            networking_results = self._analyze_networking()
            results['high_priority'].extend(networking_results.get('high_priority', []))
            results['medium_priority'].extend(networking_results.get('medium_priority', []))
            results['low_priority'].extend(networking_results.get('low_priority', []))
            results['passed_checks'].extend(networking_results.get('passed_checks', []))
            results['failed_checks'].extend(networking_results.get('failed_checks', []))
            
            # Analyze resource usage
            resource_results = self._analyze_resource_usage()
            results['high_priority'].extend(resource_results.get('high_priority', []))
            results['medium_priority'].extend(resource_results.get('medium_priority', []))
            results['low_priority'].extend(resource_results.get('low_priority', []))
            results['passed_checks'].extend(resource_results.get('passed_checks', []))
            results['failed_checks'].extend(resource_results.get('failed_checks', []))
            
            return results
        except Exception as e:
            logger.warning(f"Error analyzing cluster: {e}")
            raise
    
    def _get_cluster_info(self) -> Dict[str, Any]:
        """Get basic cluster information"""
        try:
            namespaces = self.k8s_client.get_all_namespaces()
            pods = self.k8s_client.get_all_pods()
            deployments = self.k8s_client.get_all_deployments()
            services = self.k8s_client.get_all_services()
            
            return {
                'namespaces': len(namespaces),
                'pods': len(pods),
                'deployments': len(deployments),
                'services': len(services),
                'namespace_list': namespaces
            }
        except Exception as e:
            logger.error(f"Error getting cluster info: {e}")
            return {}
    
    def _analyze_workloads(self) -> Dict[str, Any]:
        """Analyze workloads in the cluster"""
        results = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'passed_checks': [],
            'failed_checks': []
        }
        
        try:
            # Get all pods
            pods = self.k8s_client.get_all_pods()
            
            # Check for privileged containers
            privileged_pods = [pod for pod in pods if any(container.get('privileged', False) for container in pod['containers'])]
            if privileged_pods:
                results['high_priority'].append({
                    'category': 'Security',
                    'title': 'Privileged Containers Detected',
                    'description': f'Found {len(privileged_pods)} pods running with privileged containers',
                    'impact': 'Privileged containers can escape container isolation and access host resources',
                    'action_items': [
                        'Remove privileged flag from container security contexts',
                        'Use more specific capabilities instead of privileged mode',
                        'Implement Pod Security Standards to prevent privileged containers'
                    ],
                    'affected_resources': [f"{pod['namespace']}/{pod['name']}" for pod in privileged_pods[:5]]
                })
                results['failed_checks'].append({
                    'check': 'Privileged Containers',
                    'status': 'FAILED'
                })
            else:
                results['passed_checks'].append({
                    'check': 'Privileged Containers',
                    'status': 'PASSED'
                })
            
            # Check for resource requests and limits
            pods_without_resources = [pod for pod in pods if any(not container.get('resources', {}) for container in pod['containers'])]
            if pods_without_resources:
                results['medium_priority'].append({
                    'category': 'Resource Management',
                    'title': 'Missing Resource Requests and Limits',
                    'description': f'Found {len(pods_without_resources)} pods without resource requests or limits',
                    'impact': 'Pods without resource constraints can consume excessive resources and cause cluster instability',
                    'action_items': [
                        'Define resource requests and limits for all containers',
                        'Implement LimitRange objects for namespaces',
                        'Use ResourceQuotas to limit namespace resource consumption'
                    ],
                    'affected_resources': [f"{pod['namespace']}/{pod['name']}" for pod in pods_without_resources[:5]]
                })
                results['failed_checks'].append({
                    'check': 'Resource Constraints',
                    'status': 'FAILED'
                })
            else:
                results['passed_checks'].append({
                    'check': 'Resource Constraints',
                    'status': 'PASSED'
                })
            
            # Get all deployments
            deployments = self.k8s_client.get_all_deployments()
            
            # Check for single replica deployments
            single_replica_deployments = [deployment for deployment in deployments if deployment['replicas'] == 1]
            if single_replica_deployments:
                results['medium_priority'].append({
                    'category': 'Reliability',
                    'title': 'Single Replica Deployments',
                    'description': f'Found {len(single_replica_deployments)} deployments with only one replica',
                    'impact': 'Single replica deployments have no high availability and can cause service disruptions during updates or node failures',
                    'action_items': [
                        'Increase replica count to at least 2 for important services',
                        'Implement Pod Disruption Budgets to ensure availability during updates',
                        'Use Horizontal Pod Autoscaler for dynamic scaling'
                    ],
                    'affected_resources': [f"{deployment['namespace']}/{deployment['name']}" for deployment in single_replica_deployments[:5]]
                })
                results['failed_checks'].append({
                    'check': 'Deployment Replicas',
                    'status': 'FAILED'
                })
            else:
                results['passed_checks'].append({
                    'check': 'Deployment Replicas',
                    'status': 'PASSED'
                })
            
            return results
        except Exception as e:
            logger.error(f"Error analyzing workloads: {e}")
            return results
    
    def _analyze_security(self) -> Dict[str, Any]:
        """Analyze security configuration in the cluster"""
        results = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'passed_checks': [],
            'failed_checks': []
        }
        
        try:
            # Check Pod Security Standards
            pss_namespaces = self.k8s_client.get_pod_security_standards()
            if not pss_namespaces:
                results['high_priority'].append({
                    'category': 'Security',
                    'title': 'Pod Security Standards Not Enforced',
                    'description': 'No namespaces have Pod Security Standards labels',
                    'impact': 'Pods may run with excessive privileges, increasing security risks',
                    'action_items': [
                        'Enable Pod Security Standards for all namespaces',
                        'Use "baseline" or "restricted" profiles for production namespaces',
                        'Configure audit and warning modes to identify violations'
                    ]
                })
                results['failed_checks'].append({
                    'check': 'Pod Security Standards',
                    'status': 'FAILED'
                })
            else:
                # Check if default namespace has PSS
                default_ns_pss = next((ns for ns in pss_namespaces if ns['namespace'] == 'default'), None)
                if not default_ns_pss:
                    results['medium_priority'].append({
                        'category': 'Security',
                        'title': 'Pod Security Standards Not Enforced in Default Namespace',
                        'description': 'The default namespace does not have Pod Security Standards labels',
                        'impact': 'Pods in the default namespace may run with excessive privileges',
                        'action_items': [
                            'Enable Pod Security Standards for the default namespace',
                            'Use at least "baseline" profile for the default namespace',
                            'Consider using "restricted" profile for production workloads'
                        ]
                    })
                    results['failed_checks'].append({
                        'check': 'Default Namespace Security',
                        'status': 'FAILED'
                    })
                else:
                    results['passed_checks'].append({
                        'check': 'Default Namespace Security',
                        'status': 'PASSED'
                    })
            
            # Check RBAC configuration
            cluster_roles = self.k8s_client.get_cluster_roles()
            cluster_role_bindings = self.k8s_client.get_cluster_role_bindings()
            
            # Check for wildcard permissions
            wildcard_roles = [role for role in cluster_roles if any(
                '*' in rule.get('resources', []) or '*' in rule.get('verbs', []) 
                for rule in role.get('rules', [])
            )]
            
            if wildcard_roles:
                results['high_priority'].append({
                    'category': 'Security',
                    'title': 'Wildcard Permissions in RBAC Roles',
                    'description': f'Found {len(wildcard_roles)} cluster roles with wildcard permissions',
                    'impact': 'Excessive permissions increase the risk of privilege escalation and unauthorized access',
                    'action_items': [
                        'Review and restrict wildcard permissions in RBAC roles',
                        'Follow principle of least privilege for all service accounts',
                        'Use specific resources and verbs instead of wildcards'
                    ],
                    'affected_resources': [role['name'] for role in wildcard_roles[:5]]
                })
                results['failed_checks'].append({
                    'check': 'RBAC Wildcard Permissions',
                    'status': 'FAILED'
                })
            else:
                results['passed_checks'].append({
                    'check': 'RBAC Wildcard Permissions',
                    'status': 'PASSED'
                })
            
            return results
        except Exception as e:
            logger.error(f"Error analyzing security: {e}")
            return results
    
    def _analyze_networking(self) -> Dict[str, Any]:
        """Analyze networking configuration in the cluster"""
        results = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'passed_checks': [],
            'failed_checks': []
        }
        
        try:
            # Check for network policies
            network_policies = self.k8s_client.get_all_network_policies()
            if not network_policies:
                results['high_priority'].append({
                    'category': 'Network Security',
                    'title': 'No Network Policies Defined',
                    'description': 'No network policies found in the cluster',
                    'impact': 'All pods can communicate with each other without restrictions',
                    'action_items': [
                        'Implement default deny network policies for all namespaces',
                        'Create specific network policies for required communication paths',
                        'Use namespace isolation for multi-tenant clusters'
                    ]
                })
                results['failed_checks'].append({
                    'check': 'Network Policies',
                    'status': 'FAILED'
                })
            else:
                # Check if default namespace has network policies
                default_ns_policies = [policy for policy in network_policies if policy['namespace'] == 'default']
                if not default_ns_policies:
                    results['medium_priority'].append({
                        'category': 'Network Security',
                        'title': 'No Network Policies in Default Namespace',
                        'description': 'No network policies found in the default namespace',
                        'impact': 'Pods in the default namespace can communicate without restrictions',
                        'action_items': [
                            'Implement network policies for the default namespace',
                            'Create a default deny policy as a baseline',
                            'Add specific allow rules for required communication'
                        ]
                    })
                    results['failed_checks'].append({
                        'check': 'Default Namespace Network Policies',
                        'status': 'FAILED'
                    })
                else:
                    results['passed_checks'].append({
                        'check': 'Default Namespace Network Policies',
                        'status': 'PASSED'
                    })
            
            # Check for services with external IPs
            services = self.k8s_client.get_all_services()
            external_services = [service for service in services if service['type'] in ['LoadBalancer', 'NodePort']]
            if external_services:
                results['medium_priority'].append({
                    'category': 'Network Security',
                    'title': 'Services Exposed Externally',
                    'description': f'Found {len(external_services)} services exposed externally',
                    'impact': 'Externally exposed services increase the attack surface',
                    'action_items': [
                        'Review and limit externally exposed services',
                        'Use internal load balancers where possible',
                        'Implement ingress controllers with proper security controls'
                    ],
                    'affected_resources': [f"{service['namespace']}/{service['name']}" for service in external_services[:5]]
                })
                results['failed_checks'].append({
                    'check': 'External Service Exposure',
                    'status': 'FAILED'
                })
            else:
                results['passed_checks'].append({
                    'check': 'External Service Exposure',
                    'status': 'PASSED'
                })
            
            return results
        except Exception as e:
            logger.error(f"Error analyzing networking: {e}")
            return results
    
    def _analyze_resource_usage(self) -> Dict[str, Any]:
        """Analyze resource usage in the cluster"""
        results = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'passed_checks': [],
            'failed_checks': []
        }
        
        try:
            # Get all pods
            pods = self.k8s_client.get_all_pods()
            
            # Check for pods in pending state
            pending_pods = [pod for pod in pods if pod['status'] == 'Pending']
            if pending_pods:
                results['high_priority'].append({
                    'category': 'Resource Management',
                    'title': 'Pending Pods Detected',
                    'description': f'Found {len(pending_pods)} pods in pending state',
                    'impact': 'Pending pods indicate resource constraints or configuration issues',
                    'action_items': [
                        'Check node resources and scale up if necessary',
                        'Review pod resource requests and limits',
                        'Check for node taints or pod affinity/anti-affinity issues'
                    ],
                    'affected_resources': [f"{pod['namespace']}/{pod['name']}" for pod in pending_pods[:5]]
                })
                results['failed_checks'].append({
                    'check': 'Pending Pods',
                    'status': 'FAILED'
                })
            else:
                results['passed_checks'].append({
                    'check': 'Pending Pods',
                    'status': 'PASSED'
                })
            
            # Check for pods not in Running state
            non_running_pods = [pod for pod in pods if pod['status'] not in ['Running', 'Succeeded', 'Pending']]
            if non_running_pods:
                results['high_priority'].append({
                    'category': 'Reliability',
                    'title': 'Pods in Failed or Unknown State',
                    'description': f'Found {len(non_running_pods)} pods not in Running or Succeeded state',
                    'impact': 'Failed pods indicate application or configuration issues',
                    'action_items': [
                        'Check pod logs for error messages',
                        'Review pod events for failure reasons',
                        'Check container image and configuration'
                    ],
                    'affected_resources': [f"{pod['namespace']}/{pod['name']}" for pod in non_running_pods[:5]]
                })
                results['failed_checks'].append({
                    'check': 'Pod Status',
                    'status': 'FAILED'
                })
            else:
                results['passed_checks'].append({
                    'check': 'Pod Status',
                    'status': 'PASSED'
                })
            
            return results
        except Exception as e:
            logger.error(f"Error analyzing resource usage: {e}")
            return results