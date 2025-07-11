import re
import logging
import json
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional

# Specific imports to avoid broad library imports
import requests
from bs4 import BeautifulSoup
from ..config.constants import BEST_PRACTICES_URLS

# Import specific MCP components if they exist
try:
    from ..mcp import MCPSchemas, MCPContextProcessor
except ImportError:
    # Fallback if MCP module doesn't exist
    class MCPSchemas:
        CLUSTER_CONTEXT = {}
        RECOMMENDATION = {}
    
    class MCPContextProcessor:
        @staticmethod
        def extract_reasoning(rec):
            return rec.get('description', 'No reasoning provided')
        
        @staticmethod
        def format_context(cluster_context, recommendations):
            return {'cluster': cluster_context, 'recommendations': recommendations}

logger = logging.getLogger(__name__)

class EKSBestPracticesAnalyzer:
    def __init__(self):
        self.best_practices_urls = BEST_PRACTICES_URLS
        self.best_practices_cache = {}
        self.latest_k8s_version = "1.29"  # This should be dynamically fetched
        self.recommendations_cache = self._initialize_recommendations()
        try:
            self.mcp_schemas = MCPSchemas()
        except Exception:
            self.mcp_schemas = type('MCPSchemas', (), {'CLUSTER_CONTEXT': {}, 'RECOMMENDATION': {}})()
    
    def _sanitize_log_input(self, text: str) -> str:
        """Sanitize input for logging to prevent log injection."""
        if not isinstance(text, str):
            return str(text)
        # Remove newlines and control characters
        sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
        return sanitized[:200]  # Limit length

    def _initialize_recommendations(self):
        """Initialize comprehensive recommendations database"""
        return {
            'Security': self._get_security_recommendations(),
            'Networking': self._get_networking_recommendations(),
            'Cost_optimization': self._get_cost_recommendations(),
            'Reliability': self._get_reliability_recommendations(),
            'Performance': self._get_performance_recommendations(),
            'Operations': self._get_operations_recommendations(),
            'Compliance': self._get_compliance_recommendations(),
            'Addons': self._get_addons_recommendations(),
            'Upgrade': self._get_upgrade_recommendations()
        }

    def _create_cluster_context(self, cluster_details: Dict[str, Any]) -> Dict[str, Any]:
        """Create structured MCP context from cluster details"""
        # Extract relevant information from cluster_details
        context = {
            "cluster_name": cluster_details.get('cluster', {}).get('name', ''),
            "kubernetes_version": cluster_details.get('version_info', {}).get('current', ''),
            "region": cluster_details.get('cluster', {}).get('region', ''),
            "networking": {
                "vpc_id": cluster_details.get('networking', {}).get('vpc_id', ''),
                "endpoint_public_access": cluster_details.get('networking', {}).get('endpoint_access', {}).get('public', False),
                "endpoint_private_access": cluster_details.get('networking', {}).get('endpoint_access', {}).get('private', False),
                "network_policies_enabled": bool(cluster_details.get('networking', {}).get('network_policies', False)),
                "custom_networking_enabled": bool(cluster_details.get('networking', {}).get('pod_networking', {}).get('custom_networking', False))
            },
            "security": {
                "secrets_encryption": bool(cluster_details.get('security', {}).get('encryption', {}).get('secrets', False)),
                "oidc_provider": bool(cluster_details.get('security', {}).get('iam', {}).get('oidc_provider', False)),
                "audit_logging": bool(cluster_details.get('security', {}).get('audit', {}).get('enabled', False))
            },
            "nodegroups": [],
            "addons": []
        }
        
        # Add nodegroups
        for ng in cluster_details.get('nodegroups', []):
            context["nodegroups"].append({
                "name": ng.get('name', ''),
                "capacity_type": ng.get('capacityType', ''),
                "instance_type": ng.get('instanceType', ''),
                "availability_zones": ng.get('subnets', [])
            })
            
        # Add addons
        for addon in cluster_details.get('addons', []):
            context["addons"].append({
                "name": addon.get('name', ''),
                "version": addon.get('version', '')
            })
            
        return context

    def analyze_cluster(self, cluster_details, inputs):
        """Comprehensive analysis of cluster state and configuration using MCP"""
        # Create structured context for the cluster
        cluster_context = self._create_cluster_context(cluster_details)
        
        analysis_results = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'recommendations': [],
            'mcp_context': {
                'cluster': cluster_context,
                'schema': getattr(self.mcp_schemas, 'CLUSTER_CONTEXT', {})
            }
        }

        # Core components analysis with MCP context
        self._analyze_version(cluster_details.get('version_info', {}), analysis_results)
        self._analyze_networking(cluster_details.get('networking', {}), analysis_results)
        self._analyze_security(cluster_details.get('security', {}), analysis_results)
        self._analyze_nodegroups(cluster_details.get('nodegroups', []), analysis_results)
        self._analyze_addons(cluster_details.get('addons', []), analysis_results)
        self._analyze_workloads(cluster_details.get('workloads', {}), analysis_results)

        # Additional analysis areas
        self._analyze_cost_optimization(cluster_details, inputs, analysis_results)
        self._analyze_reliability(cluster_details, inputs, analysis_results)
        self._analyze_performance(cluster_details.get('metrics', {}), analysis_results)
        self._analyze_operational_excellence(cluster_details, inputs, analysis_results)
        self._analyze_compliance(cluster_details, inputs, analysis_results)
        
        # Add user input based recommendations
        self._analyze_user_inputs(inputs, analysis_results)
        
        # Add MCP schema for recommendations
        analysis_results['mcp_recommendation_schema'] = getattr(self.mcp_schemas, 'RECOMMENDATION', {})
        
        # Process recommendations for MCP
        all_recommendations = []
        for priority in ['high_priority', 'medium_priority', 'low_priority']:
            for rec in analysis_results[priority]:
                # Ensure all recommendations have reasoning
                if 'reasoning' not in rec:
                    try:
                        rec['reasoning'] = MCPContextProcessor.extract_reasoning(rec)
                    except Exception:
                        rec['reasoning'] = rec.get('description', 'No reasoning provided')
                all_recommendations.append(rec)
        
        # Add formatted MCP context if available
        try:
            analysis_results['mcp_formatted_context'] = MCPContextProcessor.format_context(
                cluster_context, 
                all_recommendations
            )
        except Exception as e:
            logger.warning(f"MCP context formatting failed: {self._sanitize_log_input(str(e))}")
            analysis_results['mcp_formatted_context'] = {'cluster': cluster_context, 'recommendations': all_recommendations}

        return analysis_results

    def _analyze_version(self, version_info, results):
        """Analyze Kubernetes version and provide recommendations with MCP context"""
        current_version = version_info.get('current', '')
        if not current_version:
            return

        # Version upgrade recommendations
        if current_version < self.latest_k8s_version:
            recommendation = {
                'category': 'Operations',
                'title': 'Kubernetes Version Upgrade Required',
                'description': f"Current version {current_version} is behind latest {self.latest_k8s_version}",
                'impact': 'Missing security patches and feature updates',
                'action_items': [
                    f'Plan upgrade to version {self.latest_k8s_version}',
                    'Review breaking changes in new version',
                    'Schedule maintenance window',
                    'Test upgrade process in non-production environment',
                    'Update add-ons to compatible versions',
                    'Review deprecated API usage'
                ],
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html',
                'priority': 'High',
                'reasoning': f"The cluster is running Kubernetes {current_version} which is {int(float(self.latest_k8s_version) - float(current_version))} minor versions behind the latest available version {self.latest_k8s_version}. Newer versions contain important security patches and feature updates."
            }
            results['high_priority'].append(recommendation)
            
            # Add upgrade best practices
            recommendation = {
                'category': 'Operations',
                'title': 'Implement Upgrade Best Practices',
                'description': 'Comprehensive upgrade strategy recommended',
                'impact': 'Smoother upgrades with minimal disruption',
                'action_items': [
                    'Keep your cluster up-to-date with regular updates',
                    'Review the EKS release calendar for planning',
                    'Upgrade control plane and data plane in sequence',
                    'Use tools like Kube-no-trouble and Pluto for cluster insights',
                    'Configure PodDisruptionBudgets and topologySpreadConstraints',
                    'Use Managed Node Groups or Karpenter for simpler data plane upgrades',
                    'Backup the cluster before upgrading',
                    'Create a detailed upgrade checklist'
                ],
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html',
                'priority': 'Medium',
                'reasoning': 'Following best practices for EKS upgrades reduces the risk of service disruption and ensures a smoother upgrade process. A comprehensive upgrade strategy is essential for maintaining cluster health and stability.'
            }
            results['medium_priority'].append(recommendation)

        # End of support warnings
        if current_version <= "1.23":
            recommendation = {
                'category': 'Operations',
                'title': 'Kubernetes Version End of Support',
                'description': f'Version {current_version} has reached end of support',
                'impact': 'No security updates or bug fixes available',
                'action_items': [
                    'Immediately plan upgrade to supported version',
                    'Review application compatibility',
                    'Schedule emergency upgrade window',
                    'Update deprecated API usage'
                ],
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html',
                'priority': 'High',
                'reasoning': f'Kubernetes version {current_version} has reached end of support and is no longer receiving security updates or bug fixes. Running unsupported versions poses significant security and stability risks to the cluster.'
            }
            results['high_priority'].append(recommendation)
            
        # Version-specific deprecation warnings
        if current_version < "1.25":
            results['high_priority'].append({
                'category': 'Operations',
                'title': 'Critical Kubernetes Deprecations',
                'description': 'Upcoming version contains breaking changes',
                'impact': 'Application disruption if not addressed before upgrade',
                'action_items': [
                    'Address Dockershim removal in 1.25 - Use Detector for Docker Socket (DDS)',
                    'Migrate from PodSecurityPolicy in 1.25 to Pod Security Standards',
                    'Migrate from In-Tree Storage Driver in 1.23 to Container Storage Interface (CSI) Drivers',
                    'Update Kubernetes workloads using kubectl-convert',
                    'Test applications against future Kubernetes versions'
                ],
                'reference': 'https://kubernetes.io/docs/reference/using-api/deprecation-guide/'
            })

    def _analyze_networking(self, networking, results):
        """Analyze networking configuration and provide recommendations"""
        # Check endpoint access
        if networking.get('endpoint_access', {}).get('public', False):
            results['high_priority'].append({
                'category': 'Networking',
                'title': 'Public Endpoint Access Enabled',
                'description': 'Cluster API endpoint is publicly accessible',
                'impact': 'Increased attack surface and security risk',
                'action_items': [
                    'Enable private endpoint access',
                    'Disable public endpoint access if not required',
                    'If public access is needed, restrict to specific CIDRs',
                    'Implement VPN or Direct Connect for cluster access',
                    'Enable API server logging'
                ],
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html'
            })

        # Check CNI configuration
        cni_config = networking.get('pod_networking', {})
        if not cni_config.get('custom_networking'):
            results['medium_priority'].append({
                'category': 'Networking',
                'title': 'Standard CNI Configuration',
                'description': 'Using default VPC CNI settings',
                'impact': 'Potential IP address exhaustion and scaling limitations',
                'action_items': [
                    'Enable custom networking',
                    'Configure secondary CIDR blocks',
                    'Enable prefix delegation',
                    'Configure security groups for pods',
                    'Optimize MTU settings'
                ],
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/cni-custom-network.html'
            })

        # Check network policies
        if not networking.get('network_policies'):
            results['high_priority'].append({
                'category': 'Networking',
                'title': 'Network Policies Not Implemented',
                'description': 'No network policies defined for pod communication',
                'impact': 'Unrestricted pod-to-pod communication',
                'action_items': [
                    'Install Calico or AWS VPC CNI network policy',
                    'Define default deny policies',
                    'Implement namespace isolation',
                    'Create application-specific network policies',
                    'Monitor policy violations'
                ],
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/calico.html'
            })

    def _analyze_security(self, security, results):
        """Analyze security configuration and provide recommendations"""
        # Check encryption configuration
        if not security.get('encryption', {}).get('secrets'):
            results['high_priority'].append({
                'category': 'Security',
                'title': 'Secrets Encryption Not Enabled',
                'description': 'Kubernetes secrets not encrypted at rest',
                'impact': 'Sensitive data vulnerable to unauthorized access',
                'action_items': [
                    'Enable envelope encryption using KMS',
                    'Create dedicated KMS key for secrets',
                    'Enable automatic key rotation',
                    'Implement secret rotation',
                    'Use external secrets management'
                ],
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/enable-secrets-encryption.html'
            })

        # Check IAM configuration
        if not security.get('iam', {}).get('oidc_provider'):
            results['high_priority'].append({
                'category': 'Security',
                'title': 'IRSA Not Configured',
                'description': 'IAM roles for service accounts not set up',
                'impact': 'Pods using instance roles with broad permissions',
                'action_items': [
                    'Create IAM OIDC provider',
                    'Create IAM roles for service accounts',
                    'Configure pod service accounts',
                    'Implement least privilege access',
                    'Audit IAM role usage'
                ],
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html'
            })

    def _analyze_nodegroups(self, nodegroups, results):
        """Analyze node groups and provide recommendations"""
        for ng in nodegroups:
            # Check capacity type
            if ng.get('capacityType') == 'ON_DEMAND':
                results['medium_priority'].append({
                    'category': 'Cost Optimization',
                    'title': f"Spot Instance Opportunity for {ng['name']}",
                    'description': 'Node group using only On-Demand instances',
                    'impact': 'Higher compute costs',
                    'action_items': [
                        'Evaluate workloads for Spot compatibility',
                        'Create Spot node group',
                        'Implement interruption handling',
                        'Use instance diversity',
                        'Configure capacity rebalancing'
                    ],
                    'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html#spot-capacity'
                })

            # Check availability zones
            if len(ng.get('subnets', [])) < 3:
                results['high_priority'].append({
                    'category': 'Reliability',
                    'title': f"Limited Availability Zones for {ng['name']}",
                    'description': 'Node group not using all available AZs',
                    'impact': 'Reduced fault tolerance',
                    'action_items': [
                        'Spread nodes across all AZs',
                        'Update launch template',
                        'Configure pod topology spread constraints',
                        'Implement node anti-affinity',
                        'Use Cluster Autoscaler or Karpenter'
                    ],
                    'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/create-managed-node-group.html'
                })

    def _analyze_addons(self, addons, results):
        """Analyze cluster add-ons and provide recommendations"""
        addon_recommendations = {
            'vpc-cni': {
                'title': 'VPC CNI Version',
                'min_version': '1.12.0',
                'description': 'AWS VPC CNI should be updated',
                'impact': 'Missing security fixes and features',
                'category': 'Networking'
            },
            'kube-proxy': {
                'title': 'kube-proxy Version',
                'min_version': '1.12.0',
                'description': 'kube-proxy should be updated',
                'impact': 'Networking performance and security issues',
                'category': 'Networking'
            },
            'coredns': {
                'title': 'CoreDNS Version',
                'min_version': '1.8.7',
                'description': 'CoreDNS should be updated',
                'impact': 'DNS resolution performance and security',
                'category': 'Networking'
            }
        }

        for addon in addons:
            name = addon.get('name')
            if name in addon_recommendations:
                rec = addon_recommendations[name]
                if addon.get('version') < rec['min_version']:
                    results['medium_priority'].append({
                        'category': rec['category'],
                        'title': rec['title'],
                        'description': rec['description'],
                        'impact': rec['impact'],
                        'action_items': [
                            f'Update {name} to latest version',
                            'Review compatibility',
                            'Schedule maintenance window',
                            'Monitor for issues after update'
                        ],
                        'reference': f'https://docs.aws.amazon.com/eks/latest/userguide/managing-{name}.html'
                    })

    def _analyze_cost_optimization(self, cluster_details, inputs, results):
        """Analyze cost optimization opportunities"""
        # Check for cost optimization opportunities
        cost_checks = [
            {
                'check': lambda x: not any('spot' in ng.get('capacityType', '').lower() 
                                         for ng in x.get('nodegroups', [])),
                'title': 'No Spot Instances Usage',
                'description': 'Cluster not utilizing Spot instances',
                'impact': 'Higher compute costs',
                'action_items': [
                    'Identify Spot-compatible workloads',
                    'Create Spot node groups',
                    'Implement interruption handling',
                    'Use capacity-optimized allocation strategy',
                    'Monitor Spot savings'
                ]
            },
            {
                'check': lambda x: not x.get('cluster', {}).get('logging', {}).get('types'),
                'title': 'Control Plane Logging Disabled',
                'description': 'Cluster logging not enabled',
                'impact': 'Limited visibility and troubleshooting capability',
                'action_items': [
                    'Enable control plane logging',
                    'Configure log retention',
                    'Set up log analysis',
                    'Monitor logging costs',
                    'Implement log aggregation'
                ]
            }
        ]

        for check in cost_checks:
            if check['check'](cluster_details):
                results['medium_priority'].append({
                    'category': 'Cost Optimization',
                    'title': check['title'],
                    'description': check['description'],
                    'impact': check['impact'],
                    'action_items': check['action_items'],
                    'reference': 'https://aws.github.io/aws-eks-best-practices/cost_optimization/'
                })

    def _analyze_reliability(self, cluster_details, inputs, results):
        """Analyze cluster reliability"""
        reliability_checks = [
            {
                'check': lambda x: len(x.get('nodegroups', [])) < 2,
                'title': 'Single Node Group Configuration',
                'description': 'Cluster using single node group',
                'impact': 'Limited failure isolation and scaling flexibility',
                'action_items': [
                    'Create separate node groups for different workloads',
                    'Implement node group autoscaling',
                    'Configure pod disruption budgets',
                    'Use node selectors and taints',
                    'Plan for node group updates'
                ]
            },
            {
                'check': lambda x: not x.get('cluster', {}).get('endpointPrivateAccess'),
                'title': 'No Private Endpoint Access',
                'description': 'Cluster endpoint only accessible publicly',
                'impact': 'Reduced network reliability and security',
                'action_items': [
                    'Enable private endpoint access',
                    'Configure VPC endpoints',
                    'Set up VPN or Direct Connect',
                    'Implement proper DNS resolution',
                    'Monitor endpoint availability'
                ]
            }
        ]

        for check in reliability_checks:
            if check['check'](cluster_details):
                results['high_priority'].append({
                    'category': 'Reliability',
                    'title': check['title'],
                    'description': check['description'],
                    'impact': check['impact'],
                    'action_items': check['action_items'],
                    'reference': 'https://aws.github.io/aws-eks-best-practices/reliability/'
                })

    def _analyze_performance(self, metrics, results):
        """Analyze cluster performance"""
        if not metrics:
            return

        # Check CPU utilization
        cpu_util = metrics.get('cpu', {}).get('Average', 0)
        if cpu_util > 80:
            results['high_priority'].append({
                'category': 'Performance',
                'title': 'High CPU Utilization',
                'description': f'Average CPU utilization at {cpu_util}%',
                'impact': 'Risk of performance degradation',
                'action_items': [
                    'Analyze workload resource usage',
                    'Configure horizontal pod autoscaling',
                    'Optimize container resource requests',
                    'Consider vertical pod autoscaling',
                    'Evaluate node sizing'
                ],
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/horizontal-pod-autoscaler.html'
            })

        # Check memory utilization
        mem_util = metrics.get('memory', {}).get('Average', 0)
        if mem_util > 80:
            results['high_priority'].append({
                'category': 'Performance',
                'title': 'High Memory Utilization',
                'description': f'Average memory utilization at {mem_util}%',
                'impact': 'Risk of OOM kills and performance issues',
                'action_items': [
                    'Analyze workload memory usage',
                    'Adjust container memory limits',
                    'Implement memory-based HPA',
                    'Consider memory-optimized instance types',
                    'Monitor for memory leaks'
                ],
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/vertical-pod-autoscaler.html'
            })

    def _analyze_operational_excellence(self, cluster_details, inputs, results):
        """Analyze operational practices"""
        ops_checks = [
            {
                'check': lambda x: not x.get('cluster', {}).get('logging', {}).get('types'),
                'title': 'Control Plane Logging Disabled',
                'description': 'Cluster control plane logging not enabled',
                'impact': 'Limited visibility and troubleshooting capability',
                'action_items': [
                    'Enable control plane logging',
                    'Set up log analysis',
                    'Configure alerts on critical log events',
                    'Implement log retention policy',
                    'Use AWS CloudWatch Logs Insights'
                ]
            },
            {
                'check': lambda x: 'container insights' not in str(x).lower(),
                'title': 'Container Insights Not Enabled',
                'description': 'Container Insights monitoring not detected',
                'impact': 'Limited visibility into container performance',
                'action_items': [
                    'Enable Container Insights',
                    'Set up custom dashboards',
                    'Configure performance alarms',
                    'Implement log correlation',
                    'Use CloudWatch Anomaly Detection'
                ]
            }
        ]

        for check in ops_checks:
            if check['check'](cluster_details):
                results['medium_priority'].append({
                    'category': 'Operational Excellence',
                    'title': check['title'],
                    'description': check['description'],
                    'impact': check['impact'],
                    'action_items': check['action_items'],
                    'reference': 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html'
                })

    def _analyze_compliance(self, cluster_details, inputs, results):
        """Analyze compliance and governance"""
        compliance_checks = [
            {
                'check': lambda x: not x.get('security', {}).get('encryption', {}).get('secrets'),
                'title': 'Secrets Encryption Not Enabled',
                'description': 'Kubernetes secrets not encrypted at rest',
                'impact': 'Non-compliance with data protection regulations',
                'action_items': [
                    'Enable envelope encryption for secrets',
                    'Use AWS KMS for key management',
                    'Implement secret rotation',
                    'Audit secret access',
                    'Consider using AWS Secrets Manager'
                ]
            },
            {
                'check': lambda x: not x.get('security', {}).get('audit', {}).get('enabled'),
                'title': 'Kubernetes Audit Logging Disabled',
                'description': 'Kubernetes API server audit logging not enabled',
                'impact': 'Limited ability to track and audit cluster activities',
                'action_items': [
                    'Enable Kubernetes audit logging',
                    'Configure audit log retention',
                    'Set up log analysis for compliance',
                    'Implement automated compliance checks',
                    'Regular review of audit logs'
                ]
            }
        ]

        for check in compliance_checks:
            if check['check'](cluster_details):
                results['high_priority'].append({
                    'category': 'Compliance',
                    'title': check['title'],
                    'description': check['description'],
                    'impact': check['impact'],
                    'action_items': check['action_items'],
                    'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html'
                })

    def _analyze_workloads(self, workloads, results):
        """Analyze workload configurations"""
        # This is a placeholder. In a real implementation, you'd analyze actual workload data.
        pass

    def _analyze_user_inputs(self, inputs, results):
        """Analyze user inputs for potential issues"""
        for category, practices in self.recommendations_cache.items():
            for practice in practices:
                is_implemented = self._check_implementation(practice, inputs)
                if not is_implemented:
                    finding = {
                        'category': category,
                        'title': practice['title'],
                        'description': practice['description'],
                        'impact': practice['impact'],
                        'action_items': practice['action_items'],
                        'priority': practice['priority'],
                        'reference': practice['reference']
                    }
                    results[f"{practice['priority'].lower()}_priority"].append(finding)

    def _check_implementation(self, practice, inputs):
        """Check if a best practice is implemented based on user inputs"""
        for section in inputs.values():
            for content in section.values():
                if isinstance(content, str):
                    content_lower = content.lower()
                    if practice['check'](content_lower):
                        return True
        return False

    def fetch_best_practices(self) -> None:
        """Fetch and parse best practices from AWS documentation with proper resource management."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'EKS-Operational-Review-Agent/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        
        try:
            for category, urls in self.best_practices_urls.items():
                try:
                    if isinstance(urls, dict):
                        main_url = urls.get("main")
                        if main_url and self._is_valid_url(main_url):
                            # Add timeout and size limits for security
                            response = session.get(
                                main_url, 
                                timeout=30,
                                stream=True,
                                allow_redirects=True
                            )
                            response.raise_for_status()
                            
                            # Check content size to prevent memory exhaustion
                            content_length = response.headers.get('content-length')
                            if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB limit
                                logger.warning(f"Content too large for {main_url}, skipping")
                                continue
                            
                            # Read content with size limit
                            content = response.text[:1024 * 1024]  # 1MB limit
                            
                            self.best_practices_cache[category] = [{
                                'title': f'{category.replace("_", " ").title()} Best Practices',
                                'content': f'Refer to AWS documentation at: {main_url}',
                                'priority': self._determine_priority(category),
                                'url': main_url
                            }]
                            
                            if 'text/html' in response.headers.get('content-type', ''):
                                soup = BeautifulSoup(content, 'html.parser')
                                parsed_content = self._parse_content(soup)
                                self.best_practices_cache[category].extend(parsed_content[:50])  # Limit results
                        
                except (requests.RequestException, ValueError) as e:
                    logger.error(f"Error fetching best practices for {category}: {e}")
                    self.best_practices_cache[category] = [{
                        'title': f'{category.replace("_", " ").title()} Best Practices',
                        'content': 'Unable to fetch best practices. Please refer to AWS documentation.',
                        'priority': 'Medium'
                    }]
                except Exception as e:
                    logger.error(f"Unexpected error fetching best practices for {category}: {e}")
                    self.best_practices_cache[category] = [{
                        'title': f'{category.replace("_", " ").title()} Best Practices',
                        'content': 'Error occurred while fetching best practices.',
                        'priority': 'Medium'
                    }]
        finally:
            session.close()

    def _parse_content(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Parse HTML content for best practices with resource limits.
        
        Args:
            soup: BeautifulSoup object to parse
            
        Returns:
            List of parsed practices
        """
        practices = []
        sections_processed = 0
        max_sections = 100  # Limit processing to prevent resource exhaustion
        
        try:
            for section in soup.find_all(['h2', 'h3']):
                if sections_processed >= max_sections:
                    logger.warning("Reached maximum section processing limit")
                    break
                    
                sections_processed += 1
                
                if self._is_valid_section(section.text):
                    practice = {
                        'title': section.text.strip()[:200],  # Limit title length
                        'content': '',
                        'priority': self._determine_priority(section.text)
                    }
                    
                    content_length = 0
                    max_content_length = 2000  # Limit content length
                    
                    next_elem = section.find_next_sibling()
                    while (next_elem and 
                           next_elem.name not in ['h2', 'h3'] and 
                           content_length < max_content_length):
                        if next_elem.text and next_elem.text.strip():
                            text_content = next_elem.text.strip()
                            remaining_space = max_content_length - content_length
                            if len(text_content) > remaining_space:
                                text_content = text_content[:remaining_space] + '...'
                            practice['content'] += text_content + '\n'
                            content_length += len(text_content)
                        next_elem = next_elem.find_next_sibling()
                    
                    if practice['content'].strip():  # Only add if has content
                        practices.append(practice)
        except Exception as e:
            logger.error(f"Error parsing content: {e}")
        
        return practices
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL to prevent SSRF attacks.
        
        Args:
            url: URL to validate
            
        Returns:
            bool: True if URL is valid and safe
        """
        try:
            parsed = urlparse(url)
            # Only allow HTTPS URLs from AWS domains
            if parsed.scheme != 'https':
                return False
            if not parsed.netloc.endswith(('.amazonaws.com', '.aws.amazon.com')):
                return False
            return True
        except Exception:
            return False

    def _is_valid_section(self, title):
        """Check if section is valid and not just a documentation heading"""
        invalid_patterns = [
            '¶', 'overview', 'introduction', 'how to use', 'further reading',
            'references', 'feedback', 'tools and resources', 'has moved', 'guide'
        ]
        return not any(pattern in title.lower() for pattern in invalid_patterns)

    def _determine_priority(self, title):
        """Determine priority based on keywords in title"""
        high_priority_keywords = ['security', 'encryption', 'authentication', 'critical', 'vulnerability']
        medium_priority_keywords = ['performance', 'optimization', 'monitoring', 'cost']
        
        title_lower = title.lower()
        if any(keyword in title_lower for keyword in high_priority_keywords):
            return 'High'
        elif any(keyword in title_lower for keyword in medium_priority_keywords):
            return 'Medium'
        return 'Low'

    def _get_security_recommendations(self):
        """Get security-specific recommendations"""
        return [
            {
                'title': 'Enable IRSA',
                'description': 'IAM Roles for Service Accounts not implemented',
                'impact': 'Overly permissive pod permissions',
                'check': lambda x: 'irsa' in x or 'iam roles for service accounts' in x,
                'action_items': [
                    'Enable IRSA for the cluster',
                    'Create IAM roles for each service account',
                    'Update pod specs to use service accounts',
                    'Implement least privilege access',
                    'Regularly audit IRSA usage'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html'
            },
            {
                'title': 'Implement Pod Security Standards',
                'description': 'Pod Security Standards not enforced',
                'impact': 'Pods may run with excessive privileges',
                'check': lambda x: 'pod security standard' in x or 'pss' in x,
                'action_items': [
                    'Enable Pod Security Admission',
                    'Define and apply Pod Security Standards',
                    'Use Security Context in pod specifications',
                    'Implement Pod Security Policies (for older K8s versions)',
                    'Regularly audit pod security configurations'
                ],
                'priority': 'High',
                'reference': 'https://kubernetes.io/docs/concepts/security/pod-security-standards/'
            },
            # Add more security recommendations...
        ]

    def _get_networking_recommendations(self):
        """Get networking-specific recommendations"""
        return [
            # Application Deployment
            {
                'title': 'Multi-AZ Deployment',
                'description': 'Applications not deployed across multiple availability zones',
                'impact': 'Reduced fault tolerance and availability',
                'check': lambda x: 'multi-az' in x or 'multiple availability zone' in x,
                'action_items': [
                    'Deploy nodes across multiple availability zones',
                    'Use topology spread constraints for pod distribution',
                    'Configure pod anti-affinity rules',
                    'Implement inter-AZ load balancing',
                    'Test failover scenarios'
                ],
                'priority': 'High',
                'reference': 'https://aws.github.io/aws-eks-best-practices/reliability/docs/dataplane/'
            },
            {
                'title': 'Private Subnet Deployment',
                'description': 'Nodes not deployed in private subnets',
                'impact': 'Increased security risk and exposure',
                'check': lambda x: 'private subnet' in x or 'private network' in x,
                'action_items': [
                    'Deploy nodes to private subnets',
                    'Configure NAT gateways for outbound traffic',
                    'Use VPC endpoints for AWS services',
                    'Implement proper security groups',
                    'Configure private DNS resolution'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html'
            },
            {
                'title': 'Cluster Endpoint Configuration',
                'description': 'Suboptimal cluster endpoint configuration',
                'impact': 'Security risks or accessibility issues',
                'check': lambda x: 'cluster endpoint' in x or 'endpoint access' in x,
                'action_items': [
                    'Consider public and private mode for cluster endpoint',
                    'Restrict public access to specific CIDRs',
                    'Enable private endpoint access',
                    'Use Cloud9 to access private clusters',
                    'Implement proper security groups for endpoint access'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html'
            },
            {
                'title': 'NAT Gateway Deployment',
                'description': 'NAT gateways not deployed in each availability zone',
                'impact': 'Single point of failure for outbound traffic',
                'check': lambda x: 'nat gateway' in x or 'nat gateways in each az' in x,
                'action_items': [
                    'Deploy NAT gateways in each availability zone',
                    'Configure route tables for each private subnet',
                    'Monitor NAT gateway performance',
                    'Consider NAT gateway bandwidth requirements',
                    'Implement NAT gateway high availability'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html'
            },
            {
                'title': 'VPC CNI Managed Add-On',
                'description': 'Not using VPC CNI as a managed add-on',
                'impact': 'Manual updates and potential compatibility issues',
                'check': lambda x: 'vpc cni managed add-on' in x or 'managed vpc cni' in x,
                'action_items': [
                    'Deploy VPC CNI as a managed add-on',
                    'Configure automatic updates',
                    'Monitor add-on status',
                    'Review version compatibility',
                    'Test updates in non-production'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html'
            },
            
            # Security
            {
                'title': 'Security Context Configuration',
                'description': 'Pod security context not properly configured',
                'impact': 'Potential security vulnerabilities',
                'check': lambda x: 'security context' in x,
                'action_items': [
                    'Understand security context settings',
                    'Configure pod security context',
                    'Set appropriate container security context',
                    'Implement least privilege principle',
                    'Regularly audit security context configurations'
                ],
                'priority': 'High',
                'reference': 'https://kubernetes.io/docs/tasks/configure-pod-container/security-context/'
            },
            {
                'title': 'Separate IAM Role for CNI',
                'description': 'CNI using node instance role instead of dedicated role',
                'impact': 'Overly permissive permissions for CNI',
                'check': lambda x: 'separate iam role for cni' in x or 'dedicated cni role' in x,
                'action_items': [
                    'Create separate IAM role for CNI',
                    'Configure CNI to use dedicated role',
                    'Implement least privilege permissions',
                    'Use IAM roles for service accounts',
                    'Regularly audit CNI permissions'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/vpc-cni.html'
            },
            
            # Health Checks
            {
                'title': 'Liveness/Readiness Probe Configuration',
                'description': 'Improper configuration of health probes',
                'impact': 'Unreliable service availability and unnecessary restarts',
                'check': lambda x: 'liveness probe' in x or 'readiness probe' in x,
                'action_items': [
                    'Handle liveness/readiness probe failures properly',
                    'Configure appropriate probe timeouts',
                    'Implement graceful shutdown',
                    'Use different endpoints for different probes',
                    'Monitor probe failures'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/vpc-cni.html'
            },
            {
                'title': 'IPTables Forward Policy',
                'description': 'IPTables forward policy not configured on non-EKS optimized AMIs',
                'impact': 'Network connectivity issues between pods',
                'check': lambda x: 'iptables forward policy' in x or 'iptables configuration' in x,
                'action_items': [
                    'Configure IPTables forward policy on non-EKS optimized AMI instances',
                    'Set default FORWARD policy to ACCEPT',
                    'Verify network connectivity between pods',
                    'Implement proper network security',
                    'Consider using EKS-optimized AMIs'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/vpc-cni.html'
            },
            {
                'title': 'CNI Version Management',
                'description': 'CNI version not regularly updated',
                'impact': 'Missing security patches and performance improvements',
                'check': lambda x: 'upgrade cni version' in x or 'cni update' in x,
                'action_items': [
                    'Routinely upgrade CNI version',
                    'Test upgrades in non-production',
                    'Monitor for issues after upgrades',
                    'Review release notes for breaking changes',
                    'Configure automatic updates for managed add-ons'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html'
            },
            {
                'title': 'Node-level IP Consumption',
                'description': 'Inefficient IP address usage at node level',
                'impact': 'IP address exhaustion and scaling limitations',
                'check': lambda x: 'node-level ip' in x or 'ip consumption' in x,
                'action_items': [
                    'Optimize node-level IP consumption',
                    'Configure appropriate max-pods setting',
                    'Use prefix delegation where appropriate',
                    'Monitor IP address usage',
                    'Plan for IP address growth'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/ip-opt.html'
            },
            
            # IP Exhaustion
            {
                'title': 'IPv6 Implementation',
                'description': 'Not using IPv6 for pod networking',
                'impact': 'Limited IP address space and potential exhaustion',
                'check': lambda x: 'ipv6' in x,
                'action_items': [
                    'Use IPv6 for pod networking (recommended)',
                    'Configure dual-stack VPC',
                    'Update CNI configuration for IPv6',
                    'Test application compatibility with IPv6',
                    'Maintain access to IPv4 EKS APIs'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/ip-opt.html'
            },
            {
                'title': 'IP Address Management',
                'description': 'No IP address management strategy',
                'impact': 'IP exhaustion and scaling limitations',
                'check': lambda x: 'ip address management' in x or 'ip planning' in x,
                'action_items': [
                    'Plan for IP address growth',
                    'Expand the IP space when needed',
                    'Optimize the IPs warm pool',
                    'Monitor IP address inventory',
                    'Consider IPv6 for long-term scalability'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/ip-opt.html'
            },
            {
                'title': 'Custom Networking Evaluation',
                'description': 'Custom networking not properly evaluated',
                'impact': 'Potential networking issues or unnecessary complexity',
                'check': lambda x: 'custom networking evaluation' in x or 'custom networking purpose' in x,
                'action_items': [
                    'Evaluate purpose of existing custom networking',
                    'Use custom networking when additional IP space is needed',
                    'Avoid custom networking when standard CNI is sufficient',
                    'Consider security implications of custom networking',
                    'Test thoroughly before implementing'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/custom-networking.html'
            },
            {
                'title': 'Load Balancer Controller',
                'description': 'AWS Load Balancer Controller not deployed',
                'impact': 'Limited load balancing options and features',
                'check': lambda x: 'load balancer controller' in x or 'aws lbc' in x,
                'action_items': [
                    'Deploy the AWS Load Balancer Controller (LBC)',
                    'Configure service annotations properly',
                    'Implement target group binding',
                    'Use IP target type for pods',
                    'Configure proper security groups'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/load-balancing.html'
            },
            
            # Prefix Mode
            {
                'title': 'Prefix Delegation for Linux',
                'description': 'Not using prefix delegation for Linux nodes',
                'impact': 'Inefficient IP address usage',
                'check': lambda x: 'prefix mode' in x or 'prefix delegation' in x,
                'action_items': [
                    'Use prefix mode when IP address efficiency is needed',
                    'Configure WARM_PREFIX_TARGET to conserve IPv4 addresses',
                    'Prefer allocating new prefixes over attaching new ENIs',
                    'Use subnet reservations to avoid subnet fragmentation',
                    'Replace all nodes during transition to prefix delegation'
                ],
                'priority': 'Medium',
                'reference': 'https://aws.github.io/aws-eks-best-practices/networking/prefix-mode/index_linux/'
            },
            {
                'title': 'Prefix Delegation for Windows',
                'description': 'Not using prefix delegation for Windows nodes',
                'impact': 'Inefficient IP address usage on Windows nodes',
                'check': lambda x: 'windows prefix' in x or 'windows delegation' in x,
                'action_items': [
                    'Use prefix delegation when IP address efficiency is needed',
                    'Configure parameters to conserve IPv4 addresses',
                    'Use subnet reservations to avoid subnet fragmentation',
                    'Replace all nodes when migrating between modes',
                    'Test thoroughly in non-production'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/prefix-mode-win.html'
            },
            
            # Security Groups for Pods
            {
                'title': 'Security Groups for Pods',
                'description': 'Not using security groups for pods',
                'impact': 'Limited network security granularity',
                'check': lambda x: 'security groups for pods' in x or 'pod security groups' in x,
                'action_items': [
                    'Use security groups for pods to leverage existing AWS configurations',
                    'Configure pod security group enforcing mode',
                    'Use strict mode for isolating pod and node traffic',
                    'Deploy pods with security groups to private subnets',
                    'Verify terminationGracePeriodSeconds in pod specifications'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/sgpp.html'
            },
            {
                'title': 'TCP Early Demux for Liveness Probe',
                'description': 'TCP early demux not disabled for liveness probes',
                'impact': 'Potential health check failures',
                'check': lambda x: 'tcp early demux' in x or 'disable tcp early' in x,
                'action_items': [
                    'Disable TCP early demux for liveness probe',
                    'Configure proper health check endpoints',
                    'Test health checks thoroughly',
                    'Monitor for probe failures',
                    'Implement proper error handling'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/sgpp.html'
            },
            
            # Load Balancing
            {
                'title': 'Load Balancer Configuration',
                'description': 'Suboptimal load balancer configuration',
                'impact': 'Errors, timeouts, and service disruptions',
                'check': lambda x: 'load balancer configuration' in x or 'alb configuration' in x,
                'action_items': [
                    'Use IP target-type load balancers',
                    'Utilize pod readiness gates',
                    'Ensure pods are deregistered before termination',
                    'Configure pod disruption budgets',
                    'Gracefully handle termination signals'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/best-practices/load-balancing.html'
            },
            {
                'title': 'Implement Network Policies',
                'description': 'Network Policies not configured',
                'impact': 'Unrestricted pod-to-pod communication',
                'check': lambda x: 'network polic' in x,
                'action_items': [
                    'Install a Network Policy provider (e.g., Calico)',
                    'Define default deny policies',
                    'Create policies for each application',
                    'Implement namespace isolation',
                    'Regularly review and update policies'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/calico.html'
            },
            {
                'title': 'Optimize VPC CNI',
                'description': 'VPC CNI not optimized',
                'impact': 'Suboptimal IP address management and performance',
                'check': lambda x: 'vpc cni' in x and 'custom networking' in x,
                'action_items': [
                    'Enable prefix delegation',
                    'Configure custom networking',
                    'Optimize MTU settings',
                    'Enable security groups for pods',
                    'Monitor and tune CNI performance'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/cni-increase-ip-addresses.html'
            }
        ]

    def _get_cost_recommendations(self):
        """Get cost optimization recommendations"""
        return [
            {
                'title': 'Utilize Spot Instances',
                'description': 'Spot Instances not used for cost savings',
                'impact': 'Higher compute costs',
                'check': lambda x: 'spot instances' in x or 'spot nodes' in x,
                'action_items': [
                    'Identify Spot-compatible workloads',
                    'Create Spot node groups',
                    'Implement interruption handling',
                    'Use capacity-optimized allocation strategy',
                    'Monitor Spot savings and adjust strategy'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html#spot-capacity'
            },
            {
                'title': 'Implement Cluster Autoscaler',
                'description': 'Cluster Autoscaler not configured',
                'impact': 'Inefficient resource utilization',
                'check': lambda x: 'cluster autoscaler' in x or 'node autoscaling' in x,
                'action_items': [
                    'Deploy Cluster Autoscaler',
                    'Configure scaling policies',
                    'Set appropriate min/max node counts',
                    'Implement pod disruption budgets',
                    'Monitor autoscaling events and optimize'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/autoscaling.html'
            },
            # Add more cost optimization recommendations...
        ]

    def _get_reliability_recommendations(self):
        """Get reliability recommendations"""
        return [
            {
                'title': 'Implement Multi-AZ Deployment',
                'description': 'Workloads not distributed across AZs',
                'impact': 'Reduced fault tolerance',
                'check': lambda x: 'multi-az' in x or 'availability zone' in x,
                'action_items': [
                    'Distribute nodes across multiple AZs',
                    'Use topology spread constraints',
                    'Implement inter-AZ load balancing',
                    'Configure pod anti-affinity rules',
                    'Test failover scenarios'
                ],
                'priority': 'High',
                'reference': 'https://aws.github.io/aws-eks-best-practices/reliability/docs/dataplane/'
            },
            {
                'title': 'Configure Pod Disruption Budgets',
                'description': 'Pod Disruption Budgets not set',
                'impact': 'Risk of service unavailability during updates',
                'check': lambda x: 'pod disruption budget' in x or 'pdb' in x,
                'action_items': [
                    'Define PDBs for critical workloads',
                    'Set appropriate maxUnavailable/minAvailable',
                    'Test PDBs during maintenance windows',
                    'Monitor PDB violations',
                    'Adjust PDBs based on application requirements'
                ],
                'priority': 'Medium',
                'reference': 'https://kubernetes.io/docs/tasks/run-application/configure-pdb/'
            },
            # Add more reliability recommendations...
        ]

    def _get_performance_recommendations(self):
        """Get performance optimization recommendations"""
        return [
            {
                'title': 'Optimize Resource Requests and Limits',
                'description': 'Resource requests and limits not properly set',
                'impact': 'Inefficient resource utilization and potential performance issues',
                'check': lambda x: 'resource requests' in x and 'resource limits' in x,
                'action_items': [
                    'Analyze workload resource usage patterns',
                    'Set appropriate CPU and memory requests',
                    'Configure resource limits to prevent resource hogging',
                    'Use Vertical Pod Autoscaler for right-sizing',
                    'Regularly review and adjust resource configurations'
                ],
                'priority': 'High',
                'reference': 'https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/'
            },
            {
                'title':

 'Implement Horizontal Pod Autoscaler',
                'description': 'HPA not configured for scalable workloads',
                'impact': 'Manual scaling leading to under/over provisioning',
                'check': lambda x: 'horizontal pod autoscaler' in x or 'hpa' in x,
                'action_items': [
                    'Identify workloads suitable for HPA',
                    'Configure HPA with appropriate metrics',
                    'Set min and max replica counts',
                    'Use custom metrics for application-specific scaling',
                    'Monitor HPA performance and adjust'
                ],
                'priority': 'Medium',
                'reference': 'https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/'
            },
            # Add more performance recommendations...
        ]

    def _get_operations_recommendations(self):
        """Get operational excellence recommendations"""
        return [
            {
                'title': 'Implement Comprehensive Monitoring',
                'description': 'Insufficient monitoring and alerting',
                'impact': 'Reduced visibility and delayed incident response',
                'check': lambda x: 'monitoring' in x and 'alerting' in x,
                'action_items': [
                    'Enable Container Insights',
                    'Set up custom CloudWatch dashboards',
                    'Configure alarms for key metrics',
                    'Implement log aggregation and analysis',
                    'Use AWS X-Ray for distributed tracing'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html'
            },
            {
                'title': 'Implement GitOps for Cluster Management',
                'description': 'Manual cluster management practices',
                'impact': 'Inconsistent configurations and potential errors',
                'check': lambda x: 'gitops' in x or 'infrastructure as code' in x,
                'action_items': [
                    'Implement GitOps tools (e.g., Flux, ArgoCD)',
                    'Store cluster configurations in version control',
                    'Set up CI/CD pipelines for cluster updates',
                    'Implement approval processes for changes',
                    'Regular audits of cluster state vs. desired state'
                ],
                'priority': 'Medium',
                'reference': 'https://aws.amazon.com/blogs/containers/gitops-model-for-provisioning-and-bootstrapping-amazon-eks-clusters-using-crossplane-and-argo-cd/'
            },
            # Add more operational recommendations...
        ]

    def _get_compliance_recommendations(self):
        """Get compliance and governance recommendations"""
        return [
            {
                'title': 'Implement Compliance Monitoring',
                'description': 'Lack of continuous compliance monitoring',
                'impact': 'Risk of non-compliance with regulatory requirements',
                'check': lambda x: 'compliance monitoring' in x or 'regulatory compliance' in x,
                'action_items': [
                    'Enable AWS Config for EKS',
                    'Implement custom Config rules for EKS',
                    'Use AWS Security Hub for compliance checks',
                    'Regular compliance audits and reporting',
                    'Automate compliance remediation where possible'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_use-managed-rules.html'
            },
            {
                'title': 'Implement Data Classification and Protection',
                'description': 'Insufficient data protection measures',
                'impact': 'Risk of data breaches and non-compliance',
                'check': lambda x: 'data classification' in x or 'data protection' in x,
                'action_items': [
                    'Implement data classification policies',
                    'Use AWS KMS for data encryption',
                    'Configure S3 bucket policies for sensitive data',
                    'Implement data access logging and monitoring',
                    'Regular data protection audits'
                ],
                'priority': 'High',
                'reference': 'https://aws.amazon.com/blogs/security/data-protection-in-aws/'
            },
            # Add more compliance recommendations...
        ]

    def _get_addons_recommendations(self):
        """Get recommendations for EKS add-ons"""
        return [
            {
                'title': 'Keep VPC CNI Updated',
                'description': 'Outdated VPC CNI version',
                'impact': 'Missing security patches and performance improvements',
                'check': lambda x: 'vpc cni' in x and 'version' in x,
                'action_items': [
                    'Check current VPC CNI version',
                    'Plan upgrade to latest stable version',
                    'Test upgrade in non-production environment',
                    'Monitor for networking issues post-upgrade',
                    'Keep track of VPC CNI release notes'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html'
            },
            {
                'title': 'Optimize CoreDNS',
                'description': 'CoreDNS not optimized for cluster size',
                'impact': 'Potential DNS resolution delays and performance issues',
                'check': lambda x: 'coredns' in x and 'optimization' in x,
                'action_items': [
                    'Scale CoreDNS based on cluster size',
                    'Configure CoreDNS caching',
                    'Monitor CoreDNS performance metrics',
                    'Consider using NodeLocal DNSCache',
                    'Optimize CoreDNS resource requests and limits'
                ],
                'priority': 'Medium',
                'reference': 'https://aws.amazon.com/blogs/containers/optimize-dns-resolution-in-multi-tenant-amazon-eks-clusters/'
            },
            # Add more add-on specific recommendations...
        ]
        
    def _get_upgrade_recommendations(self):
        """Get recommendations for EKS cluster upgrades"""
        return [
            {
                'title': 'Keep Cluster Up-to-Date',
                'description': 'Regular cluster updates not planned or implemented',
                'impact': 'Missing security patches and feature updates',
                'check': lambda x: 'keep cluster up-to-date' in x or 'cluster update' in x,
                'action_items': [
                    'Review the EKS release calendar',
                    'Understand the shared responsibility model for cluster upgrades',
                    'Plan for regular cluster updates',
                    'Create an upgrade testing strategy'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html'
            },
            {
                'title': 'Upgrade Clusters In-Place',
                'description': 'No clear upgrade strategy for clusters',
                'impact': 'Potential service disruption during upgrades',
                'check': lambda x: 'upgrade clusters in-place' in x or 'in-place upgrade' in x,
                'action_items': [
                    'Upgrade control plane and data plane in sequence',
                    'Use Kube-no-trouble or Pluto for cluster insights',
                    'Update Kubernetes workloads using kubectl-convert',
                    'Test upgrades in non-production environments first'
                ],
                'priority': 'High',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html'
            },
            {
                'title': 'Configure Pod Disruption Budgets',
                'description': 'Pod Disruption Budgets not configured for workloads',
                'impact': 'Potential service unavailability during node upgrades',
                'check': lambda x: 'poddisruptionbudget' in x or 'pod disruption budget' in x,
                'action_items': [
                    'Configure PodDisruptionBudgets for critical workloads',
                    'Implement topologySpreadConstraints for availability',
                    'Test PDBs during maintenance windows',
                    'Monitor PDB violations during upgrades'
                ],
                'priority': 'Medium',
                'reference': 'https://kubernetes.io/docs/tasks/run-application/configure-pdb/'
            },
            {
                'title': 'Use Managed Node Groups or Karpenter',
                'description': 'Self-managed node groups used without automation',
                'impact': 'Complex and error-prone node upgrades',
                'check': lambda x: 'managed node groups' in x or 'karpenter' in x,
                'action_items': [
                    'Migrate to Managed Node Groups or Karpenter',
                    'Confirm version compatibility with control plane',
                    'Enable node expiry for Karpenter managed nodes',
                    'Use Drift feature for Karpenter managed nodes',
                    'Use eksctl to automate upgrades for self-managed node groups'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html'
            },
            {
                'title': 'Backup Cluster Before Upgrading',
                'description': 'No backup strategy before cluster upgrades',
                'impact': 'Risk of data loss during failed upgrades',
                'check': lambda x: 'backup cluster' in x or 'cluster backup' in x,
                'action_items': [
                    'Implement a backup solution for etcd data',
                    'Backup persistent volumes before upgrades',
                    'Document and test restore procedures',
                    'Consider using Velero for Kubernetes backups'
                ],
                'priority': 'High',
                'reference': 'https://aws.amazon.com/blogs/containers/backup-and-restore-your-amazon-eks-cluster-resources-using-velero/'
            },
            {
                'title': 'Restart Fargate Deployments After Control Plane Upgrade',
                'description': 'Fargate pods not restarted after control plane upgrades',
                'impact': 'Potential compatibility issues with upgraded control plane',
                'check': lambda x: 'restart fargate' in x or 'fargate deployment' in x,
                'action_items': [
                    'Identify all Fargate deployments',
                    'Plan for pod restarts after control plane upgrades',
                    'Use rolling updates to minimize downtime',
                    'Verify Fargate pod functionality after restarts'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/fargate.html'
            },
            {
                'title': 'Consider Blue/Green Cluster Upgrades',
                'description': 'No alternative to in-place upgrades considered',
                'impact': 'Limited options for zero-downtime upgrades',
                'check': lambda x: 'blue/green' in x or 'blue green' in x,
                'action_items': [
                    'Evaluate Blue/Green cluster deployment strategy',
                    'Plan for data migration between clusters',
                    'Implement traffic shifting mechanisms',
                    'Test Blue/Green deployments in non-production'
                ],
                'priority': 'Low',
                'reference': 'https://aws.amazon.com/blogs/containers/kubernetes-cluster-upgrade-the-blue-green-deployment-strategy/'
            },
            {
                'title': 'Create Upgrade Checklist',
                'description': 'No standardized process for cluster upgrades',
                'impact': 'Inconsistent and error-prone upgrade procedures',
                'check': lambda x: 'upgrade checklist' in x or 'upgrade process' in x,
                'action_items': [
                    'Use EKS Documentation to create an upgrade checklist',
                    'Verify available IP addresses before upgrading',
                    'Verify EKS IAM role permissions',
                    'Migrate to EKS Add-ons for managed components',
                    'Document and test the upgrade process'
                ],
                'priority': 'Medium',
                'reference': 'https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html'
            },
            {
                'title': 'Handle Kubernetes Deprecations',
                'description': 'No plan for handling Kubernetes deprecations',
                'impact': 'Breaking changes during version upgrades',
                'check': lambda x: 'kubernetes deprecation' in x or 'api deprecation' in x,
                'action_items': [
                    'Address Dockershim removal in 1.25 using Detector for Docker Socket (DDS)',
                    'Migrate from PodSecurityPolicy to Pod Security Standards in 1.25',
                    'Migrate to Container Storage Interface (CSI) Drivers from In-Tree Storage in 1.23',
                    'Track planned major changes in the Kubernetes project',
                    'Test applications against future Kubernetes versions'
                ],
                'priority': 'High',
                'reference': 'https://kubernetes.io/docs/reference/using-api/deprecation-guide/'
            }
        ]
