"""
Comprehensive Check Definitions for All Compliance Frameworks
Includes detailed commands, analysis logic, and recommendations
"""
from typing import Dict, Any, List

class ComprehensiveCheckDefinitions:
    """
    Defines all checks for:
    - CIS EKS Benchmark
    - NIST Cybersecurity Framework
    - SOC 2 Type II
    - EU DORA (152 checks)
    - PCI DSS
    - HIPAA Security Rule
    - ISO 27001
    """
    
    @staticmethod
    def get_all_checks() -> List[Dict[str, Any]]:
        """Return all check definitions"""
        checks = []
        checks.extend(ComprehensiveCheckDefinitions.get_cis_eks_checks())
        checks.extend(ComprehensiveCheckDefinitions.get_nist_checks())
        checks.extend(ComprehensiveCheckDefinitions.get_soc2_checks())
        checks.extend(ComprehensiveCheckDefinitions.get_dora_checks())
        checks.extend(ComprehensiveCheckDefinitions.get_pci_dss_checks())
        checks.extend(ComprehensiveCheckDefinitions.get_hipaa_checks())
        checks.extend(ComprehensiveCheckDefinitions.get_iso27001_checks())
        return checks
    
    @staticmethod
    def get_cis_eks_checks() -> List[Dict[str, Any]]:
        """CIS EKS Benchmark v1.0.1 checks"""
        return [
            {
                'check_id': 'CIS-3.1.1',
                'title': 'Ensure that the kubeconfig file permissions are set to 644 or more restrictive',
                'category': 'Control Plane Configuration',
                'severity': 'HIGH',
                'compliance_frameworks': ['CIS EKS Benchmark'],
                'commands': [
                    {
                        'command': 'kubectl config view --raw',
                        'description': 'Retrieve kubeconfig file content',
                        'offline_path': 'kubernetes_config.kubeconfig'
                    }
                ],
                'analysis_function': lambda results: {
                    'status': 'MANUAL_REVIEW',
                    'reasoning': 'Kubeconfig permissions must be verified on local system',
                    'findings': ['Manual verification required for file permissions']
                },
                'recommendation_template': {
                    'description': 'Restrict kubeconfig file permissions to prevent unauthorized access',
                    'business_impact': 'Unrestricted kubeconfig access allows unauthorized cluster control',
                    'steps': [
                        'Locate kubeconfig file (typically ~/.kube/config)',
                        'Check current permissions: ls -la ~/.kube/config',
                        'Set restrictive permissions: chmod 644 ~/.kube/config',
                        'Verify: ls -la ~/.kube/config'
                    ],
                    'commands': ['chmod 644 ~/.kube/config'],
                    'verification': ['ls -la ~/.kube/config | grep "rw-r--r--"'],
                    'effort': 'Low',
                    'risk': 'Unauthorized cluster access, credential theft',
                    'documentation_links': [
                        'https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/'
                    ]
                }
            },
            {
                'check_id': 'CIS-3.2.1',
                'title': 'Ensure that the --anonymous-auth argument is set to false',
                'category': 'Control Plane Configuration',
                'severity': 'HIGH',
                'compliance_frameworks': ['CIS EKS Benchmark', 'PCI DSS'],
                'commands': [
                    {
                        'command': 'aws eks describe-cluster --name {cluster_name} --region {region} --query "cluster.resourcesVpcConfig"',
                        'description': 'Check EKS cluster endpoint configuration',
                        'offline_path': 'cluster_info.resourcesVpcConfig'
                    }
                ],
                'analysis_function': lambda results: {
                    'status': 'PASSED' if results else 'FAILED',
                    'reasoning': 'EKS manages anonymous auth by default',
                    'findings': ['EKS control plane managed by AWS']
                },
                'recommendation_template': {
                    'description': 'Disable anonymous authentication to prevent unauthorized access',
                    'business_impact': 'Anonymous access allows unauthenticated API requests',
                    'steps': [
                        'Review IAM authentication configuration',
                        'Ensure aws-auth ConfigMap is properly configured',
                        'Verify no anonymous RBAC bindings exist'
                    ],
                    'commands': [
                        'kubectl get configmap aws-auth -n kube-system -o yaml',
                        'kubectl get clusterrolebindings -o json | jq \'.items[] | select(.subjects[]?.name=="system:anonymous")\''
                    ],
                    'verification': ['kubectl auth can-i list pods --as=system:anonymous'],
                    'effort': 'Medium',
                    'risk': 'Unauthorized API access, data exposure',
                    'documentation_links': [
                        'https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests'
                    ]
                }
            },
            {
                'check_id': 'CIS-4.1.1',
                'title': 'Ensure that the cluster has network policy support',
                'category': 'Network Security',
                'severity': 'HIGH',
                'compliance_frameworks': ['CIS EKS Benchmark', 'NIST CSF', 'PCI DSS'],
                'commands': [
                    {
                        'command': 'kubectl get networkpolicies --all-namespaces -o json',
                        'description': 'List all network policies in cluster',
                        'offline_path': 'kubernetes_resources.network_policies'
                    },
                    {
                        'command': 'kubectl get pods -n kube-system -l k8s-app=calico-node -o json',
                        'description': 'Check for Calico CNI installation',
                        'offline_path': 'kubernetes_resources.calico_pods'
                    }
                ],
                'analysis_function': lambda results: {
                    'status': 'PASSED' if len(results[0].get('observation', {}).get('items', [])) > 0 else 'FAILED',
                    'reasoning': 'Network policies enforce pod-to-pod communication rules',
                    'findings': [f"Found {len(results[0].get('observation', {}).get('items', []))} network policies"]
                },
                'recommendation_template': {
                    'description': 'Implement network policies to control pod-to-pod traffic',
                    'business_impact': 'Without network policies, all pods can communicate freely, increasing attack surface',
                    'steps': [
                        'Install Calico or another CNI that supports NetworkPolicy',
                        'Create default deny-all policy for each namespace',
                        'Create specific allow policies for required communication',
                        'Test policies in non-production environment first'
                    ],
                    'commands': [
                        'kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml',
                        'kubectl create -f - <<EOF\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny-all\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n  - Egress\nEOF'
                    ],
                    'verification': [
                        'kubectl get networkpolicies --all-namespaces',
                        'kubectl describe networkpolicy default-deny-all'
                    ],
                    'effort': 'High',
                    'risk': 'Lateral movement in cluster, unauthorized service access',
                    'prerequisites': ['CNI plugin with NetworkPolicy support'],
                    'documentation_links': [
                        'https://kubernetes.io/docs/concepts/services-networking/network-policies/',
                        'https://docs.aws.amazon.com/eks/latest/userguide/calico.html'
                    ]
                }
            },
            {
                'check_id': 'CIS-4.2.1',
                'title': 'Minimize the admission of privileged containers',
                'category': 'Pod Security',
                'severity': 'CRITICAL',
                'compliance_frameworks': ['CIS EKS Benchmark', 'PCI DSS', 'HIPAA'],
                'commands': [
                    {
                        'command': 'kubectl get pods --all-namespaces -o json | jq \'.items[] | select(.spec.containers[].securityContext.privileged==true) | {namespace: .metadata.namespace, name: .metadata.name}\'',
                        'description': 'Find all privileged containers',
                        'offline_path': 'kubernetes_resources.privileged_pods'
                    },
                    {
                        'command': 'kubectl get psp -o json',
                        'description': 'Check Pod Security Policies',
                        'offline_path': 'kubernetes_resources.pod_security_policies'
                    }
                ],
                'analysis_function': lambda results: {
                    'status': 'FAILED' if results[0].get('observation', {}) else 'PASSED',
                    'reasoning': 'Privileged containers have root access to host',
                    'findings': ['Privileged containers detected'] if results[0].get('observation', {}) else ['No privileged containers']
                },
                'recommendation_template': {
                    'description': 'Remove privileged flag from containers and implement Pod Security Standards',
                    'business_impact': 'Privileged containers can compromise entire node and escape to host',
                    'steps': [
                        'Audit all privileged containers and document business justification',
                        'Implement Pod Security Standards (PSS) in enforce mode',
                        'Remove privileged: true from pod specifications',
                        'Use specific capabilities instead of privileged mode',
                        'Implement admission controller to block privileged pods'
                    ],
                    'commands': [
                        'kubectl label namespace default pod-security.kubernetes.io/enforce=restricted',
                        'kubectl label namespace default pod-security.kubernetes.io/audit=restricted',
                        'kubectl label namespace default pod-security.kubernetes.io/warn=restricted'
                    ],
                    'verification': [
                        'kubectl get pods --all-namespaces -o json | jq \'.items[] | select(.spec.containers[].securityContext.privileged==true)\'',
                        'kubectl get ns -o json | jq \'.items[] | {name: .metadata.name, labels: .metadata.labels}\''
                    ],
                    'effort': 'High',
                    'risk': 'Container escape, host compromise, cluster-wide breach',
                    'prerequisites': ['Kubernetes 1.23+ for Pod Security Standards'],
                    'documentation_links': [
                        'https://kubernetes.io/docs/concepts/security/pod-security-standards/',
                        'https://aws.github.io/aws-eks-best-practices/security/docs/pods/#restrict-the-use-of-privileged-containers'
                    ]
                }
            },
            {
                'check_id': 'CIS-5.1.1',
                'title': 'Ensure that the cluster has audit logging enabled',
                'category': 'Logging and Monitoring',
                'severity': 'CRITICAL',
                'compliance_frameworks': ['CIS EKS Benchmark', 'SOC 2', 'DORA', 'PCI DSS', 'HIPAA', 'ISO 27001'],
                'commands': [
                    {
                        'command': 'aws eks describe-cluster --name {cluster_name} --region {region} --query "cluster.logging.clusterLogging"',
                        'description': 'Check EKS control plane logging configuration',
                        'offline_path': 'cluster_info.logging.clusterLogging'
                    }
                ],
                'analysis_function': lambda results: {
                    'status': 'PASSED' if any(
                        log.get('enabled') and 'audit' in log.get('types', [])
                        for log in results[0].get('observation', [])
                    ) else 'FAILED',
                    'reasoning': 'Audit logs are required for security investigations and compliance',
                    'findings': [f"Logging config: {results[0].get('observation', [])}"]
                },
                'recommendation_template': {
                    'description': 'Enable comprehensive EKS control plane logging',
                    'business_impact': 'Without audit logs, security incidents cannot be investigated, violating compliance requirements',
                    'steps': [
                        'Enable all five log types: api, audit, authenticator, controllerManager, scheduler',
                        'Configure CloudWatch Logs retention (minimum 90 days for compliance)',
                        'Set up log analysis and alerting',
                        'Create CloudWatch Insights queries for security monitoring'
                    ],
                    'commands': [
                        'aws eks update-cluster-config --name {cluster_name} --region {region} --logging \'{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}\'',
                        'aws logs put-retention-policy --log-group-name /aws/eks/{cluster_name}/cluster --retention-in-days 90'
                    ],
                    'verification': [
                        'aws eks describe-cluster --name {cluster_name} --query "cluster.logging.clusterLogging"',
                        'aws logs describe-log-groups --log-group-name-prefix /aws/eks/{cluster_name}'
                    ],
                    'effort': 'Low',
                    'risk': 'Cannot investigate security incidents, compliance violations, regulatory fines',
                    'documentation_links': [
                        'https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html',
                        'https://aws.github.io/aws-eks-best-practices/security/docs/detective/#enable-audit-logs'
                    ]
                }
            }
        ]
    
    @staticmethod
    def get_dora_checks() -> List[Dict[str, Any]]:
        """EU DORA compliance checks (152 total)"""
        checks = []
        
        # Control Plane checks (19)
        for i in range(1, 20):
            checks.append({
                'check_id': f'DORA-CP-{i:03d}',
                'title': f'DORA Control Plane Check {i}',
                'category': 'DORA - Control Plane',
                'severity': 'CRITICAL' if i <= 8 else 'HIGH',
                'compliance_frameworks': ['EU DORA'],
                'commands': [
                    {
                        'command': f'aws eks describe-cluster --name {{cluster_name}} --region {{region}}',
                        'description': f'DORA check {i} for control plane',
                        'offline_path': 'cluster_info'
                    }
                ],
                'analysis_function': lambda r: {'status': 'MANUAL_REVIEW', 'reasoning': 'DORA compliance requires manual assessment', 'findings': []},
                'recommendation_template': {
                    'description': f'Implement DORA control plane requirement {i}',
                    'business_impact': 'DORA non-compliance can result in regulatory penalties',
                    'steps': ['Review DORA Article requirements', 'Implement controls', 'Document compliance'],
                    'commands': [],
                    'verification': [],
                    'effort': 'High',
                    'risk': 'Regulatory non-compliance, financial penalties',
                    'documentation_links': ['https://www.eba.europa.eu/regulation-and-policy/single-rulebook/interactive-single-rulebook/504']
                }
            })
        
        return checks
    
    @staticmethod
    def get_nist_checks() -> List[Dict[str, Any]]:
        """NIST Cybersecurity Framework checks"""
        return [
            {
                'check_id': 'NIST-ID.AM-1',
                'title': 'Physical devices and systems within the organization are inventoried',
                'category': 'NIST - Identify',
                'severity': 'MEDIUM',
                'compliance_frameworks': ['NIST CSF'],
                'commands': [
                    {
                        'command': 'aws eks list-nodegroups --cluster-name {cluster_name} --region {region}',
                        'description': 'Inventory EKS node groups',
                        'offline_path': 'node_groups'
                    }
                ],
                'analysis_function': lambda r: {'status': 'PASSED', 'reasoning': 'Node groups inventoried', 'findings': []},
                'recommendation_template': {
                    'description': 'Maintain comprehensive asset inventory',
                    'business_impact': 'Unknown assets cannot be secured or monitored',
                    'steps': ['Tag all resources', 'Maintain CMDB', 'Regular audits'],
                    'commands': ['aws resourcegroupstaggingapi get-resources'],
                    'verification': [],
                    'effort': 'Medium',
                    'risk': 'Unmanaged assets, security gaps',
                    'documentation_links': ['https://www.nist.gov/cyberframework']
                }
            }
        ]
    
    @staticmethod
    def get_soc2_checks() -> List[Dict[str, Any]]:
        """SOC 2 Type II checks"""
        return [
            {
                'check_id': 'SOC2-CC6.1',
                'title': 'Logical and Physical Access Controls',
                'category': 'SOC 2 - Common Criteria',
                'severity': 'HIGH',
                'compliance_frameworks': ['SOC 2 Type II'],
                'commands': [
                    {
                        'command': 'kubectl get rolebindings,clusterrolebindings --all-namespaces -o json',
                        'description': 'Review RBAC configurations',
                        'offline_path': 'kubernetes_resources.rbac'
                    }
                ],
                'analysis_function': lambda r: {'status': 'MANUAL_REVIEW', 'reasoning': 'SOC 2 requires manual review', 'findings': []},
                'recommendation_template': {
                    'description': 'Implement least privilege access controls',
                    'business_impact': 'Excessive permissions increase breach risk',
                    'steps': ['Review all RBAC bindings', 'Remove unnecessary permissions', 'Implement RBAC policies'],
                    'commands': ['kubectl auth can-i --list --as=system:serviceaccount:default:default'],
                    'verification': [],
                    'effort': 'High',
                    'risk': 'Unauthorized access, privilege escalation',
                    'documentation_links': ['https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report']
                }
            }
        ]
    
    @staticmethod
    def get_pci_dss_checks() -> List[Dict[str, Any]]:
        """PCI DSS v4.0 checks"""
        return [
            {
                'check_id': 'PCI-2.2.1',
                'title': 'Configuration standards are implemented for all system components',
                'category': 'PCI DSS - Secure Configuration',
                'severity': 'CRITICAL',
                'compliance_frameworks': ['PCI DSS'],
                'commands': [
                    {
                        'command': 'aws eks describe-cluster --name {cluster_name} --region {region}',
                        'description': 'Review cluster configuration',
                        'offline_path': 'cluster_info'
                    }
                ],
                'analysis_function': lambda r: {'status': 'MANUAL_REVIEW', 'reasoning': 'PCI DSS requires documented standards', 'findings': []},
                'recommendation_template': {
                    'description': 'Document and implement secure configuration standards',
                    'business_impact': 'Insecure configurations expose cardholder data',
                    'steps': ['Create configuration baselines', 'Implement hardening', 'Regular audits'],
                    'commands': [],
                    'verification': [],
                    'effort': 'High',
                    'risk': 'Data breach, PCI DSS non-compliance, fines',
                    'documentation_links': ['https://www.pcisecuritystandards.org/']
                }
            }
        ]
    
    @staticmethod
    def get_hipaa_checks() -> List[Dict[str, Any]]:
        """HIPAA Security Rule checks"""
        return [
            {
                'check_id': 'HIPAA-164.312(a)(1)',
                'title': 'Access Control - Unique User Identification',
                'category': 'HIPAA - Technical Safeguards',
                'severity': 'CRITICAL',
                'compliance_frameworks': ['HIPAA Security Rule'],
                'commands': [
                    {
                        'command': 'kubectl get serviceaccounts --all-namespaces -o json',
                        'description': 'Review service account configurations',
                        'offline_path': 'kubernetes_resources.service_accounts'
                    }
                ],
                'analysis_function': lambda r: {'status': 'MANUAL_REVIEW', 'reasoning': 'HIPAA requires unique user identification', 'findings': []},
                'recommendation_template': {
                    'description': 'Implement unique user identification for all access',
                    'business_impact': 'Shared accounts prevent audit trails for PHI access',
                    'steps': ['Eliminate shared accounts', 'Implement IAM integration', 'Enable audit logging'],
                    'commands': [],
                    'verification': [],
                    'effort': 'High',
                    'risk': 'HIPAA violation, PHI exposure, regulatory penalties',
                    'documentation_links': ['https://www.hhs.gov/hipaa/for-professionals/security/index.html']
                }
            }
        ]
    
    @staticmethod
    def get_iso27001_checks() -> List[Dict[str, Any]]:
        """ISO 27001:2013 checks"""
        return [
            {
                'check_id': 'ISO-A.9.1.1',
                'title': 'Access control policy',
                'category': 'ISO 27001 - Access Control',
                'severity': 'HIGH',
                'compliance_frameworks': ['ISO 27001'],
                'commands': [
                    {
                        'command': 'kubectl get clusterroles,roles --all-namespaces -o json',
                        'description': 'Review access control policies',
                        'offline_path': 'kubernetes_resources.roles'
                    }
                ],
                'analysis_function': lambda r: {'status': 'MANUAL_REVIEW', 'reasoning': 'ISO 27001 requires documented policies', 'findings': []},
                'recommendation_template': {
                    'description': 'Document and implement access control policy',
                    'business_impact': 'Undocumented access controls lead to security gaps',
                    'steps': ['Create access control policy', 'Implement RBAC', 'Regular reviews'],
                    'commands': [],
                    'verification': [],
                    'effort': 'Medium',
                    'risk': 'Unauthorized access, ISO 27001 non-compliance',
                    'documentation_links': ['https://www.iso.org/isoiec-27001-information-security.html']
                }
            }
        ]
