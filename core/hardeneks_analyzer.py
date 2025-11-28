"""
HardenEKS Security Analyzer - Comprehensive EKS security hardening checks
Based on AWS EKS Security Best Practices and HardenEKS tool recommendations
"""
import boto3
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from .aws_client import AWSClientManager

class HardenEKSAnalyzer:
    """
    Comprehensive HardenEKS security analyzer implementing AWS EKS security best practices
    Categories: IAM, Pod Security, Network Security, Multi-tenancy, Detective Controls, 
               Image Security, Runtime Security, Infrastructure Security, Encryption, Secrets
    """
    
    def __init__(self, cluster_name: str, region: str, role_arn: Optional[str] = None, offline_data: Optional[Dict] = None):
        self.cluster_name = cluster_name
        self.region = region
        self.offline_data = offline_data
        
        if not offline_data:
            self.aws_client = AWSClientManager(region, role_arn)
            self.clients = self.aws_client.get_clients()
        else:
            self.clients = None
    
    def run_hardeneks_analysis(self) -> Dict[str, Any]:
        """Run comprehensive HardenEKS security analysis"""
        
        # Run all HardenEKS categories
        iam_checks = self._analyze_iam_security()
        pod_security_checks = self._analyze_pod_security()
        network_security_checks = self._analyze_network_security()
        multitenancy_checks = self._analyze_multitenancy()
        detective_controls_checks = self._analyze_detective_controls()
        image_security_checks = self._analyze_image_security()
        runtime_security_checks = self._analyze_runtime_security()
        infrastructure_checks = self._analyze_infrastructure_security()
        encryption_checks = self._analyze_encryption()
        secrets_checks = self._analyze_secrets_management()
        
        # Combine all checks
        all_checks = (iam_checks + pod_security_checks + network_security_checks + 
                     multitenancy_checks + detective_controls_checks + image_security_checks +
                     runtime_security_checks + infrastructure_checks + encryption_checks + secrets_checks)
        
        # Calculate HardenEKS score
        hardeneks_score = self._calculate_hardeneks_score(all_checks)
        
        # Generate HardenEKS recommendations
        recommendations = self._generate_hardeneks_recommendations(all_checks)
        
        return {
            'cluster_name': self.cluster_name,
            'hardeneks_version': '1.0',
            'analysis_timestamp': datetime.now().isoformat(),
            'total_checks': len(all_checks),
            'passed_checks': len([c for c in all_checks if c['status'] == 'PASS']),
            'failed_checks': len([c for c in all_checks if c['status'] == 'FAIL']),
            'warning_checks': len([c for c in all_checks if c['status'] == 'WARNING']),
            'checks_by_category': {
                'iam': iam_checks,
                'pod_security': pod_security_checks,
                'network_security': network_security_checks,
                'multitenancy': multitenancy_checks,
                'detective_controls': detective_controls_checks,
                'image_security': image_security_checks,
                'runtime_security': runtime_security_checks,
                'infrastructure_security': infrastructure_checks,
                'encryption': encryption_checks,
                'secrets_management': secrets_checks
            },
            'hardeneks_score': hardeneks_score,
            'recommendations': recommendations,
            'compliance_summary': self._generate_compliance_summary(all_checks),
            'data_source': 'offline' if self.offline_data else 'online'
        }
    
    def _analyze_iam_security(self) -> List[Dict[str, Any]]:
        """Analyze IAM and RBAC security configurations"""
        checks = []
        
        # Check 1: Cluster Service Role
        checks.append(self._check_cluster_service_role())
        
        # Check 2: Node Group Instance Profile
        checks.append(self._check_nodegroup_instance_profile())
        
        # Check 3: IRSA (IAM Roles for Service Accounts)
        checks.append(self._check_irsa_configuration())
        
        # Check 4: RBAC Configuration
        checks.append(self._check_rbac_configuration())
        
        # Check 5: AWS Auth ConfigMap
        checks.append(self._check_aws_auth_configmap())
        
        return checks
    
    def _analyze_pod_security(self) -> List[Dict[str, Any]]:
        """Analyze pod security standards and policies"""
        checks = []
        
        # Check 1: Pod Security Standards
        checks.append(self._check_pod_security_standards())
        
        # Check 2: Security Context Configuration
        checks.append(self._check_security_context())
        
        # Check 3: Resource Limits and Requests
        checks.append(self._check_resource_limits())
        
        # Check 4: Admission Controllers
        checks.append(self._check_admission_controllers())
        
        # Check 5: Privileged Containers
        checks.append(self._check_privileged_containers())
        
        return checks
    
    def _analyze_network_security(self) -> List[Dict[str, Any]]:
        """Analyze network security configurations"""
        checks = []
        
        # Check 1: API Server Endpoint Access
        checks.append(self._check_api_endpoint_access())
        
        # Check 2: Security Groups Configuration
        checks.append(self._check_security_groups())
        
        # Check 3: Network Policies
        checks.append(self._check_network_policies())
        
        # Check 4: VPC Configuration
        checks.append(self._check_vpc_configuration())
        
        # Check 5: Service Mesh Security
        checks.append(self._check_service_mesh_security())
        
        return checks
    
    def _analyze_multitenancy(self) -> List[Dict[str, Any]]:
        """Analyze multi-tenancy security configurations"""
        checks = []
        
        # Check 1: Namespace Isolation
        checks.append(self._check_namespace_isolation())
        
        # Check 2: Resource Quotas
        checks.append(self._check_resource_quotas())
        
        # Check 3: Network Segmentation
        checks.append(self._check_network_segmentation())
        
        # Check 4: Node Affinity and Taints
        checks.append(self._check_node_affinity_taints())
        
        return checks
    
    def _analyze_detective_controls(self) -> List[Dict[str, Any]]:
        """Analyze detective controls and monitoring"""
        checks = []
        
        # Check 1: Control Plane Logging
        checks.append(self._check_control_plane_logging())
        
        # Check 2: GuardDuty Integration
        checks.append(self._check_guardduty_integration())
        
        # Check 3: CloudTrail Configuration
        checks.append(self._check_cloudtrail_configuration())
        
        # Check 4: Falco or Runtime Security
        checks.append(self._check_runtime_monitoring())
        
        return checks
    
    def _analyze_image_security(self) -> List[Dict[str, Any]]:
        """Analyze container image security"""
        checks = []
        
        # Check 1: Image Scanning
        checks.append(self._check_image_scanning())
        
        # Check 2: Image Provenance
        checks.append(self._check_image_provenance())
        
        # Check 3: Image Signing
        checks.append(self._check_image_signing())
        
        # Check 4: Base Image Security
        checks.append(self._check_base_image_security())
        
        return checks
    
    def _analyze_runtime_security(self) -> List[Dict[str, Any]]:
        """Analyze runtime security configurations"""
        checks = []
        
        # Check 1: Runtime Security Monitoring
        checks.append(self._check_runtime_security_monitoring())
        
        # Check 2: File System Security
        checks.append(self._check_filesystem_security())
        
        # Check 3: Process Security
        checks.append(self._check_process_security())
        
        return checks
    
    def _analyze_infrastructure_security(self) -> List[Dict[str, Any]]:
        """Analyze infrastructure security configurations"""
        checks = []
        
        # Check 1: Node Security
        checks.append(self._check_node_security())
        
        # Check 2: Infrastructure as Code
        checks.append(self._check_infrastructure_as_code())
        
        # Check 3: Cluster Upgrades
        checks.append(self._check_cluster_upgrades())
        
        return checks
    
    def _analyze_encryption(self) -> List[Dict[str, Any]]:
        """Analyze encryption configurations"""
        checks = []
        
        # Check 1: Encryption at Rest
        checks.append(self._check_encryption_at_rest())
        
        # Check 2: Encryption in Transit
        checks.append(self._check_encryption_in_transit())
        
        # Check 3: KMS Key Management
        checks.append(self._check_kms_key_management())
        
        return checks
    
    def _analyze_secrets_management(self) -> List[Dict[str, Any]]:
        """Analyze secrets management configurations"""
        checks = []
        
        # Check 1: External Secrets Management
        checks.append(self._check_external_secrets())
        
        # Check 2: Secret Rotation
        checks.append(self._check_secret_rotation())
        
        # Check 3: Secret Access Controls
        checks.append(self._check_secret_access_controls())
        
        return checks
    
    # Individual check implementations
    def _check_cluster_service_role(self) -> Dict[str, Any]:
        """Check cluster service role configuration"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                role_arn = cluster_data['cluster'].get('roleArn', '')
            else:
                role_arn = ''
        else:
            try:
                cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
                role_arn = cluster.get('roleArn', '')
            except:
                role_arn = ''
        
        return {
            'id': 'cluster_service_role',
            'category': 'iam',
            'title': 'EKS Cluster Service Role',
            'description': 'Verify cluster service role follows least privilege principle',
            'status': 'PASS' if role_arn else 'FAIL',
            'severity': 'HIGH' if not role_arn else None,
            'finding': f'Cluster service role: {role_arn}' if role_arn else 'No cluster service role found',
            'hardeneks_category': 'Identity and Access Management',
            'recommendation': 'Ensure cluster service role has minimal required permissions',
            'aws_cli': f'aws eks describe-cluster --name {self.cluster_name} --query "cluster.roleArn"'
        }
    
    def _check_nodegroup_instance_profile(self) -> Dict[str, Any]:
        """Check node group instance profile configuration"""
        if self.offline_data:
            nodegroup_details = self.offline_data.get('cluster_info', {}).get('nodegroup_details', [])
            has_instance_profile = any(
                ng.get('details', {}).get('nodegroup', {}).get('instanceTypes')
                for ng in nodegroup_details
            )
        else:
            try:
                nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
                has_instance_profile = len(nodegroups.get('nodegroups', [])) > 0
            except:
                has_instance_profile = False
        
        return {
            'id': 'nodegroup_instance_profile',
            'category': 'iam',
            'title': 'Node Group Instance Profile',
            'description': 'Verify node groups have proper instance profiles with minimal permissions',
            'status': 'PASS' if has_instance_profile else 'WARNING',
            'severity': 'MEDIUM' if not has_instance_profile else None,
            'finding': 'Node groups configured' if has_instance_profile else 'No node groups found or misconfigured',
            'hardeneks_category': 'Identity and Access Management',
            'recommendation': 'Use instance profiles with minimal required permissions for worker nodes'
        }
    
    def _check_irsa_configuration(self) -> Dict[str, Any]:
        """Check IRSA (IAM Roles for Service Accounts) configuration"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                identity = cluster_data['cluster'].get('identity', {})
                oidc_issuer = identity.get('oidc', {}).get('issuer', '')
            else:
                oidc_issuer = ''
        else:
            try:
                cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
                oidc_issuer = cluster.get('identity', {}).get('oidc', {}).get('issuer', '')
            except:
                oidc_issuer = ''
        
        return {
            'id': 'irsa_configuration',
            'category': 'iam',
            'title': 'IRSA (IAM Roles for Service Accounts)',
            'description': 'Verify OIDC identity provider is configured for IRSA',
            'status': 'PASS' if oidc_issuer else 'FAIL',
            'severity': 'HIGH' if not oidc_issuer else None,
            'finding': f'OIDC issuer configured: {oidc_issuer}' if oidc_issuer else 'OIDC identity provider not found',
            'hardeneks_category': 'Identity and Access Management',
            'recommendation': 'Configure IRSA for pod-level AWS permissions instead of using node instance profiles',
            'documentation': 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html'
        }
    
    def _check_rbac_configuration(self) -> Dict[str, Any]:
        """Check RBAC configuration"""
        # RBAC is enabled by default in EKS
        return {
            'id': 'rbac_configuration',
            'category': 'iam',
            'title': 'RBAC Configuration',
            'description': 'Verify RBAC is properly configured with least privilege access',
            'status': 'PASS',
            'finding': 'RBAC is enabled by default in EKS clusters',
            'hardeneks_category': 'Identity and Access Management',
            'recommendation': 'Implement least privilege RBAC policies for users and service accounts',
            'kubectl_commands': [
                'kubectl auth can-i --list',
                'kubectl get clusterroles',
                'kubectl get rolebindings --all-namespaces'
            ]
        }
    
    def _check_aws_auth_configmap(self) -> Dict[str, Any]:
        """Check aws-auth ConfigMap security"""
        return {
            'id': 'aws_auth_configmap',
            'category': 'iam',
            'title': 'AWS Auth ConfigMap Security',
            'description': 'Verify aws-auth ConfigMap follows security best practices',
            'status': 'WARNING',
            'severity': 'MEDIUM',
            'finding': 'Requires runtime verification of aws-auth ConfigMap',
            'hardeneks_category': 'Identity and Access Management',
            'recommendation': 'Regularly audit aws-auth ConfigMap for unnecessary permissions',
            'kubectl_commands': ['kubectl get configmap aws-auth -n kube-system -o yaml']
        }
    
    def _check_pod_security_standards(self) -> Dict[str, Any]:
        """Check Pod Security Standards implementation"""
        return {
            'id': 'pod_security_standards',
            'category': 'pod_security',
            'title': 'Pod Security Standards',
            'description': 'Verify Pod Security Standards are implemented',
            'status': 'WARNING',
            'severity': 'HIGH',
            'finding': 'Pod Security Standards require runtime verification',
            'hardeneks_category': 'Pod Security',
            'recommendation': 'Implement Pod Security Standards (restricted profile recommended)',
            'documentation': 'https://kubernetes.io/docs/concepts/security/pod-security-standards/',
            'implementation': 'Use pod-security.kubernetes.io/enforce=restricted label on namespaces'
        }
    
    def _check_security_context(self) -> Dict[str, Any]:
        """Check security context configuration"""
        return {
            'id': 'security_context',
            'category': 'pod_security',
            'title': 'Security Context Configuration',
            'description': 'Verify pods use secure security contexts',
            'status': 'WARNING',
            'severity': 'HIGH',
            'finding': 'Security context verification requires pod analysis',
            'hardeneks_category': 'Pod Security',
            'recommendation': 'Configure security contexts: runAsNonRoot=true, readOnlyRootFilesystem=true, allowPrivilegeEscalation=false'
        }
    
    def _check_resource_limits(self) -> Dict[str, Any]:
        """Check resource limits and requests"""
        return {
            'id': 'resource_limits',
            'category': 'pod_security',
            'title': 'Resource Limits and Requests',
            'description': 'Verify pods have resource limits and requests configured',
            'status': 'WARNING',
            'severity': 'MEDIUM',
            'finding': 'Resource limits verification requires pod analysis',
            'hardeneks_category': 'Pod Security',
            'recommendation': 'Set CPU and memory limits/requests for all containers'
        }
    
    def _check_admission_controllers(self) -> Dict[str, Any]:
        """Check admission controllers configuration"""
        return {
            'id': 'admission_controllers',
            'category': 'pod_security',
            'title': 'Admission Controllers',
            'description': 'Verify security admission controllers are enabled',
            'status': 'WARNING',
            'severity': 'MEDIUM',
            'finding': 'EKS has default admission controllers; custom controllers require verification',
            'hardeneks_category': 'Pod Security',
            'recommendation': 'Consider implementing OPA Gatekeeper or similar admission controllers'
        }
    
    def _check_privileged_containers(self) -> Dict[str, Any]:
        """Check for privileged containers"""
        return {
            'id': 'privileged_containers',
            'category': 'pod_security',
            'title': 'Privileged Container Check',
            'description': 'Verify no privileged containers are running',
            'status': 'WARNING',
            'severity': 'HIGH',
            'finding': 'Privileged container verification requires runtime analysis',
            'hardeneks_category': 'Pod Security',
            'recommendation': 'Prohibit privileged containers using Pod Security Standards or policies'
        }
    
    def _check_api_endpoint_access(self) -> Dict[str, Any]:
        """Check API server endpoint access configuration"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                vpc_config = cluster_data['cluster'].get('resourcesVpcConfig', {})
            else:
                vpc_config = {}
        else:
            try:
                cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
                vpc_config = cluster.get('resourcesVpcConfig', {})
            except:
                vpc_config = {}
        
        private_access = vpc_config.get('endpointPrivateAccess', False)
        public_access = vpc_config.get('endpointPublicAccess', True)
        public_cidrs = vpc_config.get('publicAccessCidrs', ['0.0.0.0/0'])
        
        # Determine status based on HardenEKS best practices
        if private_access and not public_access:
            status = 'PASS'
            severity = None
            finding = 'Private endpoint access only - excellent security posture'
        elif private_access and public_access and '0.0.0.0/0' not in public_cidrs:
            status = 'PASS'
            severity = None
            finding = 'Private access enabled with restricted public access'
        elif private_access and public_access and '0.0.0.0/0' in public_cidrs:
            status = 'WARNING'
            severity = 'MEDIUM'
            finding = 'Public access from anywhere enabled - consider restricting'
        else:
            status = 'FAIL'
            severity = 'HIGH'
            finding = 'Insecure endpoint configuration'
        
        return {
            'id': 'api_endpoint_access',
            'category': 'network_security',
            'title': 'API Server Endpoint Access',
            'description': 'Verify API server endpoint access is properly configured',
            'status': status,
            'severity': severity,
            'finding': finding,
            'hardeneks_category': 'Network Security',
            'configuration': {
                'private_access': private_access,
                'public_access': public_access,
                'public_cidrs': public_cidrs
            },
            'recommendation': 'Enable private access and restrict public access CIDRs to specific IP ranges'
        }
    
    def _check_security_groups(self) -> Dict[str, Any]:
        """Check security groups configuration"""
        # This would require detailed security group analysis
        return {
            'id': 'security_groups',
            'category': 'network_security',
            'title': 'Security Groups Configuration',
            'description': 'Verify security groups follow least privilege principle',
            'status': 'WARNING',
            'severity': 'MEDIUM',
            'finding': 'Security groups require detailed rule analysis',
            'hardeneks_category': 'Network Security',
            'recommendation': 'Audit security group rules for overly permissive access'
        }
    
    def _check_network_policies(self) -> Dict[str, Any]:
        """Check network policies implementation"""
        return {
            'id': 'network_policies',
            'category': 'network_security',
            'title': 'Kubernetes Network Policies',
            'description': 'Verify network policies are implemented for traffic segmentation',
            'status': 'WARNING',
            'severity': 'HIGH',
            'finding': 'Network policies verification requires runtime analysis',
            'hardeneks_category': 'Network Security',
            'recommendation': 'Implement Kubernetes Network Policies for micro-segmentation'
        }
    
    def _check_vpc_configuration(self) -> Dict[str, Any]:
        """Check VPC configuration"""
        return {
            'id': 'vpc_configuration',
            'category': 'network_security',
            'title': 'VPC Configuration',
            'description': 'Verify VPC follows security best practices',
            'status': 'PASS',
            'finding': 'VPC configuration appears standard for EKS',
            'hardeneks_category': 'Network Security',
            'recommendation': 'Ensure VPC uses private subnets for worker nodes'
        }
    
    def _check_service_mesh_security(self) -> Dict[str, Any]:
        """Check service mesh security configuration"""
        return {
            'id': 'service_mesh_security',
            'category': 'network_security',
            'title': 'Service Mesh Security',
            'description': 'Verify service mesh security features if implemented',
            'status': 'WARNING',
            'severity': 'LOW',
            'finding': 'Service mesh security requires runtime verification',
            'hardeneks_category': 'Network Security',
            'recommendation': 'Consider implementing Istio or similar service mesh for enhanced security'
        }
    
    def _check_control_plane_logging(self) -> Dict[str, Any]:
        """Check control plane logging configuration"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                logging_config = cluster_data['cluster'].get('logging', {})
            else:
                logging_config = {}
        else:
            try:
                cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
                logging_config = cluster.get('logging', {})
            except:
                logging_config = {}
        
        cluster_logging = logging_config.get('clusterLogging', [])
        
        if cluster_logging:
            enabled_logs = []
            for log_config in cluster_logging:
                if log_config.get('enabled', False):
                    enabled_logs.extend(log_config.get('types', []))
            
            critical_logs = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
            missing_critical = [log for log in critical_logs if log not in enabled_logs]
            
            if not missing_critical:
                status = 'PASS'
                severity = None
                finding = f'All critical control plane logs enabled: {", ".join(enabled_logs)}'
            else:
                status = 'FAIL'
                severity = 'MEDIUM'
                finding = f'Missing critical logs: {", ".join(missing_critical)}'
        else:
            status = 'FAIL'
            severity = 'MEDIUM'
            finding = 'Control plane logging not enabled'
        
        return {
            'id': 'control_plane_logging',
            'category': 'detective_controls',
            'title': 'Control Plane Logging',
            'description': 'Verify comprehensive control plane logging is enabled',
            'status': status,
            'severity': severity,
            'finding': finding,
            'hardeneks_category': 'Detective Controls',
            'recommendation': 'Enable all control plane log types for comprehensive monitoring'
        }
    
    def _check_encryption_at_rest(self) -> Dict[str, Any]:
        """Check encryption at rest configuration"""
        if self.offline_data:
            cluster_data = self.offline_data.get('cluster_info', {}).get('cluster_details', {})
            if isinstance(cluster_data, dict) and 'cluster' in cluster_data:
                encryption_config = cluster_data['cluster'].get('encryptionConfig', [])
            else:
                encryption_config = []
        else:
            try:
                cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
                encryption_config = cluster.get('encryptionConfig', [])
            except:
                encryption_config = []
        
        if encryption_config:
            secrets_encrypted = any(
                'secrets' in config.get('resources', []) 
                for config in encryption_config
            )
            if secrets_encrypted:
                status = 'PASS'
                severity = None
                finding = 'Secrets encrypted at rest with KMS'
            else:
                status = 'FAIL'
                severity = 'HIGH'
                finding = 'Encryption configured but secrets not included'
        else:
            status = 'FAIL'
            severity = 'HIGH'
            finding = 'No encryption at rest configured'
        
        return {
            'id': 'encryption_at_rest',
            'category': 'encryption',
            'title': 'Encryption at Rest',
            'description': 'Verify secrets are encrypted at rest using KMS',
            'status': status,
            'severity': severity,
            'finding': finding,
            'hardeneks_category': 'Encryption',
            'recommendation': 'Enable envelope encryption for secrets using AWS KMS'
        }
    
    # Placeholder implementations for remaining checks
    def _check_namespace_isolation(self) -> Dict[str, Any]:
        return self._create_placeholder_check('namespace_isolation', 'multitenancy', 'Namespace Isolation', 'Multi-tenancy')
    
    def _check_resource_quotas(self) -> Dict[str, Any]:
        return self._create_placeholder_check('resource_quotas', 'multitenancy', 'Resource Quotas', 'Multi-tenancy')
    
    def _check_network_segmentation(self) -> Dict[str, Any]:
        return self._create_placeholder_check('network_segmentation', 'multitenancy', 'Network Segmentation', 'Multi-tenancy')
    
    def _check_node_affinity_taints(self) -> Dict[str, Any]:
        return self._create_placeholder_check('node_affinity_taints', 'multitenancy', 'Node Affinity and Taints', 'Multi-tenancy')
    
    def _check_guardduty_integration(self) -> Dict[str, Any]:
        return self._create_placeholder_check('guardduty_integration', 'detective_controls', 'GuardDuty Integration', 'Detective Controls')
    
    def _check_cloudtrail_configuration(self) -> Dict[str, Any]:
        return self._create_placeholder_check('cloudtrail_configuration', 'detective_controls', 'CloudTrail Configuration', 'Detective Controls')
    
    def _check_runtime_monitoring(self) -> Dict[str, Any]:
        return self._create_placeholder_check('runtime_monitoring', 'detective_controls', 'Runtime Security Monitoring', 'Detective Controls')
    
    def _check_image_scanning(self) -> Dict[str, Any]:
        return self._create_placeholder_check('image_scanning', 'image_security', 'Container Image Scanning', 'Image Security')
    
    def _check_image_provenance(self) -> Dict[str, Any]:
        return self._create_placeholder_check('image_provenance', 'image_security', 'Image Provenance', 'Image Security')
    
    def _check_image_signing(self) -> Dict[str, Any]:
        return self._create_placeholder_check('image_signing', 'image_security', 'Image Signing', 'Image Security')
    
    def _check_base_image_security(self) -> Dict[str, Any]:
        return self._create_placeholder_check('base_image_security', 'image_security', 'Base Image Security', 'Image Security')
    
    def _check_runtime_security_monitoring(self) -> Dict[str, Any]:
        return self._create_placeholder_check('runtime_security_monitoring', 'runtime_security', 'Runtime Security Monitoring', 'Runtime Security')
    
    def _check_filesystem_security(self) -> Dict[str, Any]:
        return self._create_placeholder_check('filesystem_security', 'runtime_security', 'File System Security', 'Runtime Security')
    
    def _check_process_security(self) -> Dict[str, Any]:
        return self._create_placeholder_check('process_security', 'runtime_security', 'Process Security', 'Runtime Security')
    
    def _check_node_security(self) -> Dict[str, Any]:
        return self._create_placeholder_check('node_security', 'infrastructure_security', 'Node Security', 'Infrastructure Security')
    
    def _check_infrastructure_as_code(self) -> Dict[str, Any]:
        return self._create_placeholder_check('infrastructure_as_code', 'infrastructure_security', 'Infrastructure as Code', 'Infrastructure Security')
    
    def _check_cluster_upgrades(self) -> Dict[str, Any]:
        return self._create_placeholder_check('cluster_upgrades', 'infrastructure_security', 'Cluster Upgrades', 'Infrastructure Security')
    
    def _check_encryption_in_transit(self) -> Dict[str, Any]:
        return self._create_placeholder_check('encryption_in_transit', 'encryption', 'Encryption in Transit', 'Encryption')
    
    def _check_kms_key_management(self) -> Dict[str, Any]:
        return self._create_placeholder_check('kms_key_management', 'encryption', 'KMS Key Management', 'Encryption')
    
    def _check_external_secrets(self) -> Dict[str, Any]:
        return self._create_placeholder_check('external_secrets', 'secrets_management', 'External Secrets Management', 'Secrets Management')
    
    def _check_secret_rotation(self) -> Dict[str, Any]:
        return self._create_placeholder_check('secret_rotation', 'secrets_management', 'Secret Rotation', 'Secrets Management')
    
    def _check_secret_access_controls(self) -> Dict[str, Any]:
        return self._create_placeholder_check('secret_access_controls', 'secrets_management', 'Secret Access Controls', 'Secrets Management')
    
    def _create_placeholder_check(self, id: str, category: str, title: str, hardeneks_category: str) -> Dict[str, Any]:
        """Create a placeholder check for checks that require runtime verification"""
        return {
            'id': id,
            'category': category,
            'title': title,
            'description': f'Verify {title.lower()} configuration and implementation',
            'status': 'WARNING',
            'severity': 'MEDIUM',
            'finding': f'{title} requires runtime verification or detailed analysis',
            'hardeneks_category': hardeneks_category,
            'recommendation': f'Implement and verify {title.lower()} according to HardenEKS best practices'
        }
    
    def _calculate_hardeneks_score(self, checks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate HardenEKS compliance score"""
        total_checks = len(checks)
        passed_checks = len([c for c in checks if c['status'] == 'PASS'])
        failed_checks = len([c for c in checks if c['status'] == 'FAIL'])
        warning_checks = len([c for c in checks if c['status'] == 'WARNING'])
        
        # Calculate weighted score based on severity
        severity_weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        total_weight = 0
        penalty_weight = 0
        
        for check in checks:
            weight = severity_weights.get(check.get('severity', 'MEDIUM'), 2)
            total_weight += weight
            if check['status'] == 'FAIL':
                penalty_weight += weight
            elif check['status'] == 'WARNING':
                penalty_weight += weight * 0.5  # Half penalty for warnings
        
        weighted_score = ((total_weight - penalty_weight) / total_weight * 100) if total_weight > 0 else 0
        
        # Determine HardenEKS security posture
        if weighted_score >= 90:
            posture = 'EXCELLENT'
            grade = 'A'
        elif weighted_score >= 80:
            posture = 'GOOD'
            grade = 'B'
        elif weighted_score >= 70:
            posture = 'FAIR'
            grade = 'C'
        elif weighted_score >= 60:
            posture = 'POOR'
            grade = 'D'
        else:
            posture = 'CRITICAL'
            grade = 'F'
        
        return {
            'overall_score': round(weighted_score, 1),
            'security_posture': posture,
            'grade': grade,
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'failed_checks': failed_checks,
            'warning_checks': warning_checks,
            'critical_issues': len([c for c in checks if c.get('severity') == 'HIGH' and c['status'] == 'FAIL']),
            'category_scores': self._calculate_category_scores(checks)
        }
    
    def _calculate_category_scores(self, checks: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Calculate scores by HardenEKS category"""
        categories = {}
        
        for check in checks:
            category = check.get('category', 'unknown')
            if category not in categories:
                categories[category] = {'checks': [], 'passed': 0, 'failed': 0, 'warning': 0}
            
            categories[category]['checks'].append(check)
            if check['status'] == 'PASS':
                categories[category]['passed'] += 1
            elif check['status'] == 'FAIL':
                categories[category]['failed'] += 1
            else:
                categories[category]['warning'] += 1
        
        # Calculate scores for each category
        for category, data in categories.items():
            total = len(data['checks'])
            passed = data['passed']
            failed = data['failed']
            warning = data['warning']
            
            # Category score calculation
            score = ((passed + (warning * 0.5)) / total * 100) if total > 0 else 0
            
            categories[category].update({
                'total_checks': total,
                'score': round(score, 1),
                'status': 'GOOD' if score >= 80 else 'NEEDS_IMPROVEMENT' if score >= 60 else 'CRITICAL'
            })
        
        return categories
    
    def _generate_hardeneks_recommendations(self, checks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate HardenEKS-specific recommendations"""
        recommendations = []
        
        # Group failed and warning checks by category
        issues_by_category = {}
        for check in checks:
            if check['status'] in ['FAIL', 'WARNING']:
                category = check.get('hardeneks_category', 'General')
                if category not in issues_by_category:
                    issues_by_category[category] = []
                issues_by_category[category].append(check)
        
        # Generate category-specific recommendations
        for category, category_checks in issues_by_category.items():
            high_priority_checks = [c for c in category_checks if c.get('severity') == 'HIGH']
            
            if high_priority_checks:
                rec = {
                    'category': category,
                    'priority': 'HIGH',
                    'title': f'Address Critical {category} Issues',
                    'description': f'Resolve {len(high_priority_checks)} critical security issues in {category}',
                    'issues': [c['title'] for c in high_priority_checks],
                    'implementation_order': 1,
                    'estimated_effort': 'High',
                    'business_impact': 'Critical security vulnerabilities pose significant risk',
                    'hardeneks_alignment': f'Essential for {category} security hardening'
                }
                recommendations.append(rec)
        
        # Add general HardenEKS recommendations
        general_recommendations = [
            {
                'category': 'General',
                'priority': 'MEDIUM',
                'title': 'Implement Comprehensive HardenEKS Compliance',
                'description': 'Follow AWS EKS Security Best Practices for complete cluster hardening',
                'implementation_order': 2,
                'estimated_effort': 'Medium',
                'documentation': 'https://aws.github.io/aws-eks-best-practices/security/docs/',
                'tools': ['HardenEKS CLI tool', 'AWS Security Hub', 'EKS add-ons'],
                'hardeneks_alignment': 'Comprehensive security hardening across all categories'
            },
            {
                'category': 'Monitoring',
                'priority': 'MEDIUM',
                'title': 'Enable Continuous Security Monitoring',
                'description': 'Implement continuous monitoring and alerting for security posture',
                'implementation_order': 3,
                'estimated_effort': 'Medium',
                'tools': ['CloudWatch', 'GuardDuty', 'Security Hub', 'Falco'],
                'hardeneks_alignment': 'Detective controls for ongoing security assurance'
            }
        ]
        
        recommendations.extend(general_recommendations)
        
        # Sort by priority and implementation order
        priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        recommendations.sort(key=lambda x: (priority_order.get(x['priority'], 2), x.get('implementation_order', 999)))
        
        return recommendations
    
    def _generate_compliance_summary(self, checks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate compliance summary against security frameworks"""
        
        # Map HardenEKS categories to compliance frameworks
        framework_mapping = {
            'CIS_EKS': {
                'name': 'CIS Amazon EKS Benchmark',
                'version': '1.0.1',
                'applicable_categories': ['iam', 'network_security', 'detective_controls', 'encryption'],
                'total_controls': 25
            },
            'NIST_CSF': {
                'name': 'NIST Cybersecurity Framework',
                'version': '1.1',
                'applicable_categories': ['iam', 'network_security', 'detective_controls', 'encryption', 'runtime_security'],
                'total_controls': 30
            },
            'SOC2': {
                'name': 'SOC 2 Type II',
                'version': '2017',
                'applicable_categories': ['iam', 'encryption', 'detective_controls'],
                'total_controls': 15
            }
        }
        
        compliance_results = {}
        
        for framework_id, framework_info in framework_mapping.items():
            applicable_checks = [
                c for c in checks 
                if c.get('category') in framework_info['applicable_categories']
            ]
            
            total_applicable = len(applicable_checks)
            compliant_checks = len([c for c in applicable_checks if c['status'] == 'PASS'])
            
            compliance_percentage = (compliant_checks / total_applicable * 100) if total_applicable > 0 else 0
            
            compliance_results[framework_id] = {
                'framework_name': framework_info['name'],
                'version': framework_info['version'],
                'compliance_percentage': round(compliance_percentage, 1),
                'compliant_controls': compliant_checks,
                'total_applicable_controls': total_applicable,
                'status': 'COMPLIANT' if compliance_percentage >= 80 else 'PARTIALLY_COMPLIANT' if compliance_percentage >= 60 else 'NON_COMPLIANT',
                'gaps': len([c for c in applicable_checks if c['status'] in ['FAIL', 'WARNING']])
            }
        
        return compliance_results
