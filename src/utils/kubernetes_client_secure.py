import os
import logging
import subprocess
import yaml
import tempfile
import re
import shlex
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

class KubernetesClient:
    """Client for interacting with Kubernetes API"""
    
    def __init__(self, cluster_name=None, region=None):
        """Initialize Kubernetes client with admin permissions
        
        Args:
            cluster_name: Name of the EKS cluster
            region: AWS region where the cluster is located
        """
        self.cluster_name = cluster_name
        self.region = region
        self.v1 = None
        self.apps_v1 = None
        self.rbac_v1 = None
        self.networking_v1 = None
        self.initialized = False
    
    def initialize(self):
        """Initialize Kubernetes client with admin permissions"""
        try:
            # Update kubeconfig for the cluster
            if self.cluster_name and self.region:
                self._update_kubeconfig()
            
            # Load kubeconfig
            config.load_kube_config()
            
            # Initialize API clients
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.rbac_v1 = client.RbacAuthorizationV1Api()
            self.networking_v1 = client.NetworkingV1Api()
            self.initialized = True
            
            # Verify admin permissions
            self._verify_admin_permissions()
            
            logger.info("Kubernetes client initialized with admin permissions")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes client: {e}")
            return False
    
    def _update_kubeconfig(self):
        """Update kubeconfig for the cluster"""
        try:
            # Validate inputs to prevent command injection
            if not self._is_valid_cluster_name(self.cluster_name) or not self._is_valid_region(self.region):
                raise ValueError("Invalid cluster name or region format")
                
            # Use absolute path to aws command for security
            aws_cmd = "/usr/local/bin/aws"
            if not os.path.exists(aws_cmd):
                # Fall back to PATH resolution but log a warning
                aws_cmd = "aws"
                logger.warning("Using PATH to resolve aws command instead of absolute path")
                
            # Set timeout for subprocess call
            result = subprocess.run([
                aws_cmd, "eks", "update-kubeconfig",
                "--name", str(self.cluster_name),
                "--region", str(self.region)
            ], capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                logger.warning(f"Failed to update kubeconfig: {result.stderr}")
                raise Exception(f"Failed to update kubeconfig: {result.stderr}")
            logger.info("Updated kubeconfig successfully")
        except subprocess.TimeoutExpired:
            logger.warning("Timeout while updating kubeconfig")
            raise Exception("Timeout while updating kubeconfig")
        except Exception as e:
            logger.warning(f"Error updating kubeconfig: {e}")
            raise
            
    def _is_valid_cluster_name(self, name):
        """Validate cluster name to prevent command injection"""
        # EKS cluster names must be alphanumeric with hyphens and start with letter
        return bool(name and re.match(r'^[a-zA-Z][-a-zA-Z0-9]{1,99}$', name))
        
    def _is_valid_region(self, region):
        """Validate AWS region format to prevent command injection"""
        # AWS regions follow a specific pattern
        return bool(region and re.match(r'^[a-z]{2}-[a-z]+-\d{1,2}$', region))
    
    def _verify_admin_permissions(self):
        """Verify that the client has admin permissions"""
        try:
            # Try to list all namespaces (requires admin permissions)
            self.v1.list_namespace()
            
            # Try to create a test namespace
            test_namespace = "test-admin-permissions"
            namespace_manifest = client.V1Namespace(
                metadata=client.V1ObjectMeta(name=test_namespace)
            )
            
            try:
                self.v1.create_namespace(namespace_manifest)
                logger.info("Created test namespace successfully")
                
                # Clean up the test namespace
                self.v1.delete_namespace(test_namespace)
                logger.info("Deleted test namespace successfully")
            except ApiException as e:
                if e.status == 409:  # Conflict (namespace already exists)
                    logger.info("Test namespace already exists, admin permissions confirmed")
                else:
                    logger.warning(f"Limited admin permissions: {e}")
            
            return True
        except ApiException as e:
            logger.warning(f"Failed to verify admin permissions: {e}")
            raise Exception("Insufficient permissions to access the cluster. Admin permissions required.")
    
    def get_all_namespaces(self):
        """Get all namespaces in the cluster"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            namespaces = self.v1.list_namespace()
            return [ns.metadata.name for ns in namespaces.items]
        except ApiException as e:
            logger.warning(f"Failed to get namespaces: {e}")
            raise
    
    def get_all_pods(self, namespace=None):
        """Get all pods in the cluster or in a specific namespace"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                pods = self.v1.list_namespaced_pod(namespace)
            else:
                pods = self.v1.list_pod_for_all_namespaces()
            
            return [
                {
                    'name': pod.metadata.name,
                    'namespace': pod.metadata.namespace,
                    'status': pod.status.phase,
                    'node': pod.spec.node_name,
                    'ip': pod.status.pod_ip,
                    'containers': [
                        {
                            'name': container.name,
                            'image': container.image,
                            'ready': any(status.name == container.name and status.ready for status in pod.status.container_statuses) if pod.status.container_statuses else False,
                            'privileged': container.security_context.privileged if container.security_context else False
                        } for container in pod.spec.containers
                    ] if pod.spec.containers else []
                } for pod in pods.items
            ]
        except ApiException as e:
            logger.warning(f"Failed to get pods: {e}")
            raise
    
    def get_all_deployments(self, namespace=None):
        """Get all deployments in the cluster or in a specific namespace"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                deployments = self.apps_v1.list_namespaced_deployment(namespace)
            else:
                deployments = self.apps_v1.list_deployment_for_all_namespaces()
            
            return [
                {
                    'name': deployment.metadata.name,
                    'namespace': deployment.metadata.namespace,
                    'replicas': deployment.spec.replicas,
                    'available_replicas': deployment.status.available_replicas,
                    'strategy': deployment.spec.strategy.type,
                    'containers': [
                        {
                            'name': container.name,
                            'image': container.image,
                            'resources': {
                                'requests': {
                                    'cpu': container.resources.requests.get('cpu') if container.resources and container.resources.requests else None,
                                    'memory': container.resources.requests.get('memory') if container.resources and container.resources.requests else None
                                },
                                'limits': {
                                    'cpu': container.resources.limits.get('cpu') if container.resources and container.resources.limits else None,
                                    'memory': container.resources.limits.get('memory') if container.resources and container.resources.limits else None
                                }
                            } if container.resources else {}
                        } for container in deployment.spec.template.spec.containers
                    ] if deployment.spec.template.spec.containers else []
                } for deployment in deployments.items
            ]
        except ApiException as e:
            logger.warning(f"Failed to get deployments: {e}")
            raise
    
    def get_all_services(self, namespace=None):
        """Get all services in the cluster or in a specific namespace"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                services = self.v1.list_namespaced_service(namespace)
            else:
                services = self.v1.list_service_for_all_namespaces()
            
            return [
                {
                    'name': service.metadata.name,
                    'namespace': service.metadata.namespace,
                    'type': service.spec.type,
                    'cluster_ip': service.spec.cluster_ip,
                    'external_ip': service.spec.external_i_ps[0] if service.spec.external_i_ps else None,
                    'ports': [
                        {
                            'name': port.name,
                            'port': port.port,
                            'target_port': port.target_port,
                            'protocol': port.protocol
                        } for port in service.spec.ports
                    ] if service.spec.ports else []
                } for service in services.items
            ]
        except ApiException as e:
            logger.warning(f"Failed to get services: {e}")
            raise
    
    def get_all_network_policies(self, namespace=None):
        """Get all network policies in the cluster or in a specific namespace"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                network_policies = self.networking_v1.list_namespaced_network_policy(namespace)
            else:
                network_policies = self.networking_v1.list_network_policy_for_all_namespaces()
            
            return [
                {
                    'name': policy.metadata.name,
                    'namespace': policy.metadata.namespace,
                    'pod_selector': policy.spec.pod_selector.match_labels if policy.spec.pod_selector else {},
                    'ingress_rules': [
                        {
                            'from': [
                                {
                                    'pod_selector': rule_from.pod_selector.match_labels if rule_from.pod_selector else {},
                                    'namespace_selector': rule_from.namespace_selector.match_labels if rule_from.namespace_selector else {}
                                } for rule_from in rule.from_
                            ] if rule.from_ else [],
                            'ports': [
                                {
                                    'port': port.port,
                                    'protocol': port.protocol
                                } for port in rule.ports
                            ] if rule.ports else []
                        } for rule in policy.spec.ingress
                    ] if policy.spec.ingress else [],
                    'egress_rules': [
                        {
                            'to': [
                                {
                                    'pod_selector': rule_to.pod_selector.match_labels if rule_to.pod_selector else {},
                                    'namespace_selector': rule_to.namespace_selector.match_labels if rule_to.namespace_selector else {}
                                } for rule_to in rule.to
                            ] if rule.to else [],
                            'ports': [
                                {
                                    'port': port.port,
                                    'protocol': port.protocol
                                } for port in rule.ports
                            ] if rule.ports else []
                        } for rule in policy.spec.egress
                    ] if policy.spec.egress else [],
                    'policy_types': policy.spec.policy_types
                } for policy in network_policies.items
            ]
        except ApiException as e:
            logger.warning(f"Failed to get network policies: {e}")
            raise
    
    def get_pod_security_standards(self):
        """Check if Pod Security Standards are enforced in the cluster"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            namespaces = self.v1.list_namespace()
            pss_namespaces = []
            
            for ns in namespaces.items:
                labels = ns.metadata.labels if ns.metadata.labels else {}
                pss_labels = {k: v for k, v in labels.items() if k.startswith('pod-security.kubernetes.io/')}
                
                if pss_labels:
                    pss_namespaces.append({
                        'namespace': ns.metadata.name,
                        'enforce': pss_labels.get('pod-security.kubernetes.io/enforce'),
                        'audit': pss_labels.get('pod-security.kubernetes.io/audit'),
                        'warn': pss_labels.get('pod-security.kubernetes.io/warn')
                    })
            
            return pss_namespaces
        except ApiException as e:
            logger.warning(f"Failed to get Pod Security Standards: {e}")
            raise
    
    def apply_manifest(self, manifest_yaml):
        """Apply a Kubernetes manifest"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            # Validate manifest content before applying
            try:
                yaml_content = yaml.safe_load_all(manifest_yaml)
                # Convert generator to list to force validation
                list(yaml_content)
            except yaml.YAMLError as e:
                logger.warning(f"Invalid YAML manifest: {e}")
                raise ValueError(f"Invalid YAML manifest: {e}")
            
            # Write manifest to temporary file with secure permissions
            with tempfile.NamedTemporaryFile(suffix='.yaml', delete=False, mode='w') as temp_file:
                temp_file.write(manifest_yaml)
                temp_file.flush()  # Ensure data is written
                temp_file_path = temp_file.name
            
            # Set secure permissions on the file
            os.chmod(temp_file_path, 0o600)
            
            # Use absolute path to kubectl command for security
            kubectl_cmd = "/usr/local/bin/kubectl"
            if not os.path.exists(kubectl_cmd):
                # Fall back to PATH resolution but log a warning
                kubectl_cmd = "kubectl"
                logger.warning("Using PATH to resolve kubectl command instead of absolute path")
            
            # Apply manifest using kubectl with timeout
            result = subprocess.run([kubectl_cmd, "apply", "-f", temp_file_path], capture_output=True, text=True, timeout=60)
            
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except Exception as e:
                logger.warning(f"Failed to remove temporary file {temp_file_path}: {e}")
            
            if result.returncode != 0:
                logger.warning(f"Failed to apply manifest: {result.stderr}")
                raise Exception(f"Failed to apply manifest: {result.stderr}")
            
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.warning("Timeout while applying Kubernetes manifest")
            raise Exception("Timeout while applying Kubernetes manifest")
        except Exception as e:
            logger.warning(f"Error applying manifest: {e}")
            raise
    
    def get_cluster_roles(self):
        """Get all cluster roles"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            roles = self.rbac_v1.list_cluster_role()
            return [
                {
                    'name': role.metadata.name,
                    'rules': [
                        {
                            'api_groups': rule.api_groups,
                            'resources': rule.resources,
                            'verbs': rule.verbs
                        } for rule in role.rules
                    ] if role.rules else []
                } for role in roles.items
            ]
        except ApiException as e:
            logger.warning(f"Failed to get cluster roles: {e}")
            raise
    
    def get_cluster_role_bindings(self):
        """Get all cluster role bindings"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            bindings = self.rbac_v1.list_cluster_role_binding()
            return [
                {
                    'name': binding.metadata.name,
                    'role_ref': {
                        'api_group': binding.role_ref.api_group,
                        'kind': binding.role_ref.kind,
                        'name': binding.role_ref.name
                    },
                    'subjects': [
                        {
                            'kind': subject.kind,
                            'name': subject.name,
                            'namespace': subject.namespace
                        } for subject in binding.subjects
                    ] if binding.subjects else []
                } for binding in bindings.items
            ]
        except ApiException as e:
            logger.warning(f"Failed to get cluster role bindings: {e}")
            raise