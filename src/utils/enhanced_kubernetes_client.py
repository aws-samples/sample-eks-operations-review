import logging
from typing import List, Dict, Any, Optional
from kubernetes import client
from .kubernetes_client import KubernetesClient

logger = logging.getLogger(__name__)

class EnhancedKubernetesClient(KubernetesClient):
    """Enhanced Kubernetes client with additional analysis capabilities"""
    
    def __init__(self, cluster_name=None, region=None):
        super().__init__(cluster_name, region)
        self.custom_objects_v1 = None
        self.autoscaling_v1 = None
        self.autoscaling_v2 = None
        self.policy_v1 = None
    
    def initialize(self):
        """Initialize enhanced Kubernetes client"""
        if not super().initialize():
            return False
        
        try:
            # Initialize additional API clients
            self.custom_objects_v1 = client.CustomObjectsApi()
            self.autoscaling_v1 = client.AutoscalingV1Api()
            self.autoscaling_v2 = client.AutoscalingV2Api()
            self.policy_v1 = client.PolicyV1Api()
            
            logger.info("Enhanced Kubernetes client initialized")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize enhanced client: {e}")
            return False
    
    def get_resource_quotas(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get resource quotas for namespace or all namespaces"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                quotas = self.v1.list_namespaced_resource_quota(namespace)
            else:
                quotas = self.v1.list_resource_quota_for_all_namespaces()
            
            return [
                {
                    'name': quota.metadata.name,
                    'namespace': quota.metadata.namespace,
                    'hard_limits': dict(quota.spec.hard) if quota.spec.hard else {},
                    'used': dict(quota.status.used) if quota.status and quota.status.used else {}
                } for quota in quotas.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get resource quotas: {e}")
            return []
    
    def get_limit_ranges(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get limit ranges for namespace or all namespaces"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                limit_ranges = self.v1.list_namespaced_limit_range(namespace)
            else:
                limit_ranges = self.v1.list_limit_range_for_all_namespaces()
            
            return [
                {
                    'name': lr.metadata.name,
                    'namespace': lr.metadata.namespace,
                    'limits': [
                        {
                            'type': limit.type,
                            'default': dict(limit.default) if limit.default else {},
                            'default_request': dict(limit.default_request) if limit.default_request else {},
                            'max': dict(limit.max) if limit.max else {},
                            'min': dict(limit.min) if limit.min else {}
                        } for limit in lr.spec.limits
                    ] if lr.spec.limits else []
                } for lr in limit_ranges.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get limit ranges: {e}")
            return []
    
    def get_horizontal_pod_autoscalers(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get horizontal pod autoscalers"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                hpas = self.autoscaling_v2.list_namespaced_horizontal_pod_autoscaler(namespace)
            else:
                hpas = self.autoscaling_v2.list_horizontal_pod_autoscaler_for_all_namespaces()
            
            return [
                {
                    'name': hpa.metadata.name,
                    'namespace': hpa.metadata.namespace,
                    'target_ref': {
                        'kind': hpa.spec.scale_target_ref.kind,
                        'name': hpa.spec.scale_target_ref.name
                    },
                    'min_replicas': hpa.spec.min_replicas,
                    'max_replicas': hpa.spec.max_replicas,
                    'current_replicas': hpa.status.current_replicas if hpa.status else None,
                    'desired_replicas': hpa.status.desired_replicas if hpa.status else None
                } for hpa in hpas.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get HPAs: {e}")
            return []
    
    def get_pod_disruption_budgets(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get pod disruption budgets"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                pdbs = self.policy_v1.list_namespaced_pod_disruption_budget(namespace)
            else:
                pdbs = self.policy_v1.list_pod_disruption_budget_for_all_namespaces()
            
            return [
                {
                    'name': pdb.metadata.name,
                    'namespace': pdb.metadata.namespace,
                    'selector': pdb.spec.selector.match_labels if pdb.spec.selector and pdb.spec.selector.match_labels else {},
                    'min_available': pdb.spec.min_available,
                    'max_unavailable': pdb.spec.max_unavailable,
                    'current_healthy': pdb.status.current_healthy if pdb.status else None,
                    'desired_healthy': pdb.status.desired_healthy if pdb.status else None
                } for pdb in pdbs.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get PDBs: {e}")
            return []
    
    def get_daemonsets(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get all daemonsets"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                daemonsets = self.apps_v1.list_namespaced_daemon_set(namespace)
            else:
                daemonsets = self.apps_v1.list_daemon_set_for_all_namespaces()
            
            return [
                {
                    'name': ds.metadata.name,
                    'namespace': ds.metadata.namespace,
                    'desired_number_scheduled': ds.status.desired_number_scheduled,
                    'current_number_scheduled': ds.status.current_number_scheduled,
                    'number_ready': ds.status.number_ready,
                    'containers': [
                        {
                            'name': container.name,
                            'image': container.image,
                            'security_context': self._extract_security_context(container.security_context)
                        } for container in ds.spec.template.spec.containers
                    ] if ds.spec.template.spec.containers else []
                } for ds in daemonsets.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get daemonsets: {e}")
            return []
    
    def get_statefulsets(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get all statefulsets"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                statefulsets = self.apps_v1.list_namespaced_stateful_set(namespace)
            else:
                statefulsets = self.apps_v1.list_stateful_set_for_all_namespaces()
            
            return [
                {
                    'name': sts.metadata.name,
                    'namespace': sts.metadata.namespace,
                    'replicas': sts.spec.replicas,
                    'ready_replicas': sts.status.ready_replicas,
                    'service_name': sts.spec.service_name,
                    'containers': [
                        {
                            'name': container.name,
                            'image': container.image,
                            'security_context': self._extract_security_context(container.security_context)
                        } for container in sts.spec.template.spec.containers
                    ] if sts.spec.template.spec.containers else []
                } for sts in statefulsets.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get statefulsets: {e}")
            return []
    
    def get_all_pods_detailed(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get detailed information about all pods"""
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
                    'labels': dict(pod.metadata.labels) if pod.metadata.labels else {},
                    'phase': pod.status.phase,
                    'node_name': pod.spec.node_name,
                    'service_account': pod.spec.service_account_name,
                    'security_context': self._extract_pod_security_context(pod.spec.security_context),
                    'containers': [
                        {
                            'name': container.name,
                            'image': container.image,
                            'security_context': self._extract_security_context(container.security_context),
                            'resources': {
                                'requests': dict(container.resources.requests) if container.resources and container.resources.requests else {},
                                'limits': dict(container.resources.limits) if container.resources and container.resources.limits else {}
                            } if container.resources else {}
                        } for container in pod.spec.containers
                    ] if pod.spec.containers else []
                } for pod in pods.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get detailed pods: {e}")
            return []
    
    def get_service_accounts(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get service accounts"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                service_accounts = self.v1.list_namespaced_service_account(namespace)
            else:
                service_accounts = self.v1.list_service_account_for_all_namespaces()
            
            return [
                {
                    'name': sa.metadata.name,
                    'namespace': sa.metadata.namespace,
                    'annotations': dict(sa.metadata.annotations) if sa.metadata.annotations else {},
                    'secrets': [secret.name for secret in sa.secrets] if sa.secrets else [],
                    'image_pull_secrets': [secret.name for secret in sa.image_pull_secrets] if sa.image_pull_secrets else []
                } for sa in service_accounts.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get service accounts: {e}")
            return []
    
    def get_secrets(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get secrets (metadata only for security)"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                secrets = self.v1.list_namespaced_secret(namespace)
            else:
                secrets = self.v1.list_secret_for_all_namespaces()
            
            return [
                {
                    'name': secret.metadata.name,
                    'namespace': secret.metadata.namespace,
                    'type': secret.type,
                    'data_keys': list(secret.data.keys()) if secret.data else [],
                    'annotations': dict(secret.metadata.annotations) if secret.metadata.annotations else {}
                } for secret in secrets.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get secrets: {e}")
            return []
    
    def get_configmaps(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get configmaps"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                configmaps = self.v1.list_namespaced_config_map(namespace)
            else:
                configmaps = self.v1.list_config_map_for_all_namespaces()
            
            return [
                {
                    'name': cm.metadata.name,
                    'namespace': cm.metadata.namespace,
                    'data_keys': list(cm.data.keys()) if cm.data else [],
                    'binary_data_keys': list(cm.binary_data.keys()) if cm.binary_data else []
                } for cm in configmaps.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get configmaps: {e}")
            return []
    
    def get_ingresses(self, namespace: str = None) -> List[Dict[str, Any]]:
        """Get ingresses"""
        if not self.initialized:
            raise Exception("Kubernetes client not initialized")
        
        try:
            if namespace:
                ingresses = self.networking_v1.list_namespaced_ingress(namespace)
            else:
                ingresses = self.networking_v1.list_ingress_for_all_namespaces()
            
            return [
                {
                    'name': ingress.metadata.name,
                    'namespace': ingress.metadata.namespace,
                    'ingress_class': ingress.spec.ingress_class_name,
                    'rules': [
                        {
                            'host': rule.host,
                            'paths': [
                                {
                                    'path': path.path,
                                    'path_type': path.path_type,
                                    'service_name': path.backend.service.name if path.backend.service else None,
                                    'service_port': path.backend.service.port.number if path.backend.service and path.backend.service.port else None
                                } for path in rule.http.paths
                            ] if rule.http and rule.http.paths else []
                        } for rule in ingress.spec.rules
                    ] if ingress.spec.rules else [],
                    'tls': [
                        {
                            'hosts': tls.hosts,
                            'secret_name': tls.secret_name
                        } for tls in ingress.spec.tls
                    ] if ingress.spec.tls else []
                } for ingress in ingresses.items
            ]
        except Exception as e:
            logger.warning(f"Failed to get ingresses: {e}")
            return []
    
    def _extract_security_context(self, security_context) -> Dict[str, Any]:
        """Extract security context information"""
        if not security_context:
            return {}
        
        return {
            'run_as_user': security_context.run_as_user,
            'run_as_group': security_context.run_as_group,
            'run_as_non_root': security_context.run_as_non_root,
            'privileged': security_context.privileged,
            'allow_privilege_escalation': security_context.allow_privilege_escalation,
            'read_only_root_filesystem': security_context.read_only_root_filesystem,
            'capabilities': {
                'add': security_context.capabilities.add if security_context.capabilities and security_context.capabilities.add else [],
                'drop': security_context.capabilities.drop if security_context.capabilities and security_context.capabilities.drop else []
            } if security_context.capabilities else {}
        }
    
    def _extract_pod_security_context(self, security_context) -> Dict[str, Any]:
        """Extract pod-level security context information"""
        if not security_context:
            return {}
        
        return {
            'run_as_user': security_context.run_as_user,
            'run_as_group': security_context.run_as_group,
            'run_as_non_root': security_context.run_as_non_root,
            'fs_group': security_context.fs_group,
            'supplemental_groups': security_context.supplemental_groups if security_context.supplemental_groups else []
        }
