import boto3
import subprocess
import json
import yaml
from iam_role_auth import get_aws_clients

class EnhancedKubernetesInspector:
    def __init__(self, cluster_name, region, role_arn=None):
        self.cluster_name = cluster_name
        self.region = region
        self.clients = get_aws_clients(role_arn, region)
        
    def _run_kubectl(self, command):
        """Run kubectl command and return output"""
        try:
            # Update kubeconfig first
            subprocess.run([
                'aws', 'eks', 'update-kubeconfig', 
                '--region', self.region, 
                '--name', self.cluster_name
            ], check=True, capture_output=True)
            
            # Run kubectl command
            result = subprocess.run(
                ['kubectl'] + command.split(),
                capture_output=True, text=True, check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _run_aws_eks(self, command):
        """Run AWS EKS command"""
        try:
            cmd = ['aws', 'eks'] + command.split() + ['--region', self.region]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout) if result.stdout.strip() else {}
        except subprocess.CalledProcessError as e:
            return {'error': e.stderr}
        except Exception as e:
            return {'error': str(e)}

    # === ENHANCED EKS CLUSTER INFORMATION ===
    def inspect_cluster_comprehensive(self):
        """Comprehensive cluster information"""
        data = {}
        
        # Basic cluster info
        data['cluster_info'] = self._run_aws_eks(f'describe-cluster --name {self.cluster_name}')
        
        # Available updates
        data['available_updates'] = self._run_aws_eks(f'list-updates --name {self.cluster_name}')
        
        # Identity provider configs
        data['identity_providers'] = self._run_aws_eks(f'list-identity-provider-configs --cluster-name {self.cluster_name}')
        
        return data

    # === ENHANCED NODEGROUP MANAGEMENT ===
    def inspect_nodegroups_comprehensive(self):
        """Comprehensive nodegroup analysis"""
        data = {}
        
        # List all nodegroups
        nodegroups_list = self._run_aws_eks(f'list-nodegroups --cluster-name {self.cluster_name}')
        data['nodegroups_list'] = nodegroups_list
        
        if 'nodegroups' in nodegroups_list:
            data['nodegroup_details'] = []
            for ng_name in nodegroups_list['nodegroups']:
                # Detailed nodegroup info
                ng_detail = self._run_aws_eks(f'describe-nodegroup --cluster-name {self.cluster_name} --nodegroup-name {ng_name}')
                
                # Nodegroup updates
                ng_updates = self._run_aws_eks(f'list-nodegroup-updates --cluster-name {self.cluster_name} --nodegroup-name {ng_name}')
                
                data['nodegroup_details'].append({
                    'name': ng_name,
                    'details': ng_detail,
                    'updates': ng_updates
                })
        
        return data

    # === ENHANCED FARGATE PROFILES ===
    def inspect_fargate_profiles(self):
        """Fargate profile analysis"""
        data = {}
        
        # List Fargate profiles
        profiles_list = self._run_aws_eks(f'list-fargate-profiles --cluster-name {self.cluster_name}')
        data['fargate_profiles_list'] = profiles_list
        
        if 'fargateProfileNames' in profiles_list:
            data['fargate_profile_details'] = []
            for profile_name in profiles_list['fargateProfileNames']:
                profile_detail = self._run_aws_eks(f'describe-fargate-profile --cluster-name {self.cluster_name} --fargate-profile-name {profile_name}')
                data['fargate_profile_details'].append({
                    'name': profile_name,
                    'details': profile_detail
                })
        
        return data

    # === ENHANCED KUBECTL CLUSTER INFORMATION ===
    def inspect_cluster_info_kubectl(self):
        """Enhanced kubectl cluster information"""
        data = {}
        
        # Basic cluster info
        data['cluster_info'] = self._run_kubectl('cluster-info')
        data['version'] = self._run_kubectl('version --output=json')
        data['api_resources'] = self._run_kubectl('api-resources --sort-by=name -o wide')
        data['api_versions'] = self._run_kubectl('api-versions')
        
        return data

    # === ENHANCED NODE MANAGEMENT ===
    def inspect_nodes_comprehensive(self):
        """Comprehensive node analysis"""
        data = {}
        
        # Basic node info
        data['nodes_basic'] = self._run_kubectl('get nodes -o json')
        data['nodes_wide'] = self._run_kubectl('get nodes -o wide')
        data['nodes_labels'] = self._run_kubectl('get nodes --show-labels')
        
        # Node metrics (if metrics-server available)
        data['nodes_metrics'] = self._run_kubectl('top nodes')
        
        # Individual node descriptions
        nodes_output = self._run_kubectl('get nodes -o name')
        if not nodes_output.startswith('Error'):
            node_names = [line.replace('node/', '') for line in nodes_output.strip().split('\n')]
            data['node_descriptions'] = {}
            for node_name in node_names:
                data['node_descriptions'][node_name] = self._run_kubectl(f'describe node {node_name}')
        
        return data

    # === ENHANCED WORKLOAD MANAGEMENT ===
    def inspect_workloads_comprehensive(self):
        """Comprehensive workload analysis"""
        data = {}
        
        # Pods
        data['pods'] = {
            'all_namespaces': self._run_kubectl('get pods --all-namespaces -o json'),
            'wide': self._run_kubectl('get pods --all-namespaces -o wide'),
            'metrics': self._run_kubectl('top pods --all-namespaces')
        }
        
        # Deployments
        data['deployments'] = {
            'all_namespaces': self._run_kubectl('get deployments --all-namespaces -o json'),
            'wide': self._run_kubectl('get deployments --all-namespaces -o wide')
        }
        
        # Services
        data['services'] = {
            'all_namespaces': self._run_kubectl('get services --all-namespaces -o json'),
            'wide': self._run_kubectl('get services --all-namespaces -o wide')
        }
        
        # Other workload resources
        data['daemonsets'] = self._run_kubectl('get daemonsets --all-namespaces -o json')
        data['statefulsets'] = self._run_kubectl('get statefulsets --all-namespaces -o json')
        data['configmaps'] = self._run_kubectl('get configmaps --all-namespaces -o json')
        data['secrets'] = self._run_kubectl('get secrets --all-namespaces -o json')
        data['ingress'] = self._run_kubectl('get ingress --all-namespaces -o json')
        data['pv_pvc'] = self._run_kubectl('get pv,pvc --all-namespaces -o json')
        
        return data

    # === ENHANCED CLUSTER HEALTH & DIAGNOSTICS ===
    def inspect_cluster_health(self):
        """Comprehensive cluster health analysis"""
        data = {}
        
        # Events
        data['events'] = {
            'all_namespaces': self._run_kubectl('get events --all-namespaces -o json'),
            'sorted_by_time': self._run_kubectl("get events --all-namespaces --sort-by='.metadata.creationTimestamp'")
        }
        
        # Component status
        data['component_status'] = self._run_kubectl('get componentstatuses -o json')
        
        # Resource quotas
        data['resource_quotas'] = self._run_kubectl('get resourcequotas --all-namespaces -o json')
        
        # Limit ranges
        data['limit_ranges'] = self._run_kubectl('get limitranges --all-namespaces -o json')
        
        return data

    # === ENHANCED RBAC INFORMATION ===
    def inspect_rbac_comprehensive(self):
        """Comprehensive RBAC analysis"""
        data = {}
        
        # Roles and RoleBindings
        data['roles'] = self._run_kubectl('get roles --all-namespaces -o json')
        data['rolebindings'] = self._run_kubectl('get rolebindings --all-namespaces -o json')
        
        # ClusterRoles and ClusterRoleBindings
        data['clusterroles'] = self._run_kubectl('get clusterroles -o json')
        data['clusterrolebindings'] = self._run_kubectl('get clusterrolebindings -o json')
        
        # ServiceAccounts
        data['serviceaccounts'] = self._run_kubectl('get serviceaccounts --all-namespaces -o json')
        
        # RBAC permissions check (sample)
        data['rbac_checks'] = {
            'can_list_pods': self._run_kubectl('auth can-i list pods'),
            'can_create_deployments': self._run_kubectl('auth can-i create deployments'),
            'can_delete_nodes': self._run_kubectl('auth can-i delete nodes')
        }
        
        return data

    # === ENHANCED STORAGE ===
    def inspect_storage_comprehensive(self):
        """Comprehensive storage analysis"""
        data = {}
        
        # Storage Classes
        data['storage_classes'] = self._run_kubectl('get storageclasses -o json')
        
        # Persistent Volumes and Claims
        data['persistent_volumes'] = self._run_kubectl('get pv -o json')
        data['persistent_volume_claims'] = self._run_kubectl('get pvc --all-namespaces -o json')
        
        # Volume Snapshots (if available)
        data['volume_snapshots'] = self._run_kubectl('get volumesnapshots --all-namespaces -o json')
        
        return data

    # === ENHANCED NETWORK POLICIES & CONFIG ===
    def inspect_networking_comprehensive(self):
        """Comprehensive networking analysis"""
        data = {}
        
        # Network Policies
        data['network_policies'] = self._run_kubectl('get networkpolicies --all-namespaces -o json')
        
        # DNS Configuration
        data['coredns_config'] = self._run_kubectl('get configmap coredns -n kube-system -o json')
        data['dns_pods'] = self._run_kubectl('get pods -n kube-system -l k8s-app=kube-dns -o json')
        
        # Services and Endpoints
        data['endpoints'] = self._run_kubectl('get endpoints --all-namespaces -o json')
        
        # Ingress Controllers
        data['ingress_classes'] = self._run_kubectl('get ingressclasses -o json')
        
        return data

    # === CUSTOM RESOURCE DEFINITIONS ===
    def inspect_crds(self):
        """Custom Resource Definitions analysis"""
        data = {}
        
        # List all CRDs
        data['crds_list'] = self._run_kubectl('get crd -o json')
        
        # Get CRD details (sample of first few)
        crds_output = self._run_kubectl('get crd -o name')
        if not crds_output.startswith('Error'):
            crd_names = crds_output.strip().split('\n')[:5]  # Limit to first 5
            data['crd_descriptions'] = {}
            for crd_name in crd_names:
                crd_short_name = crd_name.replace('customresourcedefinition.apiextensions.k8s.io/', '')
                data['crd_descriptions'][crd_short_name] = self._run_kubectl(f'describe crd {crd_short_name}')
        
        return data

    # === COMPREHENSIVE INSPECTION ===
    def inspect_all_comprehensive(self):
        """Run all comprehensive inspections"""
        return {
            'cluster_info': self.inspect_cluster_comprehensive(),
            'nodegroups': self.inspect_nodegroups_comprehensive(),
            'fargate_profiles': self.inspect_fargate_profiles(),
            'kubectl_cluster_info': self.inspect_cluster_info_kubectl(),
            'nodes': self.inspect_nodes_comprehensive(),
            'workloads': self.inspect_workloads_comprehensive(),
            'cluster_health': self.inspect_cluster_health(),
            'rbac': self.inspect_rbac_comprehensive(),
            'storage': self.inspect_storage_comprehensive(),
            'networking': self.inspect_networking_comprehensive(),
            'crds': self.inspect_crds()
        }

def get_comprehensive_kubernetes_data(cluster_name, region, role_arn=None):
    """Get comprehensive Kubernetes and EKS data"""
    inspector = EnhancedKubernetesInspector(cluster_name, region, role_arn)
    return inspector.inspect_all_comprehensive()
