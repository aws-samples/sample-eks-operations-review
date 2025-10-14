import boto3
import subprocess
import json
import yaml
from iam_role_auth import get_aws_clients

class KubernetesInspector:
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
    
    def inspect_namespaces(self):
        """Get all namespaces"""
        output = self._run_kubectl('get namespaces -o json')
        if output.startswith('Error'):
            return {'error': output}
        
        try:
            data = json.loads(output)
            namespaces = []
            for ns in data['items']:
                namespaces.append({
                    'name': ns['metadata']['name'],
                    'status': ns['status']['phase'],
                    'created': ns['metadata']['creationTimestamp'],
                    'labels': ns['metadata'].get('labels', {}),
                    'annotations': ns['metadata'].get('annotations', {})
                })
            return namespaces
        except json.JSONDecodeError:
            return {'error': 'Failed to parse namespace data'}
    
    def inspect_pods(self):
        """Get all pods across all namespaces"""
        output = self._run_kubectl('get pods --all-namespaces -o json')
        if output.startswith('Error'):
            return {'error': output}
        
        try:
            data = json.loads(output)
            pods = []
            for pod in data['items']:
                pods.append({
                    'name': pod['metadata']['name'],
                    'namespace': pod['metadata']['namespace'],
                    'status': pod['status']['phase'],
                    'ready': self._get_pod_ready_status(pod),
                    'restarts': sum(c.get('restartCount', 0) for c in pod['status'].get('containerStatuses', [])),
                    'node': pod['spec'].get('nodeName'),
                    'created': pod['metadata']['creationTimestamp'],
                    'labels': pod['metadata'].get('labels', {}),
                    'containers': [c['name'] for c in pod['spec']['containers']]
                })
            return pods
        except json.JSONDecodeError:
            return {'error': 'Failed to parse pod data'}
    
    def _get_pod_ready_status(self, pod):
        """Get pod ready status"""
        container_statuses = pod['status'].get('containerStatuses', [])
        if not container_statuses:
            return '0/0'
        
        ready_count = sum(1 for c in container_statuses if c.get('ready', False))
        total_count = len(container_statuses)
        return f"{ready_count}/{total_count}"
    
    def inspect_nodes_k8s(self):
        """Get node details from Kubernetes API"""
        output = self._run_kubectl('get nodes -o json')
        if output.startswith('Error'):
            return {'error': output}
        
        try:
            data = json.loads(output)
            nodes = []
            for node in data['items']:
                conditions = {c['type']: c['status'] for c in node['status'].get('conditions', [])}
                
                nodes.append({
                    'name': node['metadata']['name'],
                    'status': 'Ready' if conditions.get('Ready') == 'True' else 'NotReady',
                    'roles': list(node['metadata'].get('labels', {}).keys() & {'node-role.kubernetes.io/master', 'node-role.kubernetes.io/control-plane'}),
                    'version': node['status']['nodeInfo']['kubeletVersion'],
                    'os': node['status']['nodeInfo']['osImage'],
                    'kernel': node['status']['nodeInfo']['kernelVersion'],
                    'container_runtime': node['status']['nodeInfo']['containerRuntimeVersion'],
                    'capacity': node['status']['capacity'],
                    'allocatable': node['status']['allocatable'],
                    'conditions': conditions,
                    'created': node['metadata']['creationTimestamp']
                })
            return nodes
        except json.JSONDecodeError:
            return {'error': 'Failed to parse node data'}
    
    def inspect_workloads(self):
        """Get workload summary"""
        workloads = {}
        
        # Deployments
        output = self._run_kubectl('get deployments --all-namespaces -o json')
        if not output.startswith('Error'):
            try:
                data = json.loads(output)
                workloads['deployments'] = [{
                    'name': d['metadata']['name'],
                    'namespace': d['metadata']['namespace'],
                    'replicas': f"{d['status'].get('readyReplicas', 0)}/{d['spec']['replicas']}",
                    'available': d['status'].get('availableReplicas', 0),
                    'created': d['metadata']['creationTimestamp']
                } for d in data['items']]
            except:
                workloads['deployments'] = {'error': 'Failed to parse deployments'}
        
        # Services
        output = self._run_kubectl('get services --all-namespaces -o json')
        if not output.startswith('Error'):
            try:
                data = json.loads(output)
                workloads['services'] = [{
                    'name': s['metadata']['name'],
                    'namespace': s['metadata']['namespace'],
                    'type': s['spec']['type'],
                    'cluster_ip': s['spec'].get('clusterIP'),
                    'external_ip': s['status'].get('loadBalancer', {}).get('ingress', [{}])[0].get('ip', 'None'),
                    'ports': [f"{p.get('port', '')}/{p.get('protocol', '')}" for p in s['spec'].get('ports', [])]
                } for s in data['items']]
            except:
                workloads['services'] = {'error': 'Failed to parse services'}
        
        return workloads
    
    def inspect_rbac(self):
        """Get RBAC information"""
        rbac = {}
        
        # Service Accounts
        output = self._run_kubectl('get serviceaccounts --all-namespaces -o json')
        if not output.startswith('Error'):
            try:
                data = json.loads(output)
                rbac['service_accounts'] = [{
                    'name': sa['metadata']['name'],
                    'namespace': sa['metadata']['namespace'],
                    'secrets': len(sa.get('secrets', [])),
                    'created': sa['metadata']['creationTimestamp']
                } for sa in data['items']]
            except:
                rbac['service_accounts'] = {'error': 'Failed to parse service accounts'}
        
        # Roles
        output = self._run_kubectl('get roles --all-namespaces -o json')
        if not output.startswith('Error'):
            try:
                data = json.loads(output)
                rbac['roles'] = [{
                    'name': r['metadata']['name'],
                    'namespace': r['metadata']['namespace'],
                    'rules': len(r.get('rules', [])),
                    'created': r['metadata']['creationTimestamp']
                } for r in data['items']]
            except:
                rbac['roles'] = {'error': 'Failed to parse roles'}
        
        # ClusterRoles
        output = self._run_kubectl('get clusterroles -o json')
        if not output.startswith('Error'):
            try:
                data = json.loads(output)
                rbac['cluster_roles'] = [{
                    'name': cr['metadata']['name'],
                    'rules': len(cr.get('rules', [])),
                    'created': cr['metadata']['creationTimestamp']
                } for cr in data['items']]
            except:
                rbac['cluster_roles'] = {'error': 'Failed to parse cluster roles'}
        
        return rbac

def get_kubernetes_data(cluster_name, region, role_arn=None):
    """Get comprehensive Kubernetes data"""
    inspector = KubernetesInspector(cluster_name, region, role_arn)
    
    return {
        'namespaces': inspector.inspect_namespaces(),
        'pods': inspector.inspect_pods(),
        'nodes_k8s': inspector.inspect_nodes_k8s(),
        'workloads': inspector.inspect_workloads(),
        'rbac': inspector.inspect_rbac()
    }
