import boto3
from iam_role_auth import get_aws_clients
from kubernetes import client, config
import json
from datetime import datetime

class DeepClusterInspector:
    def __init__(self, cluster_name, region, role_arn=None):
        self.cluster_name = cluster_name
        self.region = region
        self.clients = get_aws_clients(role_arn, region)
        self.k8s_client = None
        
    def _setup_k8s_client(self):
        """Setup Kubernetes client"""
        try:
            # Get cluster endpoint and certificate
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            endpoint = cluster['endpoint']
            ca_cert = cluster['certificateAuthority']['data']
            
            # Configure kubectl (simplified - in production use proper token)
            # This would need proper EKS token authentication
            pass
        except Exception:
            pass
    
    def inspect_cluster_deep(self):
        """Deep inspection of cluster components"""
        inspection = {
            'cluster_overview': self._inspect_cluster_overview(),
            'node_groups': self._inspect_node_groups(),
            'nodes': self._inspect_nodes(),
            'namespaces': self._inspect_namespaces(),
            'pods': self._inspect_pods(),
            'rbac': self._inspect_rbac(),
            'addons': self._inspect_addons(),
            'versions': self._inspect_versions(),
            'networking': self._inspect_networking(),
            'storage': self._inspect_storage(),
            'workloads': self._inspect_workloads()
        }
        
        return inspection
    
    def _inspect_cluster_overview(self):
        """Cluster basic information"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            return {
                'name': cluster['name'],
                'status': cluster['status'],
                'version': cluster['version'],
                'platform_version': cluster['platformVersion'],
                'created_at': cluster['createdAt'].strftime('%Y-%m-%d %H:%M:%S'),
                'endpoint': cluster['endpoint'],
                'arn': cluster['arn'],
                'role_arn': cluster['roleArn'],
                'vpc_config': {
                    'vpc_id': cluster['resourcesVpcConfig']['vpcId'],
                    'subnet_ids': cluster['resourcesVpcConfig']['subnetIds'],
                    'security_group_ids': cluster['resourcesVpcConfig'].get('securityGroupIds', []),
                    'cluster_security_group_id': cluster['resourcesVpcConfig'].get('clusterSecurityGroupId'),
                    'endpoint_public_access': cluster['resourcesVpcConfig']['endpointPublicAccess'],
                    'endpoint_private_access': cluster['resourcesVpcConfig']['endpointPrivateAccess'],
                    'public_access_cidrs': cluster['resourcesVpcConfig'].get('publicAccessCidrs', [])
                },
                'logging': cluster.get('logging', {}),
                'identity': cluster.get('identity', {}),
                'encryption_config': cluster.get('encryptionConfig', []),
                'tags': cluster.get('tags', {})
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _inspect_node_groups(self):
        """Node groups detailed analysis"""
        try:
            nodegroups_list = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            nodegroups = []
            
            for ng_name in nodegroups_list['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                nodegroups.append({
                    'name': ng['nodegroupName'],
                    'status': ng['status'],
                    'capacity_type': ng.get('capacityType', 'ON_DEMAND'),
                    'instance_types': ng.get('instanceTypes', []),
                    'ami_type': ng.get('amiType'),
                    'node_role': ng.get('nodeRole'),
                    'scaling_config': ng.get('scalingConfig', {}),
                    'disk_size': ng.get('diskSize'),
                    'remote_access': ng.get('remoteAccess', {}),
                    'labels': ng.get('labels', {}),
                    'taints': ng.get('taints', []),
                    'tags': ng.get('tags', {}),
                    'launch_template': ng.get('launchTemplate', {}),
                    'version': ng.get('version'),
                    'release_version': ng.get('releaseVersion'),
                    'created_at': ng['createdAt'].strftime('%Y-%m-%d %H:%M:%S'),
                    'modified_at': ng['modifiedAt'].strftime('%Y-%m-%d %H:%M:%S'),
                    'health': ng.get('health', {}),
                    'update_config': ng.get('updateConfig', {})
                })
            
            return nodegroups
        except Exception as e:
            return {'error': str(e)}
    
    def _inspect_nodes(self):
        """Individual nodes analysis via EC2"""
        try:
            # Get instances with EKS cluster tag
            instances = self.clients['ec2'].describe_instances(
                Filters=[
                    {'Name': 'tag:kubernetes.io/cluster/' + self.cluster_name, 'Values': ['owned']},
                    {'Name': 'instance-state-name', 'Values': ['running']}
                ]
            )
            
            nodes = []
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    nodes.append({
                        'instance_id': instance['InstanceId'],
                        'instance_type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'private_ip': instance.get('PrivateIpAddress'),
                        'public_ip': instance.get('PublicIpAddress'),
                        'subnet_id': instance['SubnetId'],
                        'vpc_id': instance['VpcId'],
                        'security_groups': [sg['GroupId'] for sg in instance['SecurityGroups']],
                        'launch_time': instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S'),
                        'architecture': instance.get('Architecture'),
                        'platform': instance.get('Platform', 'linux'),
                        'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    })
            
            return nodes
        except Exception as e:
            return {'error': str(e)}
    
    def _inspect_namespaces(self):
        """Kubernetes namespaces (mock data - would need k8s client)"""
        # In real implementation, would use kubernetes client
        return {
            'note': 'Kubernetes client needed for namespace inspection',
            'mock_namespaces': [
                'default', 'kube-system', 'kube-public', 'kube-node-lease'
            ]
        }
    
    def _inspect_pods(self):
        """Pod analysis (mock data - would need k8s client)"""
        return {
            'note': 'Kubernetes client needed for pod inspection',
            'analysis_needed': 'Pod counts, resource usage, security contexts, etc.'
        }
    
    def _inspect_rbac(self):
        """RBAC analysis (mock data - would need k8s client)"""
        return {
            'note': 'Kubernetes client needed for RBAC inspection',
            'analysis_needed': 'Roles, ClusterRoles, RoleBindings, ServiceAccounts'
        }
    
    def _inspect_addons(self):
        """EKS Add-ons detailed analysis"""
        try:
            addons_list = self.clients['eks'].list_addons(clusterName=self.cluster_name)
            addons = []
            
            for addon_name in addons_list['addons']:
                addon = self.clients['eks'].describe_addon(
                    clusterName=self.cluster_name,
                    addonName=addon_name
                )['addon']
                
                addons.append({
                    'name': addon['addonName'],
                    'version': addon['addonVersion'],
                    'status': addon['status'],
                    'health': addon.get('health', {}),
                    'configuration_values': addon.get('configurationValues'),
                    'resolve_conflicts': addon.get('resolveConflicts'),
                    'service_account_role_arn': addon.get('serviceAccountRoleArn'),
                    'tags': addon.get('tags', {}),
                    'created_at': addon['createdAt'].strftime('%Y-%m-%d %H:%M:%S'),
                    'modified_at': addon['modifiedAt'].strftime('%Y-%m-%d %H:%M:%S')
                })
            
            return addons
        except Exception as e:
            return {'error': str(e)}
    
    def _inspect_versions(self):
        """Version analysis across cluster components"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            
            versions = {
                'cluster': {
                    'kubernetes_version': cluster['version'],
                    'platform_version': cluster['platformVersion']
                },
                'node_groups': []
            }
            
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                versions['node_groups'].append({
                    'name': ng_name,
                    'kubernetes_version': ng.get('version'),
                    'release_version': ng.get('releaseVersion'),
                    'ami_type': ng.get('amiType')
                })
            
            return versions
        except Exception as e:
            return {'error': str(e)}
    
    def _inspect_networking(self):
        """Network configuration analysis"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            vpc_config = cluster['resourcesVpcConfig']
            
            # Get VPC details
            vpc = self.clients['ec2'].describe_vpcs(VpcIds=[vpc_config['vpcId']])['Vpcs'][0]
            
            # Get subnet details
            subnets = self.clients['ec2'].describe_subnets(SubnetIds=vpc_config['subnetIds'])['Subnets']
            
            return {
                'vpc': {
                    'vpc_id': vpc['VpcId'],
                    'cidr_block': vpc['CidrBlock'],
                    'state': vpc['State'],
                    'is_default': vpc['IsDefault']
                },
                'subnets': [{
                    'subnet_id': subnet['SubnetId'],
                    'cidr_block': subnet['CidrBlock'],
                    'availability_zone': subnet['AvailabilityZone'],
                    'map_public_ip': subnet['MapPublicIpOnLaunch'],
                    'available_ip_count': subnet['AvailableIpAddressCount']
                } for subnet in subnets],
                'endpoint_config': {
                    'public_access': vpc_config['endpointPublicAccess'],
                    'private_access': vpc_config['endpointPrivateAccess'],
                    'public_cidrs': vpc_config.get('publicAccessCidrs', [])
                }
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _inspect_storage(self):
        """Storage configuration analysis"""
        return {
            'note': 'Storage class and PV analysis would need Kubernetes client',
            'ebs_csi_addon': 'Check if aws-ebs-csi-driver addon is installed'
        }
    
    def _inspect_workloads(self):
        """Workload analysis (mock data - would need k8s client)"""
        return {
            'note': 'Workload analysis needs Kubernetes client',
            'analysis_needed': 'Deployments, StatefulSets, DaemonSets, Jobs, CronJobs'
        }

def generate_deep_inspection(cluster_name, region, role_arn=None):
    """Generate deep cluster inspection report"""
    inspector = DeepClusterInspector(cluster_name, region, role_arn)
    return inspector.inspect_cluster_deep()
