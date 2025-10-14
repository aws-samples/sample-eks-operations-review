import logging
import boto3
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class ClusterStateAnalyzer:
    """Analyzes actual cluster state using AWS APIs"""
    
    def __init__(self, aws_access_key: str, aws_secret_key: str, region: str, cluster_name: str):
        self.cluster_name = cluster_name
        self.region = region
        
        # Initialize AWS clients
        self.eks = boto3.client('eks', aws_access_key_id=aws_access_key, 
                               aws_secret_access_key=aws_secret_key, region_name=region)
        self.ec2 = boto3.client('ec2', aws_access_key_id=aws_access_key,
                               aws_secret_access_key=aws_secret_key, region_name=region)
        self.iam = boto3.client('iam', aws_access_key_id=aws_access_key,
                               aws_secret_access_key=aws_secret_key, region_name=region)
        self.logs = boto3.client('logs', aws_access_key_id=aws_access_key,
                                aws_secret_access_key=aws_secret_key, region_name=region)
        
    def get_comprehensive_cluster_state(self) -> Dict[str, Any]:
        """Get complete cluster state from AWS APIs"""
        try:
            state = {
                'cluster_info': self._get_cluster_info(),
                'security_state': self._get_security_state(),
                'networking_state': self._get_networking_state(),
                'nodegroups_state': self._get_nodegroups_state(),
                'addons_state': self._get_addons_state(),
                'logging_state': self._get_logging_state(),
                'iam_state': self._get_iam_state()
            }
            return state
        except Exception as e:
            logger.warning(f"Error getting cluster state: {e}")
            raise
    
    def _get_cluster_info(self) -> Dict[str, Any]:
        """Get basic cluster information"""
        try:
            cluster = self.eks.describe_cluster(name=self.cluster_name)['cluster']
            return {
                'name': cluster.get('name', self.cluster_name),
                'version': cluster['version'],
                'status': cluster['status'],
                'endpoint': cluster['endpoint'],
                'platform_version': cluster['platformVersion'],
                'created_at': cluster['createdAt'].isoformat() if 'createdAt' in cluster else None,
                'vpc_config': cluster['resourcesVpcConfig'],
                'encryption_config': cluster.get('encryptionConfig', []),
                'logging': cluster.get('logging', {}),
                'identity': cluster.get('identity', {})
            }
        except ClientError as e:
            logger.warning(f"Error getting cluster info: {e}")
            raise
    
    def _get_security_state(self) -> Dict[str, Any]:
        """Analyze security configuration"""
        cluster_info = self._get_cluster_info()
        
        # Check secrets encryption
        secrets_encrypted = False
        kms_key_id = None
        for config in cluster_info.get('encryption_config', []):
            if 'secrets' in config.get('resources', []):
                secrets_encrypted = True
                kms_key_id = config.get('provider', {}).get('keyArn')
                break
        
        # Check OIDC provider
        oidc_issuer = cluster_info.get('identity', {}).get('oidc', {}).get('issuer')
        oidc_provider_exists = False
        if oidc_issuer:
            try:
                # Extract OIDC provider ARN format
                oidc_id = oidc_issuer.replace('https://', '')
                self.iam.get_open_id_connect_provider(
                    OpenIDConnectProviderArn=f'arn:aws:iam::{self._get_account_id()}:oidc-provider/{oidc_id}'
                )
                oidc_provider_exists = True
            except ClientError:
                oidc_provider_exists = False
        
        return {
            'secrets_encryption': {
                'enabled': secrets_encrypted,
                'kms_key_id': kms_key_id
            },
            'oidc_provider': {
                'configured': oidc_provider_exists,
                'issuer_url': oidc_issuer
            },
            'endpoint_access': {
                'public': cluster_info['vpc_config']['endpointPublicAccess'],
                'private': cluster_info['vpc_config']['endpointPrivateAccess'],
                'public_cidrs': cluster_info['vpc_config'].get('publicAccessCidrs', [])
            }
        }
    
    def _get_networking_state(self) -> Dict[str, Any]:
        """Analyze networking configuration"""
        cluster_info = self._get_cluster_info()
        vpc_config = cluster_info['vpc_config']
        
        # Get VPC and subnet details
        vpc_id = vpc_config['vpcId']
        subnet_ids = vpc_config['subnetIds']
        
        # Check if subnets are private
        subnets = self.ec2.describe_subnets(SubnetIds=subnet_ids)['Subnets']
        private_subnets = []
        public_subnets = []
        
        for subnet in subnets:
            # Check route table to determine if subnet is private
            route_tables = self.ec2.describe_route_tables(
                Filters=[{'Name': 'association.subnet-id', 'Values': [subnet['SubnetId']]}]
            )['RouteTables']
            
            is_private = True
            for rt in route_tables:
                for route in rt.get('Routes', []):
                    if route.get('GatewayId', '').startswith('igw-'):
                        is_private = False
                        break
            
            if is_private:
                private_subnets.append(subnet)
            else:
                public_subnets.append(subnet)
        
        # Check security groups
        security_groups = self.ec2.describe_security_groups(
            GroupIds=vpc_config['securityGroupIds']
        )['SecurityGroups']
        
        return {
            'vpc_id': vpc_id,
            'subnets': {
                'private': [s['SubnetId'] for s in private_subnets],
                'public': [s['SubnetId'] for s in public_subnets],
                'total_count': len(subnets)
            },
            'security_groups': [sg['GroupId'] for sg in security_groups],
            'availability_zones': list(set(s['AvailabilityZone'] for s in subnets))
        }
    
    def _get_nodegroups_state(self) -> Dict[str, Any]:
        """Analyze node groups configuration"""
        try:
            nodegroups = self.eks.list_nodegroups(clusterName=self.cluster_name)['nodegroups']
            nodegroup_details = []
            
            for ng_name in nodegroups:
                ng = self.eks.describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                # Check if nodes are in private subnets
                ng_subnets = ng['subnets']
                subnets_info = self.ec2.describe_subnets(SubnetIds=ng_subnets)['Subnets']
                
                private_subnet_count = 0
                for subnet in subnets_info:
                    route_tables = self.ec2.describe_route_tables(
                        Filters=[{'Name': 'association.subnet-id', 'Values': [subnet['SubnetId']]}]
                    )['RouteTables']
                    
                    is_private = True
                    for rt in route_tables:
                        for route in rt.get('Routes', []):
                            if route.get('GatewayId', '').startswith('igw-'):
                                is_private = False
                                break
                    if is_private:
                        private_subnet_count += 1
                
                nodegroup_details.append({
                    'name': ng_name,
                    'status': ng['status'],
                    'capacity_type': ng.get('capacityType', 'ON_DEMAND'),
                    'instance_types': ng.get('instanceTypes', []),
                    'scaling_config': ng['scalingConfig'],
                    'subnets': ng_subnets,
                    'private_subnets_count': private_subnet_count,
                    'total_subnets_count': len(ng_subnets),
                    'ami_type': ng.get('amiType'),
                    'node_role': ng.get('nodeRole'),
                    'remote_access': ng.get('remoteAccess', {})
                })
            
            return {
                'total_nodegroups': len(nodegroups),
                'nodegroups': nodegroup_details
            }
        except ClientError as e:
            logger.error(f"Error getting nodegroups: {e}")
            return {'total_nodegroups': 0, 'nodegroups': []}
    
    def _get_addons_state(self) -> Dict[str, Any]:
        """Analyze cluster addons"""
        try:
            addons = self.eks.list_addons(clusterName=self.cluster_name)['addons']
            addon_details = []
            
            for addon_name in addons:
                addon = self.eks.describe_addon(
                    clusterName=self.cluster_name,
                    addonName=addon_name
                )['addon']
                
                # Get latest available version for this cluster version
                addon_versions = self.eks.describe_addon_versions(
                    addonName=addon_name,
                    kubernetesVersion=self._get_cluster_info()['version']
                )['addons'][0]['addonVersions']
                
                # Sort versions properly (semantic versioning)
                def version_key(version_str):
                    # Extract version numbers from strings like "v1.19.0-eksbuild.1"
                    import re
                    match = re.search(r'v?(\d+)\.(\d+)\.(\d+)', version_str)
                    if match:
                        return tuple(map(int, match.groups()))
                    return (0, 0, 0)
                
                latest_version = max(addon_versions, key=lambda x: version_key(x['addonVersion']))['addonVersion']
                current_version = addon['addonVersion']
                
                # Compare versions properly
                needs_update = version_key(current_version) < version_key(latest_version)
                
                addon_details.append({
                    'name': addon_name,
                    'version': current_version,
                    'latest_version': latest_version,
                    'status': addon['status'],
                    'service_account_role_arn': addon.get('serviceAccountRoleArn'),
                    'needs_update': needs_update
                })
            
            return {
                'total_addons': len(addons),
                'addons': addon_details,
                'vpc_cni_managed': 'vpc-cni' in addons,
                'coredns_managed': 'coredns' in addons,
                'kube_proxy_managed': 'kube-proxy' in addons
            }
        except ClientError as e:
            logger.error(f"Error getting addons: {e}")
            return {'total_addons': 0, 'addons': []}
    
    def _get_logging_state(self) -> Dict[str, Any]:
        """Analyze cluster logging configuration"""
        cluster_info = self._get_cluster_info()
        logging_config = cluster_info.get('logging', {}).get('clusterLogging', [])
        
        enabled_logs = []
        disabled_logs = []
        
        log_types = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
        
        for log_config in logging_config:
            if log_config.get('enabled', False):
                enabled_logs.extend(log_config.get('types', []))
        
        disabled_logs = [log_type for log_type in log_types if log_type not in enabled_logs]
        
        # Check log group retention
        log_retention = None
        try:
            log_groups = self.logs.describe_log_groups(
                logGroupNamePrefix=f'/aws/eks/{self.cluster_name}/cluster'
            )['logGroups']
            if log_groups:
                log_retention = log_groups[0].get('retentionInDays')
        except ClientError:
            pass
        
        return {
            'enabled_log_types': enabled_logs,
            'disabled_log_types': disabled_logs,
            'audit_logging_enabled': 'audit' in enabled_logs,
            'api_logging_enabled': 'api' in enabled_logs,
            'log_retention_days': log_retention
        }
    
    def _get_iam_state(self) -> Dict[str, Any]:
        """Analyze IAM configuration"""
        cluster_info = self._get_cluster_info()
        
        # Get cluster service role
        cluster_role_arn = cluster_info.get('roleArn')
        
        # Count IRSA roles - check both IAM roles and addon service account roles
        irsa_roles = []
        addon_irsa_count = 0
        
        # Check addons for IRSA usage
        try:
            addons = self.eks.list_addons(clusterName=self.cluster_name)['addons']
            for addon_name in addons:
                addon = self.eks.describe_addon(
                    clusterName=self.cluster_name,
                    addonName=addon_name
                )['addon']
                if addon.get('serviceAccountRoleArn'):
                    addon_irsa_count += 1
                    irsa_roles.append({
                        'role_name': addon.get('serviceAccountRoleArn', '').split('/')[-1],
                        'role_arn': addon.get('serviceAccountRoleArn'),
                        'type': 'addon',
                        'addon_name': addon_name
                    })
        except ClientError as e:
            logger.error(f"Error checking addon IRSA: {e}")
        
        # Check for custom IRSA roles
        try:
            oidc_issuer = cluster_info.get('identity', {}).get('oidc', {}).get('issuer', '')
            if oidc_issuer:
                oidc_id = oidc_issuer.replace('https://', '')
                
                paginator = self.iam.get_paginator('list_roles')
                for page in paginator.paginate():
                    for role in page['Roles']:
                        assume_policy = role.get('AssumeRolePolicyDocument', {})
                        if isinstance(assume_policy, str):
                            import json
                            assume_policy = json.loads(assume_policy)
                        
                        # Check if role is for IRSA with this cluster
                        for statement in assume_policy.get('Statement', []):
                            if (statement.get('Effect') == 'Allow' and 
                                'sts:AssumeRoleWithWebIdentity' in statement.get('Action', []) and
                                oidc_id in str(statement.get('Condition', {}))):
                                # Avoid duplicates from addons
                                if not any(r['role_arn'] == role['Arn'] for r in irsa_roles):
                                    irsa_roles.append({
                                        'role_name': role['RoleName'],
                                        'role_arn': role['Arn'],
                                        'type': 'custom'
                                    })
                                break
        except ClientError as e:
            logger.error(f"Error listing custom IRSA roles: {e}")
        
        return {
            'cluster_service_role': cluster_role_arn,
            'irsa_roles_count': len(irsa_roles),
            'irsa_roles': irsa_roles,
            'addon_irsa_count': addon_irsa_count,
            'custom_irsa_count': len(irsa_roles) - addon_irsa_count
        }
    
    def _get_account_id(self) -> str:
        """Get AWS account ID"""
        try:
            return boto3.client('sts').get_caller_identity()['Account']
        except:
            return "unknown"
