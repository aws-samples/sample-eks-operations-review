import boto3
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class AWSUtils:
    """Utility class for interacting with AWS EKS and related services."""
    def __init__(self, aws_access_key, aws_secret_key, region, cluster_name):
        """Initialize AWS clients and set cluster configuration.
        
        Args:
            aws_access_key (str): AWS access key ID
            aws_secret_key (str): AWS secret access key
            region (str): AWS region
            cluster_name (str): Name of the EKS cluster
        """        
        self.cluster_name = cluster_name
        self.region = region
        
        # Initialize AWS clients
        self.eks = boto3.client(
            'eks',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        self.ec2 = boto3.client(
            'ec2',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        self.cloudwatch = boto3.client(
            'cloudwatch',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        
        self.iam = boto3.client(
            'iam',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
        self.logs = boto3.client(
            'logs',
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=region
        )
    def _compare_versions(self, version1, version2):
        """Compare two version strings.
        
        Args:
            version1 (str): First version string
            version2 (str): Second version string
            
        Returns:
            int: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            for i in range(max(len(v1_parts), len(v2_parts))):
                v1 = v1_parts[i] if i < len(v1_parts) else 0
                v2 = v2_parts[i] if i < len(v2_parts) else 0
                if v1 < v2:
                    return -1
                if v1 > v2:
                    return 1
            return 0
        except Exception as e:
            logging.error(f"Error comparing versions: {e}")
            return 0

    def get_cluster_details(self):
        """Get comprehensive cluster details"""
        try:
            cluster_info = {
                'cluster': {},
                'nodegroups': [],
                'addons': [],
                'version_info': {},
                'networking': {},
                'security': {},
                'workloads': {},
                'resources': {},
                'metrics': {}
            }

            # Get cluster details
            cluster = self.eks.describe_cluster(name=self.cluster_name)
            logging.info(f"Raw cluster data: {cluster}")  # Log raw cluster data

            if 'cluster' not in cluster:
                raise KeyError("'cluster' key not found in EKS describe_cluster response")

            cluster_data = cluster['cluster']
            required_keys = ['version', 'status', 'endpoint', 'platformVersion', 'resourcesVpcConfig']
            
            for key in required_keys:
                if key not in cluster_data:
                    raise KeyError(f"'{key}' not found in cluster data")

            cluster_info['cluster'] = {
                'name': self.cluster_name,
                'version': cluster_data['version'],
                'status': cluster_data['status'],
                'endpoint': cluster_data['endpoint'],
                'platform_version': cluster_data['platformVersion'],
                'vpc_config': cluster_data['resourcesVpcConfig'],
                'logging': cluster_data.get('logging', {}),
                'identity': cluster_data.get('identity', {})
            }
            return cluster_info

        except KeyError as e:
            logging.error(f"KeyError in get_cluster_details: {e}")
            raise
        except Exception as e:
            logging.error(f"Error getting cluster details: {e}", exc_info=True)
            raise
            # Version analysis
            cluster_info['version_info'] = self._analyze_version(cluster['cluster']['version'])

            # Get add-ons with versions and update status
            addons = self.eks.list_addons(clusterName=self.cluster_name)
            for addon_name in addons.get('addons', []):
                addon = self.eks.describe_addon(
                    clusterName=self.cluster_name,
                    addonName=addon_name
                )
                # Get available updates for addon
                updates = self.eks.describe_addon_versions(
                    addonName=addon_name,
                    kubernetesVersion=cluster['cluster']['version']
                )
                latest_version = self._get_latest_addon_version(updates)
                
                cluster_info['addons'].append({
                    'name': addon_name,
                    'version': addon['addon']['addonVersion'],
                    'status': addon['addon']['status'],
                    'service_account': addon['addon'].get('serviceAccountRoleArn'),
                    'latest_version': latest_version,
                    'needs_update': latest_version > addon['addon']['addonVersion']
                })

            # Get nodegroups with detailed info
            nodegroups = self.eks.list_nodegroups(clusterName=self.cluster_name)
            for ng_name in nodegroups.get('nodegroups', []):
                ng = self.eks.describe_nodegroup(
                    clusterName=self.cluster_name,
                    nodegroupName=ng_name
                )
                
                # Get node details
                node_info = self._get_node_details(ng['nodegroup'])
                
                ng_info = {
                    'name': ng_name,
                    'status': ng['nodegroup']['status'],
                    'instanceTypes': ng['nodegroup'].get('instanceTypes', []),
                    'capacityType': ng['nodegroup'].get('capacityType'),
                    'scalingConfig': ng['nodegroup']['scalingConfig'],
                    'diskSize': ng['nodegroup'].get('diskSize'),
                    'subnets': ng['nodegroup']['subnets'],
                    'ami': ng['nodegroup'].get('amiType'),
                    'health': ng['nodegroup'].get('health', {}),
                    'updateConfig': ng['nodegroup'].get('updateConfig', {}),
                    'nodes': node_info
                }
                cluster_info['nodegroups'].append(ng_info)

            # Get networking details
            cluster_info['networking'] = self._get_networking_details(cluster['cluster']['resourcesVpcConfig'])

            # Get security details
            cluster_info['security'] = self._get_security_details()

            # Get workload metrics and status
            cluster_info['metrics'] = self._get_detailed_metrics()
            cluster_info['workloads'] = self._get_workload_details()

            return cluster_info

        except Exception as e:
            logging.error(f"Error getting cluster details: {e}")
            raise

    def _get_latest_addon_version(self, versions):
        """Get the latest available version for an addon"""
        latest = "0.0.0"
        for version in versions['addons']:
            for addon_version in version['addonVersions']:
                if addon_version['addonVersion'] > latest:
                    latest = addon_version['addonVersion']
        return latest
    def _get_addon_recommendations(self, addon_name, current_version, latest_version):
        """Generate recommendations for addon updates.
        
        Args:
            addon_name (str): Name of the addon
            current_version (str): Current version of the addon
            latest_version (str): Latest available version of the addon
            
        Returns:
            dict: Recommendation details
        """
        if self._compare_versions(current_version, latest_version) < 0:
            return {
                'priority': 'Medium',
                'title': f'Update {addon_name} Add-on',
                'description': f'Current version {current_version} is behind latest {latest_version}',
                'impact': 'Missing security patches and feature updates',
                'action_items': [
                    f'Plan upgrade to version {latest_version}',
                    'Review changelog for breaking changes',
                    'Test upgrade in non-production environment',
                    'Schedule maintenance window for update'
                ]
            }
        return None

    def _get_node_details(self, nodegroup):
        """Get detailed information about the nodes in a nodegroup"""
        try:
            instance_ids = []
            waiter = self.ec2.get_waiter('instance_running')
            
            # Get instance IDs from ASG
            if 'autoScalingGroups' in nodegroup:
                for asg in nodegroup['autoScalingGroups']:
                    response = self.ec2.describe_instances(
                        Filters=[
                            {
                                'Name': 'tag:aws:autoscaling:groupName',
                                'Values': [asg['name']]
                            }
                        ]
                    )
                    for reservation in response['Reservations']:
                        for instance in reservation['Instances']:
                            instance_ids.append(instance['InstanceId'])

            nodes = []
            for instance_id in instance_ids:
                instance = self.ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
                nodes.append({
                    'instance_id': instance_id,
                    'instance_type': instance['InstanceType'],
                    'availability_zone': instance['Placement']['AvailabilityZone'],
                    'private_ip': instance['PrivateIpAddress'],
                    'launch_time': instance['LaunchTime'].isoformat(),
                    'state': instance['State']['Name'],
                    'tags': instance.get('Tags', [])
                })
            
            return nodes
            
        except Exception as e:
            logging.error(f"Error getting node details: {e}")
            return []

    def _analyze_version(self, version):
        """Analyze Kubernetes version and provide recommendations"""
        try:
            # Get all available EKS versions
            versions = self.eks.describe_addon_versions(
                kubernetesVersion=version
            )
            
            latest_version = max([v['kubernetesVersion'] for v in versions.get('addons', [{'kubernetesVersion': version}])])
            
            version_info = {
                'current': version,
                'latest': latest_version,
                'status': 'current',
                'recommendations': []
            }

            if version < latest_version:
                version_info['status'] = 'outdated'
                version_info['recommendations'].append({
                    'priority': 'High',
                    'title': 'Kubernetes Version Upgrade Required',
                    'description': f'Current version {version} is behind latest {latest_version}',
                    'impact': 'Missing security patches and feature updates',
                    'action_items': [
                        f'Plan upgrade to version {latest_version}',
                        'Review breaking changes in new version',
                        'Schedule maintenance window',
                        'Test upgrade process in non-production environment'
                    ]
                })
            
            # Check for end of support
            if version <= "1.23":
                version_info['recommendations'].append({
                    'priority': 'Critical',
                    'title': 'Kubernetes Version End of Support',
                    'description': f'Version {version} has reached end of support',
                    'impact': 'No security updates or bug fixes available',
                    'action_items': [
                        'Immediately plan upgrade to supported version',
                        'Review application compatibility',
                        'Schedule emergency upgrade window'
                    ]
                })

            return version_info
            
        except Exception as e:
            logging.error(f"Error analyzing version: {e}")
            return {
                'current': version,
                'latest': 'unknown',
                'status': 'unknown',
                'recommendations': []
            }

    def _get_networking_details(self, vpc_config):
        """Get detailed networking configuration and status"""
        try:
            # Get VPC details
            vpc = self.ec2.describe_vpcs(VpcIds=[vpc_config['vpcId']])['Vpcs'][0]
            
            # Get subnet details
            subnets = self.ec2.describe_subnets(SubnetIds=vpc_config['subnetIds'])['Subnets']
            
            # Get security group details
            security_groups = self.ec2.describe_security_groups(
                GroupIds=vpc_config['securityGroupIds']
            )['SecurityGroups']

            # Analyze pod networking
            pod_networking = self._analyze_pod_networking()

            return {
                'vpc': vpc,
                'subnets': subnets,
                'security_groups': security_groups,
                'endpoint_access': {
                    'public': vpc_config['endpointPublicAccess'],
                    'private': vpc_config['endpointPrivateAccess'],
                    'public_access_cidrs': vpc_config.get('publicAccessCidrs', [])
                },
                'pod_networking': pod_networking
            }
        except Exception as e:
            logging.error(f"Error getting networking details: {e}")
            return {}

    def _analyze_pod_networking(self):
        """Analyze pod networking configuration"""
        try:
            # Get VPC CNI addon details
            vpc_cni = self.eks.describe_addon(
                clusterName=self.cluster_name,
                addonName='vpc-cni'
            )
            
            return {
                'cni_version': vpc_cni['addon']['addonVersion'],
                'custom_networking': self._check_custom_networking(),
                'prefix_delegation': self._check_prefix_delegation(),
                'security_groups_for_pods': self._check_security_groups_for_pods()
            }
        except Exception as e:
            logging.error(f"Error analyzing pod networking: {e}")
            return {}

    def _get_security_details(self):
        """Get security configuration and compliance status"""
        try:
            security_info = {
                'encryption': self._check_encryption_config(),
                'iam': self._check_iam_configuration(),
                'network_policies': self._check_network_policies(),
                'pod_security': self._check_pod_security(),
                'audit_logging': self._check_audit_logging()
            }
            return security_info
        except Exception as e:
            logging.error(f"Error getting security details: {e}")
            return {}

    def _check_encryption_config(self):
        """Check cluster encryption configuration"""
        try:
            cluster = self.eks.describe_cluster(name=self.cluster_name)
            return {
                'secrets': cluster['cluster'].get('encryptionConfig', []),
                'ebs': self._check_ebs_encryption(),
                'logging': self._check_logging_encryption()
            }
        except Exception as e:
            logging.error(f"Error checking encryption config: {e}")
            return {}

    def _check_iam_configuration(self):
        """Check IAM configuration"""
        try:
            cluster = self.eks.describe_cluster(name=self.cluster_name)
            return {
                'oidc_provider': 'oidc' in cluster['cluster']['identity'],
                'service_accounts': self._get_service_accounts(),
                'roles': self._get_cluster_roles()
            }
        except Exception as e:
            logging.error(f"Error checking IAM configuration: {e}")
            return {}

    def _get_detailed_metrics(self):
        """Get comprehensive metrics about the cluster"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=24)

            metrics = {
                'cpu': self._get_metric_data('CPUUtilization', start_time, end_time),
                'memory': self._get_metric_data('MemoryUtilization', start_time, end_time),
                'pods': self._get_metric_data('PodsInUse', start_time, end_time),
                'nodes': self._get_metric_data('NodesInUse', start_time, end_time),
                'network': {
                    'in': self._get_metric_data('NetworkIn', start_time, end_time),
                    'out': self._get_metric_data('NetworkOut', start_time, end_time)
                },
                'disk': {
                    'read': self._get_metric_data('DiskReadBytes', start_time, end_time),
                    'write': self._get_metric_data('DiskWriteBytes', start_time, end_time)
                }
            }

            return metrics
        except Exception as e:
            logging.error(f"Error getting detailed metrics: {e}")
            return {}

    def _get_metric_data(self, metric_name, start_time, end_time):
        """Get specific metric data"""
        try:
            response = self.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        'Id': metric_name.lower(),
                        'MetricStat': {
                            'Metric': {
                                'Namespace': 'AWS/EKS',
                                'MetricName': metric_name,
                                'Dimensions': [
                                    {'Name': 'ClusterName', 'Value': self.cluster_name}
                                ]
                            },
                            'Period': 300,
                            'Stat': 'Average'
                        }
                    }
                ],
                StartTime=start_time,
                EndTime=end_time
            )
            return response['MetricDataResults'][0]
        except Exception as e:
            logging.error(f"Error getting metric data for {metric_name}: {e}")
            return {}
    def _check_custom_networking(self):
        """Check if custom networking is enabled for VPC CNI"""
        try:
            addon_params = self.eks.describe_addon_configuration(
                addonName='vpc-cni',
                clusterName=self.cluster_name
            )
            config = addon_params.get('configurationValues', {})
            return 'ENABLE_CUSTOM_NETWORKING' in config.get('values', [])
        except Exception as e:
            logging.error(f"Error checking custom networking: {e}")
            return False

    def _check_prefix_delegation(self):
        """Check if prefix delegation is enabled"""
        try:
            addon_params = self.eks.describe_addon_configuration(
                addonName='vpc-cni',
                clusterName=self.cluster_name
            )
            config = addon_params.get('configurationValues', {})
            return 'ENABLE_PREFIX_DELEGATION' in config.get('values', [])
        except Exception as e:
            logging.error(f"Error checking prefix delegation: {e}")
            return False

    def _check_security_groups_for_pods(self):
        """Check if security groups for pods is enabled"""
        try:
            cluster = self.eks.describe_cluster(name=self.cluster_name)
            return cluster['cluster'].get('resourcesVpcConfig', {}).get('securityGroupsForPods', False)
        except Exception as e:
            logging.error(f"Error checking security groups for pods: {e}")
            return False

    def _check_ebs_encryption(self):
        """Check EBS encryption configuration"""
        try:
            response = self.ec2.get_ebs_encryption_by_default()
            return {
                'enabled_by_default': response['EbsEncryptionByDefault'],
                'kms_key_id': response.get('KmsKeyId')
            }
        except Exception as e:
            logging.error(f"Error checking EBS encryption: {e}")
            return {'enabled_by_default': False}

    def _check_logging_encryption(self):
        """Check logging encryption configuration"""
        try:
            cluster = self.eks.describe_cluster(name=self.cluster_name)
            logging_config = cluster['cluster'].get('logging', {}).get('clusterLogging', [])
            return {
                'enabled': any(log.get('enabled', False) for log in logging_config),
                'types': [log['types'] for log in logging_config if log.get('enabled', False)]
            }
        except Exception as e:
            logging.error(f"Error checking logging encryption: {e}")
            return {'enabled': False, 'types': []}

    def _check_network_policies(self):
        """Check network policies configuration"""
        try:
            addons = self.eks.list_addons(clusterName=self.cluster_name)
            return {
                'calico_installed': 'calico' in addons.get('addons', []),
                'vpc_cni_policy_support': self._check_vpc_cni_policy_support()
            }
        except Exception as e:
            logging.error(f"Error checking network policies: {e}")
            return {'calico_installed': False, 'vpc_cni_policy_support': False}

    def _check_vpc_cni_policy_support(self):
        """Check if VPC CNI supports network policies"""
        try:
            addon = self.eks.describe_addon(
                clusterName=self.cluster_name,
                addonName='vpc-cni'
            )
            version = addon['addon']['addonVersion']
            return version >= '1.7.0'  # Version where network policy support was added
        except Exception as e:
            logging.error(f"Error checking VPC CNI policy support: {e}")
            return False
    def _check_pod_security_policies(self):
        """Check if Pod Security Policies are in use"""
        try:
            version = self.eks.describe_cluster(name=self.cluster_name)['cluster']['version']
            # PSPs are removed in k8s 1.25+
            return {
                'available': version < '1.25',
                'enabled': self._check_psp_enabled(),
                'policies_configured': self._check_psp_configuration()
            }
        except Exception as e:
            logging.error(f"Error checking pod security policies: {e}")
            return {'available': False, 'enabled': False, 'policies_configured': False}

    def _check_psp_enabled(self):
        """Check if PSP admission controller is enabled"""
        try:
            cluster = self.eks.describe_cluster(name=self.cluster_name)
            return 'PodSecurityPolicy' in str(cluster['cluster'].get('logging', {}).get('admissionConfig', {}))
        except Exception as e:
            logging.error(f"Error checking PSP enabled: {e}")
            return False

    def _check_psp_configuration(self):
        """Check PSP configuration"""
        # This would require kubectl access to check PSP resources
        return False
    def _get_log_retention(self):
        """Get log retention period"""
        try:
            logs = boto3.client('logs',
                            region_name=self.region)
            response = logs.describe_log_groups(
                logGroupNamePrefix=f'/aws/eks/{self.cluster_name}/cluster'
            )
            if response['logGroups']:
                return response['logGroups'][0].get('retentionInDays', 0)
            return 0
        except Exception as e:
            logging.error(f"Error getting log retention: {e}")
            return 0

    def _check_pod_security(self):
        """Check pod security configuration"""
        try:
            cluster = self.eks.describe_cluster(name=self.cluster_name)
            return {
                'pod_security_standards': self._check_pod_security_standards(),
                'security_groups_pods': cluster['cluster'].get('resourcesVpcConfig', {}).get('securityGroupsForPods', False),
                'pod_security_policies': self._check_pod_security_policies()
            }
        except Exception as e:
            logging.error(f"Error checking pod security: {e}")
            return {}

    def _check_pod_security_standards(self):
        """Check if Pod Security Standards are enforced"""
        try:
            version = self.eks.describe_cluster(name=self.cluster_name)['cluster']['version']
            return {
                'available': version >= '1.25',
                'enforced': self._check_pss_enforcement()
            }
        except Exception as e:
            logging.error(f"Error checking pod security standards: {e}")
            return {'available': False, 'enforced': False}

    def _check_pss_enforcement(self):
        """Check if Pod Security Standards enforcement is configured"""
        # This would require kubectl access to check namespace labels
        return False

    def _check_audit_logging(self):
        """Check audit logging configuration"""
        try:
            cluster = self.eks.describe_cluster(name=self.cluster_name)
            logging = cluster['cluster'].get('logging', {}).get('clusterLogging', [])
            audit_logging = next((log for log in logging if 'audit' in log.get('types', [])), None)
            return {
                'enabled': audit_logging.get('enabled', False) if audit_logging else False,
                'retention': self._get_log_retention(),
                'cloudwatch_insights_enabled': self._check_cloudwatch_insights()
            }
        except Exception as e:
            logging.error(f"Error checking audit logging: {e}")
            return {'enabled': False}


    def _check_cloudwatch_insights(self):
        """Check if CloudWatch Container Insights is enabled"""
        try:
            response = self.cloudwatch.list_metrics(
                Namespace='ContainerInsights',
                MetricName='node_cpu_utilization',
                Dimensions=[{'Name': 'ClusterName', 'Value': self.cluster_name}]
            )
            return len(response['Metrics']) > 0
        except Exception as e:
            logging.error(f"Error checking CloudWatch Insights: {e}")
            return False

    def _get_service_accounts(self):
        """Get service accounts with IAM roles"""
        try:
            service_accounts = []
            paginator = self.iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    if f'eks.amazonaws.com/cluster-name/{self.cluster_name}' in str(role.get('AssumeRolePolicyDocument', {})):
                        service_accounts.append({
                            'role_name': role['RoleName'],
                            'role_arn': role['Arn'],
                            'last_used': role.get('RoleLastUsed', {}).get('LastUsedDate')
                        })
            return service_accounts
        except Exception as e:
            logging.error(f"Error getting service accounts: {e}")
            return []

    def _get_cluster_roles(self):
        """Get IAM roles associated with the cluster"""
        try:
            roles = []
            paginator = self.iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    if f'eks.amazonaws.com/cluster/{self.cluster_name}' in str(role.get('AssumeRolePolicyDocument', {})):
                        roles.append({
                            'role_name': role['RoleName'],
                            'role_arn': role['Arn'],
                            'last_used': role.get('RoleLastUsed', {}).get('LastUsedDate')
                        })
            return roles
        except Exception as e:
            logging.error(f"Error getting cluster roles: {e}")
            return []

    def _get_workload_details(self):
        """Get details about workloads running in the cluster"""
        try:
            workload_info = {
                'deployments': [],
                'statefulsets': [],
                'daemonsets': [],
                'pods': [],
                'services': [],
                'resource_usage': {}
            }

            # This would require kubectl access or kubernetes python client
            # For now, return empty structure
            return workload_info
            
        except Exception as e:
            logging.error(f"Error getting workload details: {e}")
            return {}
    def generate_summary(self):
        """Generate a summary of all findings and recommendations"""
        summary = {
            'cluster_version': self.cluster_info['cluster']['version'],
            'total_nodes': sum(ng['scalingConfig']['desiredSize'] for ng in self.cluster_info['nodegroups']),
            'total_addons': len(self.cluster_info['addons']),
            'critical_issues': [],
            'high_priority_issues': [],
            'medium_priority_issues': [],
            'low_priority_issues': [],
            'recommendations': []
        }

        # Analyze version
        version_info = self._analyze_version(self.cluster_info['cluster']['version'])
        if version_info['status'] == 'outdated':
            summary['high_priority_issues'].append(f"Cluster version outdated: {version_info['current']} < {version_info['latest']}")
            summary['recommendations'].append(f"Upgrade cluster to version {version_info['latest']}")

        # Analyze addons
        for addon in self.cluster_info['addons']:
            if addon['needs_update']:
                summary['medium_priority_issues'].append(f"Addon {addon['name']} needs update: {addon['version']} < {addon['latest_version']}")
                summary['recommendations'].append(f"Update {addon['name']} to version {addon['latest_version']}")

        # Analyze security
        security_info = self._get_security_details()
        if not security_info['encryption'].get('secrets'):
            summary['high_priority_issues'].append("Secrets encryption not enabled")
            summary['recommendations'].append("Enable envelope encryption for Kubernetes secrets")

        if not security_info['iam'].get('oidc_provider'):
            summary['medium_priority_issues'].append("OIDC provider not configured")
            summary['recommendations'].append("Set up OIDC provider for better IAM integration")

        # Add more analysis and recommendations based on other checks

        return summary
