"""
Core analysis functionality - Enhanced with detailed findings and evidence
"""
import boto3
import json
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from .aws_client import AWSClientManager
from .enhanced_analyzers import EnhancedSecurityAnalyzer

class HealthAnalyzer:
    """Comprehensive cluster health analysis"""
    
    def __init__(self, cluster_name: str, region: str, role_arn: Optional[str] = None):
        self.cluster_name = cluster_name
        self.region = region
        self.aws_client = AWSClientManager(region, role_arn)
        self.clients = self.aws_client.get_clients()
    
    def analyze_comprehensive_health(self) -> Dict[str, Any]:
        """Main health analysis method"""
        return {
            'cluster_info': self._get_cluster_info(),
            'network_analysis': self._analyze_networking(),
            'addon_analysis': self._analyze_addons(),
            'security_analysis': self._analyze_security_basics(),
            'node_analysis': self._analyze_nodes(),
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_cluster_info(self) -> Dict[str, Any]:
        """Get basic cluster information"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            return {
                'name': cluster['name'],
                'status': cluster['status'],
                'version': cluster['version'],
                'platform_version': cluster['platformVersion'],
                'endpoint': cluster['endpoint'],
                'created_at': cluster['createdAt'].isoformat() if 'createdAt' in cluster else None,
                'arn': cluster.get('arn'),
                'role_arn': cluster.get('roleArn')
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_networking(self) -> Dict[str, Any]:
        """Enhanced network analysis with detailed findings"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            vpc_config = cluster['resourcesVpcConfig']
            
            vpc = self.clients['ec2'].describe_vpcs(VpcIds=[vpc_config['vpcId']])['Vpcs'][0]
            subnets = self.clients['ec2'].describe_subnets(SubnetIds=vpc_config['subnetIds'])['Subnets']
            
            network_analysis = {
                'vpc_id': vpc_config['vpcId'],
                'vpc_cidr': vpc['CidrBlock'],
                'subnets': [],
                'endpoint_config': {
                    'public_access': vpc_config['endpointPublicAccess'],
                    'private_access': vpc_config['endpointPrivateAccess'],
                    'public_cidrs': vpc_config.get('publicAccessCidrs', [])
                },
                'issues': [],
                'security_groups': vpc_config.get('securityGroupIds', []),
                'cluster_security_group': vpc_config.get('clusterSecurityGroupId')
            }
            
            total_available_ips = 0
            high_utilization_subnets = 0
            
            for subnet in subnets:
                subnet_network = ipaddress.IPv4Network(subnet['CidrBlock'])
                total_ips = int(subnet_network.num_addresses)
                available_ips = subnet['AvailableIpAddressCount']
                utilization = ((total_ips - available_ips) / total_ips) * 100
                
                subnet_info = {
                    'subnet_id': subnet['SubnetId'],
                    'cidr': subnet['CidrBlock'],
                    'az': subnet['AvailabilityZone'],
                    'available_ips': available_ips,
                    'total_ips': total_ips,
                    'utilization_percent': round(utilization, 2),
                    'is_public': subnet.get('MapPublicIpOnLaunch', False),
                    'route_table': subnet.get('RouteTableId', 'Unknown')
                }
                
                if utilization > 80:
                    network_analysis['issues'].append(f"CRITICAL: Subnet {subnet['SubnetId']} has {utilization:.1f}% IP utilization - Risk of IP exhaustion")
                    high_utilization_subnets += 1
                elif utilization > 60:
                    network_analysis['issues'].append(f"WARNING: Subnet {subnet['SubnetId']} has {utilization:.1f}% IP utilization - Monitor closely")
                
                network_analysis['subnets'].append(subnet_info)
                total_available_ips += available_ips
            
            # Enhanced security checks
            if vpc_config['endpointPublicAccess'] and '0.0.0.0/0' in vpc_config.get('publicAccessCidrs', []):
                network_analysis['issues'].append("CRITICAL: API endpoint accessible from anywhere (0.0.0.0/0) - Major security risk")
            
            if not vpc_config['endpointPrivateAccess']:
                network_analysis['issues'].append("HIGH: Private endpoint access disabled - Reduces security and reliability")
            
            if len(vpc_config.get('publicAccessCidrs', [])) > 10:
                network_analysis['issues'].append(f"MEDIUM: Too many public access CIDRs ({len(vpc_config['publicAccessCidrs'])}) - Consider consolidation")
            
            # Add summary metrics
            network_analysis.update({
                'total_available_ips': total_available_ips,
                'high_utilization_subnets': high_utilization_subnets,
                'subnet_count': len(subnets),
                'az_distribution': len(set(s['AvailabilityZone'] for s in subnets))
            })
            
            return network_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_addons(self) -> Dict[str, Any]:
        """Enhanced addon analysis with detailed status"""
        try:
            addons_list = self.clients['eks'].list_addons(clusterName=self.cluster_name)
            addon_analysis = {
                'total_addons': len(addons_list['addons']),
                'addon_details': [],
                'issues': [],
                'healthy_addons': 0,
                'degraded_addons': 0
            }
            
            for addon_name in addons_list['addons']:
                try:
                    addon_info = self.clients['eks'].describe_addon(
                        clusterName=self.cluster_name,
                        addonName=addon_name
                    )['addon']
                    
                    addon_detail = {
                        'name': addon_name,
                        'status': addon_info['status'],
                        'version': addon_info['addonVersion'],
                        'service_account_role_arn': addon_info.get('serviceAccountRoleArn'),
                        'created_at': addon_info.get('createdAt').isoformat() if addon_info.get('createdAt') else None,
                        'modified_at': addon_info.get('modifiedAt').isoformat() if addon_info.get('modifiedAt') else None
                    }
                    
                    if addon_info['status'] == 'ACTIVE':
                        addon_analysis['healthy_addons'] += 1
                    else:
                        addon_analysis['degraded_addons'] += 1
                        severity = 'CRITICAL' if addon_name in ['vpc-cni', 'coredns'] else 'HIGH'
                        addon_analysis['issues'].append(f"{severity}: Addon {addon_name} is {addon_info['status']} - May impact cluster functionality")
                    
                    # Check for outdated versions (simplified check)
                    if 'v1.1' in addon_info['addonVersion'] or 'v1.0' in addon_info['addonVersion']:
                        addon_analysis['issues'].append(f"MEDIUM: Addon {addon_name} version {addon_info['addonVersion']} may be outdated")
                    
                    addon_analysis['addon_details'].append(addon_detail)
                    
                except Exception as addon_error:
                    addon_analysis['issues'].append(f"ERROR: Failed to describe addon {addon_name}: {str(addon_error)}")
            
            return addon_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_security_basics(self) -> Dict[str, Any]:
        """Basic security analysis - enhanced version will be called separately"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            
            security_analysis = {
                'encryption_at_rest': cluster.get('encryptionConfig', []),
                'logging': cluster.get('logging', {}),
                'issues': [],
                'kubernetes_version': cluster.get('version'),
                'platform_version': cluster.get('platformVersion')
            }
            
            # Check encryption
            if not cluster.get('encryptionConfig'):
                security_analysis['issues'].append("CRITICAL: Encryption at rest not configured - Secrets stored unencrypted")
            
            # Check logging
            logging_config = cluster.get('logging', {})
            cluster_logging = logging_config.get('clusterLogging', [])
            if not cluster_logging or not any(log.get('enabled', False) for log in cluster_logging):
                security_analysis['issues'].append("HIGH: Control plane logging not enabled - No audit trail")
            
            # Check Kubernetes version
            version = cluster.get('version', '')
            if version and version < '1.28':
                security_analysis['issues'].append(f"MEDIUM: Kubernetes version {version} may be outdated - Consider upgrading")
            
            return security_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_nodes(self) -> Dict[str, Any]:
        """Enhanced node group analysis"""
        try:
            node_groups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            node_analysis = {
                'total_node_groups': len(node_groups['nodegroups']),
                'node_groups': [],
                'total_nodes': 0,
                'issues': [],
                'instance_types': set(),
                'ami_types': set()
            }
            
            for ng_name in node_groups['nodegroups']:
                try:
                    ng_info = self.clients['eks'].describe_nodegroup(
                        clusterName=self.cluster_name,
                        nodegroupName=ng_name
                    )['nodegroup']
                    
                    node_group = {
                        'name': ng_name,
                        'status': ng_info['status'],
                        'instance_types': ng_info['instanceTypes'],
                        'ami_type': ng_info.get('amiType', 'Unknown'),
                        'capacity_type': ng_info.get('capacityType', 'ON_DEMAND'),
                        'desired_size': ng_info['scalingConfig']['desiredSize'],
                        'min_size': ng_info['scalingConfig']['minSize'],
                        'max_size': ng_info['scalingConfig']['maxSize'],
                        'disk_size': ng_info.get('diskSize', 'Unknown'),
                        'remote_access': ng_info.get('remoteAccess', {}),
                        'created_at': ng_info.get('createdAt').isoformat() if ng_info.get('createdAt') else None
                    }
                    
                    node_analysis['total_nodes'] += ng_info['scalingConfig']['desiredSize']
                    node_analysis['instance_types'].update(ng_info['instanceTypes'])
                    node_analysis['ami_types'].add(ng_info.get('amiType', 'Unknown'))
                    
                    if ng_info['status'] != 'ACTIVE':
                        node_analysis['issues'].append(f"CRITICAL: Node group {ng_name} is {ng_info['status']} - May impact workload availability")
                    
                    # Check for potential issues
                    if ng_info['scalingConfig']['desiredSize'] == ng_info['scalingConfig']['maxSize']:
                        node_analysis['issues'].append(f"WARNING: Node group {ng_name} cannot scale up (desired = max)")
                    
                    if ng_info.get('remoteAccess', {}).get('ec2SshKey'):
                        node_analysis['issues'].append(f"MEDIUM: Node group {ng_name} has SSH access enabled - Security consideration")
                    
                    node_analysis['node_groups'].append(node_group)
                    
                except Exception as ng_error:
                    node_analysis['issues'].append(f"ERROR: Failed to describe node group {ng_name}: {str(ng_error)}")
            
            # Convert sets to lists for JSON serialization
            node_analysis['instance_types'] = list(node_analysis['instance_types'])
            node_analysis['ami_types'] = list(node_analysis['ami_types'])
            
            return node_analysis
            
        except Exception as e:
            return {'error': str(e)}

class SecurityAnalyzer:
    """Enhanced security analysis using detailed methodology"""
    
    def __init__(self, cluster_name: str, region: str, role_arn: Optional[str] = None):
        self.cluster_name = cluster_name
        self.region = region
        self.enhanced_analyzer = EnhancedSecurityAnalyzer(cluster_name, region, role_arn)
    
    def run_security_checks(self) -> Dict[str, Any]:
        """Run comprehensive security checks with detailed findings"""
        return self.enhanced_analyzer.run_comprehensive_security_checks()
