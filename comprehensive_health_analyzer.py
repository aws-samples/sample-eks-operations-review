import boto3
import json
import ipaddress
from datetime import datetime, timedelta
from iam_role_auth import get_aws_clients

class ComprehensiveHealthAnalyzer:
    def __init__(self, cluster_name, region, role_arn=None):
        self.cluster_name = cluster_name
        self.region = region
        self.clients = get_aws_clients(role_arn, region)
        
    def analyze_comprehensive_health(self):
        """Comprehensive cluster health analysis"""
        analysis = {
            'network_analysis': self._analyze_networking(),
            'addon_deep_analysis': self._analyze_addons_deep(),
            'security_analysis': self._analyze_security_deep(),
            'scalability_analysis': self._analyze_scalability(),
            'reliability_analysis': self._analyze_reliability(),
            'cost_analysis': self._analyze_cost_optimization(),
            'upgrade_analysis': self._analyze_upgrade_readiness(),
            'autoscaling_analysis': self._analyze_autoscaling()
        }
        return analysis
    
    def _analyze_networking(self):
        """Deep network analysis including CIDR and IP exhaustion"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            vpc_config = cluster['resourcesVpcConfig']
            
            # Get VPC and subnet details
            vpc = self.clients['ec2'].describe_vpcs(VpcIds=[vpc_config['vpcId']])['Vpcs'][0]
            subnets = self.clients['ec2'].describe_subnets(SubnetIds=vpc_config['subnetIds'])['Subnets']
            
            # Calculate IP utilization
            network_analysis = {
                'vpc_cidr': vpc['CidrBlock'],
                'total_vpc_ips': int(ipaddress.IPv4Network(vpc['CidrBlock']).num_addresses),
                'subnets': [],
                'ip_exhaustion_risk': 'LOW',
                'network_issues': []
            }
            
            total_available_ips = 0
            for subnet in subnets:
                subnet_network = ipaddress.IPv4Network(subnet['CidrBlock'])
                total_ips = int(subnet_network.num_addresses)
                available_ips = subnet['AvailableIpAddressCount']
                utilization = ((total_ips - available_ips) / total_ips) * 100
                
                subnet_info = {
                    'subnet_id': subnet['SubnetId'],
                    'cidr': subnet['CidrBlock'],
                    'az': subnet['AvailabilityZone'],
                    'total_ips': total_ips,
                    'available_ips': available_ips,
                    'utilization_percent': round(utilization, 2),
                    'is_public': subnet['MapPublicIpOnLaunch']
                }
                
                # Check for IP exhaustion risk
                if utilization > 80:
                    network_analysis['network_issues'].append(f"Subnet {subnet['SubnetId']} has {utilization:.1f}% IP utilization - HIGH RISK")
                    network_analysis['ip_exhaustion_risk'] = 'HIGH'
                elif utilization > 60:
                    network_analysis['network_issues'].append(f"Subnet {subnet['SubnetId']} has {utilization:.1f}% IP utilization - MEDIUM RISK")
                    if network_analysis['ip_exhaustion_risk'] == 'LOW':
                        network_analysis['ip_exhaustion_risk'] = 'MEDIUM'
                
                network_analysis['subnets'].append(subnet_info)
                total_available_ips += available_ips
            
            # Check endpoint configuration
            if vpc_config['endpointPublicAccess'] and vpc_config.get('publicAccessCidrs') == ['0.0.0.0/0']:
                network_analysis['network_issues'].append("API endpoint accessible from anywhere (0.0.0.0/0) - SECURITY RISK")
            
            if not vpc_config['endpointPrivateAccess']:
                network_analysis['network_issues'].append("Private endpoint access disabled - RELIABILITY RISK")
            
            network_analysis['total_available_ips'] = total_available_ips
            
            return network_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_addons_deep(self):
        """Deep analysis of degraded add-ons"""
        try:
            addons_list = self.clients['eks'].list_addons(clusterName=self.cluster_name)
            addon_analysis = {
                'total_addons': len(addons_list['addons']),
                'healthy_addons': 0,
                'degraded_addons': 0,
                'addon_details': [],
                'critical_issues': []
            }
            
            for addon_name in addons_list['addons']:
                addon = self.clients['eks'].describe_addon(
                    clusterName=self.cluster_name,
                    addonName=addon_name
                )['addon']
                
                addon_detail = {
                    'name': addon['addonName'],
                    'version': addon['addonVersion'],
                    'status': addon['status'],
                    'health_issues': addon.get('health', {}).get('issues', []),
                    'service_account_role': addon.get('serviceAccountRoleArn'),
                    'configuration': addon.get('configurationValues')
                }
                
                if addon['status'] == 'ACTIVE':
                    addon_analysis['healthy_addons'] += 1
                elif addon['status'] == 'DEGRADED':
                    addon_analysis['degraded_addons'] += 1
                    
                    # Analyze specific issues
                    for issue in addon.get('health', {}).get('issues', []):
                        if 'InsufficientNumberOfReplicas' in issue.get('code', ''):
                            addon_analysis['critical_issues'].append(f"{addon_name}: Insufficient replicas - likely resource constraints")
                        elif 'unschedulable' in issue.get('message', '').lower():
                            addon_analysis['critical_issues'].append(f"{addon_name}: Pods unschedulable - node resource/taint issues")
                
                addon_analysis['addon_details'].append(addon_detail)
            
            return addon_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_security_deep(self):
        """Deep security analysis"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            
            security_analysis = {
                'security_score': 0,
                'max_score': 100,
                'security_issues': [],
                'compliance_status': {}
            }
            
            # Check encryption (20 points)
            if cluster.get('encryptionConfig'):
                security_analysis['security_score'] += 20
            else:
                security_analysis['security_issues'].append("Secrets encryption disabled - HIGH RISK")
            
            # Check logging (20 points)
            logging_config = cluster.get('logging', {}).get('clusterLogging', [])
            enabled_logs = [log['types'] for log in logging_config if log.get('enabled')]
            if enabled_logs and any('audit' in logs for logs in enabled_logs):
                security_analysis['security_score'] += 20
            else:
                security_analysis['security_issues'].append("Audit logging disabled - HIGH RISK")
            
            # Check IRSA (20 points)
            if cluster.get('identity', {}).get('oidc', {}).get('issuer'):
                security_analysis['security_score'] += 20
            else:
                security_analysis['security_issues'].append("IRSA not configured - HIGH RISK")
            
            # Check endpoint access (20 points)
            vpc_config = cluster['resourcesVpcConfig']
            if vpc_config['endpointPrivateAccess']:
                security_analysis['security_score'] += 10
            if vpc_config.get('publicAccessCidrs') != ['0.0.0.0/0']:
                security_analysis['security_score'] += 10
            else:
                security_analysis['security_issues'].append("API endpoint open to internet - HIGH RISK")
            
            # Check node groups (20 points)
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            secure_nodegroups = 0
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                if not ng.get('remoteAccess'):
                    secure_nodegroups += 1
                else:
                    security_analysis['security_issues'].append(f"Node group {ng_name} has SSH access enabled")
            
            if secure_nodegroups == len(nodegroups['nodegroups']):
                security_analysis['security_score'] += 20
            
            return security_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_scalability(self):
        """Analyze cluster scalability"""
        try:
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            
            scalability_analysis = {
                'current_capacity': {},
                'scaling_limits': {},
                'scalability_issues': []
            }
            
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                scaling_config = ng.get('scalingConfig', {})
                current_size = scaling_config.get('desiredSize', 0)
                max_size = scaling_config.get('maxSize', 0)
                
                scalability_analysis['current_capacity'][ng_name] = {
                    'current_nodes': current_size,
                    'max_nodes': max_size,
                    'instance_types': ng.get('instanceTypes', [])
                }
                
                # Check scaling headroom
                if max_size <= current_size:
                    scalability_analysis['scalability_issues'].append(
                        f"Node group {ng_name} has no scaling headroom"
                    )
            
            return scalability_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_reliability(self):
        """Analyze cluster reliability"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            
            reliability_analysis = {
                'reliability_score': 0,
                'reliability_issues': []
            }
            
            # Check multi-AZ deployment
            vpc_config = cluster['resourcesVpcConfig']
            subnets = self.clients['ec2'].describe_subnets(SubnetIds=vpc_config['subnetIds'])['Subnets']
            availability_zones = set(subnet['AvailabilityZone'] for subnet in subnets)
            
            if len(availability_zones) >= 2:
                reliability_analysis['reliability_score'] += 50
            else:
                reliability_analysis['reliability_issues'].append("Single AZ deployment")
            
            # Check private endpoint access
            if vpc_config['endpointPrivateAccess']:
                reliability_analysis['reliability_score'] += 50
            else:
                reliability_analysis['reliability_issues'].append("No private endpoint access")
            
            return reliability_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_cost_optimization(self):
        """Analyze cost optimization"""
        try:
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            
            cost_analysis = {
                'cost_optimization_score': 0,
                'savings_opportunities': []
            }
            
            spot_usage = 0
            total_nodegroups = len(nodegroups['nodegroups'])
            
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                capacity_type = ng.get('capacityType', 'ON_DEMAND')
                if capacity_type == 'SPOT':
                    spot_usage += 1
                else:
                    cost_analysis['savings_opportunities'].append(
                        f"Consider Spot instances for {ng_name}"
                    )
            
            if total_nodegroups > 0:
                cost_analysis['cost_optimization_score'] = (spot_usage / total_nodegroups) * 100
            
            return cost_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_upgrade_readiness(self):
        """Analyze upgrade readiness"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            
            upgrade_analysis = {
                'current_version': cluster['version'],
                'upgrade_readiness_score': 0,
                'upgrade_blockers': []
            }
            
            # Check if version is current
            current_version = float(cluster['version'])
            if current_version >= 1.30:
                upgrade_analysis['upgrade_readiness_score'] = 100
            elif current_version >= 1.28:
                upgrade_analysis['upgrade_readiness_score'] = 80
            else:
                upgrade_analysis['upgrade_blockers'].append("Version is outdated")
                upgrade_analysis['upgrade_readiness_score'] = 40
            
            return upgrade_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_autoscaling(self):
        """Analyze autoscaling configuration"""
        try:
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            
            autoscaling_analysis = {
                'autoscaling_score': 0,
                'autoscaling_issues': []
            }
            
            properly_configured = 0
            total_nodegroups = len(nodegroups['nodegroups'])
            
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                scaling_config = ng.get('scalingConfig', {})
                min_size = scaling_config.get('minSize', 0)
                max_size = scaling_config.get('maxSize', 0)
                
                if max_size > min_size:
                    properly_configured += 1
                else:
                    autoscaling_analysis['autoscaling_issues'].append(
                        f"Node group {ng_name} has no autoscaling range"
                    )
            
            if total_nodegroups > 0:
                autoscaling_analysis['autoscaling_score'] = (properly_configured / total_nodegroups) * 100
            
            return autoscaling_analysis
            
        except Exception as e:
            return {'error': str(e)}
