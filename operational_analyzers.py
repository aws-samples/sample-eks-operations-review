import boto3
from datetime import datetime, timedelta
from iam_role_auth import get_aws_clients

class OperationalAnalyzers:
    def __init__(self, cluster_name, region, role_arn=None):
        self.cluster_name = cluster_name
        self.region = region
        self.clients = get_aws_clients(role_arn, region)
    
    def analyze_scalability(self):
        """Analyze cluster scalability"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            
            scalability_analysis = {
                'current_capacity': {},
                'scaling_limits': {},
                'scalability_issues': [],
                'recommendations': []
            }
            
            total_nodes = 0
            total_max_nodes = 0
            
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                scaling_config = ng.get('scalingConfig', {})
                current_size = scaling_config.get('desiredSize', 0)
                max_size = scaling_config.get('maxSize', 0)
                min_size = scaling_config.get('minSize', 0)
                
                total_nodes += current_size
                total_max_nodes += max_size
                
                scalability_analysis['current_capacity'][ng_name] = {
                    'current_nodes': current_size,
                    'min_nodes': min_size,
                    'max_nodes': max_size,
                    'instance_types': ng.get('instanceTypes', []),
                    'capacity_type': ng.get('capacityType', 'ON_DEMAND')
                }
                
                # Check scaling headroom
                headroom_percent = ((max_size - current_size) / max_size * 100) if max_size > 0 else 0
                if headroom_percent < 50:
                    scalability_analysis['scalability_issues'].append(
                        f"Node group {ng_name} has limited scaling headroom ({headroom_percent:.1f}%)"
                    )
                
                # Check for single instance type
                if len(ng.get('instanceTypes', [])) == 1:
                    scalability_analysis['recommendations'].append(
                        f"Consider multiple instance types for {ng_name} to improve availability"
                    )
            
            scalability_analysis['cluster_totals'] = {
                'current_nodes': total_nodes,
                'max_nodes': total_max_nodes,
                'scaling_headroom_percent': ((total_max_nodes - total_nodes) / total_max_nodes * 100) if total_max_nodes > 0 else 0
            }
            
            return scalability_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_reliability(self):
        """Analyze cluster reliability"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            
            reliability_analysis = {
                'reliability_score': 0,
                'max_score': 100,
                'reliability_issues': [],
                'multi_az_deployment': False,
                'backup_status': 'Unknown'
            }
            
            # Check multi-AZ deployment (30 points)
            vpc_config = cluster['resourcesVpcConfig']
            subnets = self.clients['ec2'].describe_subnets(SubnetIds=vpc_config['subnetIds'])['Subnets']
            availability_zones = set(subnet['AvailabilityZone'] for subnet in subnets)
            
            if len(availability_zones) >= 2:
                reliability_analysis['reliability_score'] += 30
                reliability_analysis['multi_az_deployment'] = True
            else:
                reliability_analysis['reliability_issues'].append("Single AZ deployment - HIGH AVAILABILITY RISK")
            
            # Check private endpoint access (20 points)
            if vpc_config['endpointPrivateAccess']:
                reliability_analysis['reliability_score'] += 20
            else:
                reliability_analysis['reliability_issues'].append("No private endpoint access - RELIABILITY RISK")
            
            # Check logging enabled (20 points)
            logging_config = cluster.get('logging', {}).get('clusterLogging', [])
            if any(log.get('enabled') for log in logging_config):
                reliability_analysis['reliability_score'] += 20
            else:
                reliability_analysis['reliability_issues'].append("Cluster logging disabled - OBSERVABILITY RISK")
            
            # Check node group distribution (30 points)
            node_az_distribution = {}
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                ng_subnets = ng.get('subnets', [])
                ng_subnet_details = self.clients['ec2'].describe_subnets(SubnetIds=ng_subnets)['Subnets']
                ng_azs = set(subnet['AvailabilityZone'] for subnet in ng_subnet_details)
                
                node_az_distribution[ng_name] = list(ng_azs)
                
                if len(ng_azs) < 2:
                    reliability_analysis['reliability_issues'].append(f"Node group {ng_name} in single AZ - AVAILABILITY RISK")
            
            if all(len(azs) >= 2 for azs in node_az_distribution.values()):
                reliability_analysis['reliability_score'] += 30
            
            reliability_analysis['az_distribution'] = node_az_distribution
            
            return reliability_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_cost_optimization(self):
        """Analyze cost optimization opportunities"""
        try:
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            
            cost_analysis = {
                'cost_optimization_score': 0,
                'max_score': 100,
                'cost_issues': [],
                'savings_opportunities': [],
                'instance_analysis': []
            }
            
            total_on_demand = 0
            total_spot = 0
            
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                capacity_type = ng.get('capacityType', 'ON_DEMAND')
                instance_types = ng.get('instanceTypes', [])
                scaling_config = ng.get('scalingConfig', {})
                current_size = scaling_config.get('desiredSize', 0)
                
                instance_info = {
                    'nodegroup': ng_name,
                    'capacity_type': capacity_type,
                    'instance_types': instance_types,
                    'current_size': current_size
                }
                
                if capacity_type == 'ON_DEMAND':
                    total_on_demand += current_size
                    cost_analysis['savings_opportunities'].append(
                        f"Consider Spot instances for {ng_name} (potential 60-90% savings)"
                    )
                else:
                    total_spot += current_size
                
                # Check for oversized instances
                if any('xlarge' in inst_type for inst_type in instance_types):
                    cost_analysis['cost_issues'].append(
                        f"Node group {ng_name} uses large instances - consider rightsizing"
                    )
                
                cost_analysis['instance_analysis'].append(instance_info)
            
            # Calculate spot usage score (40 points)
            total_nodes = total_on_demand + total_spot
            if total_nodes > 0:
                spot_percentage = (total_spot / total_nodes) * 100
                cost_analysis['cost_optimization_score'] += min(40, spot_percentage * 0.4)
                cost_analysis['spot_usage_percent'] = spot_percentage
            
            # Check for multiple instance types (30 points)
            diverse_nodegroups = 0
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                if len(ng.get('instanceTypes', [])) > 1:
                    diverse_nodegroups += 1
            
            if diverse_nodegroups == len(nodegroups['nodegroups']):
                cost_analysis['cost_optimization_score'] += 30
            else:
                cost_analysis['cost_issues'].append("Use multiple instance types for better cost optimization")
            
            # Check for appropriate instance sizes (30 points)
            appropriate_sizing = True
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                instance_types = ng.get('instanceTypes', [])
                if any('2xlarge' in inst_type or '4xlarge' in inst_type for inst_type in instance_types):
                    appropriate_sizing = False
                    break
            
            if appropriate_sizing:
                cost_analysis['cost_optimization_score'] += 30
            
            return cost_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_upgrade_readiness(self):
        """Analyze cluster upgrade readiness"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            
            upgrade_analysis = {
                'current_version': cluster['version'],
                'platform_version': cluster['platformVersion'],
                'upgrade_readiness_score': 0,
                'max_score': 100,
                'upgrade_blockers': [],
                'recommendations': []
            }
            
            current_version = float(cluster['version'])
            
            # Check if version is supported (40 points)
            if current_version >= 1.28:
                upgrade_analysis['upgrade_readiness_score'] += 40
            else:
                upgrade_analysis['upgrade_blockers'].append(f"Kubernetes version {cluster['version']} is outdated")
            
            # Check node group version alignment (30 points)
            version_aligned = True
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                ng_version = ng.get('version')
                if ng_version != cluster['version']:
                    version_aligned = False
                    upgrade_analysis['upgrade_blockers'].append(f"Node group {ng_name} version mismatch: {ng_version} vs {cluster['version']}")
            
            if version_aligned:
                upgrade_analysis['upgrade_readiness_score'] += 30
            
            # Check add-on compatibility (30 points)
            addons = self.clients['eks'].list_addons(clusterName=self.cluster_name)
            healthy_addons = 0
            total_addons = len(addons['addons'])
            
            for addon_name in addons['addons']:
                addon = self.clients['eks'].describe_addon(
                    clusterName=self.cluster_name,
                    addonName=addon_name
                )['addon']
                
                if addon['status'] == 'ACTIVE':
                    healthy_addons += 1
                else:
                    upgrade_analysis['upgrade_blockers'].append(f"Add-on {addon_name} is {addon['status']}")
            
            if total_addons > 0 and healthy_addons == total_addons:
                upgrade_analysis['upgrade_readiness_score'] += 30
            
            # Recommendations
            if current_version < 1.30:
                upgrade_analysis['recommendations'].append("Plan upgrade to Kubernetes 1.30+ for latest features and security")
            
            return upgrade_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_autoscaling(self):
        """Analyze autoscaling configuration"""
        try:
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            
            autoscaling_analysis = {
                'cluster_autoscaler_detected': False,
                'autoscaling_score': 0,
                'max_score': 100,
                'autoscaling_issues': [],
                'nodegroup_scaling': []
            }
            
            properly_configured_nodegroups = 0
            
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                scaling_config = ng.get('scalingConfig', {})
                min_size = scaling_config.get('minSize', 0)
                max_size = scaling_config.get('maxSize', 0)
                desired_size = scaling_config.get('desiredSize', 0)
                
                ng_scaling = {
                    'nodegroup': ng_name,
                    'min_size': min_size,
                    'max_size': max_size,
                    'desired_size': desired_size,
                    'scaling_range': max_size - min_size,
                    'properly_configured': False
                }
                
                # Check if autoscaling is properly configured
                if max_size > min_size and max_size > desired_size:
                    ng_scaling['properly_configured'] = True
                    properly_configured_nodegroups += 1
                else:
                    autoscaling_analysis['autoscaling_issues'].append(
                        f"Node group {ng_name} has limited/no autoscaling range (min:{min_size}, max:{max_size})"
                    )
                
                autoscaling_analysis['nodegroup_scaling'].append(ng_scaling)
            
            # Calculate autoscaling score
            total_nodegroups = len(nodegroups['nodegroups'])
            if total_nodegroups > 0:
                autoscaling_analysis['autoscaling_score'] = (properly_configured_nodegroups / total_nodegroups) * 100
            
            return autoscaling_analysis
            
        except Exception as e:
            return {'error': str(e)}
