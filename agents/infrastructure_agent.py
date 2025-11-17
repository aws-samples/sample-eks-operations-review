"""
Infrastructure Agent - Network topology analysis and infrastructure optimization
"""
import boto3
import json
from datetime import datetime
from typing import Dict, Any, List
from .base_agent import BaseAgent, AgentTask, AgentResult

class InfrastructureAgent(BaseAgent):
    """Infrastructure analysis and network topology agent"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("infrastructure-analysis", config)
        self.region = config.get('region', 'us-west-2')
    
    async def process_task(self, task: AgentTask) -> AgentResult:
        """Process infrastructure analysis task"""
        try:
            cluster_name = task.cluster_id
            region = task.payload.get('region', self.region)
            role_arn = task.payload.get('role_arn')
            
            # Initialize AWS clients
            if role_arn:
                from core.aws_client import AWSClientManager
                aws_client = AWSClientManager(region, role_arn)
                clients = aws_client.get_clients()
            else:
                clients = {
                    'eks': boto3.client('eks', region_name=region),
                    'ec2': boto3.client('ec2', region_name=region),
                    'elbv2': boto3.client('elbv2', region_name=region),
                    'route53': boto3.client('route53', region_name=region),
                    'cloudformation': boto3.client('cloudformation', region_name=region)
                }
            
            # Perform infrastructure analysis
            infrastructure_results = await self._analyze_infrastructure(cluster_name, clients)
            
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="completed",
                data=infrastructure_results,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            return AgentResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                status="failed",
                data={"error": str(e)},
                timestamp=datetime.now()
            )
    
    async def _analyze_infrastructure(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Comprehensive infrastructure analysis"""
        analysis = {
            'cluster_name': cluster_name,
            'analysis_timestamp': datetime.now().isoformat(),
            'network_topology': await self._analyze_network_topology(cluster_name, clients),
            'storage_analysis': await self._analyze_storage(cluster_name, clients),
            'load_balancer_analysis': await self._analyze_load_balancers(cluster_name, clients),
            'dns_analysis': await self._analyze_dns_configuration(cluster_name, clients),
            'iac_analysis': await self._analyze_infrastructure_as_code(cluster_name, clients),
            'multi_az_resilience': await self._analyze_multi_az_resilience(cluster_name, clients),
            'recommendations': []
        }
        
        # Generate infrastructure recommendations
        analysis['recommendations'] = self._generate_infrastructure_recommendations(analysis)
        
        return analysis
    
    async def _analyze_network_topology(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze network topology and architecture"""
        try:
            # Get cluster VPC configuration
            cluster = clients['eks'].describe_cluster(name=cluster_name)['cluster']
            vpc_config = cluster['resourcesVpcConfig']
            vpc_id = vpc_config['vpcId']
            
            network_topology = {
                'vpc_id': vpc_id,
                'subnets': [],
                'route_tables': [],
                'internet_gateways': [],
                'nat_gateways': [],
                'vpc_endpoints': [],
                'network_acls': [],
                'topology_score': 0,
                'architecture_issues': []
            }
            
            # Analyze VPC components
            vpc_info = clients['ec2'].describe_vpcs(VpcIds=[vpc_id])['Vpcs'][0]
            network_topology['vpc_cidr'] = vpc_info['CidrBlock']
            
            # Analyze subnets
            subnets = clients['ec2'].describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['Subnets']
            
            public_subnets = 0
            private_subnets = 0
            availability_zones = set()
            
            for subnet in subnets:
                subnet_info = {
                    'subnet_id': subnet['SubnetId'],
                    'cidr': subnet['CidrBlock'],
                    'az': subnet['AvailabilityZone'],
                    'is_public': subnet.get('MapPublicIpOnLaunch', False),
                    'available_ips': subnet['AvailableIpAddressCount']
                }
                
                network_topology['subnets'].append(subnet_info)
                availability_zones.add(subnet['AvailabilityZone'])
                
                if subnet_info['is_public']:
                    public_subnets += 1
                else:
                    private_subnets += 1
            
            # Analyze route tables
            route_tables = clients['ec2'].describe_route_tables(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['RouteTables']
            
            for rt in route_tables:
                rt_info = {
                    'route_table_id': rt['RouteTableId'],
                    'routes': len(rt['Routes']),
                    'associations': len(rt.get('Associations', []))
                }
                network_topology['route_tables'].append(rt_info)
            
            # Analyze Internet Gateways
            igws = clients['ec2'].describe_internet_gateways(
                Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
            )['InternetGateways']
            
            network_topology['internet_gateways'] = [
                {'igw_id': igw['InternetGatewayId']} for igw in igws
            ]
            
            # Analyze NAT Gateways
            nat_gws = clients['ec2'].describe_nat_gateways(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['NatGateways']
            
            for nat in nat_gws:
                nat_info = {
                    'nat_gateway_id': nat['NatGatewayId'],
                    'subnet_id': nat['SubnetId'],
                    'state': nat['State']
                }
                network_topology['nat_gateways'].append(nat_info)
            
            # Analyze VPC Endpoints
            vpc_endpoints = clients['ec2'].describe_vpc_endpoints(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['VpcEndpoints']
            
            for endpoint in vpc_endpoints:
                endpoint_info = {
                    'endpoint_id': endpoint['VpcEndpointId'],
                    'service_name': endpoint['ServiceName'],
                    'endpoint_type': endpoint['VpcEndpointType'],
                    'state': endpoint['State']
                }
                network_topology['vpc_endpoints'].append(endpoint_info)
            
            # Calculate topology score and identify issues
            topology_score = 100
            
            # Check for multi-AZ deployment
            if len(availability_zones) < 2:
                network_topology['architecture_issues'].append('Single AZ deployment - no high availability')
                topology_score -= 30
            elif len(availability_zones) < 3:
                network_topology['architecture_issues'].append('Only 2 AZs used - consider 3 AZs for better resilience')
                topology_score -= 10
            
            # Check for proper subnet architecture
            if private_subnets == 0:
                network_topology['architecture_issues'].append('No private subnets - security risk')
                topology_score -= 25
            
            if public_subnets == 0 and len(network_topology['nat_gateways']) == 0:
                network_topology['architecture_issues'].append('No internet access path for private subnets')
                topology_score -= 20
            
            # Check for VPC endpoints
            if len(network_topology['vpc_endpoints']) == 0:
                network_topology['architecture_issues'].append('No VPC endpoints - traffic goes through internet')
                topology_score -= 15
            
            network_topology['topology_score'] = max(0, topology_score)
            network_topology['az_count'] = len(availability_zones)
            network_topology['public_subnets'] = public_subnets
            network_topology['private_subnets'] = private_subnets
            
            return network_topology
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_storage(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze storage configuration and optimization"""
        try:
            storage_analysis = {
                'ebs_volumes': [],
                'storage_classes': [],
                'persistent_volumes': 0,
                'storage_optimization': [],
                'cost_optimization': []
            }
            
            # Get EBS volumes associated with the cluster
            # This would typically require kubectl access to get PV information
            # For now, we'll provide general storage analysis
            
            storage_analysis['storage_optimization'] = [
                'Use gp3 volumes for better price-performance',
                'Implement volume snapshots for backup',
                'Consider EFS for shared storage needs',
                'Monitor storage utilization for right-sizing'
            ]
            
            storage_analysis['cost_optimization'] = [
                'Migrate from gp2 to gp3 volumes',
                'Delete unused EBS snapshots',
                'Implement lifecycle policies for backups',
                'Use appropriate storage classes for workloads'
            ]
            
            return storage_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_load_balancers(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze load balancer configuration"""
        try:
            lb_analysis = {
                'application_load_balancers': [],
                'network_load_balancers': [],
                'classic_load_balancers': [],
                'total_load_balancers': 0,
                'configuration_issues': [],
                'optimization_opportunities': []
            }
            
            # Get all load balancers
            albs = clients['elbv2'].describe_load_balancers()['LoadBalancers']
            
            for lb in albs:
                lb_info = {
                    'name': lb['LoadBalancerName'],
                    'type': lb['Type'],
                    'scheme': lb['Scheme'],
                    'state': lb['State']['Code'],
                    'availability_zones': len(lb['AvailabilityZones'])
                }
                
                if lb['Type'] == 'application':
                    lb_analysis['application_load_balancers'].append(lb_info)
                elif lb['Type'] == 'network':
                    lb_analysis['network_load_balancers'].append(lb_info)
                
                # Check for configuration issues
                if lb_info['availability_zones'] < 2:
                    lb_analysis['configuration_issues'].append(
                        f"Load balancer {lb_info['name']} only in {lb_info['availability_zones']} AZ"
                    )
                
                if lb_info['scheme'] == 'internet-facing' and lb['Type'] == 'application':
                    # Check for WAF association (would require additional API call)
                    lb_analysis['optimization_opportunities'].append(
                        f"Consider WAF for internet-facing ALB {lb_info['name']}"
                    )
            
            lb_analysis['total_load_balancers'] = len(albs)
            
            return lb_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_dns_configuration(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze DNS configuration"""
        try:
            dns_analysis = {
                'hosted_zones': 0,
                'dns_records': 0,
                'health_checks': 0,
                'dns_optimization': []
            }
            
            # Get Route53 hosted zones
            try:
                hosted_zones = clients['route53'].list_hosted_zones()['HostedZones']
                dns_analysis['hosted_zones'] = len(hosted_zones)
                
                # Count DNS records in first hosted zone
                if hosted_zones:
                    records = clients['route53'].list_resource_record_sets(
                        HostedZoneId=hosted_zones[0]['Id']
                    )['ResourceRecordSets']
                    dns_analysis['dns_records'] = len(records)
                
                # Get health checks
                health_checks = clients['route53'].list_health_checks()['HealthChecks']
                dns_analysis['health_checks'] = len(health_checks)
                
            except Exception as e:
                dns_analysis['route53_error'] = str(e)
            
            dns_analysis['dns_optimization'] = [
                'Implement health checks for critical endpoints',
                'Use Route53 resolver for private DNS',
                'Consider geolocation routing for global applications',
                'Implement DNS failover for high availability'
            ]
            
            return dns_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_infrastructure_as_code(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze Infrastructure as Code usage"""
        try:
            iac_analysis = {
                'cloudformation_stacks': 0,
                'stack_analysis': [],
                'drift_detection': [],
                'iac_recommendations': []
            }
            
            # Get CloudFormation stacks
            try:
                stacks = clients['cloudformation'].describe_stacks()['Stacks']
                
                # Filter stacks related to EKS or the cluster
                eks_stacks = [
                    stack for stack in stacks 
                    if cluster_name.lower() in stack['StackName'].lower() or 
                       'eks' in stack['StackName'].lower()
                ]
                
                iac_analysis['cloudformation_stacks'] = len(eks_stacks)
                
                for stack in eks_stacks[:5]:  # Analyze first 5 stacks
                    stack_info = {
                        'stack_name': stack['StackName'],
                        'status': stack['StackStatus'],
                        'creation_time': stack['CreationTime'].isoformat(),
                        'drift_status': 'UNKNOWN'
                    }
                    
                    # Check for drift (simplified)
                    try:
                        drift_result = clients['cloudformation'].describe_stack_drift_detection_status(
                            StackDriftDetectionId=stack['StackId']
                        )
                        stack_info['drift_status'] = drift_result.get('StackDriftStatus', 'UNKNOWN')
                    except Exception:
                        pass  # Drift detection not available
                    
                    iac_analysis['stack_analysis'].append(stack_info)
                
            except Exception as e:
                iac_analysis['cloudformation_error'] = str(e)
            
            iac_analysis['iac_recommendations'] = [
                'Use Infrastructure as Code for all resources',
                'Implement drift detection and remediation',
                'Version control your IaC templates',
                'Use CDK or Terraform for complex deployments',
                'Implement automated testing for IaC changes'
            ]
            
            return iac_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_multi_az_resilience(self, cluster_name: str, clients: Dict) -> Dict[str, Any]:
        """Analyze multi-AZ resilience and disaster recovery"""
        try:
            resilience_analysis = {
                'availability_zones': [],
                'resilience_score': 0,
                'single_points_of_failure': [],
                'disaster_recovery': {
                    'backup_strategy': 'UNKNOWN',
                    'rto_estimate': 'UNKNOWN',
                    'rpo_estimate': 'UNKNOWN'
                },
                'recommendations': []
            }
            
            # Get cluster information
            cluster = clients['eks'].describe_cluster(name=cluster_name)['cluster']
            vpc_config = cluster['resourcesVpcConfig']
            
            # Analyze subnet distribution
            subnets = clients['ec2'].describe_subnets(
                SubnetIds=vpc_config['subnetIds']
            )['Subnets']
            
            az_distribution = {}
            for subnet in subnets:
                az = subnet['AvailabilityZone']
                if az not in az_distribution:
                    az_distribution[az] = []
                az_distribution[az].append(subnet['SubnetId'])
            
            resilience_analysis['availability_zones'] = list(az_distribution.keys())
            
            # Calculate resilience score
            resilience_score = 100
            
            if len(az_distribution) < 2:
                resilience_analysis['single_points_of_failure'].append('Single AZ deployment')
                resilience_score -= 50
            elif len(az_distribution) < 3:
                resilience_analysis['single_points_of_failure'].append('Only 2 AZs - limited resilience')
                resilience_score -= 20
            
            # Check node group distribution
            node_groups = clients['eks'].list_nodegroups(clusterName=cluster_name)['nodegroups']
            
            for ng_name in node_groups:
                ng_info = clients['eks'].describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=ng_name
                )['nodegroup']
                
                ng_subnets = ng_info['subnets']
                ng_azs = set()
                
                for subnet_id in ng_subnets:
                    for subnet in subnets:
                        if subnet['SubnetId'] == subnet_id:
                            ng_azs.add(subnet['AvailabilityZone'])
                            break
                
                if len(ng_azs) < 2:
                    resilience_analysis['single_points_of_failure'].append(
                        f'Node group {ng_name} only in {len(ng_azs)} AZ'
                    )
                    resilience_score -= 15
            
            resilience_analysis['resilience_score'] = max(0, resilience_score)
            
            # Disaster recovery recommendations
            resilience_analysis['recommendations'] = [
                'Deploy across at least 3 availability zones',
                'Implement automated backup strategies',
                'Test disaster recovery procedures regularly',
                'Use cross-region replication for critical data',
                'Implement infrastructure as code for quick recovery'
            ]
            
            return resilience_analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def _generate_infrastructure_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate infrastructure-specific recommendations"""
        recommendations = []
        
        # Network topology recommendations
        network_topology = analysis.get('network_topology', {})
        topology_score = network_topology.get('topology_score', 100)
        architecture_issues = network_topology.get('architecture_issues', [])
        
        if topology_score < 80:
            recommendations.append({
                'category': 'Network Architecture',
                'title': 'Improve Network Topology',
                'priority': 'HIGH',
                'description': f'Network topology score: {topology_score}/100. Issues: {", ".join(architecture_issues[:3])}',
                'implementation': 'Implement multi-AZ deployment with proper subnet architecture',
                'expected_benefit': 'Improved availability and security posture'
            })
        
        # Multi-AZ resilience recommendations
        resilience_analysis = analysis.get('multi_az_resilience', {})
        resilience_score = resilience_analysis.get('resilience_score', 100)
        spofs = resilience_analysis.get('single_points_of_failure', [])
        
        if resilience_score < 90:
            recommendations.append({
                'category': 'High Availability',
                'title': 'Eliminate Single Points of Failure',
                'priority': 'HIGH',
                'description': f'Resilience score: {resilience_score}/100. SPOFs: {", ".join(spofs[:2])}',
                'implementation': 'Deploy resources across multiple availability zones',
                'expected_benefit': 'Improved fault tolerance and availability'
            })
        
        # Load balancer recommendations
        lb_analysis = analysis.get('load_balancer_analysis', {})
        config_issues = lb_analysis.get('configuration_issues', [])
        
        if config_issues:
            recommendations.append({
                'category': 'Load Balancer',
                'title': 'Fix Load Balancer Configuration',
                'priority': 'MEDIUM',
                'description': f'Configuration issues found: {", ".join(config_issues[:2])}',
                'implementation': 'Ensure load balancers span multiple AZs and implement WAF',
                'expected_benefit': 'Better load distribution and security'
            })
        
        # Storage optimization recommendations
        storage_analysis = analysis.get('storage_analysis', {})
        cost_optimizations = storage_analysis.get('cost_optimization', [])
        
        if cost_optimizations:
            recommendations.append({
                'category': 'Storage Optimization',
                'title': 'Optimize Storage Costs',
                'priority': 'MEDIUM',
                'description': 'Storage cost optimization opportunities identified',
                'implementation': 'Migrate to gp3 volumes and implement lifecycle policies',
                'expected_benefit': 'Reduced storage costs and improved performance'
            })
        
        return recommendations
