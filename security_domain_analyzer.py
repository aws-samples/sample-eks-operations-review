import boto3
from iam_role_auth import get_aws_clients

class SecurityDomainAnalyzer:
    def __init__(self, cluster_name, region, role_arn=None):
        self.cluster_name = cluster_name
        self.region = region
        self.clients = get_aws_clients(role_arn, region)
    
    def analyze_security_by_domain(self):
        """Analyze security issues by domain with specific recommendations"""
        try:
            cluster = self.clients['eks'].describe_cluster(name=self.cluster_name)['cluster']
            
            security_domains = {
                'data_protection': self._analyze_data_protection(cluster),
                'monitoring_logging': self._analyze_monitoring_logging(cluster),
                'network_security': self._analyze_network_security(cluster),
                'iam_access_control': self._analyze_iam_access_control(cluster),
                'node_security': self._analyze_node_security(),
                'addon_security': self._analyze_addon_security(),
                'platform_security': self._analyze_platform_security(cluster)
            }
            
            # Calculate priority counts
            all_findings = []
            for domain_findings in security_domains.values():
                if isinstance(domain_findings, list):
                    all_findings.extend(domain_findings)
            
            high_priority = len([f for f in all_findings if f.get('priority') == 'HIGH'])
            medium_priority = len([f for f in all_findings if f.get('priority') == 'MEDIUM'])
            low_priority = len([f for f in all_findings if f.get('priority') == 'LOW'])
            
            return {
                'total_issues': len(all_findings),
                'high_priority': high_priority,
                'medium_priority': medium_priority,
                'low_priority': low_priority,
                'domains': security_domains
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_data_protection(self, cluster):
        """Analyze data protection domain"""
        findings = []
        
        # Check encryption
        encryption_config = cluster.get('encryptionConfig', [])
        if not encryption_config:
            findings.append({
                'issue': 'Secrets encryption disabled',
                'priority': 'HIGH',
                'current_state': 'No encryption configuration found',
                'recommendation': f'Enable envelope encryption for cluster {self.cluster_name}',
                'aws_cli_fix': f'aws eks update-cluster-config --region {self.region} --name {self.cluster_name} --encryption-config resources=secrets,provider={{keyArn=arn:aws:kms:{self.region}:ACCOUNT:key/KEY-ID}}'
            })
        
        return findings
    
    def _analyze_monitoring_logging(self, cluster):
        """Analyze monitoring and logging domain"""
        findings = []
        
        logging_config = cluster.get('logging', {}).get('clusterLogging', [])
        enabled_logs = [log['types'] for log in logging_config if log.get('enabled')]
        
        required_logs = ['audit', 'api', 'authenticator']
        missing_logs = []
        
        for log_type in required_logs:
            if not any(log_type in logs for logs in enabled_logs):
                missing_logs.append(log_type)
        
        if missing_logs:
            findings.append({
                'issue': f'Critical logging disabled: {", ".join(missing_logs)}',
                'priority': 'HIGH',
                'current_state': f'Enabled logs: {enabled_logs}',
                'recommendation': f'Enable {", ".join(missing_logs)} logging',
                'aws_cli_fix': f'aws eks update-cluster-config --region {self.region} --name {self.cluster_name} --logging \'{{\"clusterLogging\":[{{\"types\":{missing_logs},\"enabled\":true}}]}}\''
            })
        
        return findings
    
    def _analyze_network_security(self, cluster):
        """Analyze network security domain"""
        findings = []
        
        vpc_config = cluster['resourcesVpcConfig']
        public_access = vpc_config['endpointPublicAccess']
        private_access = vpc_config['endpointPrivateAccess']
        public_cidrs = vpc_config.get('publicAccessCidrs', [])
        
        # Check endpoint access
        if public_access and not private_access:
            findings.append({
                'issue': 'API endpoint only publicly accessible',
                'priority': 'MEDIUM',
                'current_state': f'Public: {public_access}, Private: {private_access}',
                'recommendation': 'Enable private endpoint access',
                'aws_cli_fix': f'aws eks update-cluster-config --region {self.region} --name {self.cluster_name} --resources-vpc-config endpointPrivateAccess=true'
            })
        
        if public_access and '0.0.0.0/0' in public_cidrs:
            findings.append({
                'issue': 'API endpoint accessible from anywhere',
                'priority': 'HIGH',
                'current_state': f'Public CIDRs: {public_cidrs}',
                'recommendation': 'Restrict public access to specific IP ranges',
                'aws_cli_fix': f'aws eks update-cluster-config --region {self.region} --name {self.cluster_name} --resources-vpc-config publicAccessCidrs=YOUR-IP/32'
            })
        
        return findings
    
    def _analyze_iam_access_control(self, cluster):
        """Analyze IAM and access control domain"""
        findings = []
        
        # Check IRSA
        identity = cluster.get('identity', {})
        oidc_issuer = identity.get('oidc', {}).get('issuer')
        
        if not oidc_issuer:
            findings.append({
                'issue': 'IRSA not configured',
                'priority': 'HIGH',
                'current_state': 'No OIDC identity provider found',
                'recommendation': 'Configure IAM OIDC identity provider',
                'aws_cli_fix': f'eksctl utils associate-iam-oidc-provider --cluster {self.cluster_name} --region {self.region} --approve'
            })
        
        return findings
    
    def _analyze_node_security(self):
        """Analyze node security domain"""
        findings = []
        
        try:
            nodegroups = self.clients['eks'].list_nodegroups(clusterName=self.cluster_name)
            
            for ng_name in nodegroups['nodegroups']:
                ng = self.clients['eks'].describe_nodegroup(
                    clusterName=self.cluster_name, 
                    nodegroupName=ng_name
                )['nodegroup']
                
                # Check remote access
                remote_access = ng.get('remoteAccess', {})
                if remote_access:
                    findings.append({
                        'issue': f'Node group {ng_name} has SSH access enabled',
                        'priority': 'MEDIUM',
                        'current_state': f'Remote access configured: {remote_access}',
                        'recommendation': 'Disable SSH access and use Session Manager',
                        'aws_cli_fix': 'Remove remoteAccess configuration and use AWS Systems Manager Session Manager'
                    })
        except Exception:
            pass
        
        return findings
    
    def _analyze_addon_security(self):
        """Analyze add-on security domain"""
        findings = []
        
        try:
            addons = self.clients['eks'].list_addons(clusterName=self.cluster_name)
            
            for addon_name in addons['addons']:
                addon = self.clients['eks'].describe_addon(
                    clusterName=self.cluster_name,
                    addonName=addon_name
                )['addon']
                
                if addon['status'] == 'DEGRADED':
                    findings.append({
                        'issue': f'Add-on {addon_name} is degraded',
                        'priority': 'HIGH',
                        'current_state': f'Status: {addon["status"]}',
                        'recommendation': f'Fix {addon_name} add-on issues',
                        'aws_cli_fix': f'kubectl describe pods -n kube-system -l app={addon_name}'
                    })
        except Exception:
            pass
        
        return findings
    
    def _analyze_platform_security(self, cluster):
        """Analyze platform security domain"""
        findings = []
        
        # Check version
        version = cluster.get('version', 'Unknown')
        try:
            version_float = float(version)
            if version_float < 1.28:
                findings.append({
                    'issue': f'EKS version {version} is outdated',
                    'priority': 'HIGH',
                    'current_state': f'Current version: {version}',
                    'recommendation': 'Upgrade to latest supported EKS version',
                    'aws_cli_fix': f'aws eks update-cluster-version --name {self.cluster_name} --kubernetes-version 1.30'
                })
        except ValueError:
            pass
        
        return findings
