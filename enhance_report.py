#!/usr/bin/env python3
"""
Simple script to enhance existing JSON reports with detailed checks
Run this after generating a report to add detailed information
"""
import json
import sys
from pathlib import Path

def enhance_json_report(json_file):
    """Add detailed check information to existing JSON report"""
    
    print(f"📖 Reading report: {json_file}")
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    cluster_name = data.get('cluster_name', 'unknown')
    region = data.get('region', 'us-west-2')
    
    print(f"🔍 Enhancing report for cluster: {cluster_name}")
    
    # Add detailed checks based on existing data
    enhanced_checks = []
    
    # Extract existing security analysis
    security = data.get('security_analysis', {})
    
    # Check 1: Cluster Encryption
    enhanced_checks.append({
        'check_id': 'SEC-001',
        'title': 'EKS Cluster Encryption at Rest',
        'category': 'Security',
        'severity': 'CRITICAL',
        'status': 'PASSED' if security.get('encryption_enabled') else 'FAILED',
        'compliance_frameworks': ['CIS EKS Benchmark', 'PCI DSS', 'HIPAA', 'DORA'],
        'command_executed': f'aws eks describe-cluster --name {cluster_name} --region {region} --query "cluster.encryptionConfig"',
        'observation': security.get('encryption_config', 'Not configured'),
        'reasoning': 'Encryption at rest protects sensitive data in etcd database' if security.get('encryption_enabled') else 'Encryption is not enabled, exposing sensitive data',
        'risk_score': 0 if security.get('encryption_enabled') else 10,
        'recommendation': {
            'description': 'Enable KMS encryption for EKS cluster secrets',
            'business_impact': 'Unencrypted secrets expose sensitive data to unauthorized access',
            'steps': [
                'Create KMS key for EKS encryption',
                'Enable encryption on cluster',
                'Rotate existing secrets'
            ],
            'commands': [
                f'aws kms create-key --description "EKS {cluster_name} encryption"',
                f'aws eks update-cluster-config --name {cluster_name} --encryption-config resources=secrets,provider={{keyArn=arn:aws:kms:REGION:ACCOUNT:key/KEY_ID}}'
            ],
            'verification': [f'aws eks describe-cluster --name {cluster_name} --query "cluster.encryptionConfig"'],
            'effort': 'Medium',
            'documentation': ['https://docs.aws.amazon.com/eks/latest/userguide/enable-kms.html']
        }
    })
    
    # Check 2: Cluster Logging
    enhanced_checks.append({
        'check_id': 'SEC-002',
        'title': 'EKS Control Plane Logging',
        'category': 'Logging',
        'severity': 'CRITICAL',
        'status': 'PASSED' if security.get('logging_enabled') else 'FAILED',
        'compliance_frameworks': ['CIS EKS Benchmark', 'SOC 2', 'PCI DSS', 'HIPAA', 'DORA'],
        'command_executed': f'aws eks describe-cluster --name {cluster_name} --region {region} --query "cluster.logging.clusterLogging"',
        'observation': security.get('logging_config', {}),
        'reasoning': 'Audit logs are required for security investigations and compliance' if security.get('logging_enabled') else 'Logging is disabled, preventing security investigations',
        'risk_score': 0 if security.get('logging_enabled') else 10,
        'recommendation': {
            'description': 'Enable all five EKS control plane log types',
            'business_impact': 'Without audit logs, security incidents cannot be investigated',
            'steps': [
                'Enable api, audit, authenticator, controllerManager, scheduler logs',
                'Configure CloudWatch Logs retention (90 days minimum)',
                'Set up log analysis and alerting'
            ],
            'commands': [
                f'aws eks update-cluster-config --name {cluster_name} --logging \'{{"clusterLogging":[{{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}}]}}\'',
                f'aws logs put-retention-policy --log-group-name /aws/eks/{cluster_name}/cluster --retention-in-days 90'
            ],
            'verification': [f'aws eks describe-cluster --name {cluster_name} --query "cluster.logging.clusterLogging"'],
            'effort': 'Low',
            'documentation': ['https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html']
        }
    })
    
    # Check 3: Endpoint Access
    network = data.get('health_analysis', {}).get('network_analysis', {})
    endpoint_config = network.get('endpoint_config', {})
    public_access = endpoint_config.get('public_access', False)
    public_cidrs = endpoint_config.get('public_cidrs', [])
    
    enhanced_checks.append({
        'check_id': 'NET-001',
        'title': 'EKS API Endpoint Access Control',
        'category': 'Network Security',
        'severity': 'CRITICAL',
        'status': 'FAILED' if '0.0.0.0/0' in public_cidrs else 'PASSED',
        'compliance_frameworks': ['CIS EKS Benchmark', 'PCI DSS', 'DORA'],
        'command_executed': f'aws eks describe-cluster --name {cluster_name} --region {region} --query "cluster.resourcesVpcConfig"',
        'observation': endpoint_config,
        'reasoning': 'Unrestricted public API access creates significant attack surface' if '0.0.0.0/0' in public_cidrs else 'API access is properly restricted',
        'risk_score': 10 if '0.0.0.0/0' in public_cidrs else 0,
        'recommendation': {
            'description': 'Restrict API endpoint access to authorized IP ranges',
            'business_impact': 'Cluster API exposed to internet allows unauthorized access attempts',
            'steps': [
                'Identify authorized IP ranges (office, VPN, CI/CD)',
                'Update cluster endpoint configuration',
                'Enable private endpoint access',
                'Test connectivity from authorized locations'
            ],
            'commands': [
                f'aws eks update-cluster-config --name {cluster_name} --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=["YOUR_IP/32"],endpointPrivateAccess=true'
            ],
            'verification': [f'aws eks describe-cluster --name {cluster_name} --query "cluster.resourcesVpcConfig"'],
            'effort': 'Low',
            'documentation': ['https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html']
        }
    })
    
    # Add enhanced checks to data
    data['enhanced_analysis'] = {
        'total_checks': len(enhanced_checks),
        'checks': enhanced_checks,
        'summary': {
            'passed': sum(1 for c in enhanced_checks if c['status'] == 'PASSED'),
            'failed': sum(1 for c in enhanced_checks if c['status'] == 'FAILED'),
            'critical': sum(1 for c in enhanced_checks if c['severity'] == 'CRITICAL')
        }
    }
    
    # Save enhanced report
    output_file = json_file.replace('.json', '_enhanced.json')
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"✅ Enhanced report saved: {output_file}")
    print(f"   Total checks: {len(enhanced_checks)}")
    print(f"   Passed: {data['enhanced_analysis']['summary']['passed']}")
    print(f"   Failed: {data['enhanced_analysis']['summary']['failed']}")
    
    return output_file

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python enhance_report.py <json_report_file>")
        print("\nExample:")
        print("  python enhance_report.py reports/eks_analysis_strands-cluster_20251127_1845.json")
        sys.exit(1)
    
    json_file = sys.argv[1]
    if not Path(json_file).exists():
        print(f"Error: File not found: {json_file}")
        sys.exit(1)
    
    enhance_json_report(json_file)
