#!/usr/bin/env python3
"""
AWS Connectivity Diagnostic Script for AgentK8s
Helps identify AWS credential and EKS access issues
"""

import boto3
import sys
import os
from botocore.exceptions import ClientError, NoCredentialsError, TokenRetrievalError

def test_aws_connectivity():
    """Test basic AWS connectivity and credentials"""
    print("🔍 Testing AWS Connectivity...")
    print("-" * 50)
    
    try:
        # Test STS (Security Token Service) to verify credentials
        print("1. Testing AWS Credentials...")
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"✅ AWS Credentials OK")
        print(f"   Account ID: {identity['Account']}")
        print(f"   User/Role ARN: {identity['Arn']}")
        print(f"   User ID: {identity['UserId']}")
        
    except NoCredentialsError:
        print("❌ No AWS credentials found!")
        print("   Please configure AWS credentials using one of:")
        print("   - aws configure")
        print("   - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)")
        print("   - IAM role for EC2")
        return False
        
    except TokenRetrievalError as e:
        print(f"❌ AWS token retrieval failed: {str(e)}")
        return False
        
    except Exception as e:
        print(f"❌ AWS credentials test failed: {str(e)}")
        return False
    
    return True

def test_eks_permissions(region='us-west-2'):
    """Test EKS permissions and list available clusters"""
    print(f"\n2. Testing EKS Permissions in {region}...")
    
    try:
        eks = boto3.client('eks', region_name=region)
        
        # List clusters
        clusters = eks.list_clusters()
        cluster_names = clusters.get('clusters', [])
        
        print(f"✅ EKS List Clusters Permission OK")
        print(f"   Found {len(cluster_names)} clusters in {region}:")
        
        if cluster_names:
            for cluster in cluster_names:
                print(f"   - {cluster}")
                
                # Test describe cluster permission
                try:
                    cluster_info = eks.describe_cluster(name=cluster)
                    status = cluster_info['cluster']['status']
                    version = cluster_info['cluster']['version']
                    print(f"     Status: {status}, Version: {version}")
                except Exception as e:
                    print(f"     ⚠️ Cannot describe cluster: {str(e)}")
        else:
            print("   No EKS clusters found in this region")
            print("   Try different regions: us-east-1, eu-west-1, ap-southeast-1")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print("❌ Access Denied to EKS")
            print("   Required permissions:")
            print("   - eks:ListClusters")
            print("   - eks:DescribeCluster")
        else:
            print(f"❌ EKS API Error: {error_code} - {e.response['Error']['Message']}")
        return False
        
    except Exception as e:
        print(f"❌ EKS test failed: {str(e)}")
        return False

def test_specific_cluster(cluster_name, region='us-west-2'):
    """Test access to a specific cluster"""
    print(f"\n3. Testing Specific Cluster: {cluster_name} in {region}...")
    
    try:
        eks = boto3.client('eks', region_name=region)
        
        # Test cluster access
        cluster_info = eks.describe_cluster(name=cluster_name)
        cluster = cluster_info['cluster']
        
        print(f"✅ Cluster Access OK")
        print(f"   Name: {cluster['name']}")
        print(f"   Status: {cluster['status']}")
        print(f"   Version: {cluster['version']}")
        print(f"   Endpoint: {cluster['endpoint']}")
        
        # Test node groups
        try:
            nodegroups = eks.list_nodegroups(clusterName=cluster_name)
            ng_count = len(nodegroups.get('nodegroups', []))
            print(f"   Node Groups: {ng_count}")
        except Exception as e:
            print(f"   ⚠️ Cannot list node groups: {str(e)}")
        
        # Test addons
        try:
            addons = eks.list_addons(clusterName=cluster_name)
            addon_count = len(addons.get('addons', []))
            print(f"   Addons: {addon_count}")
        except Exception as e:
            print(f"   ⚠️ Cannot list addons: {str(e)}")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            print(f"❌ Cluster '{cluster_name}' not found in {region}")
            print("   Please check:")
            print("   - Cluster name spelling")
            print("   - AWS region")
        elif error_code == 'AccessDenied':
            print(f"❌ Access denied to cluster '{cluster_name}'")
        else:
            print(f"❌ Cluster test failed: {error_code} - {e.response['Error']['Message']}")
        return False
        
    except Exception as e:
        print(f"❌ Cluster test failed: {str(e)}")
        return False

def test_ec2_permissions(region='us-west-2'):
    """Test EC2 permissions needed for network analysis"""
    print(f"\n4. Testing EC2/VPC Permissions in {region}...")
    
    try:
        ec2 = boto3.client('ec2', region_name=region)
        
        # Test VPC list (basic permission)
        vpcs = ec2.describe_vpcs(MaxResults=5)
        vpc_count = len(vpcs.get('Vpcs', []))
        print(f"✅ EC2/VPC Permissions OK")
        print(f"   Found {vpc_count} VPCs")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        print(f"❌ EC2 Permission Error: {error_code}")
        return False
        
    except Exception as e:
        print(f"❌ EC2 test failed: {str(e)}")
        return False

def main():
    """Main diagnostic function"""
    print("🚀 AgentK8s AWS Connectivity Diagnostics")
    print("=" * 50)
    
    # Get parameters
    region = input("Enter AWS region [us-west-2]: ").strip() or 'us-west-2'
    
    # Test basic connectivity
    if not test_aws_connectivity():
        print("\n❌ Basic AWS connectivity failed. Please fix credentials first.")
        return
    
    # Test EKS permissions  
    if not test_eks_permissions(region):
        print("\n❌ EKS permissions failed. Please check IAM permissions.")
        return
    
    # Test EC2 permissions
    test_ec2_permissions(region)
    
    # Test specific cluster if provided
    cluster_name = input("\nEnter EKS cluster name to test (optional): ").strip()
    if cluster_name:
        test_specific_cluster(cluster_name, region)
    
    print("\n" + "=" * 50)
    print("🎉 Diagnostics completed!")
    print("\nIf all tests passed, AgentK8s should work correctly.")
    print("If any tests failed, please address the issues before running AgentK8s.")

if __name__ == "__main__":
    main()
