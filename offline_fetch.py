#!/usr/bin/env python3
"""
Offline Fetch Script for EKS Operations Review Tool

This script executes multiple AWS CLI and kubectl commands to gather information
about an EKS cluster and consolidates the outputs into a single JSON file for
offline analysis. The script prompts the user for the EKS cluster name and region.
"""

import json
import subprocess
import argparse
import os
import time
import logging
import re
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def run_command(command, ignore_errors=False):
    """
    Run a shell command and return its output
    """
    logging.info(f"Executing: {command}")
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=not ignore_errors,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode != 0 and not ignore_errors:
            logging.error(f"Command failed: {result.stderr}")
            return {"error": result.stderr}
            
        # Try to parse JSON if output looks like JSON
        output = result.stdout.strip()
        if output.startswith('{') or output.startswith('['):
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                # If not valid JSON, return as string
                return output
        else:
            return output
            
    except Exception as e:
        logging.error(f"Exception running command: {str(e)}")
        return {"error": str(e)}

def get_aws_regions():
    """Get list of available AWS regions"""
    regions = run_command("aws ec2 describe-regions --query 'Regions[].RegionName' --output json", ignore_errors=True)
    if isinstance(regions, list):
        return regions
    return ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-southeast-2"]

def get_aws_account_info():
    """Get basic AWS account information"""
    logging.info("Gathering AWS account information")
    return run_command("aws sts get-caller-identity")

def get_eks_clusters(region):
    """Get list of EKS clusters in the region"""
    logging.info(f"Gathering EKS clusters in {region}")
    return run_command(f"aws eks list-clusters --region {region}")

def get_cluster_info(cluster_name, region):
    """Get comprehensive detailed information about the specified EKS cluster"""
    logging.info(f"Gathering comprehensive information for cluster {cluster_name}")
    
    data = {}
    
    # Basic cluster information
    logging.info("Getting basic cluster details...")
    data["cluster_details"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --region {region}"
    )
    
    # Encryption configuration
    logging.info("Checking encryption configuration...")
    data["encryption_config"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --query 'cluster.encryptionConfig' --region {region}",
        ignore_errors=True
    )
    
    # Logging configuration
    logging.info("Checking logging configuration...")
    data["logging_config"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --query 'cluster.logging' --region {region}",
        ignore_errors=True
    )
    
    # VPC configuration
    logging.info("Getting VPC configuration...")
    data["vpc_config"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --query 'cluster.resourcesVpcConfig' --region {region}",
        ignore_errors=True
    )
    
    # Platform version
    logging.info("Getting platform version...")
    data["platform_version"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --query 'cluster.platformVersion' --region {region}",
        ignore_errors=True
    )
    
    # Get node groups
    logging.info("Getting node groups...")
    data["nodegroups"] = run_command(
        f"aws eks list-nodegroups --cluster-name {cluster_name} --region {region}", 
        ignore_errors=True
    )
    
    # Get details for each nodegroup including scaling config
    if "nodegroups" in data and isinstance(data["nodegroups"], dict) and "nodegroups" in data["nodegroups"]:
        nodegroup_details = []
        for ng in data["nodegroups"].get("nodegroups", []):
            logging.info(f"Getting details for nodegroup {ng}...")
            ng_detail = run_command(
                f"aws eks describe-nodegroup --cluster-name {cluster_name} --nodegroup-name {ng} --region {region}",
                ignore_errors=True
            )
            # Structure the data as expected by offline_analyzer.py
            nodegroup_details.append({
                "details": ng_detail  # This contains the full nodegroup response with 'nodegroup' key
            })
        data["nodegroup_details"] = nodegroup_details
    
    # Get add-ons
    logging.info("Getting add-ons...")
    data["addons"] = run_command(
        f"aws eks list-addons --cluster-name {cluster_name} --region {region}",
        ignore_errors=True
    )
    
    # Get details for each add-on
    if "addons" in data and isinstance(data["addons"], dict) and "addons" in data["addons"]:
        addon_details = []
        common_addons = ["aws-ebs-csi-driver", "coredns", "metrics-server", "vpc-cni", "kube-proxy"]
        
        for addon in data["addons"].get("addons", []):
            logging.info(f"Getting details for add-on {addon}...")
            addon_detail = run_command(
                f"aws eks describe-addon --cluster-name {cluster_name} --addon-name {addon} --region {region}",
                ignore_errors=True
            )
            # Structure the data as expected by offline_analyzer.py - it expects 'addon' key directly
            if isinstance(addon_detail, dict) and 'addon' in addon_detail:
                addon_details.append(addon_detail)
        
        # Check for common add-ons that might not be listed
        for addon in common_addons:
            if addon not in data["addons"].get("addons", []):
                logging.info(f"Checking for add-on {addon}...")
                addon_detail = run_command(
                    f"aws eks describe-addon --cluster-name {cluster_name} --addon-name {addon} --region {region}",
                    ignore_errors=True
                )
                if isinstance(addon_detail, dict) and 'addon' in addon_detail and ("error" not in addon_detail):
                    addon_details.append(addon_detail)
        
        data["addon_details"] = addon_details
    
    # Get OIDC provider if exists
    if "cluster_details" in data and "cluster" in data["cluster_details"]:
        oidc_provider = data["cluster_details"]["cluster"].get("identity", {}).get("oidc", {}).get("issuer", "")
        if oidc_provider:
            oidc_id = oidc_provider.split('/')[-1]
            logging.info("Getting OIDC provider details...")
            data["oidc_details"] = run_command(
                f"aws iam list-open-id-connect-providers | grep {oidc_id}", 
                ignore_errors=True
            )
            # Also get IAM roles with web identity conditions (for IRSA)
            account_info = get_aws_account_info()
            if isinstance(account_info, dict) and "Account" in account_info:
                data["irsa_roles"] = run_command(
                    f"aws iam list-roles --query \"Roles[?AssumeRolePolicyDocument.Statement[?Principal.Federated=='arn:aws:iam::{account_info['Account']}:oidc-provider/{oidc_provider.replace('https://', '')}']]\"",
                    ignore_errors=True
                )
    
    # Check if encryption is configured for the cluster
    if "cluster_details" in data and "cluster" in data["cluster_details"]:
        enc_config = data["cluster_details"]["cluster"].get("encryptionConfig", [])
        if not enc_config:
            data["encryption_status"] = "disabled"
        else:
            data["encryption_status"] = "enabled"
            data["encryption_details"] = enc_config
    
    # Check if logging is enabled for the cluster
    if "cluster_details" in data and "cluster" in data["cluster_details"]:
        logging_config = data["cluster_details"]["cluster"].get("logging", {}).get("clusterLogging", [])
        if not logging_config:
            data["logging_status"] = "disabled"
        else:
            # Check if any logging types are enabled
            enabled_types = []
            for config in logging_config:
                if config.get("enabled", False):
                    enabled_types.extend(config.get("types", []))
            
            if enabled_types:
                data["logging_status"] = "enabled"
                data["enabled_log_types"] = enabled_types
            else:
                data["logging_status"] = "disabled"
    
    # Get VPC info if applicable
    if "cluster_details" in data and "cluster" in data["cluster_details"]:
        vpc_id = data["cluster_details"]["cluster"].get("resourcesVpcConfig", {}).get("vpcId")
        if vpc_id:
            data["vpc_details"] = run_command(
                f"aws ec2 describe-vpcs --vpc-ids {vpc_id} --region {region}",
                ignore_errors=True
            )
            
            # Get subnet details
            subnet_ids = data["cluster_details"]["cluster"].get("resourcesVpcConfig", {}).get("subnetIds", [])
            if subnet_ids:
                subnet_ids_str = " ".join(subnet_ids)
                data["subnet_details"] = run_command(
                    f"aws ec2 describe-subnets --subnet-ids {subnet_ids_str} --region {region}",
                    ignore_errors=True
                )
                
            # Get security groups
            security_groups = data["cluster_details"]["cluster"].get("resourcesVpcConfig", {}).get("securityGroupIds", [])
            if security_groups:
                sg_ids_str = " ".join(security_groups)
                data["security_group_details"] = run_command(
                    f"aws ec2 describe-security-groups --group-ids {sg_ids_str} --region {region}",
                    ignore_errors=True
                )
    
    # Check public/private access status
    if "cluster_details" in data and "cluster" in data["cluster_details"]:
        vpc_config = data["cluster_details"]["cluster"].get("resourcesVpcConfig", {})
        data["endpoint_public_access"] = vpc_config.get("endpointPublicAccess", False)
        data["endpoint_private_access"] = vpc_config.get("endpointPrivateAccess", False)
        data["public_access_cidrs"] = vpc_config.get("publicAccessCidrs", [])
    
    # Get cluster authentication details
    data["auth_config"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --region {region} --query 'cluster.identity'",
        ignore_errors=True
    )
    
    # Get EKS updates
    data["updates"] = run_command(
        f"aws eks list-updates --name {cluster_name} --region {region}",
        ignore_errors=True
    )
    
    # Get associated EC2 instances
    data["ec2_instances"] = run_command(
        f"aws ec2 describe-instances --region {region} --filters \"Name=tag:kubernetes.io/cluster/{cluster_name},Values=owned\" --query \"Reservations[].Instances[]\"",
        ignore_errors=True
    )
    
    return data

def get_kubernetes_info(cluster_name, region):
    """Get Kubernetes resources information using kubectl"""
    logging.info(f"Gathering Kubernetes resources for cluster {cluster_name}")
    
    # First update kubeconfig
    run_command(
        f"aws eks update-kubeconfig --name {cluster_name} --region {region}",
        ignore_errors=True
    )
    
    data = {}
    
    # Basic cluster info
    data["kubectl_cluster_info"] = run_command(
        "kubectl cluster-info", 
        ignore_errors=True
    )
    
    # Get nodes
    data["nodes"] = run_command(
        "kubectl get nodes -o json", 
        ignore_errors=True
    )
    
    # Get more detailed node information
    data["nodes_describe"] = run_command(
        "kubectl describe nodes", 
        ignore_errors=True
    )
    
    # Get namespaces
    data["namespaces"] = run_command(
        "kubectl get namespaces -o json", 
        ignore_errors=True
    )
    
    # Get pods across all namespaces
    data["pods"] = run_command(
        "kubectl get pods --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get pod resource usage
    data["pod_top"] = run_command(
        "kubectl top pods --all-namespaces", 
        ignore_errors=True
    )
    
    # Get node resource usage
    data["node_top"] = run_command(
        "kubectl top nodes", 
        ignore_errors=True
    )
    
    # Get services across all namespaces
    data["services"] = run_command(
        "kubectl get services --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get deployments across all namespaces
    data["deployments"] = run_command(
        "kubectl get deployments --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get daemonsets across all namespaces
    data["daemonsets"] = run_command(
        "kubectl get daemonsets --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get statefulsets across all namespaces
    data["statefulsets"] = run_command(
        "kubectl get statefulsets --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get replicasets across all namespaces
    data["replicasets"] = run_command(
        "kubectl get replicasets --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get jobs across all namespaces
    data["jobs"] = run_command(
        "kubectl get jobs --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get cronjobs across all namespaces
    data["cronjobs"] = run_command(
        "kubectl get cronjobs --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get configmaps across all namespaces
    data["configmaps"] = run_command(
        "kubectl get configmaps --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get secrets across all namespaces (just metadata, not content)
    data["secrets"] = run_command(
        "kubectl get secrets --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get storage classes
    data["storageclasses"] = run_command(
        "kubectl get storageclasses -o json", 
        ignore_errors=True
    )
    
    # Get persistent volumes
    data["persistentvolumes"] = run_command(
        "kubectl get pv -o json", 
        ignore_errors=True
    )
    
    # Get persistent volume claims
    data["persistentvolumeclaims"] = run_command(
        "kubectl get pvc --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get ingresses
    data["ingresses"] = run_command(
        "kubectl get ingress --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get horizontal pod autoscalers
    data["hpa"] = run_command(
        "kubectl get hpa --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get pod disruption budgets
    data["pdb"] = run_command(
        "kubectl get poddisruptionbudgets --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get custom resource definitions
    data["crds"] = run_command(
        "kubectl get crds -o json", 
        ignore_errors=True
    )
    
    # Get RBAC info
    data["roles"] = run_command(
        "kubectl get roles --all-namespaces -o json", 
        ignore_errors=True
    )
    
    data["clusterroles"] = run_command(
        "kubectl get clusterroles -o json", 
        ignore_errors=True
    )
    
    data["rolebindings"] = run_command(
        "kubectl get rolebindings --all-namespaces -o json", 
        ignore_errors=True
    )
    
    data["clusterrolebindings"] = run_command(
        "kubectl get clusterrolebindings -o json", 
        ignore_errors=True
    )
    
    # Get networking resources
    data["networkpolicies"] = run_command(
        "kubectl get networkpolicies --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get service accounts
    data["serviceaccounts"] = run_command(
        "kubectl get serviceaccounts --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get events (recent cluster events)
    data["events"] = run_command(
        "kubectl get events --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get resource quotas
    data["resourcequotas"] = run_command(
        "kubectl get resourcequotas --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get limit ranges
    data["limitranges"] = run_command(
        "kubectl get limitranges --all-namespaces -o json", 
        ignore_errors=True
    )
    
    # Get pod security policies (if available)
    data["podsecuritypolicies"] = run_command(
        "kubectl get podsecuritypolicies -o json", 
        ignore_errors=True
    )
    
    return data

def get_comprehensive_network_info(cluster_name, region):
    """Get comprehensive network information for the EKS cluster"""
    logging.info(f"Gathering comprehensive network information for cluster {cluster_name}")
    
    data = {}
    
    # Get VPC information from cluster
    cluster_vpc_info = run_command(
        f"aws eks describe-cluster --name {cluster_name} --query 'cluster.resourcesVpcConfig' --region {region}",
        ignore_errors=True
    )
    
    if isinstance(cluster_vpc_info, dict) and 'vpcId' in cluster_vpc_info:
        vpc_id = cluster_vpc_info['vpcId']
        subnet_ids = cluster_vpc_info.get('subnetIds', [])
        security_group_ids = cluster_vpc_info.get('securityGroupIds', [])
        
        # VPC Deep Dive
        logging.info("Getting VPC details...")
        data["vpc_details"] = run_command(
            f"aws ec2 describe-vpcs --vpc-ids {vpc_id} --region {region}",
            ignore_errors=True
        )
        
        # Subnet Deep Dive
        logging.info("Getting subnet details...")
        if subnet_ids:
            subnet_ids_str = ' '.join(subnet_ids)
            data["subnet_details"] = run_command(
                f"aws ec2 describe-subnets --subnet-ids {subnet_ids_str} --region {region}",
                ignore_errors=True
            )
            # Get subnet IP availability
            data["subnet_ip_availability"] = run_command(
                f"aws ec2 describe-subnets --subnet-ids {subnet_ids_str} --query 'Subnets[*].[SubnetId,AvailableIpAddressCount,CidrBlock]' --region {region}",
                ignore_errors=True
            )
        
        # Get all subnets in VPC
        data["all_vpc_subnets"] = run_command(
            f"aws ec2 describe-subnets --filters \"Name=vpc-id,Values={vpc_id}\" --region {region}",
            ignore_errors=True
        )
        
        # Security Groups Deep Dive
        logging.info("Getting security group details...")
        if security_group_ids:
            sg_ids_str = ' '.join(security_group_ids)
            data["security_groups"] = run_command(
                f"aws ec2 describe-security-groups --group-ids {sg_ids_str} --region {region}",
                ignore_errors=True
            )
        
        # Get all security groups in VPC
        data["all_vpc_security_groups"] = run_command(
            f"aws ec2 describe-security-groups --filters \"Name=vpc-id,Values={vpc_id}\" --region {region}",
            ignore_errors=True
        )
        
        # Route Tables
        logging.info("Getting route table information...")
        data["route_tables"] = run_command(
            f"aws ec2 describe-route-tables --filters \"Name=vpc-id,Values={vpc_id}\" --region {region}",
            ignore_errors=True
        )
        
        # Internet Gateways
        data["internet_gateways"] = run_command(
            f"aws ec2 describe-internet-gateways --filters \"Name=attachment.vpc-id,Values={vpc_id}\" --region {region}",
            ignore_errors=True
        )
        
        # NAT Gateways
        data["nat_gateways"] = run_command(
            f"aws ec2 describe-nat-gateways --filter \"Name=vpc-id,Values={vpc_id}\" --region {region}",
            ignore_errors=True
        )
        
        # VPC Endpoints
        data["vpc_endpoints"] = run_command(
            f"aws ec2 describe-vpc-endpoints --filters \"Name=vpc-id,Values={vpc_id}\" --region {region}",
            ignore_errors=True
        )
        
        # Network ACLs
        data["network_acls"] = run_command(
            f"aws ec2 describe-network-acls --filters \"Name=vpc-id,Values={vpc_id}\" --region {region}",
            ignore_errors=True
        )
    
    return data

def get_comprehensive_infrastructure_info(cluster_name, region):
    """Get comprehensive infrastructure information for the EKS cluster"""
    logging.info(f"Gathering comprehensive infrastructure information for cluster {cluster_name}")
    
    data = {}
    
    # EC2 Instances associated with the cluster
    logging.info("Getting EC2 instances for the cluster...")
    data["ec2_instances"] = run_command(
        f"aws ec2 describe-instances --region {region} --filters \"Name=tag:kubernetes.io/cluster/{cluster_name},Values=owned\" --query 'Reservations[].Instances[].[InstanceId,Tags[?Key==`Name`].Value|[0],InstanceType,State.Name,PrivateIpAddress,PublicIpAddress,SubnetId,VpcId]'",
        ignore_errors=True
    )
    
    # Get detailed EC2 instance information
    data["ec2_instances_detailed"] = run_command(
        f"aws ec2 describe-instances --region {region} --filters \"Name=tag:kubernetes.io/cluster/{cluster_name},Values=owned\"",
        ignore_errors=True
    )
    
    # Check for Spot instances
    data["spot_instances"] = run_command(
        f"aws ec2 describe-instances --filters \"Name=tag:kubernetes.io/cluster/{cluster_name},Values=owned\" --query 'Reservations[].Instances[].InstanceLifecycle' --region {region}",
        ignore_errors=True
    )
    
    # Auto Scaling Groups
    logging.info("Getting Auto Scaling Groups...")
    data["autoscaling_groups"] = run_command(
        f"aws autoscaling describe-auto-scaling-groups --region {region}",
        ignore_errors=True
    )
    
    # Launch Templates
    data["launch_templates"] = run_command(
        f"aws ec2 describe-launch-templates --region {region}",
        ignore_errors=True
    )
    
    # Load Balancers
    logging.info("Getting Load Balancers...")
    data["classic_load_balancers"] = run_command(
        f"aws elb describe-load-balancers --region {region}",
        ignore_errors=True
    )
    data["application_load_balancers"] = run_command(
        f"aws elbv2 describe-load-balancers --region {region}",
        ignore_errors=True
    )
    data["network_load_balancers"] = run_command(
        f"aws elbv2 describe-load-balancers --region {region}",
        ignore_errors=True
    )
    
    # EBS Volumes
    logging.info("Getting EBS volumes...")
    data["ebs_volumes"] = run_command(
        f"aws ec2 describe-volumes --region {region}",
        ignore_errors=True
    )
    
    # EFS File Systems
    data["efs_filesystems"] = run_command(
        f"aws efs describe-file-systems --region {region}",
        ignore_errors=True
    )
    
    # CloudWatch Log Groups
    logging.info("Getting CloudWatch log groups...")
    data["cloudwatch_log_groups"] = run_command(
        f"aws logs describe-log-groups --region {region}",
        ignore_errors=True
    )
    
    # IAM Roles related to EKS
    logging.info("Getting IAM roles...")
    data["eks_service_roles"] = run_command(
        f"aws iam list-roles --path-prefix /aws-service-role/eks",
        ignore_errors=True
    )
    data["cluster_service_role"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --query 'cluster.roleArn' --region {region}",
        ignore_errors=True
    )
    
    return data

def get_security_info(cluster_name, region):
    """Get security-related information for the cluster"""
    logging.info("Gathering security information")
    
    data = {}
    
    # Check if Security Groups for Pods is enabled
    data["sg_pods"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --region {region} --query 'cluster.resourcesVpcConfig.securityGroupIds'",
        ignore_errors=True
    )
    
    # Check if Control Plane Logging is enabled
    data["control_plane_logging"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --region {region} --query 'cluster.logging'",
        ignore_errors=True
    )
    
    # Check if Secrets Encryption is enabled
    data["secrets_encryption"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --region {region} --query 'cluster.encryptionConfig'",
        ignore_errors=True
    )
    
    # Check if Private Access is enabled
    data["private_access"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --region {region} --query 'cluster.resourcesVpcConfig.endpointPrivateAccess'",
        ignore_errors=True
    )
    
    # Check public access CIDR restrictions
    data["public_access_cidrs"] = run_command(
        f"aws eks describe-cluster --name {cluster_name} --region {region} --query 'cluster.resourcesVpcConfig.publicAccessCidrs'",
        ignore_errors=True
    )
    
    # Check IAM roles associated with the cluster
    account_id = get_aws_account_info().get('Account', '')
    if account_id:
        data["cluster_iam_roles"] = run_command(
            f"aws iam list-roles --query \"Roles[?contains(AssumeRolePolicyDocument.Statement[].Principal.Service, 'eks.amazonaws.com')]\"",
            ignore_errors=True
        )
    
    # Check for GuardDuty EKS Protection
    data["guardduty_eks"] = run_command(
        f"aws guardduty list-detectors --region {region} --query 'DetectorIds'",
        ignore_errors=True
    )
    
    if isinstance(data["guardduty_eks"], list) and data["guardduty_eks"]:
        detector_id = data["guardduty_eks"][0]
        data["guardduty_features"] = run_command(
            f"aws guardduty get-detector --detector-id {detector_id} --region {region}",
            ignore_errors=True
        )
    
    # Check Security Hub findings related to EKS
    data["security_hub_findings"] = run_command(
        f"aws securityhub get-findings --filters '{{\"ResourceType\":[{{\"Value\":\"AwsEksCluster\",\"Comparison\":\"EQUALS\"}}],\"ResourceId\":[{{\"Value\":\"{cluster_name}\",\"Comparison\":\"EQUALS\"}}]}}' --region {region}",
        ignore_errors=True
    )
    
    # Check for[ERROR] Failed to process response: Too many requests, please wait before trying again. You have sent too many requests.  Wait before trying again.
    # Check for AWS Config rules related to EKS
    data["config_rules"] = run_command(
        f"aws configservice describe-config-rules --region {region}",
        ignore_errors=True
    )
    
    # Check for CloudTrail logs
    data["cloudtrail_trails"] = run_command(
        f"aws cloudtrail describe-trails --region {region}",
        ignore_errors=True
    )
    
    # HardenEKS-specific data collection
    logging.info("Collecting HardenEKS-specific security data...")
    
    # Get KMS keys for encryption analysis
    data["kms_keys"] = run_command(
        f"aws kms list-keys --region {region}",
        ignore_errors=True
    )
    
    # Get detailed VPC Flow Logs status
    data["vpc_flow_logs"] = run_command(
        f"aws ec2 describe-flow-logs --region {region}",
        ignore_errors=True
    )
    
    # Get ECR repositories and scanning configuration
    data["ecr_repositories"] = run_command(
        f"aws ecr describe-repositories --region {region}",
        ignore_errors=True
    )
    
    # Get AWS Systems Manager patch compliance (for node security)
    data["ssm_patch_compliance"] = run_command(
        f"aws ssm describe-instance-patch-states --region {region}",
        ignore_errors=True
    )
    
    # Get AWS Certificate Manager certificates
    data["acm_certificates"] = run_command(
        f"aws acm list-certificates --region {region}",
        ignore_errors=True
    )
    
    # Get AWS Secrets Manager secrets
    data["secrets_manager"] = run_command(
        f"aws secretsmanager list-secrets --region {region}",
        ignore_errors=True
    )
    
    return data

def main():
    """Main function to orchestrate the data collection"""
    print("🚀 EKS Offline Data Collection Script")
    print("=" * 50)
    
    # Get cluster name from user
    cluster_name = input("Enter EKS cluster name: ").strip()
    if not cluster_name:
        print("❌ Cluster name is required!")
        return
    
    # Get region from user
    print("\nAvailable regions:")
    regions = get_aws_regions()
    for i, region in enumerate(regions[:10], 1):  # Show first 10 regions
        print(f"{i}. {region}")
    
    region_input = input(f"\nEnter region (or number 1-{min(10, len(regions))}): ").strip()
    
    # Handle region selection
    if region_input.isdigit():
        region_idx = int(region_input) - 1
        if 0 <= region_idx < min(10, len(regions)):
            region = regions[region_idx]
        else:
            print("❌ Invalid region number!")
            return
    else:
        region = region_input
    
    if not region:
        print("❌ Region is required!")
        return
    
    print(f"\n🔍 Collecting data for cluster: {cluster_name} in region: {region}")
    print("This may take several minutes...")
    
    # Initialize the consolidated data structure
    consolidated_data = {
        "metadata": {
            "cluster_name": cluster_name,
            "region": region,
            "collection_timestamp": datetime.now().isoformat(),
            "script_version": "2.0-comprehensive"
        }
    }
    
    try:
        # Collect AWS account information
        print("\n📋 Collecting AWS account information...")
        consolidated_data["aws_account"] = get_aws_account_info()
        
        # Collect cluster information
        print("\n🏗️ Collecting comprehensive cluster information...")
        consolidated_data["cluster_info"] = get_cluster_info(cluster_name, region)
        
        # Collect Kubernetes information
        print("\n☸️ Collecting comprehensive Kubernetes information...")
        consolidated_data["k8s_data"] = get_kubernetes_info(cluster_name, region)
        
        # Collect comprehensive network information
        print("\n🌐 Collecting comprehensive network information...")
        consolidated_data["network_info"] = get_comprehensive_network_info(cluster_name, region)
        
        # Collect comprehensive infrastructure information
        print("\n🏗️ Collecting comprehensive infrastructure information...")
        consolidated_data["infrastructure_info"] = get_comprehensive_infrastructure_info(cluster_name, region)
        
        # Collect security information
        print("\n🔒 Collecting comprehensive security information...")
        consolidated_data["security_info"] = get_security_info(cluster_name, region)
        
        # Generate output filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"eks_offline_data_{cluster_name}_{timestamp}.json"
        
        # Write consolidated data to JSON file
        print(f"\n💾 Writing data to {output_filename}...")
        with open(output_filename, 'w') as f:
            json.dump(consolidated_data, f, indent=2, default=str)
        
        print(f"\n✅ Data collection completed successfully!")
        print(f"📄 Output file: {output_filename}")
        print(f"📊 File size: {os.path.getsize(output_filename) / 1024 / 1024:.2f} MB")
        
        # Print summary
        print(f"\n📈 Collection Summary:")
        print(f"   • Cluster: {cluster_name}")
        print(f"   • Region: {region}")
        print(f"   • Timestamp: {consolidated_data['metadata']['collection_timestamp']}")
        print(f"   • Data sections: {len(consolidated_data) - 1}")  # -1 for metadata
        
        # Check if kubectl data was collected successfully
        if 'k8s_data' in consolidated_data and consolidated_data['k8s_data']:
            k8s_data = consolidated_data['k8s_data']
            if 'nodes' in k8s_data and isinstance(k8s_data['nodes'], dict) and 'items' in k8s_data['nodes']:
                print(f"   • Nodes: {len(k8s_data['nodes']['items'])}")
            if 'pods' in k8s_data and isinstance(k8s_data['pods'], dict) and 'items' in k8s_data['pods']:
                print(f"   • Pods: {len(k8s_data['pods']['items'])}")
            if 'namespaces' in k8s_data and isinstance(k8s_data['namespaces'], dict) and 'items' in k8s_data['namespaces']:
                print(f"   • Namespaces: {len(k8s_data['namespaces']['items'])}")
        
        print(f"\n🎯 Next steps:")
        print(f"   1. Upload {output_filename} to the offline analyzer")
        print(f"   2. Generate comprehensive PDF reports")
        print(f"   3. Review security and operational recommendations")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Collection interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during data collection: {str(e)}")
        logging.error(f"Collection failed: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()
