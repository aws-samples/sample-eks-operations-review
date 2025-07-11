# Installation Guide

This document provides detailed instructions for installing and configuring the EKS Operational Review Agent with all its features.

## Prerequisites

Before installing the EKS Operational Review Agent, ensure you have the following:

- Python 3.8 or higher
- AWS Account with EKS cluster access
- AWS CLI installed and configured
- Valid AWS credentials with appropriate permissions
- For Bedrock Agent functionality:
  - Access to Amazon Bedrock service
  - IAM permissions for Bedrock, Bedrock Agent, and Bedrock Agent Runtime
  - S3 bucket for knowledge base storage
- For Security Hub integration:
  - Security Hub enabled in your AWS account
  - Appropriate permissions for Security Hub API calls
- For Kubernetes remediation:
  - kubectl installed and configured

## Required AWS Permissions

The EKS Operational Review Agent requires the following AWS permissions:

### EKS Permissions
- eks:DescribeCluster
- eks:ListClusters
- eks:DescribeNodegroup
- eks:ListNodegroups
- eks:DescribeAddon
- eks:ListAddons
- eks:DescribeUpdate
- eks:ListUpdates

### CloudWatch Permissions
- cloudwatch:GetMetricData
- cloudwatch:GetMetricStatistics
- logs:DescribeLogGroups
- logs:DescribeLogStreams
- logs:GetLogEvents

### Security Hub Permissions
- securityhub:BatchImportFindings
- securityhub:BatchUpdateFindings
- securityhub:GetFindings
- securityhub:EnableSecurityHub
- securityhub:GetEnabledStandards

### CloudFormation Permissions (for remediation)
- cloudformation:CreateStack
- cloudformation:DescribeStacks
- cloudformation:DeleteStack
- cloudformation:UpdateStack
- cloudformation:ListStacks

### IAM Permissions (for remediation)
- iam:CreateRole
- iam:AttachRolePolicy
- iam:CreateOpenIDConnectProvider
- iam:GetRole
- iam:ListAttachedRolePolicies

### Kubernetes Permissions (for cluster analysis)
- Access to Kubernetes API server
- Cluster admin permissions for comprehensive analysis
- Read access to all namespaces and resources

## Installation Steps

### 1. Clone the Repository

```bash
git clone <repository-url>
cd eks-operational-review-agent
```

### 2. Create and Activate a Virtual Environment

```bash
# MacOS/Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure AWS Credentials

You can configure AWS credentials in several ways:

#### Option 1: AWS CLI Configuration

```bash
aws configure
```

#### Option 2: Environment Variables

```bash
# MacOS/Linux
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=your_region

# Windows
set AWS_ACCESS_KEY_ID=your_access_key
set AWS_SECRET_ACCESS_KEY=your_secret_key
set AWS_REGION=your_region
```

#### Option 3: In-App Configuration

You can also provide AWS credentials directly in the application's sidebar.

### 5. Enable Security Hub (Optional)

If you want to use the Security Hub integration, enable Security Hub in your AWS account:

```bash
aws securityhub enable-security-hub
```

### 6. Create a Bedrock Knowledge Base (Optional)

If you want to use the Bedrock Agent functionality, create a knowledge base:

```bash
# Create an S3 bucket for the knowledge base
aws s3 mb s3://eks-best-practices-kb

# Upload EKS best practices documentation
aws s3 cp eks-bpg.pdf s3://eks-best-practices-kb/eks-docs/
```

Then use the Bedrock console to create a knowledge base using this S3 bucket.

### 7. Start the Application

```bash
streamlit run app.py
```

## Configuration Options

### Storage Directory

By default, the application stores historical data in the `~/.eks-operational-review` directory. You can customize this by modifying the `HistoryManager` initialization in `app.py`:

```python
history_manager = HistoryManager(storage_dir="/path/to/storage")
```

### Monitoring Interval

By default, the monitoring system scans the cluster every hour. You can customize this by modifying the `ClusterMonitor` initialization in `app.py`:

```python
cluster_monitor = ClusterMonitor(aws_utils, monitoring_interval=1800)  # 30 minutes
```

### Compliance Frameworks

The compliance frameworks are stored in the `src/compliance/frameworks` directory. You can add custom frameworks by creating new JSON files in this directory.

### Remediation Templates

The remediation templates are stored in the `src/remediation/templates` directory. You can add custom templates by creating new YAML files in this directory.

## Troubleshooting

### AWS Authentication Issues

If you encounter AWS authentication issues:

1. Verify your AWS credentials:
```bash
aws sts get-caller-identity
```

2. Check that your credentials have the necessary permissions:
```bash
aws iam get-user
aws iam list-attached-user-policies --user-name <your-username>
```

3. Ensure your AWS region is set correctly:
```bash
aws configure get region
```

### Application Startup Issues

If the application fails to start:

1. Check that all dependencies are installed:
```bash
pip install -r requirements.txt
```

2. Verify that Streamlit is installed:
```bash
streamlit --version
```

3. Check for Python version compatibility:
```bash
python --version
```

### Monitoring Issues

If monitoring doesn't start or work correctly:

1. Check AWS credentials have sufficient permissions
2. Verify the cluster exists and is accessible:
```bash
aws eks describe-cluster --name <cluster-name>
```

3. Check for errors in the application logs

### Remediation Issues

If remediation fails to apply:

1. Check AWS permissions for the specific service (CloudFormation, EKS)
2. Verify kubectl is installed for Kubernetes remediations:
```bash
kubectl version --client
```

3. Check for conflicts with existing resources

### Security Hub Issues

If findings don't appear in Security Hub:

1. Verify Security Hub is enabled:
```bash
aws securityhub get-enabled-standards
```

2. Check IAM permissions for Security Hub API calls
3. Ensure the region matches your Security Hub configuration

## Next Steps

After installation, proceed to the [User Guide](USER_GUIDE.md) for detailed instructions on using the application.