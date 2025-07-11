# Feature Guide

This document provides detailed information on the new features added to the EKS Operational Review Agent.

## Table of Contents

1. [Real-time Cluster Monitoring](#real-time-cluster-monitoring)
2. [Automated Remediation](#automated-remediation)
3. [Compliance Framework Validation](#compliance-framework-validation)
4. [Historical Trend Analysis](#historical-trend-analysis)
5. [Multi-cluster Comparison](#multi-cluster-comparison)
6. [AWS Security Hub Integration](#aws-security-hub-integration)

## Real-time Cluster Monitoring

### Overview

The real-time cluster monitoring feature allows you to continuously monitor your EKS clusters for security issues. It runs in the background and periodically scans your clusters, tracking security posture over time and alerting you to new issues.

### Implementation

The monitoring system is implemented in the `src/monitoring/cluster_monitor.py` file. It uses a background thread to periodically scan the cluster and store the results in memory.

### Usage

1. Navigate to the Monitoring tab in the application
2. Click "Start Monitoring" to begin monitoring your cluster
3. The monitoring will run at regular intervals (default: 1 hour)
4. View the monitoring history table to see scan results over time
5. Check the security trend to see if your cluster's security is improving
6. Click "Stop Monitoring" to end the monitoring process

### Configuration

You can configure the monitoring interval by modifying the `monitoring_interval` parameter when initializing the `ClusterMonitor` class:

```python
# Initialize with a custom interval (in seconds)
cluster_monitor = ClusterMonitor(aws_utils, monitoring_interval=1800)  # 30 minutes
```

### Monitoring History

The monitoring history includes:
- Timestamp of each scan
- HardenEKS security score
- Number of passed and failed checks
- Number of high, medium, and low priority issues

### Trend Analysis

The trend analysis shows:
- Whether security is improving, deteriorating, or stable
- Change in security score over time
- Change in number of passed and failed checks

## Automated Remediation

### Overview

The automated remediation feature allows you to automatically fix security issues in your EKS clusters. It provides templates for common remediation actions and applies them with minimal user intervention.

### Implementation

The remediation system is implemented in the `src/remediation/remediation_manager.py` file. It uses three types of remediation:

1. **CloudFormation**: Creates CloudFormation stacks to fix infrastructure issues
2. **EKS API**: Makes direct API calls to the EKS service
3. **Kubernetes**: Applies Kubernetes manifests to fix workload issues

### Usage

1. Navigate to the Remediation tab in the application
2. View the available remediation actions for failed security checks
3. Expand a remediation to see details about what it will fix
4. Click "Apply Remediation" to automatically fix the issue
5. Provide any required parameters when prompted
6. Check the success message to confirm the remediation was applied

### Remediation Templates

Remediation templates are stored in the `src/remediation/templates` directory as YAML files. Each template includes:

- Name and description of the remediation
- The security check it addresses
- The type of remediation (CloudFormation, EKS API, Kubernetes)
- The template content (CloudFormation template, API call parameters, or Kubernetes manifest)

### Adding Custom Remediations

You can add custom remediation templates by creating new YAML files in the templates directory:

```yaml
name: Enable VPC Flow Logs
description: Enable VPC Flow Logs for network traffic visibility
check_id: VPC Flow Logs
remediation_type: cloudformation
template:
  AWSTemplateFormatVersion: '2010-09-09'
  Resources:
    FlowLog:
      Type: AWS::EC2::FlowLog
      Properties:
        ResourceId: '{{vpc_id}}'
        ResourceType: VPC
        TrafficType: ALL
        LogDestinationType: cloud-watch-logs
        LogGroupName: /aws/vpc/flowlogs
        DeliverLogsPermissionArn: '{{log_delivery_role_arn}}'
```

## Compliance Framework Validation

### Overview

The compliance framework validation feature allows you to validate your EKS clusters against industry compliance frameworks. It maps security checks to compliance controls and provides a compliance score.

### Implementation

The compliance system is implemented in the `src/compliance/compliance_manager.py` file. It uses JSON files to define compliance frameworks and their controls.

### Usage

1. Navigate to the Compliance tab in the application
2. Select a compliance framework from the dropdown
3. Click "Validate Compliance" to check your cluster against the framework
4. View your compliance score as a percentage
5. See which controls are compliant and which are non-compliant
6. Address the non-compliant controls to improve your score

### Supported Frameworks

The system currently supports the following compliance frameworks:

1. **CIS Amazon EKS Benchmark**: Security best practices specific to EKS
2. **NIST SP 800-53**: Federal security controls mapped to EKS
3. **PCI DSS**: Payment card industry requirements for EKS

### Framework Structure

Each framework is defined in a JSON file in the `src/compliance/frameworks` directory. The file includes:

- Name and version of the framework
- Description of the framework
- List of controls with their IDs, titles, descriptions, and severity
- Mapping of controls to security checks

### Adding Custom Frameworks

You can add custom compliance frameworks by creating new JSON files in the frameworks directory:

```json
{
  "name": "Custom Framework",
  "version": "1.0.0",
  "description": "Custom compliance framework for EKS",
  "controls": [
    {
      "id": "CUSTOM-1",
      "title": "Enable Secrets Encryption",
      "description": "Ensure that envelope encryption is enabled for Kubernetes secrets",
      "severity": "HIGH",
      "checks": [
        {
          "check_id": "Secrets Encryption",
          "expected_result": "PASSED"
        }
      ]
    }
  ]
}
```

## Historical Trend Analysis

### Overview

The historical trend analysis feature allows you to track your cluster's security posture over time. It stores scan results and provides visualizations of security trends.

### Implementation

The history system is implemented in the `src/history/history_manager.py` file. It stores scan results in JSON files on disk and provides methods to retrieve and analyze historical data.

### Usage

1. Navigate to the History tab in the application
2. View the trend chart showing security score and issues over time
3. Expand individual scans to see details about that point in time
4. Click "View Details" to see the full scan results
5. Compare different scans to track your progress

### Storage Location

By default, scan results are stored in the `~/.eks-operational-review/history` directory. You can customize this location by providing a `storage_dir` parameter when initializing the `HistoryManager` class:

```python
# Initialize with a custom storage directory
history_manager = HistoryManager(storage_dir="/path/to/storage")
```

### Scan Storage

Each scan is stored in two files:
1. An entry in the `index.json` file with summary information
2. A separate JSON file with the full scan results

### Trend Visualization

The trend visualization shows:
- Security score over time
- Number of high, medium, and low priority issues over time

### Scan Comparison

You can compare two scans to see:
- Change in security score
- New passed checks
- Lost passed checks
- New failed checks
- Resolved failed checks

## Multi-cluster Comparison

### Overview

The multi-cluster comparison feature allows you to compare security postures across multiple EKS clusters. It provides side-by-side comparisons and identifies common issues.

### Implementation

The comparison system is implemented in the `src/comparison/cluster_comparison.py` file. It analyzes multiple clusters and generates comparison results.

### Usage

1. Navigate to the Comparison tab in the application
2. Click "Add Current Cluster to Comparison" to add your current cluster
3. Configure and add another cluster to compare with
4. Click "Compare Clusters" to see a side-by-side comparison
5. View the comparison chart showing security scores and issues
6. See common issues affecting multiple clusters

### Comparison Results

The comparison results include:
- Security scores for each cluster
- Number of passed and failed checks for each cluster
- Number of high, medium, and low priority issues for each cluster
- Common issues affecting multiple clusters
- Security categories with issues in each cluster

### Cluster Differences

You can also get detailed differences between two specific clusters:
- Score difference
- Unique passed checks in each cluster
- Unique failed checks in each cluster

### Visualization

The comparison includes a chart showing:
- Security scores for each cluster
- Issue counts by priority for each cluster

## AWS Security Hub Integration

### Overview

The AWS Security Hub integration feature allows you to centralize your security findings in AWS Security Hub. It sends findings for failed security checks and tracks their status.

### Implementation

The Security Hub integration is implemented in the `src/security_hub/security_hub_integration.py` file. It uses the AWS Security Hub API to send and manage findings.

### Usage

1. Ensure Security Hub is enabled in your AWS account
2. Generate a report or start monitoring
3. Findings will automatically be sent to Security Hub
4. View and manage findings in the AWS console

### Finding Structure

Each finding includes:
- Title and description of the issue
- Severity based on the priority
- Resource information (cluster ARN)
- Remediation guidance
- References to documentation

### Finding Management

You can manage findings in Security Hub:
- Update finding status (RESOLVED, SUPPRESSED, etc.)
- Add notes to findings
- Create custom insights based on findings
- Set up EventBridge rules for automation

### AWS Integration

The Security Hub integration works with other AWS services:
- Findings appear in Security Hub dashboards
- Findings can be included in AWS Config compliance reports
- Findings can trigger EventBridge rules for automation
- Findings can be exported to Amazon S3 for long-term storage