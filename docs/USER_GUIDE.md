# User Guide

This document provides detailed instructions for using the EKS Operational Review Agent and all its features.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Analysis Tab](#analysis-tab)
3. [Cluster Analysis Tab](#cluster-analysis-tab)
4. [HardenEKS Tab](#hardeneks-tab)
5. [Monitoring Tab](#monitoring-tab)
6. [Remediation Tab](#remediation-tab)
7. [Compliance Tab](#compliance-tab)
8. [History Tab](#history-tab)
9. [Comparison Tab](#comparison-tab)
10. [Advanced Usage](#advanced-usage)

## Getting Started

### Launching the Application

1. Start the Streamlit application:
```bash
streamlit run app.py
```

2. The application will open in your default web browser at `http://localhost:8501`

### Configuring AWS Credentials

1. In the sidebar, enter your AWS credentials:
   - AWS Access Key
   - AWS Secret Key
   - AWS Region
   - EKS Cluster Name
   - Knowledge Base ID (if using Bedrock Agent functionality)

2. Click "Initialize" to connect to your AWS account and EKS cluster

3. If successful, you'll see a success message and can proceed to use the application

## Analysis Tab

The Analysis tab is the main interface for analyzing your EKS cluster.

### Filling in Cluster Information

1. Navigate through the different sections (Security, Networking, etc.)
2. Fill in the information about your cluster configuration
3. You can use the default values as a starting point

### Analyzing Individual Sections

1. Click "Analyze" next to a specific section to get AI-powered insights
2. The analysis will appear in the right column
3. This uses the Bedrock Agent to provide context-aware recommendations

### Generating a Comprehensive Report

1. Click "Generate Report" at the bottom of the page
2. The tool will analyze your cluster using both the best practices analyzer and HardenEKS
3. View the summary of findings, including:
   - High, medium, and low priority issues
   - HardenEKS security score
   - Top findings

4. Download the reports:
   - PDF Report: Detailed analysis and recommendations
   - CSV Action Items: Actionable items in spreadsheet format

## Cluster Analysis Tab

The Cluster Analysis tab provides comprehensive analysis of your EKS cluster using admin permissions.

### Running Cluster Analysis

1. Click "Analyze Cluster with Admin Permissions"
2. The tool will connect to your cluster using Kubernetes API
3. View comprehensive cluster information including:
   - Number of namespaces, pods, deployments, and services
   - Security findings categorized by priority
   - Affected resources for each finding

### Viewing Analysis Results

1. Review the cluster metrics displayed at the top
2. Expand high and medium priority findings to see details
3. Each finding includes:
   - Category and description
   - Security impact
   - Action items to address the issue
   - List of affected resources

### Generating Reports

1. Click "Generate Cluster Analysis Report" to create a detailed PDF
2. The report includes all findings and recommendations
3. Download the report for sharing or documentation

## HardenEKS Tab

The HardenEKS tab focuses specifically on security analysis using HardenEKS methodology.

### Running HardenEKS Analysis

1. Click "Run HardenEKS Analysis"
2. View your HardenEKS security score (0-100%)
3. Review security findings by priority level
4. See which security checks passed or failed

### Understanding Results

1. **HardenEKS Score**: Overall security posture percentage
2. **Failed Security Checks**: List of specific checks that failed
3. **Priority Findings**: Categorized recommendations
   - High Priority: Critical security issues
   - Medium Priority: Important improvements
   - Low Priority: Best practice recommendations

### Generating HardenEKS Reports

1. Click "Generate HardenEKS Report" for a security-focused PDF
2. The report includes detailed security analysis and remediation steps

## Monitoring Tab

The Monitoring tab allows you to continuously monitor your EKS cluster for security issues.

### Starting Monitoring

1. Click "Start Monitoring" to begin real-time monitoring
2. The monitoring will run in the background at regular intervals (default: 1 hour)
3. You can continue using other parts of the application while monitoring runs

### Viewing Monitoring Results

1. The monitoring history table shows scan results over time
2. Each row includes:
   - Timestamp
   - HardenEKS score
   - Number of passed and failed checks
   - Number of high, medium, and low priority issues

### Analyzing Trends

1. The security trend metric shows if your security is improving, deteriorating, or stable
2. The delta value shows the change in security score since the first scan

### Stopping Monitoring

1. Click "Stop Monitoring" to end the monitoring process
2. The monitoring thread will be terminated
3. Monitoring history will remain available until you close the application

## Remediation Tab

The Remediation tab allows you to automatically fix security issues in your EKS cluster.

### Viewing Available Remediations

1. The tool will display available remediation actions for failed security checks
2. Each remediation includes:
   - Name of the remediation
   - Security check it addresses
   - Description of what it will fix
   - Type of remediation (CloudFormation, EKS API, Kubernetes)

### Applying Remediations

1. Expand a remediation to see details
2. Click "Apply Remediation" to automatically fix the issue
3. If the remediation requires parameters, you'll be prompted to provide them
4. The tool will apply the remediation and show a success or error message

### Verifying Remediations

1. After applying a remediation, generate a new report
2. Check if the security check now passes
3. The HardenEKS score should improve if the remediation was successful

## Compliance Tab

The Compliance tab allows you to validate your EKS cluster against industry compliance frameworks.

### Selecting a Compliance Framework

1. Choose a compliance framework from the dropdown:
   - CIS Amazon EKS Benchmark
   - NIST SP 800-53
   - PCI DSS

### Validating Compliance

1. Click "Validate Compliance" to check your cluster against the selected framework
2. The tool will map your security checks to compliance controls
3. View your compliance score as a percentage

### Reviewing Compliance Results

1. The "Compliant Controls" section shows which controls your cluster passes
2. The "Non-Compliant Controls" section shows which controls your cluster fails
3. Each control includes:
   - Control ID
   - Title
   - Description
   - Severity

### Improving Compliance

1. Address the non-compliant controls to improve your score
2. Use the remediation tab to fix issues automatically
3. Re-validate compliance to see your improved score

## History Tab

The History tab allows you to track your cluster's security posture over time.

### Viewing Historical Data

1. The trend chart shows security score and issues over time
2. The total scans metric shows how many scans have been performed

### Exploring Individual Scans

1. Expand a scan to see summary information:
   - HardenEKS score
   - Number of passed and failed checks
   - Timestamp

2. Click "View Details" to see the full scan results:
   - All security checks
   - All recommendations
   - Raw scan data

### Comparing Scans

1. Select two scans to compare
2. View the differences:
   - Change in security score
   - New passed checks
   - Lost passed checks
   - New failed checks
   - Resolved failed checks

## Comparison Tab

The Comparison tab allows you to compare security postures across multiple EKS clusters.

### Adding Clusters to Comparison

1. Click "Add Current Cluster to Comparison" to add your current cluster
2. Change to another cluster by updating the cluster name in the sidebar and reinitializing
3. Add the new cluster to the comparison
4. Repeat for all clusters you want to compare

### Comparing Clusters

1. Click "Compare Clusters" to see a side-by-side comparison
2. The comparison chart shows:
   - Security scores for each cluster
   - Issue counts by priority for each cluster

### Analyzing Common Issues

1. The "Common Issues Across Clusters" section shows issues affecting multiple clusters
2. Issues are sorted by the number of affected clusters
3. Address these common issues to improve security across your organization

### Detailed Cluster Differences

1. Select two specific clusters to compare
2. View detailed differences:
   - Score difference
   - Unique passed checks in each cluster
   - Unique failed checks in each cluster

## Advanced Usage

### Using the HardenEKS Analyzer Programmatically

```python
from src.analyzers.hardeneks_analyzer import HardenEKSAnalyzer

# Initialize the analyzer
analyzer = HardenEKSAnalyzer()

# Analyze the cluster
analysis_results = analyzer.analyze_cluster(cluster_details, inputs)

# Get the security score
security_score = analysis_results['hardeneks_score']

# Get the recommendations
high_priority = analysis_results['high_priority']
medium_priority = analysis_results['medium_priority']
low_priority = analysis_results['low_priority']
```

### Using the Remediation Manager Programmatically

```python
from src.remediation.remediation_manager import RemediationManager

# Initialize the remediation manager
remediation_manager = RemediationManager(aws_access_key, aws_secret_key, region)

# Get available remediations
remediations = remediation_manager.get_available_remediations(failed_checks)

# Apply a remediation
result = remediation_manager.apply_remediation(
    cluster_name="my-cluster",
    template_id="irsa",
    parameters={"oidc_thumbprint": "1234567890abcdef"}
)
```

### Using the Compliance Manager Programmatically

```python
from src.compliance.compliance_manager import ComplianceManager

# Initialize the compliance manager
compliance_manager = ComplianceManager()

# Get available frameworks
frameworks = compliance_manager.get_available_frameworks()

# Validate compliance
compliance_results = compliance_manager.validate_compliance(
    framework_id="cis",
    analysis_results=analysis_results
)

# Get compliance score
compliance_score = compliance_results['compliance_score']
```

### Using the History Manager Programmatically

```python
from src.history.history_manager import HistoryManager

# Initialize the history manager
history_manager = HistoryManager()

# Save scan results
history_manager.save_scan_results(
    cluster_name="my-cluster",
    analysis_results=analysis_results
)

# Get cluster history
history = history_manager.get_cluster_history("my-cluster")

# Compare scans
comparison = history_manager.compare_scans(
    cluster_name="my-cluster",
    timestamp1="20230101_120000",
    timestamp2="20230201_120000"
)
```

### Using the Security Hub Integration Programmatically

```python
from src.security_hub.security_hub_integration import SecurityHubIntegration

# Initialize the Security Hub integration
security_hub = SecurityHubIntegration(aws_access_key, aws_secret_key, region)

# Check if Security Hub is enabled
is_enabled = security_hub.is_security_hub_enabled()

# Send findings
result = security_hub.send_findings(
    cluster_name="my-cluster",
    analysis_results=analysis_results
)

# Get existing findings
findings = security_hub.get_existing_findings("my-cluster")

# Update finding status
security_hub.update_finding_status(
    finding_id="finding-id",
    status="RESOLVED"
)
```