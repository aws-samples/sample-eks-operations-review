# HardenEKS Integration Guide

This document provides detailed information on the HardenEKS integration in the EKS Operational Review Agent.

## Overview

HardenEKS is a tool for validating best practices for Amazon EKS clusters programmatically. The EKS Operational Review Agent integrates HardenEKS functionality through a custom implementation that performs comprehensive security checks on EKS clusters and provides actionable recommendations.

## Implementation Details

The HardenEKS integration is implemented in the `src/analyzers/hardeneks_analyzer.py` file. The analyzer performs the following security checks:

1. **IAM Security**
   - IRSA Implementation
   - Node IAM Role Permissions

2. **Pod Security**
   - Pod Security Standards
   - Privileged Containers

3. **Network Security**
   - Network Policies
   - Private API Endpoint

4. **Runtime Security**
   - Runtime Security Solution

5. **Detective Controls**
   - Audit Logging
   - Container Insights

6. **Infrastructure Security**
   - Nodes in Private Subnets
   - Security Group Configuration

7. **Data Security**
   - Secrets Encryption
   - EBS Encryption

## Security Score Calculation

The HardenEKS analyzer calculates a security score based on the number of passed checks:

```
Security Score = (Number of Passed Checks / Total Number of Checks) * 100
```

This score provides a quick assessment of the cluster's security posture and can be tracked over time to measure improvements.

## Check Categories

Each security check is categorized by priority:

- **High Priority**: Critical security issues that should be addressed immediately
- **Medium Priority**: Important security issues that should be addressed soon
- **Low Priority**: Security improvements that should be considered

## Recommendation Structure

Each recommendation includes:

- **Category**: The security category (IAM, Pod Security, etc.)
- **Title**: A brief description of the issue
- **Description**: Detailed explanation of the issue
- **Impact**: The security impact of the issue
- **Priority**: The priority level (High, Medium, Low)
- **Action Items**: Specific steps to address the issue
- **Reference**: Documentation reference for more information
- **Reasoning**: Explanation of why this is a security concern

## Usage

### Basic Usage

The HardenEKS analyzer is automatically used when generating a report:

1. Navigate to the Analysis tab
2. Fill in the cluster information forms
3. Click "Generate Report"
4. The HardenEKS score and recommendations will be included in the report

### Programmatic Usage

You can also use the HardenEKS analyzer programmatically:

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

# Get passed and failed checks
passed_checks = analysis_results['passed_checks']
failed_checks = analysis_results['failed_checks']
```

## Integration with Other Components

The HardenEKS analyzer integrates with other components of the EKS Operational Review Agent:

1. **Remediation Manager**: Failed checks can be automatically remediated
2. **Compliance Manager**: Checks are mapped to compliance controls
3. **Monitoring System**: Security score is tracked over time
4. **History Manager**: Security posture history is stored
5. **Comparison System**: Security scores can be compared across clusters
6. **Security Hub**: Findings are sent to AWS Security Hub

## Customizing Checks

You can customize the security checks by modifying the `hardeneks_analyzer.py` file:

1. Add new check methods in the appropriate category method
2. Update the check helper methods to implement the check logic
3. Add new recommendations to the results

Example of adding a new check:

```python
def _check_network_security(self, cluster_details, inputs):
    # Existing code...
    
    # Add a new check
    results['total_checks'] += 1
    if self._check_vpc_flow_logs(cluster_details):
        results['passed_checks'].append({
            'check': 'VPC Flow Logs',
            'status': 'PASSED'
        })
        results['passed_checks_count'] += 1
    else:
        results['failed_checks'].append({
            'check': 'VPC Flow Logs',
            'status': 'FAILED'
        })
        results['recommendations'].append({
            'category': 'Network Security',
            'title': 'Enable VPC Flow Logs',
            'description': 'VPC Flow Logs not enabled for the cluster VPC',
            'impact': 'Limited network traffic visibility',
            'priority': 'Medium',
            'action_items': [
                'Enable VPC Flow Logs for the cluster VPC',
                'Configure logs to be sent to CloudWatch Logs',
                'Set up log retention policy',
                'Create CloudWatch alarms for suspicious traffic'
            ],
            'reference': 'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html',
            'reasoning': 'VPC Flow Logs provide visibility into network traffic that can help identify security issues.'
        })
    
    # Existing code...
```

## References

- [HardenEKS GitHub Repository](https://github.com/aws-samples/hardeneks)
- [HardenEKS Blog Post](https://aws.amazon.com/blogs/containers/hardeneks-validating-best-practices-for-amazon-eks-clusters-programmatically/)
- [EKS Best Practices Guide](https://aws.github.io/aws-eks-best-practices/)