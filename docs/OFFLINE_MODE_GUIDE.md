HardenEKS# EKS Operations Review Tool - Offline Mode Guide

## Overview

The EKS Operations Review Tool now supports **Offline Mode**, enabling analysis of EKS clusters without requiring direct AWS connectivity. This feature is particularly useful for:

- Air-gapped environments
- Historical data analysis
- Compliance audits with specific point-in-time data
- Situations where direct AWS access is restricted

## How It Works

### 1. Data Collection (offline_fetch.py)

The `offline_fetch.py` script collects comprehensive EKS cluster data and stores it in a JSON file:

**Key Data Collected:**
- **AWS Account Information:** Account ID, regions, basic metadata
- **Cluster Details:** Configuration, encryption, logging, platform version
- **Network Information:** VPC, subnets, security groups, route tables, NAT gateways
- **Node Groups:** Scaling configuration, instance types, AMI details
- **Add-ons:** Status, versions, configurations
- **Kubernetes Resources:** Pods, services, deployments, RBAC, network policies
- **Security Data:** IAM roles, OIDC providers, security group rules
- **Infrastructure:** EC2 instances, load balancers, EBS volumes

**Usage:**
```bash
python offline_fetch.py
# Follow prompts to enter:
# - EKS cluster name
# - AWS region
```

**Output:**
- JSON file: `eks_offline_data_{cluster_name}_{timestamp}.json`
- Comprehensive data ready for offline analysis

### 2. Offline Analysis Engine

The `OfflineAnalyzer` class processes the collected JSON data through the same analysis pipeline as online mode:

**Analysis Capabilities:**
- **Health Analysis:** Cluster status, network configuration, addon health
- **Security Analysis:** Encryption, logging, endpoint access, RBAC
- **HardenEKS Analysis:** Comprehensive 39-check security assessment across 10 categories
- **Compliance Mapping:** CIS EKS, NIST CSF, SOC2 framework alignment with scoring
- **Network Security:** Security group analysis, IP utilization, endpoint security
- **Node Analysis:** Scaling configuration, security posture, instance security

### 3. Web Interface Integration

The Streamlit application now includes:
- **Mode Selection:** Toggle between Online and Offline modes
- **File Upload:** Drag-and-drop JSON import with validation
- **Data Validation:** Ensures uploaded JSON has required structure
- **Analysis Pipeline:** Same UI and reporting as online mode

## Data Coverage Comparison

### ✅ Complete Coverage (Same as Online)

| Category | Offline Script | Online Tool | Status |
|----------|----------------|-------------|--------|
| Cluster Configuration | ✅ | ✅ | **Complete** |
| Encryption Settings | ✅ | ✅ | **Complete** |
| Logging Configuration | ✅ | ✅ | **Complete** |
| Network Configuration | ✅ | ✅ | **Complete** |
| Node Group Details | ✅ | ✅ | **Complete** |
| Add-on Management | ✅ | ✅ | **Complete** |
| Security Groups | ✅ | ✅ | **Complete** |
| VPC/Subnet Analysis | ✅ | ✅ | **Complete** |
| RBAC Resources | ✅ | ✅ | **Complete** |
| Pod Security Analysis | ✅ | ✅ | **Complete** |

### 🔶 Limited Coverage (Static Analysis Only)

| Category | Limitation | Recommendation |
|----------|------------|----------------|
| Real-time Metrics | No live CPU/memory data | Use CloudWatch exports |
| GuardDuty Findings | Snapshot only | Include recent findings in script |
| Security Hub Data | Point-in-time | Export findings separately |
| Cost Analysis | No current pricing | Use AWS Cost Explorer exports |

## Usage Instructions

### Step 1: Collect Offline Data

1. **Prerequisites:**
   ```bash
   # Ensure AWS CLI is configured
   aws configure list
   
   # Ensure kubectl access
   kubectl cluster-info
   ```

2. **Run Data Collection:**
   ```bash
   python offline_fetch.py
   ```

3. **Verify Output:**
   ```bash
   # Check generated file
   ls -la eks_offline_data_*.json
   
   # Verify file size (should be several MB)
   du -h eks_offline_data_*.json
   ```

### Step 2: Use Offline Mode

1. **Launch Application:**
   ```bash
   streamlit run ui/streamlit_app.py
   ```

2. **Select Offline Mode:**
   - Choose "📁 Offline Mode" in the sidebar
   - Upload your JSON file using the file uploader
   - Verify data summary shows correct cluster information

3. **Run Analysis:**
   - Click "🚀 Generate Analysis Report"
   - Review results in the dashboard tabs
   - Generate PDF reports as needed

### Step 3: Generate Reports

The offline mode supports the same reporting capabilities:
- **PDF Reports:** Complete analysis documentation
- **JSON Export:** Raw analysis data for further processing
- **Security Findings:** Detailed security assessment
- **Recommendations:** Actionable improvement suggestions

## File Structure

```
eks_offline_data_example_20231120_140500.json
├── metadata/
│   ├── cluster_name: "my-eks-cluster"
│   ├── region: "us-west-2"
│   ├── collection_timestamp: "2023-11-20T14:05:00"
│   └── script_version: "2.0-comprehensive"
├── aws_account/
├── cluster_info/
├── k8s_data/
├── network_info/
├── infrastructure_info/
└── security_info/
```

## Validation and Quality Assurance

### Data Validation
- **Required Sections:** Validates presence of all critical data sections
- **Metadata Verification:** Ensures cluster name and region are present
- **Structure Validation:** Confirms JSON follows expected schema

### Analysis Validation
- **Security Checks:** Same validation logic as online mode
- **Network Analysis:** Identical IP utilization and security assessments
- **Compliance Mapping:** Consistent framework alignment

## Benefits of Offline Mode

### Security Benefits
- **No AWS Credentials Required:** Analysis environment doesn't need AWS access
- **Data Sovereignty:** Complete control over where analysis occurs
- **Audit Trail:** Immutable point-in-time data snapshot

### Operational Benefits
- **Air-gap Compatibility:** Works in isolated environments
- **Historical Analysis:** Compare configurations over time
- **Consistent Results:** Same data produces identical analysis
- **Faster Analysis:** No network dependencies during analysis

### Compliance Benefits
- **Evidence Preservation:** Timestamped data collection
- **Reproducible Results:** Analysis can be re-run with same data
- **Multi-framework Support:** CIS EKS, NIST CSF, SOC2 compliance mapping

## 🆕 Latest Enhancements (November 2024)

### 🔧 **PDF Reporting Improvements**
- **✅ Fixed Cluster Name Extraction**: Offline analysis now properly displays actual cluster names in PDF reports
- **✅ Enhanced VPC Analysis**: Added comprehensive subnet utilization analysis with risk level assessment
- **✅ Network Issue Remediation**: Network security issues now include actionable AWS CLI commands
- **✅ Instance Types Formatting**: Fixed node group instance types display for proper formatting
- **✅ AWS Documentation Integration**: All recommendations include direct links to AWS documentation

### 📊 **DORA Metrics Integration**
- **✅ DevOps Performance Assessment**: Added DORA (DevOps Research and Assessment) metrics analysis
- **✅ Performance Categorization**: Elite, High, Medium, and Low performer classification
- **✅ Automation Level Assessment**: Infrastructure as Code and automation capability evaluation
- **✅ Deployment Frequency Analysis**: Auto-scaling and deployment readiness assessment
- **✅ Recovery Time Evaluation**: Monitoring setup and incident response capability analysis

### 🤖 **Multi-Agent Architecture Support**
- **✅ Enhanced Analysis Pipeline**: Offline mode now supports multi-agent analysis framework
- **✅ Cross-Agent Insights**: Unified recommendations from security, performance, and compliance agents
- **✅ Executive Summary Generation**: High-level insights suitable for leadership reporting
- **✅ Risk Correlation Analysis**: Security-performance trade-off evaluation

### 📋 **Compliance Framework Enhancements**
- **✅ CIS EKS Benchmark Integration**: Complete CIS EKS Benchmark v1.0.1 assessment
- **✅ NIST Cybersecurity Framework**: NIST CSF v1.1 compliance validation  
- **✅ SOC 2 Type II Assessment**: Trust service criteria evaluation
- **✅ Multi-Framework Gap Analysis**: Cross-framework compliance recommendations
- **✅ Prescriptive Remediation**: Step-by-step implementation guidance with business impact

## Enhanced Security Analysis Features

### HardenEKS Integration

The offline analysis now includes comprehensive **HardenEKS** security assessment, providing industry-standard security hardening recommendations aligned with AWS EKS Security Best Practices.

### Security Check Categories (39 Total Checks)

1. **Identity and Access Management (5 checks)**
   - EKS Cluster Service Role verification
   - Node Group Instance Profile validation
   - IRSA (IAM Roles for Service Accounts) configuration
   - RBAC configuration assessment
   - AWS Auth ConfigMap security review

2. **Pod Security (5 checks)**
   - Pod Security Standards implementation
   - Security Context configuration
   - Resource limits and requests
   - Admission controllers validation
   - Privileged container detection

3. **Network Security (5 checks)**
   - API Server endpoint access control
   - Security groups configuration
   - Kubernetes Network Policies
   - VPC configuration validation
   - Service mesh security assessment

4. **Multi-tenancy (4 checks)**
   - Namespace isolation verification
   - Resource quotas implementation
   - Network segmentation validation
   - Node affinity and taints configuration

5. **Detective Controls (4 checks)**
   - Control plane logging enablement
   - GuardDuty integration status
   - CloudTrail configuration
   - Runtime security monitoring

6. **Image Security (4 checks)**
   - Container image scanning
   - Image provenance verification
   - Image signing validation
   - Base image security assessment

7. **Runtime Security (3 checks)**
   - Runtime security monitoring
   - File system security
   - Process security validation

8. **Infrastructure Security (3 checks)**
   - Node security configuration
   - Infrastructure as Code practices
   - Cluster upgrade procedures

9. **Encryption (3 checks)**
   - Encryption at rest (KMS integration)
   - Encryption in transit validation
   - KMS key management practices

10. **Secrets Management (3 checks)**
    - External secrets management
    - Secret rotation policies
    - Secret access controls

### Security Scoring and Grading

The HardenEKS analysis provides comprehensive scoring:

- **Overall Security Score:** 0-100 scale with letter grade (A-F)
- **Category-specific Scores:** Individual scores for each security domain
- **Security Posture Assessment:** EXCELLENT, GOOD, FAIR, POOR, CRITICAL
- **Priority-based Recommendations:** HIGH, MEDIUM, LOW priority issues

### Compliance Framework Mapping

The analysis maps findings to multiple compliance frameworks:

| Framework | Coverage | Metrics |
|-----------|----------|---------|
| **CIS Amazon EKS Benchmark v1.0.1** | 17 applicable controls | Compliance percentage, gaps analysis |
| **NIST Cybersecurity Framework v1.1** | 20 applicable controls | Framework alignment, improvement areas |
| **SOC 2 Type II** | 12 applicable controls | Trust service criteria mapping |

### Report Output Enhancements

The enhanced security analysis provides:

- **Executive Summary:** High-level security posture overview
- **Detailed Findings:** Technical details for each failed check
- **Remediation Guidance:** Step-by-step implementation instructions
- **AWS CLI Commands:** Ready-to-execute remediation commands
- **Priority Matrix:** Risk-based implementation prioritization
- **Compliance Dashboard:** Framework-specific compliance status

### Sample Security Assessment Output

```json
{
  "hardeneks_score": {
    "overall_score": 51.2,
    "security_posture": "CRITICAL",
    "grade": "F",
    "total_checks": 39,
    "passed_checks": 5,
    "failed_checks": 3,
    "warning_checks": 31,
    "critical_issues": 2
  },
  "compliance_summary": {
    "CIS_EKS": {
      "compliance_percentage": 29.4,
      "status": "NON_COMPLIANT",
      "gaps": 12
    }
  }
}
```

### Integration Benefits

- **Consistent Assessment:** Same security standards across online and offline modes
- **Industry Alignment:** Based on AWS EKS Security Best Practices and CIS benchmarks
- **Actionable Results:** Specific remediation steps with AWS CLI commands
- **Progress Tracking:** Score improvements over time with historical analysis
- **Audit Readiness:** Compliance framework alignment for audit purposes

## Troubleshooting

### Common Issues

1. **Missing kubectl Access:**
   ```bash
   # Update kubeconfig
   aws eks update-kubeconfig --name CLUSTER_NAME --region REGION
   ```

2. **Insufficient Permissions:**
   ```bash
   # Required AWS permissions:
   # - eks:DescribeCluster
   # - eks:ListClusters
   # - eks:ListNodegroups
   # - eks:DescribeNodegroup
   # - ec2:DescribeVpcs, Subnets, SecurityGroups
   # - iam:ListRoles
   ```

3. **Large File Size:**
   ```bash
   # Compress large JSON files
   gzip eks_offline_data_*.json
   
   # Upload .gz files (supported by web interface)
   ```

4. **Incomplete Data:**
   ```bash
   # Verify script completed successfully
   tail -n 50 offline_collection.log
   
   # Re-run with verbose logging
   python offline_fetch.py --verbose
   ```

### File Size Expectations

| Cluster Size | Expected File Size | Collection Time |
|--------------|-------------------|-----------------|
| Small (1-5 nodes) | 2-5 MB | 2-3 minutes |
| Medium (6-20 nodes) | 5-15 MB | 3-5 minutes |
| Large (21+ nodes) | 15-50 MB | 5-10 minutes |

## Next Steps for Implementation

### Immediate Actions
1. **Test Integration:** Verify offline mode works end-to-end
2. **Validate PDF Generation:** Ensure reports generate correctly from offline data
3. **Performance Testing:** Test with various cluster sizes and configurations

### Future Enhancements
1. **Compression Support:** Add support for compressed JSON files
2. **Multi-cluster Analysis:** Support analyzing multiple clusters in one session
3. **Data Export Options:** Additional export formats (CSV, XML)
4. **Incremental Updates:** Merge new data with existing offline collections

### Recommended Testing Scenarios
1. **Small Development Cluster:** Basic functionality validation
2. **Production Cluster:** Full-scale data collection and analysis
3. **Security-focused Cluster:** Validate security analysis accuracy
4. **Multi-region Deployment:** Test with clusters in different regions

## Security Considerations

### Data Handling
- **Sensitive Information:** JSON may contain cluster endpoints, subnet CIDRs
- **Access Control:** Secure storage and transmission of offline data files
- **Data Retention:** Establish policies for offline data lifecycle

### Best Practices
- **Encryption at Rest:** Encrypt stored JSON files
- **Secure Transfer:** Use secure channels for moving offline data
- **Access Logging:** Log who accesses offline analysis results

## Support and Maintenance

### Regular Updates
- **Script Maintenance:** Keep offline_fetch.py synchronized with online analyzers
- **API Compatibility:** Update for new AWS EKS features and APIs
- **Security Patches:** Regular updates for security improvements

### Monitoring
- **Data Quality:** Validate completeness of offline collections
- **Analysis Accuracy:** Compare offline results with online analysis
- **Performance Metrics:** Track collection and analysis times

---

**Note:** This offline mode implementation provides comprehensive EKS cluster analysis capabilities while maintaining the same quality and depth as the online version. The approach ensures consistency, security, and usability across different deployment scenarios.
