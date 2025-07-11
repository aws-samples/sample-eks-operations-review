# EKS Operational Review Agent - Automated Kubernetes Cluster Analysis and Reporting

The EKS Operational Review Agent is a comprehensive analysis tool that automates the assessment of Amazon EKS (Elastic Kubernetes Service) clusters. It provides detailed insights into cluster configuration, security posture, cost optimization opportunities, and operational best practices through an interactive web interface and generates actionable reports.

## Key Features

### HardenEKS Integration
- Custom implementation of HardenEKS security checks
- Security score based on passed/failed checks
- Detailed recommendations for addressing security issues
- Prioritized findings based on security impact

### Real-time Cluster Monitoring
- Background monitoring thread that runs periodic scans
- Configurable monitoring interval
- Historical tracking of security posture
- Trend analysis to identify improvements or regressions

### Automated Remediation
- CloudFormation templates for infrastructure changes
- EKS API calls for cluster configuration
- Kubernetes manifests for workload security
- Customizable remediation templates

### Compliance Framework Validation
- CIS Benchmarks for EKS
- NIST SP 800-53 controls
- PCI DSS requirements
- Compliance scoring and reporting

### Historical Trend Analysis
- Historical storage of scan results
- Trend visualization with charts
- Comparison between scans
- Progress tracking for remediation efforts

### Multi-cluster Comparison
- Side-by-side comparison of security scores
- Identification of common issues
- Detailed differences between clusters
- Best practice sharing across clusters

### AWS Security Hub Integration
- Automatic sending of findings to Security Hub
- Severity mapping based on priority
- Tracking of finding status
- Integration with AWS security services

### Model Context Protocol (MCP) Integration
- Structured representation of EKS cluster configuration
- Standardized recommendation format with explicit reasoning
- Enhanced context for better LLM understanding and reasoning
- Improved explainability of recommendations

### Amazon Bedrock Agent Integration
- Answer questions about EKS best practices
- Provide context-aware recommendations based on your cluster configuration
- Reference knowledge bases containing EKS documentation and best practices
- Assist with interpreting analysis results and suggesting remediation steps

## Repository Structure
```
.
├── app.py                      # Main Streamlit application entry point
├── bedrock_agent.py           # Amazon Bedrock Agent implementation
├── security_audit.py          # Security audit script
├── requirements.txt           # Project dependencies
├── README.md                  # Main documentation
├── SECURITY_FIXES_SUMMARY.md  # Security fixes documentation
├── VULNERABILITY_FIXES_COMPLETE.md # Vulnerability fixes report
├── docs/                      # Documentation directory
│   ├── INSTALLATION.md       # Installation guide
│   ├── USER_GUIDE.md         # User guide
│   ├── FEATURE_GUIDE.md      # Feature documentation
│   └── HARDENEKS_INTEGRATION.md # HardenEKS integration guide
├── src/                      # Source code directory
│   ├── analyzers/           # Analysis modules
│   │   ├── best_practices_analyzer.py    # Core analysis logic
│   │   ├── cluster_analyzer.py          # Cluster analysis with admin permissions
│   │   ├── cost_analyzer.py             # Cost optimization analysis
│   │   ├── hardeneks_analyzer.py        # HardenEKS security checks
│   │   └── security_analyzer.py         # Security configuration analysis
│   ├── compliance/          # Compliance framework validation
│   │   ├── compliance_manager.py        # Compliance validation logic
│   │   └── frameworks/                  # Compliance framework definitions
│   ├── comparison/          # Multi-cluster comparison
│   │   └── cluster_comparison.py        # Cluster comparison logic
│   ├── config/              # Configuration files
│   │   ├── constants.py     # System constants and form structure
│   │   ├── default_values.py # Default configuration values
│   │   └── security_config.py # Security configuration utilities
│   ├── history/             # Historical trend analysis
│   │   └── history_manager.py           # History tracking logic
│   ├── mcp/                 # Model Context Protocol implementation
│   │   ├── schemas.py       # JSON schemas for structured context
│   │   ├── context_processor.py # MCP context processing utilities
│   │   └── README.md        # MCP module documentation
│   ├── monitoring/          # Real-time cluster monitoring
│   │   └── cluster_monitor.py           # Monitoring logic
│   ├── remediation/         # Automated remediation
│   │   ├── remediation_manager.py       # Remediation logic
│   │   ├── remediation_manager_secure.py # Secure remediation manager
│   │   └── templates/                   # Remediation templates
│   ├── security_hub/        # AWS Security Hub integration
│   │   └── security_hub_integration.py  # Security Hub integration logic
│   └── utils/               # Utility functions
│       ├── aws_utils.py     # AWS service interaction helpers
│       ├── csv_generator.py # CSV report generation
│       ├── kubernetes_client.py # Kubernetes client
│       ├── kubernetes_client_secure.py # Secure Kubernetes client
│       ├── pdf_report_generator.py # PDF report generation
│       ├── report_generator.py # Report generation
│       └── simple_report_generator.py # Simple report generator
├── tests/                   # Test suite directory
│   ├── test_analyzers.py    # Analyzer component tests
│   └── test_utils.py        # Utility function tests
└── reports/                 # Generated reports directory
```

## Usage Instructions

### Prerequisites
- Python 3.6 or higher
- AWS Account with EKS cluster access
- AWS CLI configured with appropriate permissions
- Valid AWS credentials with EKS cluster access permissions
- For Bedrock Agent functionality:
  - Access to Amazon Bedrock service
  - IAM permissions for Bedrock, Bedrock Agent, and Bedrock Agent Runtime
  - S3 bucket for knowledge base storage
- For Security Hub integration:
  - Security Hub enabled in your AWS account
  - Appropriate permissions for Security Hub API calls

Required Python packages:
```
streamlit>=1.29.0
boto3>=1.34.0
requests>=2.32.0
beautifulsoup4>=4.12.3
python-dotenv>=1.0.1
plotly>=5.19.0
reportlab>=4.2.0
urllib3>=2.2.0
chardet>=5.2.0
charset-normalizer>=3.3.0
PyMuPDF>=1.24.0
matplotlib>=3.8.0
pandas>=2.2.0
pyyaml>=6.0.1
kubernetes>=29.0.0
botocore>=1.34.0
```

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd eks-operational-review-agent
```

2. Create and activate a virtual environment:
```bash
# MacOS/Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
.\venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Quick Start
1. Start the Streamlit application:
```bash
streamlit run app.py
```

2. Configure AWS credentials in the sidebar:
   - Enter AWS Access Key
   - Enter AWS Secret Key
   - Select AWS Region
   - Enter EKS Cluster Name
   - Enter Knowledge Base ID (if using Bedrock Agent functionality)

3. Navigate through the tabs to access different features:
   - **Analysis**: Fill in the cluster information forms and analyze the cluster
   - **Cluster Analysis**: Comprehensive cluster analysis with admin permissions
   - **HardenEKS**: Run HardenEKS security analysis
   - **Monitoring**: Start real-time monitoring of the cluster
   - **Remediation**: View and apply automated remediation actions
   - **Compliance**: Validate the cluster against compliance frameworks
   - **History**: View historical security posture and trends
   - **Comparison**: Compare multiple clusters

4. Click "Generate Report" in the Analysis tab to analyze the cluster and generate reports

### Step-by-Step Usage Guide

#### 1. Analysis Tab

1. Fill in the cluster information forms with details about your EKS cluster
2. Click "Analyze" for specific sections to get AI-powered insights
3. Click "Generate Report" to perform a comprehensive analysis
4. View the summary of findings, including HardenEKS score
5. Download the PDF report and CSV action items

#### 2. Monitoring Tab

1. Click "Start Monitoring" to begin real-time monitoring of your cluster
2. The monitoring will run in the background at regular intervals
3. View the monitoring history table showing scan results over time
4. Check the security trend to see if your cluster's security is improving
5. Click "Stop Monitoring" to end the monitoring process

#### 3. Remediation Tab

1. The tool will display available remediation actions for failed security checks
2. Expand a remediation to see details about what it will fix
3. Click "Apply Remediation" to automatically fix the issue
4. The remediation will be applied using CloudFormation, EKS API, or Kubernetes manifests
5. Check the success message to confirm the remediation was applied

#### 4. Compliance Tab

1. Select a compliance framework from the dropdown (CIS, NIST, PCI DSS)
2. Click "Validate Compliance" to check your cluster against the framework
3. View your compliance score as a percentage
4. See which controls are compliant and which are non-compliant
5. Address the non-compliant controls to improve your score

#### 5. History Tab

1. View the total number of scans performed on your cluster
2. Check the trend chart showing security score and issues over time
3. Expand individual scans to see details about that point in time
4. Click "View Details" to see the full scan results
5. Compare different scans to track your progress

#### 6. Comparison Tab

1. Click "Add Current Cluster to Comparison" to add your current cluster
2. Configure and add another cluster to compare with
3. Click "Compare Clusters" to see a side-by-side comparison
4. View the comparison chart showing security scores and issues
5. See common issues affecting multiple clusters

### Using HardenEKS Security Validation

The HardenEKS analyzer performs comprehensive security checks on your EKS cluster:

1. **IAM Security**: Checks for IRSA implementation, node IAM role permissions, etc.
2. **Pod Security**: Validates Pod Security Standards, privileged containers, etc.
3. **Network Security**: Checks for network policies, private API endpoints, etc.
4. **Runtime Security**: Validates runtime security solutions
5. **Detective Controls**: Checks for audit logging, Container Insights, etc.
6. **Infrastructure Security**: Validates private subnets, security groups, etc.
7. **Data Security**: Checks for secrets encryption, EBS encryption, etc.

Each check is categorized by priority (High, Medium, Low) and includes:
- Description of the issue
- Security impact
- Specific action items to address the issue
- Reference documentation

### Using Automated Remediation

The remediation system provides automated fixes for common security issues:

1. **CloudFormation Remediation**:
   - Creates CloudFormation stacks to fix infrastructure issues
   - Example: Creating an IAM OIDC provider for IRSA

2. **EKS API Remediation**:
   - Makes direct API calls to the EKS service
   - Example: Enabling secrets encryption

3. **Kubernetes Remediation**:
   - Applies Kubernetes manifests to fix workload issues
   - Example: Installing Calico for network policies

To apply a remediation:
1. Go to the Remediation tab
2. Find the issue you want to fix
3. Click "Apply Remediation"
4. Provide any required parameters
5. Confirm the remediation

### Using Compliance Validation

The compliance validation system checks your cluster against industry standards:

1. **CIS Amazon EKS Benchmark**:
   - Security best practices specific to EKS
   - Example controls: Restrict API endpoint access, enable secrets encryption

2. **NIST SP 800-53**:
   - Federal security controls mapped to EKS
   - Example controls: Access enforcement, audit events, data protection

3. **PCI DSS**:
   - Payment card industry requirements for EKS
   - Example controls: Network segmentation, encryption, access control

To validate compliance:
1. Go to the Compliance tab
2. Select a framework
3. Click "Validate Compliance"
4. Review your compliance score and control status
5. Address non-compliant controls

### Using Historical Trend Analysis

The history system tracks your cluster's security posture over time:

1. **Scan Storage**:
   - Each scan is saved with a timestamp
   - Includes security score, passed/failed checks, and issues

2. **Trend Visualization**:
   - Charts showing security score over time
   - Issue counts by priority

3. **Scan Comparison**:
   - Compare two scans to see what changed
   - Track progress on addressing issues

To use historical analysis:
1. Go to the History tab
2. View the trend chart
3. Expand individual scans to see details
4. Click "View Details" for full scan results

### Using Multi-cluster Comparison

The comparison system allows you to compare multiple EKS clusters:

1. **Cluster Addition**:
   - Add your current cluster to the comparison
   - Add other clusters by changing the cluster name and re-adding

2. **Comparison Visualization**:
   - Charts showing security scores side by side
   - Issue counts by priority for each cluster

3. **Common Issues**:
   - Identification of issues affecting multiple clusters
   - Prioritization based on prevalence

To compare clusters:
1. Go to the Comparison tab
2. Click "Add Current Cluster to Comparison"
3. Change to another cluster and add it as well
4. Click "Compare Clusters"
5. Review the comparison results

### Using Security Hub Integration

The Security Hub integration centralizes your security findings:

1. **Finding Creation**:
   - Each failed check becomes a Security Hub finding
   - Includes severity, description, and remediation guidance

2. **Finding Management**:
   - Track finding status in Security Hub
   - Update findings as issues are resolved

3. **Integration with AWS Security**:
   - Findings appear in Security Hub dashboards
   - Can trigger EventBridge rules for automation

To use Security Hub integration:
1. Ensure Security Hub is enabled in your AWS account
2. Generate a report or start monitoring
3. Findings will automatically be sent to Security Hub
4. View and manage findings in the AWS console

### Troubleshooting

1. AWS Authentication Issues
- Problem: "Could not connect to AWS services"
- Solution:
```bash
# Verify AWS credentials
aws configure list
aws eks list-clusters --region <your-region>
```

2. Report Generation Errors
- Problem: "Error generating PDF report"
- Solution:
  - Check write permissions in the current directory
  - Verify all required fields are filled in the forms
  - Check logs for detailed error messages:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

3. Monitoring Issues
- Problem: "Monitoring not starting"
- Solution:
  - Check AWS credentials have sufficient permissions
  - Verify the cluster exists and is accessible
  - Check for errors in the application logs

4. Remediation Issues
- Problem: "Remediation failed to apply"
- Solution:
  - Check AWS permissions for the specific service (CloudFormation, EKS)
  - Verify kubectl is installed for Kubernetes remediations
  - Check for conflicts with existing resources

5. Security Hub Issues
- Problem: "Findings not appearing in Security Hub"
- Solution:
  - Verify Security Hub is enabled in your account
  - Check IAM permissions for Security Hub API calls
  - Ensure the region matches your Security Hub configuration

## Architecture

### Complete Solution Architecture

```ascii
+-----------------------------------------------------------------------------------------------------+
|                                      EKS Operational Review Agent                                    |
+-----------------------------------------------------------------------------------------------------+
|                                                                                                     |
|  +----------------+     +----------------+     +----------------+     +----------------+             |
|  |                |     |                |     |                |     |                |             |
|  |  Streamlit UI  |<--->|  AWS Services  |<--->|   Analyzers    |<--->| Report & CSV   |             |
|  |                |     |                |     |                |     |  Generators    |             |
|  +-------+--------+     +-------+--------+     +-------+--------+     +-------+--------+             |
|          ^                      ^                      ^                      ^                      |
|          |                      |                      |                      |                      |
|          v                      v                      v                      v                      |
|  +-------+--------+     +-------+--------+     +-------+--------+     +-------+--------+             |
|  |                |     |                |     |                |     |                |             |
|  | User Interface |     |  EKS Cluster   |     | MCP Context    |     | PDF/CSV Reports|             |
|  |                |     |  Configuration |     | Processor      |     |                |             |
|  +-------+--------+     +-------+--------+     +-------+--------+     +----------------+             |
|          ^                      |                      ^                                             |
|          |                      |                      |                                             |
|          |                      v                      |                                             |
|  +-------+--------------------+-------------------------+-------------+                              |
|  |                                                                    |                              |
|  |                        Amazon Bedrock Agent                        |                              |
|  |                                                                    |                              |
|  |  +----------------+     +----------------+     +----------------+  |                              |
|  |  |                |     |                |     |                |  |                              |
|  |  | Knowledge Base |<--->| Claude 3 Model |<--->| AI-Powered     |  |                              |
|  |  | (Vector Store) |     |                |     | Recommendations |  |                              |
|  |  +----------------+     +----------------+     +----------------+  |                              |
|  |                                                                    |                              |
|  +--------------------------------------------------------------------+                              |
|                                                                                                     |
+-----------------------------------------------------------------------------------------------------+
```

### Enhanced Architecture with New Components

```ascii
+-----------------------------------------------------------------------------------------------------+
|                                      EKS Operational Review Agent                                    |
+-----------------------------------------------------------------------------------------------------+
|                                                                                                     |
|  +----------------+     +----------------+     +----------------+     +----------------+             |
|  |                |     |                |     |                |     |                |             |
|  |  Streamlit UI  |<--->|  AWS Services  |<--->|   Analyzers    |<--->| Report & CSV   |             |
|  |                |     |                |     |                |     |  Generators    |             |
|  +-------+--------+     +-------+--------+     +-------+--------+     +-------+--------+             |
|          ^                      ^                      ^                      ^                      |
|          |                      |                      |                      |                      |
|          v                      v                      v                      v                      |
|  +-------+--------+     +-------+--------+     +-------+--------+     +-------+--------+             |
|  |                |     |                |     |                |     |                |             |
|  | User Interface |     |  EKS Cluster   |     | HardenEKS      |     | PDF/CSV Reports|             |
|  | (Tabbed UI)    |     |  Configuration |     | Analyzer       |     |                |             |
|  +-------+--------+     +-------+--------+     +-------+--------+     +----------------+             |
|          ^                      |                      ^                                             |
|          |                      |                      |                                             |
|          |                      v                      |                                             |
|  +-------+--------+     +-------+--------+     +-------+--------+     +----------------+             |
|  |                |     |                |     |                |     |                |             |
|  | Monitoring     |     | Remediation    |     | Compliance     |     | History &      |             |
|  | System         |     | Manager        |     | Manager        |     | Comparison     |             |
|  +-------+--------+     +-------+--------+     +-------+--------+     +-------+--------+             |
|          ^                      ^                      ^                      ^                      |
|          |                      |                      |                      |                      |
|          v                      v                      v                      v                      |
|  +-------+--------------------+-------------------------+-------------------+--------------------+    |
|  |                                                                                              |    |
|  |                                  AWS Security Hub                                            |    |
|  |                                                                                              |    |
|  +----------------------------------------------------------------------------------------------+    |
|                                                                                                     |
+-----------------------------------------------------------------------------------------------------+
```

### Data Flow with Enhanced Components

```ascii
                                                +----------------+
                                                | Amazon Bedrock |
                                                |    Agent       |
                                                +-------+--------+
                                                        |
                                                        v
[AWS EKS Cluster] -> [AWS Utils] -> [Analyzers] -> [MCP Context] -> [AI Insights]
     |                   |              |               |                |
     v                   v              v               v                v
  Raw Data         Cluster Details   Analysis     Structured Context  Recommendations
     |                   |              |               |                |
     |                   |              v               |                |
     |                   |        [HardenEKS]           |                |
     |                   |              |               |                |
     |                   |              v               |                |
     |                   |        [Security Score]      |                |
     |                   |              |               |                |
     v                   v              v               v                v
[Monitoring] -> [Remediation] -> [Compliance] -> [History] -> [Comparison]
     |                   |              |               |                |
     v                   v              v               v                v
Real-time Scans    Auto-fixes    Framework Validation  Trends      Multi-cluster
     |                   |              |               |                |
     v                   v              v               v                v
                   [Report Generators]--+---------------+----------------+
                        |
                        v
                   PDF/CSV Reports
                        |
                        v
                [Security Hub]
```

## Security

This project has undergone comprehensive security hardening:

- **260+ security vulnerabilities fixed** across all severity levels
- **Input validation and sanitization** implemented throughout
- **Path traversal protection** for file operations
- **Log injection prevention** with input sanitization
- **Secure credential handling** using environment variables
- **Resource limits** to prevent DoS attacks
- **Secure subprocess execution** with parameter sanitization

For detailed information about security fixes, see:
- [SECURITY_FIXES_SUMMARY.md](SECURITY_FIXES_SUMMARY.md)
- [VULNERABILITY_FIXES_COMPLETE.md](VULNERABILITY_FIXES_COMPLETE.md)

## Contributing

We welcome contributions to the EKS Operational Review Agent! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

