# AgentK8s - The Ultimate Elastic Kubernetes Service Analyzer with AI Assistant

**Built by Pravinkumar Menghani & Qais Poonawala**

AgentK8s is a comprehensive analysis tool that automates the assessment of Amazon EKS (Elastic Kubernetes Service) clusters. It provides detailed insights into cluster configuration, security posture, cost optimization opportunities, and operational best practices through an interactive web interface with AI-powered recommendations.

## 🚀 **Quick Start**

### Windows Quick Start (Fully Tested & Working)

**One-command setup for Windows users:**
```cmd
quick-start.bat
```

This will:
- ✅ Install all prerequisites (kubectl, AWS CLI)
- ✅ Help configure AWS credentials
- ✅ Start AgentK8s Application
- ✅ Open at http://localhost:8501

**Note**: You need an existing EKS cluster to analyze

### Linux/Mac Setup

1. **Install Dependencies**:
```bash
pip install -r requirements.txt
```

2. **Configure AWS Credentials**:
```bash
aws configure
# OR set environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-west-2
```

3. **Run the Application**:
```bash
streamlit run app_ultimate_with_chatbot.py
```

## Key Features

### Real-time Cluster Gap Analysis
- **Actual State Checking**: Queries your live EKS cluster configuration via AWS APIs
- **Gap Identification**: Compares current state against security best practices
- **Actionable Recommendations**: Provides specific remediation steps only for identified issues
- **Priority-based Findings**: Categorizes issues by High/Medium/Low security impact

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

### Enhanced Knowledge Base Integration
- **Gap Analysis Approach**: Compares actual cluster state with best practices
- **Cluster-Specific Insights**: Only shows recommendations for actual issues in your cluster
- **Fast Analysis**: No unnecessary knowledge base queries for generic advice
- **Structured Output**: Clean, actionable recommendations with priority levels

## What's New in Gap Analysis

### Before (Generic Approach):
- Provided generic EKS best practices regardless of cluster state
- Made 25+ knowledge base queries for every analysis
- Returned wall-of-text responses with theoretical advice

### Now (Gap Analysis Approach):
- **Checks actual cluster configuration** (encryption, logging, IRSA, etc.)
- **Identifies specific gaps** in YOUR cluster only
- **Provides targeted recommendations** for actual issues found
- **Fast execution** with no unnecessary API calls

### Example Output:
```
Security Gap Analysis

Secrets Encryption
**Status**: Gap Identified
**Current State**: Disabled
**Priority**: High
**Recommendation**: Enable envelope encryption with AWS KMS
**Details**: Encryption config: []

IRSA Configuration
**Status**: Gap Identified
**Current State**: Not configured
**Priority**: High
**Recommendation**: Configure IAM OIDC identity provider for service account roles
**Details**: OIDC issuer: Not configured
```

## Prerequisites

### Windows Users (Recommended Setup)
- **Windows 10/11** ✅ Tested and verified
- **Python 3.8+** (tested with 3.13.3)
- **AWS Account** with EKS cluster access
- **Administrator privileges** for initial setup

### Windows Setup Instructions

#### Step 1: Prerequisites
```cmd
# Run the setup script (installs kubectl, AWS CLI if needed)
setup-prerequisites.bat
```

#### Step 2: AWS Configuration
```cmd
# Configure your AWS credentials
aws configure

# Test the configuration
aws sts get-caller-identity
aws eks list-clusters --region us-west-2
```

#### Step 3: Start Application
```cmd
# Start the EKS Operations Review application
start_app.bat
```

#### Step 4: Configure in Browser
1. Open http://localhost:8501
2. Enter your AWS credentials in the sidebar
3. Select your AWS region
4. Enter your existing EKS cluster name
5. Click "Generate Report"

### General Requirements
- Python 3.8 or higher
- AWS Account with EKS cluster access
- AWS CLI configured with appropriate permissions
- Valid AWS credentials with EKS cluster access permissions
- For Bedrock Agent functionality:
  - Access to Amazon Bedrock service
  - IAM permissions for Bedrock, Bedrock Agent, and Bedrock Agent Runtime
  - S3 bucket for knowledge base storage (optional - gap analysis works without KB)
- For Security Hub integration:
  - Security Hub enabled in your AWS account
  - Appropriate permissions for Security Hub API calls

## Production Deployment

### Windows Production Deployment

1. **Docker Deployment** (Recommended):
```cmd
deploy_docker.bat
```

2. **Manual Production Setup**:
```cmd
# Create production environment
python -m venv prod_env
prod_env\Scripts\activate
pip install -r requirements.txt

# Set environment variables
set AWS_ACCESS_KEY_ID=your_access_key
set AWS_SECRET_ACCESS_KEY=your_secret_key
set AWS_DEFAULT_REGION=us-west-2
set STREAMLIT_SERVER_PORT=8501

# Run application
streamlit run app_ultimate_with_chatbot.py --server.port=8501 --server.address=0.0.0.0
```

### Linux/Mac Production Deployment

1. **Docker Deployment**:
```bash
docker build -t eks-review-agent .
docker run -p 8501:8501 --env-file .env eks-review-agent
```

2. **Manual Production Setup**:
```bash
# Create production environment
python -m venv prod_env
source prod_env/bin/activate
pip install -r requirements.txt

# Set environment variables
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-west-2
export STREAMLIT_SERVER_PORT=8501

# Run application
streamlit run app_ultimate_with_chatbot.py --server.port=8501 --server.address=0.0.0.0
```

### Environment Variables
```cmd
# Windows
set AWS_ACCESS_KEY_ID=your_access_key
set AWS_SECRET_ACCESS_KEY=your_secret_key
set AWS_DEFAULT_REGION=us-west-2
set BEDROCK_KNOWLEDGE_BASE_ID=your_kb_id
set LOG_LEVEL=INFO
set STREAMLIT_SERVER_PORT=8501
```

```bash
# Linux/Mac
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-west-2
export BEDROCK_KNOWLEDGE_BASE_ID=your_kb_id
export LOG_LEVEL=INFO
export STREAMLIT_SERVER_PORT=8501
```

### Docker Deployment
Use the provided `deploy_docker.bat` script or run manually:
```cmd
docker build -t eks-review-agent .
docker run -p 8501:8501 --env-file .env eks-review-agent
```

### Security Considerations
- Use IAM roles instead of access keys in production
- Enable VPC endpoints for AWS API calls
- Implement proper logging and monitoring
- Regular security updates and dependency scanning

## Cleanup & Cost Management
**Important**: Test clusters can cost ~$174/month. Always clean up when done:

```cmd
# Windows - Complete cleanup
cleanup.bat

# Manual cleanup of AWS resources
# Delete EKS clusters, EC2 instances, Load Balancers via AWS Console or CLI
```

## Key Analysis Features

### Real-time Cluster Analysis
- **10 Comprehensive Tabs**: Analysis Dashboard, Cluster Analysis, HardenEKS, Unified Analysis, Monitoring, Remediation, Compliance, History, Comparison, AI Assistant
- **Interactive AI Assistant**: Natural language queries about your cluster with contextual responses
- **Executive PDF Reports**: Professional reports with AWS CLI commands and prioritized action plans
- **Real-time Error Handling**: Intelligent error detection and resolution guidance for kubeconfig and access issues

### Enhanced User Experience
- **Analysis Depth Options**: Choose between Comprehensive (5 min), Quick (2 min), or Security Focus (3 min) analysis modes
- **Progress Tracking**: Real-time progress indicators during analysis execution
- **Dynamic Commands**: AWS CLI commands automatically generated with your cluster name and region
- **Error Recovery**: Automatic detection and guidance for common configuration issues

### HardenEKS Security Validation
- Over 30 security checks across 7 categories
- Quantitative security score (0-100%)
- Prioritized findings (High/Medium/Low)
- Specific remediation guidance

### Compliance Validation
- CIS Amazon EKS Benchmark
- NIST SP 800-53 controls
- PCI DSS requirements
- Automated compliance scoring

## Troubleshooting

### Common Issues

1. **AWS Authentication Errors**:
```bash
aws sts get-caller-identity  # Verify credentials
aws eks list-clusters --region your-region  # Test EKS access
```

2. **Knowledge Base Access Issues**:
- Ensure Bedrock service is available in your region
- Verify IAM permissions for Bedrock Agent Runtime
- Check knowledge base ID is correct

3. **Cluster Access Issues**:
- Verify EKS cluster exists and is accessible
- Check IAM permissions for EKS describe operations
- Ensure cluster name is correct

4. **Application Startup Issues**:
- Check that all dependencies are installed
- Verify that Streamlit is installed
- Check for Python version compatibility

### Windows-Specific Troubleshooting

1. **"Command not found" errors**
```cmd
# Restart command prompt after installing tools
# Or add tools to PATH manually
```

2. **EKS cluster access denied**
```cmd
# Verify cluster exists
aws eks list-clusters --region your-region

# Check IAM permissions for EKS describe operations
```

3. **Python/pip not found**
```cmd
# Install Python from: https://python.org
# Make sure to check "Add to PATH" during installation
```

## Repository Structure
```
.
├── app_ultimate_with_chatbot.py      # Main application entry point
├── chatbot_interface.py              # Chatbot implementation
├── comprehensive_health_analyzer.py  # Health analyzer
├── deep_cluster_inspector.py         # Cluster inspector
├── k8s_inspector.py                  # Kubernetes inspector
├── security_domain_analyzer.py       # Security analyzer
├── comprehensive_pdf_generator.py    # PDF generator
├── operational_analyzers.py          # Operational analyzers
├── requirements.txt                  # Project dependencies
├── README.md                         # Main documentation
├── SECURITY_FIXES_SUMMARY.md         # Security fixes documentation
├── VULNERABILITY_FIXES_COMPLETE.md   # Vulnerability fixes report
├── docs/                             # Documentation directory
│   ├── INSTALLATION.md               # Installation guide
│   ├── USER_GUIDE.md                 # User guide
│   ├── FEATURE_GUIDE.md              # Feature documentation
│   └── HARDENEKS_INTEGRATION.md      # HardenEKS integration guide
├── src/                              # Source code directory
│   ├── analyzers/                    # Analysis modules
│   ├── compliance/                   # Compliance framework validation
│   ├── comparison/                   # Multi-cluster comparison
│   ├── config/                       # Configuration files
│   ├── history/                      # Historical trend analysis
│   ├── mcp/                          # Model Context Protocol implementation
│   ├── monitoring/                   # Real-time monitoring
│   ├── remediation/                  # Automated remediation
│   ├── security_hub/                 # AWS Security Hub integration
│   └── utils/                        # Utility functions
└── tests/                            # Test suite directory
```

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

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
