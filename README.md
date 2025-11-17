# AgentK8s - EKS Operational Review Agent - Automated Kubernetes Cluster Analysis and Reporting

## 🚀 Overview

The EKS Operational Review Agent is a comprehensive analysis tool that automates the assessment of Amazon EKS (Elastic Kubernetes Service) clusters. It provides detailed insights into cluster configuration, security posture, cost optimization opportunities, and operational best practices through an interactive web interface and generates actionable reports.


## 📁 Directory Structure

```
AgentK8snew/
├── main.py                 # Application entry point
├── requirements.txt        # Dependencies
├── README.md              # This file
├── core/                  # Core functionality
│   ├── config.py          # Configuration management
│   ├── aws_client.py      # AWS client management
│   └── analyzers.py       # Health and security analyzers
├── ui/                    # User interface
│   ├── streamlit_app.py   # Main Streamlit application
│   └── components.py      # Reusable UI components
├── utils/                 # Utilities
│   └── report_generator.py # Report generation
├── agents/                # Multi-agent framework (future)
├── config/                # Configuration files
├── tests/                 # Test files
├── docs/                  # Documentation
└── infrastructure/        # IaC templates
```

## 🔧 Features Preserved

### ✅ Current Working Features
- **AWS Authentication**: IAM Role and Access Key support
- **Cluster Analysis**: Comprehensive health analysis
- **Security Analysis**: HardenEKS-style security checks
- **Network Analysis**: VPC, subnet, and endpoint analysis
- **Node Analysis**: Node group status and configuration
- **Addon Analysis**: EKS addon health monitoring
- **Streamlit UI**: Clean, organized interface with tabs
- **Real Data**: All data fetched from actual AWS APIs

### 🚀 Enhanced Architecture
- **Modular Design**: Clean separation of concerns
- **Type Hints**: Full type annotation for better code quality
- **Error Handling**: Comprehensive error handling
- **Configuration**: Centralized configuration management
- **Extensible**: Ready for multi-agent framework integration

## 🚀 Quick Start (Windows)

### Prerequisites
- Python 3.8 or higher
- AWS CLI configured or AWS credentials
- Access to your EKS cluster

### 1. Deploy Application

**Option A: Simple Start (Recommended)**
```cmd
run.bat
```

**Option B: Clean Start**
```cmd
start_clean.bat
```

**Option C: Manual Start**
```cmd
pip install -r requirements.txt
streamlit run main.py
```

### 2. Configure Environment (Optional)
Create `.env` file from template:
```cmd
copy .env.template .env
```
Edit `.env` with your AWS settings.

### 3. Access Application
1. Open http://localhost:8501 in your browser
2. Configure AWS credentials in the sidebar:
   - **AWS Region**: Your EKS cluster region (e.g., us-west-2)
   - **Cluster Name**: Your EKS cluster name (exact spelling)
   - **Auth Method**: Choose IAM Role, Access Keys, or AWS Profile
3. Click "🔍 Test AWS Connection" to verify your setup
4. If test passes, click "🚀 Generate Analysis Report"

### 4. Troubleshooting
If the analysis gets stuck or fails:

**Run AWS Diagnostics:**
```cmd
python diagnose_aws.py
```

**Common Issues:**
- **Credentials**: Ensure AWS credentials are configured
- **Permissions**: Check IAM permissions (see Required AWS Permissions below)
- **Cluster Name**: Verify exact cluster name spelling
- **Region**: Ensure correct AWS region
- **Network**: Check internet connectivity to AWS APIs

## 🔐 AWS Authentication Setup

### Option 1: AWS Profile (Recommended)
```cmd
aws configure
```
Then use profile name in the application.

### Option 2: IAM Role (Production)
```
IAM Role ARN: arn:aws:iam::123456789012:role/AgentK8sRole
```

### Option 3: Access Keys (Development)
```
AWS Access Key ID: AKIA...
AWS Secret Access Key: ...
```

### Required AWS Permissions
Your AWS credentials need the following permissions:
- `eks:DescribeCluster`
- `eks:ListClusters` 
- `eks:DescribeNodegroup`
- `eks:ListNodegroups`
- `eks:DescribeAddon`
- `eks:ListAddons`
- `ec2:DescribeVpcs`
- `ec2:DescribeSubnets`
- `ec2:DescribeSecurityGroups`
- `iam:GetRole`
- `logs:DescribeLogGroups`

## 📊 Analysis Features

### Health Analysis
- Cluster status and configuration
- Network topology and IP utilization
- Node group analysis
- Addon health monitoring

### Security Analysis
- Encryption at rest validation
- Control plane logging checks
- API endpoint security
- Network security assessment
- RBAC configuration review

### Recommendations
- Automated remediation suggestions
- AWS CLI commands for fixes
- Priority-based recommendations
- Security best practices

## 🔄 Migration from Old Version

This implementation maintains **100% backward compatibility** with existing features while providing:

1. **Cleaner Code Structure**: Organized modules and clear separation
2. **Better Error Handling**: Comprehensive error management
3. **Type Safety**: Full type annotations
4. **Extensibility**: Ready for multi-agent framework
5. **Maintainability**: Easier to understand and modify

## 🤖 Multi-Agent Framework Ready

The architecture is designed to easily integrate the multi-agent framework:

- **Core Module**: Contains base analyzers that agents will extend
- **Agents Directory**: Ready for agent implementations
- **Configuration**: Supports multi-agent settings
- **UI**: Extensible for agent-specific features

## 🧪 Testing

```bash
# Run tests (when implemented)
pytest tests/

# Code formatting
black .

# Linting
flake8 .
```

## 🔧 Configuration

Environment variables:
```bash
export AWS_DEFAULT_REGION=us-west-2
export DEBUG=false
export ENABLE_MULTI_AGENT=false
```

## 📞 Support

This clean implementation provides:
- ✅ Implement agent-based architecture
- ✅ Improved code organization
- ✅ Better error handling
- ✅ Type safety
- ✅ Multi-agent framework foundation
- ✅ more HardenEKS checks
- ✅ CIS, NIST, PCI DSS validation


Ready for immediate use and future enhancements!
