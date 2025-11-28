# AgentK8s - EKS Operational Review Agent - Advanced Kubernetes Cluster Analysis & Reporting

## 🚀 Overview

The EKS Operational Review Agent is a comprehensive, AI-powered analysis tool that automates the assessment of Amazon EKS (Elastic Kubernetes Service) clusters. It provides detailed insights into cluster configuration, security posture, compliance status, cost optimization opportunities, and operational best practices through an interactive web interface with professional PDF reporting capabilities.

### ✨ Core Features (v2.0)
- 🔄 **Dual Mode Operation**: Online (live AWS) and Offline (pre-collected data) analysis modes
- 🤖 **Multi-Agent Architecture**: Specialized AI agents for security, performance, and compliance analysis
- 📋 **Advanced Compliance**: CIS EKS Benchmark, NIST Cybersecurity Framework, SOC 2, and EU DORA
- 📄 **Professional PDF Reports**: Enhanced reports with AWS documentation links and prescriptive guidance
- 🛡️ **HardenEKS Integration**: Comprehensive security analysis based on AWS best practices
- 🔍 **Professional Formatting**: Proper instance types display and improved data visualization
- 📊 **EU DORA Compliance**: European Union's Digital Operational Resilience Act assessment


## 📁 Directory Structure

```
AgentK8snew/
├── main.py                    # Application entry point
├── offline_cli.py             # Offline mode CLI tool
├── offline_fetch.py           # Data collection for offline mode
├── requirements.txt           # Dependencies
├── README.md                 # This file
├── core/                     # Core functionality
│   ├── config.py             # Configuration management
│   ├── aws_client.py         # AWS client management
│   ├── analyzers.py          # Health and security analyzers
│   ├── offline_analyzer.py   # Offline mode analyzers
│   ├── hardeneks_analyzer.py # HardenEKS security analysis
│   ├── enhanced_analyzers.py # Enhanced analysis capabilities
│   └── compliance_analyzer.py # Multi-framework compliance
├── ui/                       # User interface
│   ├── streamlit_app.py      # Main Streamlit application (enhanced)
│   └── components.py         # Reusable UI components
├── utils/                    # Utilities
│   ├── pdf_generator.py      # Enhanced PDF report generation
│   └── report_generator.py   # Report generation utilities
├── agents/                   # Multi-agent framework
│   ├── base_agent.py         # Base agent class
│   ├── security_agent.py     # Security intelligence agent
│   ├── performance_agent.py  # Performance optimization agent
│   ├── compliance_agent.py   # Compliance orchestration agent
│   └── multi_agent_manager.py # Multi-agent coordination
├── docs/                     # Documentation
│   └── OFFLINE_MODE_GUIDE.md # Offline mode documentation
└── infrastructure/           # IaC templates
```

## 🔧 Core Features

### ✅ **Dual Operation Modes**
- **🌐 Online Mode**: Live AWS API analysis with real-time data
- **📁 Offline Mode**: Pre-collected data analysis for air-gapped environments
- **🔄 Seamless Switching**: Easy mode selection in the UI

### ✅ **Multi-Agent Architecture**
- **🛡️ Security Intelligence Agent**: Advanced security analysis with threat intelligence
- **📊 Performance Optimization Agent**: Resource utilization and cost optimization
- **📋 Compliance Orchestration Agent**: Multi-framework compliance validation
- **🤖 Cross-Agent Insights**: Unified recommendations from multiple perspectives

### ✅ **Advanced Analysis Capabilities**
- **AWS Authentication**: IAM Role, Access Keys, and AWS Profile support
- **Cluster Health**: Comprehensive cluster status and configuration analysis
- **Security Assessment**: HardenEKS-based security checks with 100+ validations
- **Network Analysis**: VPC, subnet, endpoint, and security group analysis
- **Node Group Analysis**: Instance types, scaling, and health monitoring
- **Addon Analysis**: EKS addon health and version compliance
- **Compliance Frameworks**: CIS EKS Benchmark, NIST CSF, SOC 2 Type II

### ✅ **Professional Reporting**
- **📄 Enhanced PDF Reports**: Professional reports with AWS documentation links
- **📊 Interactive Dashboard**: Real-time charts and metrics
- **🔍 Prescriptive Guidance**: Step-by-step remediation instructions
- **📋 EU DORA Compliance**: European Union's Digital Operational Resilience Act assessment
- **💾 Multiple Formats**: PDF, JSON, and interactive web reports

### ✅ **Enhanced Architecture**
- **Modular Design**: Clean separation of concerns with extensible architecture
- **Type Safety**: Full type annotation for better code quality
- **Error Handling**: Comprehensive error handling and user feedback
- **Configuration**: Centralized configuration management
- **Offline Capability**: Air-gapped environment support with data collection tools

## 🚀 First-Time User Setup

### For Someone Trying This Application for the First Time

**Prerequisites:**
- Python 3.8+ installed
- AWS credentials configured
- EKS cluster access

**Step 1: Clone & Setup**
```bash
# Clone the repository
git clone <repository-url>
cd AgentK8snew

# Install dependencies
pip install -r requirements.txt
```

**Step 2: Run the Application**
```bash
# Start the web application
streamlit run main.py
```

**Step 3: Access & Configure**
1. Open http://localhost:8501 in your browser
2. In the sidebar, configure:
   - AWS Region (e.g., us-west-2)
   - EKS Cluster Name (exact name)
   - Authentication (IAM Role/Access Keys)
3. Click "🔍 Test AWS Connection"
4. If successful, click "🚀 Generate Analysis Report"

**That's it!** The application will analyze your EKS cluster and generate comprehensive reports.

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

## 📊 Advanced Analysis Features

### 🌐 **Online Mode Analysis**
- **Real-time AWS API Integration**: Live cluster data collection
- **Comprehensive Health Analysis**: Cluster status, network topology, and IP utilization
- **Security Assessment**: 100+ HardenEKS-based security validations
- **Node Group Analysis**: Instance types, scaling configuration, and health monitoring
- **Addon Analysis**: EKS addon health, versions, and compatibility
- **Network Security**: VPC, subnet, endpoint, and security group analysis

### 📁 **Offline Mode Analysis**
- **Air-gapped Environment Support**: Analysis without internet connectivity
- **Pre-collected Data**: Use `offline_fetch.py` to collect cluster data
- **Historical Analysis**: Analyze cluster snapshots from different time periods
- **Consistent Results**: Same analysis capabilities as online mode
- **Data Portability**: JSON-based data files for easy sharing and storage

### 🤖 **Multi-Agent Intelligence**
- **🛡️ Security Intelligence Agent**: Advanced threat detection and security posture assessment
- **📊 Performance Optimization Agent**: Resource utilization analysis and cost optimization recommendations
- **📋 Compliance Orchestration Agent**: Multi-framework compliance validation and gap analysis
- **🔗 Cross-Agent Insights**: Unified recommendations from multiple AI perspectives
- **⚡ Parallel Processing**: Simultaneous analysis across all agents for comprehensive coverage

### 📋 **Compliance Framework Assessment**
- **CIS EKS Benchmark v1.0.1**: Industry-standard security controls validation
- **NIST Cybersecurity Framework v1.1**: Federal security standards compliance
- **SOC 2 Type II**: Trust service criteria assessment
- **EU DORA**: European Union's Digital Operational Resilience Act compliance
- **Multi-Framework Gap Analysis**: Cross-framework compliance recommendations
- **Compliance Scoring**: Percentage-based compliance ratings with detailed breakdowns

### 🛡️ **Enhanced Security Analysis**
- **HardenEKS Integration**: 100+ security checks based on AWS best practices
- **Threat Intelligence**: Security posture assessment with risk scoring
- **Encryption Validation**: At-rest and in-transit encryption verification
- **Control Plane Security**: Logging, endpoint access, and API security analysis
- **Network Security Assessment**: VPC configuration and network policy validation
- **RBAC Analysis**: Role-based access control configuration review

### 📄 **Professional PDF Reports**
- **AWS Documentation Links**: Direct links to official AWS documentation
- **Prescriptive Guidance**: Step-by-step remediation instructions
- **Implementation Commands**: Ready-to-use AWS CLI commands
- **Business Impact Assessment**: Risk analysis and business justification
- **Verification Procedures**: Post-implementation validation steps
- **EU DORA Integration**: European Union's Digital Operational Resilience Act compliance assessment

### 🔍 **Actionable Recommendations**
- **Priority-Based Remediation**: Critical, High, Medium, and Low priority classifications
- **AWS CLI Commands**: Copy-paste ready implementation commands
- **Business Justification**: Risk analysis and compliance impact
- **Implementation Time Estimates**: Expected effort and complexity ratings
- **Verification Steps**: Post-implementation validation procedures
- **Cross-Agent Consensus**: Unified recommendations from multiple analysis perspectives

## 📁 **Offline Mode Usage**

For air-gapped environments or historical analysis:

### 1. **Data Collection** (with internet access)
```cmd
python offline_fetch.py --cluster-name my-eks-cluster --region us-west-2
```

### 2. **Transfer Data** (to offline environment)
Copy the generated JSON file to your offline environment.

### 3. **Offline Analysis** (without internet)
1. Launch the application: `streamlit run main.py`
2. Select "📁 Offline Mode" in the sidebar
3. Upload your JSON data file
4. Run comprehensive analysis with full capabilities

### 4. **CLI Analysis** (optional)
```cmd
python offline_cli.py --data-file eks_offline_data_cluster_20231121.json
```

## 🤖 **Multi-Agent Analysis Usage**

For comprehensive AI-powered analysis:

### 1. **Enable Multi-Agent Mode**
1. Select "🤖 Multi-Agent Analysis (7 min)" in the Analysis Depth dropdown
2. Choose which agents to enable:
   - 🛡️ Security Intelligence Agent
   - 📊 Performance Optimization Agent  
   - 📋 Compliance Orchestration Agent

### 2. **Advanced Features**
- **Cross-Agent Insights**: Unified recommendations from multiple AI perspectives
- **Risk Correlation**: Security-performance trade-off analysis
- **Compliance Gap Analysis**: Multi-framework compliance validation
- **Executive Summary**: High-level insights for leadership

### 3. **Multi-Agent Reports**
- **Comprehensive PDF**: Enhanced reports with multi-agent insights
- **Executive Dashboard**: Summary view with key metrics
- **Agent-Specific Analysis**: Detailed findings from each agent
- **Unified Recommendations**: Prioritized action items

## 🔄 Migration from Old Version

This implementation maintains **100% backward compatibility** with existing features while providing:

1. **Cleaner Code Structure**: Organized modules and clear separation
2. **Better Error Handling**: Comprehensive error management
3. **Type Safety**: Full type annotations
4. **Extensibility**: Ready for multi-agent framework
5. **Maintainability**: Easier to understand and modify
6. **Enhanced Features**: Offline mode, multi-agent analysis, DORA metrics
7. **Professional Reporting**: AWS documentation links and prescriptive guidance

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

## 🆕 **Recent Improvements (November 2024)**

### 🔧 **PDF Reporting Enhancements**
- **✅ Fixed Cluster Name Display**: Proper cluster name extraction from analysis results
- **✅ Enhanced VPC Configuration**: Added comprehensive subnet analysis with utilization metrics
- **✅ Network Issue Recommendations**: Actionable remediation steps with AWS CLI commands
- **✅ Instance Types Formatting**: Fixed display from "t, 3, ., m, e, d, i, u, m" to "t3.medium, m5.large"
- **✅ EU DORA Integration**: European Union's Digital Operational Resilience Act compliance assessment
- **✅ AWS Documentation Links**: Direct links to official documentation for each recommendation

### 📊 **UI/UX Improvements**
- **✅ Enhanced Compliance Tab**: Added EU DORA, CIS EKS Benchmark, NIST CSF, and SOC 2 assessments
- **✅ Multi-Agent Dashboard**: Specialized tabs for security, performance, and compliance agents
- **✅ Improved Data Formatting**: Consistent formatting across all tables and metrics
- **✅ Real-time Progress Updates**: Better user feedback during analysis execution
- **✅ Error Handling**: Comprehensive error messages with troubleshooting guidance

### 🛡️ **Security & Compliance**
- **✅ HardenEKS Integration**: 100+ security checks based on AWS best practices
- **✅ Multi-Framework Assessment**: CIS, NIST, SOC 2, and EU DORA compliance evaluation
- **✅ Threat Intelligence**: Advanced security posture assessment with risk scoring
- **✅ Cross-Agent Correlation**: Security-performance trade-off analysis
- **✅ Prescriptive Guidance**: Step-by-step remediation with business impact assessment

### 🤖 **Multi-Agent Intelligence**
- **✅ Security Intelligence Agent**: Advanced threat detection and security analysis
- **✅ Performance Optimization Agent**: Resource utilization and cost optimization
- **✅ Compliance Orchestration Agent**: Multi-framework compliance validation
- **✅ Executive Summary**: High-level insights for leadership and decision-making
- **✅ Unified Recommendations**: Prioritized action items from all agent perspectives

## 📞 Support & Documentation

### 📚 **Additional Resources**
- **[Offline Mode Guide](docs/OFFLINE_MODE_GUIDE.md)**: Complete guide for air-gapped environments
- **[AWS Best Practices](https://aws.github.io/aws-eks-best-practices/)**: Official AWS EKS security guidelines
- **[CIS EKS Benchmark](https://www.cisecurity.org/)**: Industry-standard security controls
- **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)**: Federal security standards

### ✅ **Implementation Status**
- ✅ **Agent-based architecture**: Multi-agent framework with specialized intelligence
- ✅ **Enhanced organization**: Modular design with clear separation of concerns
- ✅ **Comprehensive error handling**: User-friendly error messages and troubleshooting
- ✅ **Type safety**: Full type annotations for better code quality
- ✅ **Multi-framework compliance**: CIS, NIST, SOC 2, EU DORA integration
- ✅ **Professional reporting**: AWS documentation links and prescriptive guidance
- ✅ **Offline capabilities**: Air-gapped environment support with data portability

🚀 **Ready for immediate deployment and GitHub publication!**
