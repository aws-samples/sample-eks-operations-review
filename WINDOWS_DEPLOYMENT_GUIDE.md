# Windows Deployment Guide - EKS Operational Review Agent

## ✅ Verified Working Setup

This guide has been tested and verified on Windows 11 with the following configuration:
- **Python**: 3.13.3 ✅
- **AWS CLI**: 2.27.21 ✅  
- **Docker**: 28.3.2 ✅
- **EKS Cluster**: eks-opsreview (created and tested) ✅
- **Application**: Fully functional with all features working ✅

## Quick Start (Recommended - Tested & Working)

### Prerequisites ✅ Verified
- Python 3.8+ (✅ Tested with Python 3.13.3)
- AWS CLI (✅ Tested with AWS CLI 2.27.21)
- Docker (✅ Tested with Docker 28.3.2) - Optional for containerized deployment

### Option 1: Complete Setup (EKS Cluster + Application)

1. **Install prerequisites:**
   ```cmd
   setup-prerequisites.bat
   ```

2. **Configure AWS credentials:**
   ```cmd
   aws configure
   ```

3. **Create EKS cluster:**
   ```cmd
   create-eks-cluster.bat
   ```
   *This creates an optimized EKS cluster named 'eks-opsreview' (takes 15-20 minutes)*

4. **Start the application:**
   ```cmd
   start_app.bat
   ```
   
5. **Open your browser and go to:**
   ```
   http://localhost:8501
   ```

6. **Configure in the app sidebar:**
   - Cluster Name: `eks-opsreview`
   - Region: `us-west-2`
   - AWS credentials (auto-detected if configured via AWS CLI)

### Option 2: Application Only (Use Existing EKS Cluster)

1. **Start the application:**
   ```cmd
   start_app.bat
   ```
   
2. **Configure with your existing cluster:**
   - Enter your EKS cluster name
   - Select your AWS region
   - Enter AWS credentials

### Option 2: Docker Deployment (Production-Ready)

1. **Configure environment variables:**
   ```cmd
   # Edit the .env file that will be created
   deploy_docker.bat
   ```

2. **Edit the .env file with your AWS credentials:**
   ```
   AWS_ACCESS_KEY_ID=your_actual_access_key
   AWS_SECRET_ACCESS_KEY=your_actual_secret_key
   AWS_DEFAULT_REGION=us-west-2
   ```

3. **Run the deployment script:**
   ```cmd
   deploy_docker.bat
   ```

## AWS Configuration

### Method 1: AWS CLI Configuration (Recommended)
```cmd
aws configure
```
Enter your:
- AWS Access Key ID
- AWS Secret Access Key  
- Default region (e.g., us-west-2)
- Default output format (json)

### Method 2: Environment Variables
```cmd
set AWS_ACCESS_KEY_ID=your_access_key
set AWS_SECRET_ACCESS_KEY=your_secret_key
set AWS_DEFAULT_REGION=us-west-2
```

### Method 3: In-App Configuration
Configure directly in the Streamlit sidebar when the app is running.

## Required AWS Permissions

Your AWS credentials need these permissions:

### EKS Permissions
- `eks:DescribeCluster`
- `eks:ListClusters`
- `eks:DescribeNodegroup`
- `eks:ListNodegroups`
- `eks:DescribeAddon`
- `eks:ListAddons`

### CloudWatch Permissions
- `cloudwatch:GetMetricData`
- `cloudwatch:GetMetricStatistics`
- `logs:DescribeLogGroups`

### Security Hub Permissions (Optional)
- `securityhub:BatchImportFindings`
- `securityhub:BatchUpdateFindings`

## Application Features

### 🔍 **Gap Analysis**
- Compares your actual EKS cluster configuration against best practices
- Identifies specific security gaps in YOUR cluster
- Provides targeted recommendations only for actual issues

### 🛡️ **HardenEKS Security Validation**
- 30+ security checks across 7 categories
- Quantitative security score (0-100%)
- Prioritized findings (High/Medium/Low)

### 📊 **Real-time Monitoring**
- Background monitoring with configurable intervals
- Historical trend analysis
- Progress tracking for remediation efforts

### 🔧 **Automated Remediation**
- CloudFormation templates for infrastructure fixes
- EKS API calls for cluster configuration
- Kubernetes manifests for workload security

### 📋 **Compliance Validation**
- CIS Benchmarks for EKS
- NIST SP 800-53 controls
- PCI DSS requirements

### 📈 **Multi-cluster Comparison**
- Side-by-side security score comparison
- Common issue identification
- Best practice sharing

## Usage Instructions

1. **Start the application** using one of the deployment methods above

2. **Configure AWS credentials** in the sidebar

3. **Navigate through the tabs:**
   - **Analysis**: Fill cluster information and generate reports
   - **Cluster Analysis**: Comprehensive analysis with admin permissions
   - **HardenEKS**: Security validation and scoring
   - **Monitoring**: Real-time cluster monitoring
   - **Remediation**: Automated security fixes
   - **Compliance**: Framework validation
   - **History**: Historical trends and progress tracking
   - **Comparison**: Multi-cluster comparison

4. **Generate Reports:**
   - Click "Generate Report" in the Analysis tab
   - Download PDF reports and CSV action items
   - Review security findings and recommendations

## ✅ Verified Features & Fixes

### Issues Fixed During Testing
1. **CSV Generation Error**: ✅ Fixed `defusedcsv.writer` compatibility issue
2. **Compliance KeyError**: ✅ Fixed `cluster_details['name']` access issue
3. **Virtual Environment**: ✅ Proper activation and dependency management
4. **EKS Integration**: ✅ Full cluster creation and analysis workflow

### Tested & Working Features
- ✅ **Gap Analysis**: Real-time cluster configuration analysis
- ✅ **HardenEKS Security**: 30+ security checks with scoring
- ✅ **Compliance Validation**: CIS, NIST, PCI DSS frameworks
- ✅ **PDF Report Generation**: Comprehensive security reports
- ✅ **CSV Export**: Action items and findings export
- ✅ **Real-time Monitoring**: Background cluster monitoring
- ✅ **Multi-cluster Comparison**: Side-by-side analysis
- ✅ **Automated Remediation**: One-click security fixes

## Troubleshooting

### Application Won't Start
```cmd
# Ensure virtual environment is activated
.\venv\Scripts\activate

# Check Python version
python --version

# Reinstall dependencies if needed
pip install -r requirements.txt

# Check for port conflicts
netstat -an | findstr :8501
```

### AWS Authentication Issues
```cmd
# Test AWS credentials
aws sts get-caller-identity

# Test EKS access
aws eks list-clusters --region us-west-2

# Check AWS configuration
aws configure list
```

### EKS Cluster Issues
```cmd
# Check cluster status
aws eks describe-cluster --name eks-opsreview --region us-west-2

# Check nodes
kubectl get nodes

# Update kubeconfig if needed
aws eks update-kubeconfig --region us-west-2 --name eks-opsreview
```

### Docker Issues
```cmd
# Check Docker is running
docker version

# View container logs
docker logs <container-id>

# Rebuild image
docker build -t eks-review-agent . --no-cache
```

## Security Best Practices

1. **Use IAM Roles instead of access keys in production**
2. **Enable VPC endpoints for AWS API calls**
3. **Regularly rotate AWS credentials**
4. **Use least privilege permissions**
5. **Enable CloudTrail logging**
6. **Monitor application logs**

## Support

- Check the logs in the application for detailed error messages
- Ensure your AWS credentials have sufficient permissions
- Verify your EKS cluster is accessible from your network
- For Bedrock features, ensure the service is available in your region

## Next Steps

After deployment:
1. Run your first cluster analysis
2. Review the security findings
3. Set up monitoring for ongoing assessment
4. Apply recommended remediations
5. Track your security posture improvements over time

---

**🎉 Your EKS Operational Review Agent is now ready to help secure and optimize your Kubernetes clusters!**