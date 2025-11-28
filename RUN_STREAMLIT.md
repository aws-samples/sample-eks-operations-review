# How to Run Streamlit App and Generate Reports

## Quick Start

### Step 1: Install Dependencies

```bash
# Option 1: Using pip with --user flag (recommended for macOS)
pip3 install --user streamlit boto3 openpyxl reportlab

# Option 2: Using virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install streamlit boto3 openpyxl reportlab

# Option 3: Using requirements.txt
pip3 install --user -r requirements.txt
```

### Step 2: Run Streamlit App

```bash
# Navigate to project directory
cd /Users/pmenghan/Downloads/AgentK8

# Run the app
streamlit run main.py

# Or if using virtual environment
source venv/bin/activate
streamlit run main.py
```

### Step 3: Access the App

The app will automatically open in your browser at:
```
http://localhost:8501
```

If it doesn't open automatically, manually navigate to that URL.

## Using the App to Generate Reports

### 1. Configure AWS Credentials

In the sidebar, enter:
- **AWS Region**: e.g., `us-west-2`
- **Cluster Name**: Your EKS cluster name
- **Authentication Method**: Choose one:
  - IAM Role ARN
  - Access Keys
  - AWS Profile

### 2. Test Connection

Click **"🔍 Test AWS Connection"** to verify your credentials.

### 3. Generate Analysis Report

Once connection is successful:
1. Select **Analysis Depth**: Choose "🤖 Multi-Agent Analysis (7 min)" for comprehensive analysis
2. Click **"🚀 Generate Analysis Report"**
3. Wait for analysis to complete (5-10 minutes)

### 4. View & Download Reports

After analysis completes:
- **View in Browser**: Interactive dashboard with all results
- **Download PDF**: Click "Download PDF Report" button
- **Download Excel**: Click "Download Excel Report" button
- **Download JSON**: Click "Download JSON Report" button

Reports are also saved in `./reports` directory.

## Offline Mode (Without AWS Connection)

If you have pre-collected cluster data:

1. In the sidebar, select **"📁 Offline Mode"**
2. Upload your JSON data file
3. Click **"🚀 Generate Analysis Report"**
4. Download reports as above

## Troubleshooting

### Issue: Streamlit not found
```bash
# Check if streamlit is installed
pip3 list | grep streamlit

# If not found, install it
pip3 install --user streamlit
```

### Issue: Module import errors
```bash
# Install all dependencies
pip3 install --user -r requirements.txt
```

### Issue: AWS credentials error
- Ensure AWS CLI is configured: `aws configure`
- Or use IAM role/access keys in the app
- Check permissions (see README.md for required permissions)

### Issue: Port already in use
```bash
# Use a different port
streamlit run main.py --server.port 8502
```

### Issue: App doesn't open in browser
```bash
# Manually open: http://localhost:8501
# Or disable auto-open
streamlit run main.py --server.headless true
```

## Enhanced Features (New in V2.0)

The Streamlit app now includes:
- ✅ All 152 DORA compliance checks
- ✅ 7 compliance frameworks (CIS, NIST, SOC 2, DORA, PCI DSS, HIPAA, ISO 27001)
- ✅ Detailed command tracking for each check
- ✅ Comprehensive observations and reasoning
- ✅ Enhanced observation agent analysis
- ✅ Enterprise-grade PDF reports
- ✅ Prioritized remediation plans

## Report Contents

### PDF Report Includes:
1. Cover page with cluster information
2. Executive summary with risk assessment
3. Table of contents
4. Compliance framework summary
5. Detailed check results with:
   - Commands executed
   - Observations made
   - Analysis reasoning
   - Recommendations with steps
6. Observation agent analysis
7. Remediation plan
8. Commands appendix

### Excel Report Includes:
- Summary sheet
- All Checks sheet (300+ checks)
- Failed Checks sheet
- Recommendations sheet
- HardenEKS Details sheet
- Compliance Frameworks sheet

### JSON Report Includes:
- Complete raw data
- All check results
- Commands executed
- Observations
- Recommendations
- Compliance percentages

## Alternative: Command Line

If you prefer command line:

```bash
# For offline analysis
python3 offline_cli.py --data-file your_cluster_data.json

# For online analysis (requires AWS credentials)
python3 -c "
from core.enhanced_analyzer_integration import EnhancedAnalyzerIntegration
analyzer = EnhancedAnalyzerIntegration({'cluster_name': 'my-cluster', 'region': 'us-west-2'}, is_offline=False)
results = analyzer.run_comprehensive_analysis()
reports = analyzer.generate_reports(results)
print('Reports generated:', reports)
"
```

## Quick Demo (No AWS Required)

To see the enhanced features without AWS:

```bash
python3 demo_enhancements.py
```

This demonstrates all new features without requiring AWS credentials or dependencies.

---

**Need Help?**
- Check `QUICK_START_V2.md` for detailed setup
- Review `IMPLEMENTATION_SUMMARY.md` for feature overview
- See `README.md` for AWS permissions required
