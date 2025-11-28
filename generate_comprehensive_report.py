"""
Generate Comprehensive Excel Report with ALL checks
"""
import json
import sys
from datetime import datetime

# Load existing report data
with open('./reports/eks_analysis_strands-cluster_20251127_2034.json', 'r') as f:
    cluster_data = json.load(f)

print("🚀 Generating Comprehensive Excel Report...")
print(f"   Cluster: {cluster_data.get('cluster_name', 'unknown')}")
print()

# Run enhanced analysis
from core.enhanced_analyzer_integration import EnhancedAnalyzerIntegration

analyzer = EnhancedAnalyzerIntegration(cluster_data, is_offline=True)
results = analyzer.run_comprehensive_analysis()

# Generate reports
print()
print("📄 Generating Reports...")
report_paths = analyzer.generate_reports(results, output_dir='./reports')

print()
print("✅ Comprehensive Report Generated!")
print()
print("Report includes:")
print("  • Executive Summary")
print("  • DORA All 152 Checks")
print("  • CIS EKS All Checks")
print("  • NIST CSF All Checks")
print("  • SOC 2 All Checks")
print("  • PCI DSS All Checks")
print("  • HIPAA All Checks")
print("  • ISO 27001 All Checks")
print("  • All 300+ Checks Combined")
print("  • Failed Checks Detailed")
print("  • Prioritized Recommendations")
print("  • HardenEKS Detailed")
print("  • Commands Executed")
print()
print(f"Excel Report: {report_paths['excel']}")
