"""
Test script for Enhanced Analyzer V2
Demonstrates all new features with sample data
"""
import json
import sys
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, '.')

from core.enhanced_analyzer_integration import EnhancedAnalyzerIntegration

def load_sample_data():
    """Load sample cluster data from existing report"""
    try:
        with open('./reports/eks_analysis_strands-cluster_20251127_1845.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("❌ Sample data file not found. Using minimal test data.")
        return {
            'cluster_name': 'test-cluster',
            'region': 'us-west-2',
            'cluster_info': {
                'name': 'test-cluster',
                'status': 'ACTIVE',
                'version': '1.30',
                'logging': {
                    'clusterLogging': []
                },
                'encryptionConfig': None,
                'resourcesVpcConfig': {
                    'publicAccessCidrs': ['0.0.0.0/0'],
                    'endpointPublicAccess': True,
                    'endpointPrivateAccess': False
                }
            }
        }

def main():
    print("=" * 80)
    print("🚀 Enhanced EKS Analyzer V2 - Test Run")
    print("=" * 80)
    print()
    
    # Load sample data
    print("📂 Loading sample cluster data...")
    cluster_data = load_sample_data()
    print(f"   ✓ Loaded data for cluster: {cluster_data.get('cluster_name', 'unknown')}")
    print()
    
    # Initialize enhanced analyzer
    print("🔧 Initializing Enhanced Analyzer...")
    analyzer = EnhancedAnalyzerIntegration(cluster_data, is_offline=True)
    print("   ✓ Analyzer initialized")
    print()
    
    # Run comprehensive analysis
    print("🔍 Running Comprehensive Analysis...")
    print("   This will execute all compliance framework checks:")
    print("   • EU DORA (152 checks)")
    print("   • CIS EKS Benchmark")
    print("   • NIST Cybersecurity Framework")
    print("   • SOC 2 Type II")
    print("   • PCI DSS")
    print("   • HIPAA Security Rule")
    print("   • ISO 27001")
    print()
    
    try:
        results = analyzer.run_comprehensive_analysis()
        print()
        print("✅ Analysis Complete!")
        print()
        
        # Display summary
        print("=" * 80)
        print("📊 ANALYSIS SUMMARY")
        print("=" * 80)
        
        overall = results.get('overall_metrics', {})
        print(f"Total Checks Executed: {overall.get('total_checks_across_all_frameworks', 0)}")
        print(f"Passed: {overall.get('total_passed', 0)}")
        print(f"Failed: {overall.get('total_failed', 0)}")
        print(f"Overall Compliance: {overall.get('overall_compliance_percentage', 0):.1f}%")
        print(f"Risk Level: {overall.get('risk_level', 'UNKNOWN')}")
        print()
        
        # Framework breakdown
        print("=" * 80)
        print("📋 FRAMEWORK BREAKDOWN")
        print("=" * 80)
        
        frameworks = [
            ('EU DORA', 'dora_analysis'),
            ('CIS EKS Benchmark', 'cis_analysis'),
            ('NIST CSF', 'nist_analysis'),
            ('SOC 2 Type II', 'soc2_analysis'),
            ('PCI DSS', 'pci_analysis'),
            ('HIPAA', 'hipaa_analysis'),
            ('ISO 27001', 'iso27001_analysis')
        ]
        
        for name, key in frameworks:
            framework_data = results.get(key, {})
            summary = framework_data.get('summary', {})
            total = summary.get('total_checks', 0)
            passed = summary.get('passed', 0)
            compliance = summary.get('compliance_percentage', 0)
            
            print(f"{name:25} | Checks: {total:3} | Passed: {passed:3} | Compliance: {compliance:5.1f}%")
        
        print()
        
        # Observation agent summary
        print("=" * 80)
        print("🤖 OBSERVATION AGENT ANALYSIS")
        print("=" * 80)
        
        obs_analysis = results.get('observation_analysis', {})
        exec_summary = obs_analysis.get('executive_summary', {})
        
        print(f"Total Findings: {obs_analysis.get('total_findings', 0)}")
        print(f"  • Critical: {len(obs_analysis.get('critical_findings', []))}")
        print(f"  • High: {len(obs_analysis.get('high_findings', []))}")
        print(f"  • Medium: {len(obs_analysis.get('medium_findings', []))}")
        print(f"  • Low: {len(obs_analysis.get('low_findings', []))}")
        print()
        print(f"Risk Assessment: {exec_summary.get('risk_assessment', 'Unknown')}")
        print()
        
        # Top priorities
        if exec_summary.get('top_priorities'):
            print("Top 5 Priorities:")
            for idx, priority in enumerate(exec_summary['top_priorities'][:5], 1):
                print(f"  {idx}. [{priority['severity']}] {priority['title']}")
        
        print()
        
        # Sample detailed check
        print("=" * 80)
        print("📝 SAMPLE DETAILED CHECK RESULT")
        print("=" * 80)
        
        dora_results = results.get('dora_analysis', {}).get('detailed_results', [])
        if dora_results:
            sample = dora_results[0]
            print(f"Check ID: {sample.get('check_id', 'N/A')}")
            print(f"Title: {sample.get('title', 'N/A')}")
            print(f"Status: {sample.get('status', 'N/A')}")
            print(f"Severity: {sample.get('severity', 'N/A')}")
            print()
            print("Commands Executed:")
            for cmd in sample.get('commands_executed', [])[:2]:
                print(f"  • {cmd.get('command', 'N/A')}")
            print()
            print("Observations:")
            for obs in sample.get('observations', [])[:3]:
                print(f"  • [{obs.get('severity', 'INFO')}] {obs.get('text', 'N/A')}")
            print()
            print(f"Reasoning: {sample.get('reasoning', 'N/A')[:100]}...")
        
        print()
        
        # Generate reports
        print("=" * 80)
        print("📄 GENERATING REPORTS")
        print("=" * 80)
        
        report_paths = analyzer.generate_reports(results, output_dir='./reports')
        
        print()
        print("✅ All reports generated successfully!")
        print()
        print("Report Locations:")
        for format_type, path in report_paths.items():
            print(f"  • {format_type.upper()}: {path}")
        
        print()
        print("=" * 80)
        print("🎉 TEST COMPLETE!")
        print("=" * 80)
        print()
        print("Next Steps:")
        print("1. Review the generated reports in ./reports directory")
        print("2. Check the PDF for enterprise-grade formatting")
        print("3. Examine the JSON for complete detailed results")
        print("4. Review the Excel file for tabular analysis")
        print()
        
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
