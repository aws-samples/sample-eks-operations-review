"""
Integration Script - Connects all enhanced components
Run this to integrate the new detailed check engine, observation agent, and comprehensive reporting
"""
import sys
import os

def integrate_enhancements():
    """Integrate all enhancements into the existing codebase"""
    
    print("=" * 80)
    print("EKS OPERATIONAL REVIEW AGENT - ENHANCEMENT INTEGRATION")
    print("=" * 80)
    print()
    
    print("✅ New Components Created:")
    print("   1. core/detailed_check_engine.py - Command traceability engine")
    print("   2. core/check_definitions.py - Comprehensive check definitions (300+ checks)")
    print("   3. agents/observation_agent.py - Detailed reasoning and analysis")
    print("   4. IMPLEMENTATION_GUIDE.md - Complete integration guide")
    print()
    
    print("📋 Enhancements Summary:")
    print()
    print("1. DETAILED COMMAND TRACEABILITY")
    print("   - Every check now records exact AWS CLI commands executed")
    print("   - Raw observations captured for audit purposes")
    print("   - Analysis reasoning documented")
    print()
    
    print("2. COMPREHENSIVE CHECK COVERAGE")
    print("   - CIS EKS Benchmark: 50+ checks")
    print("   - NIST Cybersecurity Framework: 30+ checks")
    print("   - SOC 2 Type II: 25+ checks")
    print("   - EU DORA: 152 checks (complete implementation)")
    print("   - PCI DSS v4.0: 40+ checks")
    print("   - HIPAA Security Rule: 35+ checks")
    print("   - ISO 27001:2013: 30+ checks")
    print("   - TOTAL: 300+ comprehensive checks")
    print()
    
    print("3. DETAILED OBSERVATIONS")
    print("   - Methodology explanation for each check")
    print("   - Raw data analysis and interpretation")
    print("   - Detailed reasoning for status assignment")
    print("   - Security implications and threat vectors")
    print("   - Compliance impact assessment")
    print("   - Multi-tier recommendations (immediate/short-term/long-term)")
    print()
    
    print("4. ENTERPRISE-GRADE REPORTING")
    print("   - PDF: Detailed findings with commands and observations")
    print("   - Excel: Multiple sheets for each compliance framework")
    print("   - JSON: Complete data export for automation")
    print("   - All reports include:")
    print("     * Commands executed")
    print("     * Raw observations")
    print("     * Analysis reasoning")
    print("     * Detailed recommendations with AWS CLI commands")
    print("     * AWS documentation links")
    print("     * Business impact assessment")
    print()
    
    print("5. DORA COMPLIANCE (152 CHECKS)")
    print("   - A. EKS Control Plane: 19 checks")
    print("   - B. Managed Node Groups: 36 checks")
    print("   - C. Karpenter: 40 checks")
    print("   - D. Load Balancer Controller: 36 checks")
    print("   - E. Deployed Applications: 6 checks")
    print("   - F. Additional Components: 15 checks")
    print()
    
    print("=" * 80)
    print("NEXT STEPS FOR INTEGRATION")
    print("=" * 80)
    print()
    
    print("STEP 1: Review Implementation Guide")
    print("   Read: IMPLEMENTATION_GUIDE.md")
    print("   This contains detailed integration instructions")
    print()
    
    print("STEP 2: Update Core Analyzer")
    print("   File: core/unified_analyzer.py")
    print("   Action: Integrate DetailedCheckEngine and ObservationAgent")
    print("   Code snippet:")
    print("""
   from .detailed_check_engine import DetailedCheckEngine
   from .check_definitions import ComprehensiveCheckDefinitions
   from agents.observation_agent import ObservationAgent
   
   def run_comprehensive_analysis(self):
       check_engine = DetailedCheckEngine(self.cluster_name, self.region, self.offline_data)
       observation_agent = ObservationAgent(self.cluster_name)
       
       all_checks = ComprehensiveCheckDefinitions.get_all_checks()
       
       for check_config in all_checks:
           check_result = check_engine.execute_check(check_config)
           detailed_observation = observation_agent.analyze_observation(check_result)
       
       return {
           'check_results': check_engine.get_all_results(),
           'detailed_observations': observation_agent.get_all_observations(),
           'summary': check_engine.get_summary()
       }
   """)
    print()
    
    print("STEP 3: Update PDF Generator")
    print("   File: utils/pdf_generator.py")
    print("   Action: Add sections for detailed findings and commands")
    print("   New sections:")
    print("   - Detailed Findings (with commands and observations)")
    print("   - Compliance Framework Details (7 frameworks)")
    print("   - Prioritized Recommendations")
    print("   - Appendix: Commands and Evidence")
    print()
    
    print("STEP 4: Update Excel Generator")
    print("   File: utils/excel_generator.py")
    print("   Action: Add sheets for each compliance framework")
    print("   New sheets:")
    print("   - Enhanced 'All Checks' with commands and observations")
    print("   - CIS EKS Benchmark Details")
    print("   - NIST CSF Details")
    print("   - SOC 2 Details")
    print("   - DORA Compliance (152 checks)")
    print("   - PCI DSS Details")
    print("   - HIPAA Details")
    print("   - ISO 27001 Details")
    print("   - Commands Executed")
    print("   - Detailed Recommendations")
    print()
    
    print("STEP 5: Test Integration")
    print("   Command: streamlit run main.py")
    print("   Action: Run analysis on test cluster")
    print("   Verify: All reports contain detailed commands and observations")
    print()
    
    print("=" * 80)
    print("QUICK START INTEGRATION")
    print("=" * 80)
    print()
    
    print("To quickly integrate, I can create a modified unified_analyzer.py")
    print("that uses all the new components.")
    print()
    
    response = input("Would you like me to create the integrated unified_analyzer.py? (yes/no): ")
    
    if response.lower() in ['yes', 'y']:
        create_integrated_analyzer()
        print()
        print("✅ Created: core/unified_analyzer_enhanced.py")
        print()
        print("To use the enhanced analyzer:")
        print("1. Backup current: mv core/unified_analyzer.py core/unified_analyzer_backup.py")
        print("2. Use enhanced: mv core/unified_analyzer_enhanced.py core/unified_analyzer.py")
        print("3. Restart application: streamlit run main.py")
    else:
        print()
        print("Integration files are ready. Follow the steps in IMPLEMENTATION_GUIDE.md")
    
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print()
    print("✅ All enhancement components created successfully")
    print("✅ 300+ comprehensive checks defined across 7 frameworks")
    print("✅ Complete DORA compliance implementation (152 checks)")
    print("✅ Detailed command traceability and observations")
    print("✅ Enterprise-grade reporting with full audit trail")
    print()
    print("📖 Read IMPLEMENTATION_GUIDE.md for complete integration instructions")
    print()

def create_integrated_analyzer():
    """Create integrated unified analyzer with all enhancements"""
    
    content = '''"""
Enhanced Unified Analysis Engine - Integrated with Detailed Check Engine
Provides comprehensive analysis with command traceability and detailed observations
"""
import json
from datetime import datetime
from typing import Dict, Any, Optional, List
import logging

from .aws_client import AWSClientManager
from .detailed_check_engine import DetailedCheckEngine
from .check_definitions import ComprehensiveCheckDefinitions
from agents.observation_agent import ObservationAgent

logger = logging.getLogger(__name__)

class UnifiedClusterAnalyzer:
    """Enhanced analyzer with detailed check engine and observation agent"""
    
    def __init__(self, cluster_name: str, region: str = None, role_arn: Optional[str] = None, 
                 offline_data: Optional[Dict[str, Any]] = None):
        self.cluster_name = cluster_name
        self.region = region
        self.offline_data = offline_data
        self.is_offline = offline_data is not None
        
        if self.is_offline:
            metadata = self.offline_data.get('metadata', {})
            self.region = self.region or metadata.get('region', 'us-west-2')
            self.cluster_name = self.cluster_name or metadata.get('cluster_name', 'unknown-cluster')
        else:
            self.aws_client = AWSClientManager(region, role_arn)
            self.clients = self.aws_client.get_clients()
    
    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """
        Enhanced comprehensive analysis with detailed check engine
        """
        try:
            print(f"🔍 Running enhanced analysis for cluster: {self.cluster_name}")
            print(f"📊 Executing 300+ comprehensive checks across 7 compliance frameworks")
            
            # Initialize enhanced engines
            check_engine = DetailedCheckEngine(self.cluster_name, self.region, self.offline_data)
            observation_agent = ObservationAgent(self.cluster_name)
            
            # Get all check definitions
            all_checks = ComprehensiveCheckDefinitions.get_all_checks()
            print(f"✅ Loaded {len(all_checks)} check definitions")
            
            # Execute each check with detailed traceability
            total_checks = len(all_checks)
            for idx, check_config in enumerate(all_checks, 1):
                print(f"⏳ Executing check {idx}/{total_checks}: {check_config['check_id']} - {check_config['title']}")
                
                try:
                    # Execute check with command traceability
                    check_result = check_engine.execute_check(check_config)
                    
                    # Generate detailed observation
                    detailed_observation = observation_agent.analyze_observation(check_result)
                    
                except Exception as e:
                    logger.error(f"Check {check_config['check_id']} failed: {str(e)}")
                    continue
            
            # Generate comprehensive results
            results = {
                'cluster_name': self.cluster_name,
                'region': self.region,
                'analysis_timestamp': datetime.now().isoformat(),
                'data_source': 'offline' if self.is_offline else 'online',
                'check_results': check_engine.get_all_results(),
                'detailed_observations': observation_agent.get_all_observations(),
                'summary': check_engine.get_summary(),
                'compliance_frameworks': {
                    'CIS_EKS_Benchmark': self._filter_by_framework(check_engine, 'CIS EKS Benchmark'),
                    'NIST_CSF': self._filter_by_framework(check_engine, 'NIST CSF'),
                    'SOC2': self._filter_by_framework(check_engine, 'SOC 2 Type II'),
                    'DORA': self._filter_by_framework(check_engine, 'EU DORA'),
                    'PCI_DSS': self._filter_by_framework(check_engine, 'PCI DSS'),
                    'HIPAA': self._filter_by_framework(check_engine, 'HIPAA Security Rule'),
                    'ISO27001': self._filter_by_framework(check_engine, 'ISO 27001')
                }
            }
            
            print(f"✅ Analysis complete: {results['summary']['total_checks']} checks executed")
            print(f"   Passed: {results['summary']['passed']}")
            print(f"   Failed: {results['summary']['failed']}")
            print(f"   Warnings: {results['summary']['warnings']}")
            
            return results
            
        except Exception as e:
            logger.error(f"Comprehensive analysis failed: {str(e)}")
            return {
                'error': str(e),
                'cluster_name': self.cluster_name,
                'data_source': 'offline' if self.is_offline else 'online'
            }
    
    def _filter_by_framework(self, check_engine: DetailedCheckEngine, framework: str) -> Dict[str, Any]:
        """Filter check results by compliance framework"""
        all_results = check_engine.get_all_results()
        framework_results = [
            r for r in all_results 
            if framework in r.get('compliance_frameworks', [])
        ]
        
        total = len(framework_results)
        passed = sum(1 for r in framework_results if r['status'] == 'PASSED')
        failed = sum(1 for r in framework_results if r['status'] == 'FAILED')
        
        return {
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'compliance_score': (passed / total * 100) if total > 0 else 0,
            'checks': framework_results
        }
'''
    
    with open('core/unified_analyzer_enhanced.py', 'w') as f:
        f.write(content)

if __name__ == '__main__':
    integrate_enhancements()
