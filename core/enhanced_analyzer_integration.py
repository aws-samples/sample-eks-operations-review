"""
Enhanced Analyzer Integration
Integrates all new components:
- Comprehensive Check Engine
- DORA 152 checks
- Enhanced Observation Agent
- Enterprise PDF Generator
"""
from typing import Dict, Any
from datetime import datetime
import json

from core.comprehensive_check_engine import ComprehensiveCheckEngine
from core.dora_comprehensive_analyzer import DORAComprehensiveAnalyzer
from agents.enhanced_observation_agent import EnhancedObservationAgent
from utils.enterprise_pdf_generator import EnterprisePDFGenerator

class EnhancedAnalyzerIntegration:
    """
    Main integration class that orchestrates all enhanced analysis components
    """
    
    def __init__(self, cluster_data: Dict[str, Any], is_offline: bool = False):
        self.cluster_data = cluster_data
        self.is_offline = is_offline
        self.cluster_name = cluster_data.get('cluster_name', 'unknown')
        self.region = cluster_data.get('region', 'unknown')
    
    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """
        Run complete enhanced analysis with all frameworks
        Returns comprehensive results with detailed tracking
        """
        print("🚀 Starting Enhanced Comprehensive Analysis...")
        
        results = {
            'cluster_name': self.cluster_name,
            'region': self.region,
            'analysis_timestamp': datetime.now().isoformat(),
            'data_source': 'offline' if self.is_offline else 'online',
            'analysis_version': '2.0-enhanced'
        }
        
        # 1. Run DORA 152 checks
        print("📋 Running EU DORA Compliance (152 checks)...")
        dora_analyzer = DORAComprehensiveAnalyzer()
        results['dora_analysis'] = dora_analyzer.run_dora_analysis(
            self.cluster_data, self.is_offline
        )
        print(f"   ✓ DORA: {results['dora_analysis']['summary']['passed']}/{results['dora_analysis']['total_checks']} passed")
        
        # 2. Run CIS EKS Benchmark
        print("🔒 Running CIS EKS Benchmark...")
        results['cis_analysis'] = self._run_cis_checks()
        print(f"   ✓ CIS: {results['cis_analysis']['summary']['passed']}/{results['cis_analysis']['summary']['total_checks']} passed")
        
        # 3. Run NIST CSF
        print("🏛️ Running NIST Cybersecurity Framework...")
        results['nist_analysis'] = self._run_nist_checks()
        print(f"   ✓ NIST: {results['nist_analysis']['summary']['passed']}/{results['nist_analysis']['summary']['total_checks']} passed")
        
        # 4. Run SOC 2
        print("📊 Running SOC 2 Type II...")
        results['soc2_analysis'] = self._run_soc2_checks()
        print(f"   ✓ SOC 2: {results['soc2_analysis']['summary']['passed']}/{results['soc2_analysis']['summary']['total_checks']} passed")
        
        # 5. Run PCI DSS
        print("💳 Running PCI DSS...")
        results['pci_analysis'] = self._run_pci_checks()
        print(f"   ✓ PCI DSS: {results['pci_analysis']['summary']['passed']}/{results['pci_analysis']['summary']['total_checks']} passed")
        
        # 6. Run HIPAA
        print("🏥 Running HIPAA Security Rule...")
        results['hipaa_analysis'] = self._run_hipaa_checks()
        print(f"   ✓ HIPAA: {results['hipaa_analysis']['summary']['passed']}/{results['hipaa_analysis']['summary']['total_checks']} passed")
        
        # 7. Run ISO 27001
        print("🌐 Running ISO 27001...")
        results['iso27001_analysis'] = self._run_iso27001_checks()
        print(f"   ✓ ISO 27001: {results['iso27001_analysis']['summary']['passed']}/{results['iso27001_analysis']['summary']['total_checks']} passed")
        
        # 8. Run Observation Agent Analysis
        print("🤖 Running Observation Agent Analysis...")
        results['observation_analysis'] = self._run_observation_analysis(results)
        print(f"   ✓ Generated {results['observation_analysis']['total_findings']} detailed findings")
        
        # 9. Calculate overall metrics
        results['overall_metrics'] = self._calculate_overall_metrics(results)
        
        print("✅ Enhanced Analysis Complete!")
        return results
    
    def _run_cis_checks(self) -> Dict[str, Any]:
        """Run CIS EKS Benchmark checks"""
        from core.check_definitions import ComprehensiveCheckDefinitions
        
        engine = ComprehensiveCheckEngine(self.cluster_data, self.is_offline)
        cis_checks = [c for c in ComprehensiveCheckDefinitions.get_all_checks() 
                      if 'CIS EKS Benchmark' in c.get('compliance_frameworks', [])]
        
        for check in cis_checks:
            engine.execute_check(check)
        
        return {
            'framework': 'CIS EKS Benchmark v1.0.1',
            'summary': engine.get_summary(),
            'detailed_results': engine.get_all_results()
        }
    
    def _run_nist_checks(self) -> Dict[str, Any]:
        """Run NIST CSF checks"""
        from core.check_definitions import ComprehensiveCheckDefinitions
        
        engine = ComprehensiveCheckEngine(self.cluster_data, self.is_offline)
        nist_checks = [c for c in ComprehensiveCheckDefinitions.get_all_checks() 
                       if 'NIST CSF' in c.get('compliance_frameworks', [])]
        
        for check in nist_checks:
            engine.execute_check(check)
        
        return {
            'framework': 'NIST Cybersecurity Framework v1.1',
            'summary': engine.get_summary(),
            'detailed_results': engine.get_all_results()
        }
    
    def _run_soc2_checks(self) -> Dict[str, Any]:
        """Run SOC 2 Type II checks"""
        from core.check_definitions import ComprehensiveCheckDefinitions
        
        engine = ComprehensiveCheckEngine(self.cluster_data, self.is_offline)
        soc2_checks = [c for c in ComprehensiveCheckDefinitions.get_all_checks() 
                       if 'SOC 2' in c.get('compliance_frameworks', [])]
        
        for check in soc2_checks:
            engine.execute_check(check)
        
        return {
            'framework': 'SOC 2 Type II',
            'summary': engine.get_summary(),
            'detailed_results': engine.get_all_results()
        }
    
    def _run_pci_checks(self) -> Dict[str, Any]:
        """Run PCI DSS checks"""
        from core.check_definitions import ComprehensiveCheckDefinitions
        
        engine = ComprehensiveCheckEngine(self.cluster_data, self.is_offline)
        pci_checks = [c for c in ComprehensiveCheckDefinitions.get_all_checks() 
                      if 'PCI DSS' in c.get('compliance_frameworks', [])]
        
        for check in pci_checks:
            engine.execute_check(check)
        
        return {
            'framework': 'PCI DSS v3.2.1',
            'summary': engine.get_summary(),
            'detailed_results': engine.get_all_results()
        }
    
    def _run_hipaa_checks(self) -> Dict[str, Any]:
        """Run HIPAA Security Rule checks"""
        from core.check_definitions import ComprehensiveCheckDefinitions
        
        engine = ComprehensiveCheckEngine(self.cluster_data, self.is_offline)
        hipaa_checks = [c for c in ComprehensiveCheckDefinitions.get_all_checks() 
                        if 'HIPAA' in c.get('compliance_frameworks', [])]
        
        for check in hipaa_checks:
            engine.execute_check(check)
        
        return {
            'framework': 'HIPAA Security Rule',
            'summary': engine.get_summary(),
            'detailed_results': engine.get_all_results()
        }
    
    def _run_iso27001_checks(self) -> Dict[str, Any]:
        """Run ISO 27001 checks"""
        from core.check_definitions import ComprehensiveCheckDefinitions
        
        engine = ComprehensiveCheckEngine(self.cluster_data, self.is_offline)
        iso_checks = [c for c in ComprehensiveCheckDefinitions.get_all_checks() 
                      if 'ISO 27001' in c.get('compliance_frameworks', [])]
        
        for check in iso_checks:
            engine.execute_check(check)
        
        return {
            'framework': 'ISO 27001:2013',
            'summary': engine.get_summary(),
            'detailed_results': engine.get_all_results()
        }
    
    def _run_observation_analysis(self, all_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run observation agent analysis on all results"""
        agent = EnhancedObservationAgent()
        
        # Collect all check results from all frameworks
        all_checks = []
        for framework_key in ['dora_analysis', 'cis_analysis', 'nist_analysis', 
                              'soc2_analysis', 'pci_analysis', 'hipaa_analysis', 
                              'iso27001_analysis']:
            framework_data = all_results.get(framework_key, {})
            all_checks.extend(framework_data.get('detailed_results', []))
        
        return agent.analyze_check_results(all_checks)
    
    def _calculate_overall_metrics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall compliance metrics"""
        total_checks = 0
        total_passed = 0
        total_failed = 0
        
        for framework_key in ['dora_analysis', 'cis_analysis', 'nist_analysis', 
                              'soc2_analysis', 'pci_analysis', 'hipaa_analysis', 
                              'iso27001_analysis']:
            summary = results.get(framework_key, {}).get('summary', {})
            total_checks += summary.get('total_checks', 0)
            total_passed += summary.get('passed', 0)
            total_failed += summary.get('failed', 0)
        
        return {
            'total_checks_across_all_frameworks': total_checks,
            'total_passed': total_passed,
            'total_failed': total_failed,
            'overall_compliance_percentage': (total_passed / total_checks * 100) if total_checks > 0 else 0,
            'frameworks_assessed': 7,
            'risk_level': self._assess_risk_level(total_failed, total_checks)
        }
    
    def _assess_risk_level(self, failed: int, total: int) -> str:
        """Assess overall risk level"""
        if total == 0:
            return 'UNKNOWN'
        
        failure_rate = (failed / total) * 100
        
        if failure_rate > 50:
            return 'CRITICAL'
        elif failure_rate > 30:
            return 'HIGH'
        elif failure_rate > 15:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_reports(self, analysis_results: Dict[str, Any], output_dir: str = './reports'):
        """Generate all report formats"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M')
        base_filename = f"eks_enhanced_analysis_{self.cluster_name}_{timestamp}"
        
        # 1. JSON Report
        json_path = os.path.join(output_dir, f"{base_filename}.json")
        with open(json_path, 'w') as f:
            json.dump(analysis_results, f, indent=2, default=str)
        print(f"✓ JSON Report: {json_path}")
        
        # 2. Enterprise PDF Report
        pdf_path = os.path.join(output_dir, f"{base_filename}.pdf")
        pdf_gen = EnterprisePDFGenerator(pdf_path)
        pdf_gen.generate_comprehensive_report(
            analysis_results,
            analysis_results.get('observation_analysis', {})
        )
        print(f"✓ PDF Report: {pdf_path}")
        
        # 3. Comprehensive Excel Report
        from utils.comprehensive_excel_generator import ComprehensiveExcelGenerator
        excel_path = os.path.join(output_dir, f"{base_filename}.xlsx")
        excel_gen = ComprehensiveExcelGenerator()
        excel_gen.generate_report(analysis_results, excel_path)
        print(f"✓ Excel Report: {excel_path}")
        
        return {
            'json': json_path,
            'pdf': pdf_path,
            'excel': excel_path
        }
