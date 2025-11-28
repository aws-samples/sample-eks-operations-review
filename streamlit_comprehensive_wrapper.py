"""
Streamlit Comprehensive Analysis Wrapper
Ensures all 300+ checks are included in reports
"""
from core.enhanced_analyzer_integration import EnhancedAnalyzerIntegration
from core.unified_analyzer import UnifiedClusterAnalyzer
from typing import Dict, Any

def run_comprehensive_analysis(cluster_name: str, region: str, role_arn: str = None, 
                               offline_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Run comprehensive analysis with ALL checks
    Returns results compatible with Streamlit app
    """
    
    # Determine if offline mode
    is_offline = offline_data is not None
    
    if is_offline:
        # Use offline data
        cluster_data = offline_data
    else:
        # Run online analysis first to get cluster data
        analyzer = UnifiedClusterAnalyzer(cluster_name, region, role_arn, offline_data)
        cluster_data = analyzer.run_comprehensive_analysis()
    
    # Run enhanced comprehensive analysis
    enhanced_analyzer = EnhancedAnalyzerIntegration(cluster_data, is_offline=is_offline)
    comprehensive_results = enhanced_analyzer.run_comprehensive_analysis()
    
    # Merge with original results for backward compatibility
    if not is_offline:
        comprehensive_results.update({
            'health_analysis': cluster_data.get('health_analysis', {}),
            'security_analysis': cluster_data.get('security_analysis', {}),
            'hardeneks_analysis': cluster_data.get('hardeneks_analysis', {})
        })
    
    return comprehensive_results

def generate_comprehensive_reports(analysis_results: Dict[str, Any], output_dir: str = './reports'):
    """
    Generate all comprehensive reports (PDF, Excel, JSON)
    """
    from core.enhanced_analyzer_integration import EnhancedAnalyzerIntegration
    from datetime import datetime
    import os
    import json
    
    os.makedirs(output_dir, exist_ok=True)
    
    cluster_name = analysis_results.get('cluster_name', 'unknown')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M')
    base_filename = f"eks_comprehensive_{cluster_name}_{timestamp}"
    
    # 1. JSON Report
    json_path = os.path.join(output_dir, f"{base_filename}.json")
    with open(json_path, 'w') as f:
        json.dump(analysis_results, f, indent=2, default=str)
    
    # 2. Excel Report (Comprehensive)
    try:
        from utils.comprehensive_excel_generator import ComprehensiveExcelGenerator
        excel_path = os.path.join(output_dir, f"{base_filename}.xlsx")
        excel_gen = ComprehensiveExcelGenerator()
        excel_gen.generate_report(analysis_results, excel_path)
    except Exception as e:
        print(f"Excel generation error: {e}")
        excel_path = None
    
    # 3. PDF Report (Enterprise)
    try:
        from utils.enterprise_pdf_generator import EnterprisePDFGenerator
        pdf_path = os.path.join(output_dir, f"{base_filename}.pdf")
        pdf_gen = EnterprisePDFGenerator(pdf_path)
        pdf_gen.generate_comprehensive_report(
            analysis_results,
            analysis_results.get('observation_analysis', {})
        )
    except Exception as e:
        print(f"PDF generation error: {e}")
        # Fallback to basic PDF
        try:
            from utils.pdf_generator import PDFGenerator
            pdf_path = os.path.join(output_dir, f"{base_filename}.pdf")
            pdf_gen = PDFGenerator()
            pdf_bytes = pdf_gen.generate_report(analysis_results, cluster_name)
            with open(pdf_path, 'wb') as f:
                f.write(pdf_bytes)
        except Exception as e2:
            print(f"Fallback PDF generation error: {e2}")
            pdf_path = None
    
    return {
        'json': json_path,
        'excel': excel_path,
        'pdf': pdf_path
    }
