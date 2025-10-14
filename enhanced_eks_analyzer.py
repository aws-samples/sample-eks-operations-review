#!/usr/bin/env python3
"""
Enhanced EKS Cluster Analyzer
Comprehensive analysis tool for EKS clusters with deep dive capabilities
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from analyzers.deep_cluster_analyzer import DeepClusterAnalyzer
from utils.enhanced_kubernetes_client import EnhancedKubernetesClient
from utils.comprehensive_report_generator import ComprehensiveReportGenerator
from utils.csv_generator import CSVGenerator

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EnhancedEKSAnalyzer:
    """Enhanced EKS Analyzer with comprehensive analysis capabilities"""
    
    def __init__(self, aws_access_key: str, aws_secret_key: str, region: str, cluster_name: str):
        """Initialize the enhanced analyzer"""
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.region = region
        self.cluster_name = cluster_name
        
        # Initialize components
        self.deep_analyzer = DeepClusterAnalyzer(aws_access_key, aws_secret_key, region, cluster_name)
        self.report_generator = ComprehensiveReportGenerator()
        self.csv_generator = CSVGenerator()
        
        logger.info(f"Enhanced EKS Analyzer initialized for cluster: {cluster_name}")
    
    def run_comprehensive_analysis(self, output_dir: str = "reports") -> Dict[str, Any]:
        """Run comprehensive analysis and generate reports"""
        try:
            logger.info("Starting comprehensive EKS cluster analysis...")
            
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            # Run deep analysis
            logger.info("Running deep cluster analysis...")
            analysis_results = self.deep_analyzer.analyze_comprehensive()
            
            # Generate timestamp for file names
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Generate comprehensive PDF report
            pdf_filename = f"eks_comprehensive_report_{self.cluster_name}_{timestamp}.pdf"
            pdf_path = os.path.join(output_dir, pdf_filename)
            
            logger.info("Generating comprehensive PDF report...")
            self.report_generator.generate_comprehensive_report(
                analysis_results, self.cluster_name, pdf_path
            )
            
            # Generate detailed CSV with action items
            csv_filename = f"eks_action_items_{self.cluster_name}_{timestamp}.csv"
            csv_path = os.path.join(output_dir, csv_filename)
            
            logger.info("Generating detailed CSV action items...")
            self._generate_detailed_csv(analysis_results, csv_path)
            
            # Generate summary JSON for programmatic access
            json_filename = f"eks_analysis_summary_{self.cluster_name}_{timestamp}.json"
            json_path = os.path.join(output_dir, json_filename)
            
            logger.info("Generating analysis summary JSON...")
            self._generate_summary_json(analysis_results, json_path)
            
            # Return summary
            summary = self._create_analysis_summary(analysis_results)
            summary.update({
                'reports_generated': {
                    'pdf_report': pdf_path,
                    'csv_action_items': csv_path,
                    'json_summary': json_path
                }
            })
            
            logger.info("Comprehensive analysis completed successfully!")
            return summary
            
        except Exception as e:
            logger.error(f"Comprehensive analysis failed: {e}")
            raise
    
    def _generate_detailed_csv(self, analysis_results: Dict[str, Any], output_path: str):
        """Generate detailed CSV with all findings and recommendations"""
        try:
            # Collect all findings from different analysis areas
            all_findings = []
            
            # Get consolidated recommendations
            recommendations = analysis_results.get('consolidated_recommendations', [])
            
            for rec in recommendations:
                finding_data = {
                    'Category': rec.get('category', 'General'),
                    'Severity': rec.get('severity', 'Low'),
                    'Finding': rec.get('finding', rec.get('title', 'N/A')),
                    'Current_State': rec.get('current_state', 'N/A'),
                    'Recommendation': rec.get('recommendation', 'N/A'),
                    'Impact': rec.get('impact', 'N/A'),
                    'Analysis_Area': rec.get('analysis_area', 'N/A'),
                    'Priority_Score': self._calculate_priority_score(rec.get('severity', 'Low')),
                    'Estimated_Effort': self._estimate_effort(rec),
                    'Reference': rec.get('reference', 'N/A')
                }
                all_findings.append(finding_data)
            
            # Sort by priority score (high to low)
            all_findings.sort(key=lambda x: x['Priority_Score'], reverse=True)
            
            # Write to CSV
            if all_findings:
                fieldnames = list(all_findings[0].keys())
                self.csv_generator.generate_csv(all_findings, output_path, fieldnames)
            else:
                # Create empty CSV with headers
                fieldnames = ['Category', 'Severity', 'Finding', 'Recommendation', 'Impact']
                self.csv_generator.generate_csv([], output_path, fieldnames)
            
            logger.info(f"Detailed CSV generated: {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate detailed CSV: {e}")
            raise
    
    def _generate_summary_json(self, analysis_results: Dict[str, Any], output_path: str):
        """Generate JSON summary for programmatic access"""
        try:
            summary = self._create_analysis_summary(analysis_results)
            
            # Add detailed breakdown
            summary['detailed_analysis'] = {
                'cluster_level_findings': len(analysis_results.get('cluster_level', {}).get('findings', [])),
                'namespace_analysis': analysis_results.get('namespace_level', {}).get('summary', {}),
                'security_metrics': {
                    'privileged_containers': analysis_results.get('security_deep_dive', {}).get('privileged_containers_count', 0),
                    'root_containers': analysis_results.get('security_deep_dive', {}).get('root_containers_count', 0)
                },
                'workload_counts': {
                    'deployments': len(analysis_results.get('workload_level', {}).get('deployments', [])),
                    'daemonsets': len(analysis_results.get('workload_level', {}).get('daemonsets', [])),
                    'statefulsets': len(analysis_results.get('workload_level', {}).get('statefulsets', [])),
                    'services': len(analysis_results.get('workload_level', {}).get('services', []))
                },
                'performance_metrics': {
                    'hpa_count': analysis_results.get('performance_analysis', {}).get('hpa_count', 0),
                    'deployments_without_hpa': analysis_results.get('performance_analysis', {}).get('deployments_without_hpa', 0)
                },
                'reliability_metrics': {
                    'pdb_count': analysis_results.get('reliability_analysis', {}).get('pdb_count', 0),
                    'deployments_without_pdb': analysis_results.get('reliability_analysis', {}).get('deployments_without_pdb', 0)
                }
            }
            
            with open(output_path, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            
            logger.info(f"Summary JSON generated: {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to generate summary JSON: {e}")
            raise
    
    def _create_analysis_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create high-level analysis summary"""
        recommendations = analysis_results.get('consolidated_recommendations', [])
        
        # Count findings by severity
        high_count = len([r for r in recommendations if r.get('severity') == 'High'])
        medium_count = len([r for r in recommendations if r.get('severity') == 'Medium'])
        low_count = len([r for r in recommendations if r.get('severity') == 'Low'])
        
        # Calculate overall score (0-100)
        total_findings = len(recommendations)
        if total_findings == 0:
            overall_score = 100
        else:
            # Weight: High=3, Medium=2, Low=1
            weighted_score = (high_count * 3 + medium_count * 2 + low_count * 1)
            max_possible_score = total_findings * 3
            overall_score = max(0, 100 - (weighted_score / max_possible_score * 100))
        
        return {
            'cluster_name': self.cluster_name,
            'analysis_timestamp': datetime.now().isoformat(),
            'overall_score': round(overall_score, 1),
            'total_findings': total_findings,
            'findings_by_severity': {
                'high': high_count,
                'medium': medium_count,
                'low': low_count
            },
            'top_recommendations': [
                rec.get('recommendation', 'N/A') for rec in recommendations[:5]
            ],
            'analysis_areas_covered': [
                'cluster_level', 'namespace_level', 'workload_level',
                'security_deep_dive', 'cost_optimization', 'performance_analysis',
                'reliability_analysis', 'addon_analysis', 'upgrade_analysis'
            ]
        }
    
    def _calculate_priority_score(self, severity: str) -> int:
        """Calculate numeric priority score for sorting"""
        severity_scores = {
            'High': 3,
            'Medium': 2,
            'Low': 1
        }
        return severity_scores.get(severity, 1)
    
    def _estimate_effort(self, recommendation: Dict[str, Any]) -> str:
        """Estimate implementation effort"""
        category = recommendation.get('category', '').lower()
        severity = recommendation.get('severity', 'Low')
        
        # Simple effort estimation based on category and severity
        if 'upgrade' in category or 'migration' in category:
            return 'High'
        elif severity == 'High':
            return 'Medium'
        elif 'configuration' in category or 'policy' in category:
            return 'Low'
        else:
            return 'Medium'

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced EKS Cluster Analyzer')
    parser.add_argument('--cluster-name', required=True, help='EKS cluster name')
    parser.add_argument('--region', required=True, help='AWS region')
    parser.add_argument('--aws-access-key', help='AWS access key (or use AWS_ACCESS_KEY_ID env var)')
    parser.add_argument('--aws-secret-key', help='AWS secret key (or use AWS_SECRET_ACCESS_KEY env var)')
    parser.add_argument('--output-dir', default='reports', help='Output directory for reports')
    
    args = parser.parse_args()
    
    # Get AWS credentials
    aws_access_key = args.aws_access_key or os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_key = args.aws_secret_key or os.getenv('AWS_SECRET_ACCESS_KEY')
    
    if not aws_access_key or not aws_secret_key:
        print("Error: AWS credentials not provided. Use --aws-access-key and --aws-secret-key or set environment variables.")
        sys.exit(1)
    
    try:
        # Initialize analyzer
        analyzer = EnhancedEKSAnalyzer(
            aws_access_key=aws_access_key,
            aws_secret_key=aws_secret_key,
            region=args.region,
            cluster_name=args.cluster_name
        )
        
        # Run analysis
        results = analyzer.run_comprehensive_analysis(args.output_dir)
        
        # Print summary
        print("\n" + "="*60)
        print("EKS CLUSTER ANALYSIS SUMMARY")
        print("="*60)
        print(f"Cluster: {results['cluster_name']}")
        print(f"Overall Score: {results['overall_score']}/100")
        print(f"Total Findings: {results['total_findings']}")
        print(f"High Priority: {results['findings_by_severity']['high']}")
        print(f"Medium Priority: {results['findings_by_severity']['medium']}")
        print(f"Low Priority: {results['findings_by_severity']['low']}")
        print("\nReports Generated:")
        for report_type, path in results['reports_generated'].items():
            print(f"  {report_type}: {path}")
        print("="*60)
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
