import os
import json
import logging
import argparse
from datetime import datetime
from src.analyzers.hardeneks_analyzer import HardenEKSAnalyzer
from src.analyzers.best_practices_analyzer import EKSBestPracticesAnalyzer
from src.utils.report_generator import ReportGenerator
from src.utils.csv_generator import CSVGenerator
from src.remediation.remediation_manager import RemediationManager
from src.compliance.compliance_manager import ComplianceManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main entry point for the EKS Operational Review Agent"""
    parser = argparse.ArgumentParser(description='EKS Operational Review Agent')
    parser.add_argument('--cluster-config', type=str, required=True, help='Path to cluster configuration JSON file')
    parser.add_argument('--inputs', type=str, required=False, help='Path to user inputs JSON file')
    parser.add_argument('--output-dir', type=str, default='reports', help='Directory to store output reports')
    parser.add_argument('--aws-access-key', type=str, required=False, help='AWS access key')
    parser.add_argument('--aws-secret-key', type=str, required=False, help='AWS secret key')
    parser.add_argument('--region', type=str, required=False, help='AWS region')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    # Load cluster configuration
    with open(args.cluster_config, 'r', encoding='utf-8') as file:
        cluster_details = json.load(file)
    
    # Load user inputs if provided
    inputs = {}
    if args.inputs and os.path.exists(args.inputs):
        with open(args.inputs, 'r', encoding='utf-8') as file:
            inputs = json.load(file)
    
    # Run HardenEKS analysis
    logger.info("Running HardenEKS analysis...")
    hardeneks_analyzer = HardenEKSAnalyzer()
    hardeneks_results = hardeneks_analyzer.analyze_cluster(cluster_details, inputs)
    
    # Generate PDF report directly with HardenEKS results
    logger.info("Generating PDF report...")
    report_generator = ReportGenerator()
    report_path = report_generator.generate_report(hardeneks_results, cluster_details)
    logger.info(f"PDF report generated: {report_path}")
    
    # Generate CSV report directly with HardenEKS results
    logger.info("Generating CSV report...")
    csv_generator = CSVGenerator()
    csv_path = csv_generator.generate_csv(hardeneks_results, cluster_details)
    logger.info(f"CSV report generated: {csv_path}")
    
    # Initialize remediation manager
    aws_access_key = args.aws_access_key or os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = args.aws_secret_key or os.environ.get('AWS_SECRET_ACCESS_KEY')
    region = args.region or os.environ.get('AWS_REGION', 'us-west-2')
    
    remediation_manager = RemediationManager(aws_access_key, aws_secret_key, region)
    
    # Get available remediations
    available_remediations = remediation_manager.get_available_remediations(hardeneks_results['failed_checks'])
    logger.info(f"Available remediations: {len(available_remediations)}")
    
    # Initialize compliance manager
    compliance_manager = ComplianceManager()
    
    # Get available compliance frameworks
    available_frameworks = compliance_manager.get_available_frameworks()
    logger.info(f"Available compliance frameworks: {len(available_frameworks)}")
    
    # Validate compliance against each framework
    compliance_results = {}
    for framework in available_frameworks:
        framework_id = framework['id']
        compliance_result = compliance_manager.validate_compliance(framework_id, hardeneks_results)
        compliance_results[framework_id] = compliance_result
        logger.info(f"Compliance score for {framework['name']}: {compliance_result.get('compliance_score', 0)}%")
    
    # Save all results to a JSON file
    results = {
        'timestamp': datetime.now().isoformat(),
        'cluster_name': cluster_details.get('cluster', {}).get('name', 'unknown'),
        'analysis_results': hardeneks_results,
        'available_remediations': available_remediations,
        'compliance_results': compliance_results
    }
    
    results_path = os.path.join(args.output_dir, f"eks_review_results_{datetime.now().strftime('%Y%m%d_%H%M')}.json")
    with open(results_path, 'w', encoding='utf-8') as file:
        json.dump(results, file, indent=2)
    
    logger.info(f"Results saved to {results_path}")
    logger.info("EKS Operational Review completed successfully")

if __name__ == "__main__":
    main()