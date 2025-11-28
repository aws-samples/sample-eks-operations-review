#!/usr/bin/env python3
"""
Dedicated CLI tool for EKS offline analysis
Usage: python offline_cli.py <json_file> [--format pdf|json|both]
"""

import sys
import json
import argparse
from datetime import datetime
import os

# Import our core components
from core.unified_analyzer import UnifiedClusterAnalyzer
from utils.pdf_generator import PDFGenerator
from utils.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description='EKS Offline Analysis Tool')
    parser.add_argument('json_file', help='Path to the offline data JSON file')
    parser.add_argument('--format', choices=['pdf', 'json', 'both'], default='both', 
                       help='Output format (default: both)')
    parser.add_argument('--output-dir', default='.', help='Output directory (default: current directory)')
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not os.path.exists(args.json_file):
        print(f"Error: File '{args.json_file}' not found.")
        sys.exit(1)
    
    print(f"Starting EKS offline analysis...")
    print(f"Input file: {args.json_file}")
    print(f"Output format: {args.format}")
    print(f"Output directory: {args.output_dir}")
    print("-" * 50)
    
    try:
        # Load offline data
        print("Loading offline data...")
        with open(args.json_file, 'r') as f:
            offline_data = json.load(f)
        
        cluster_name = offline_data.get('cluster_name', 'unknown-cluster')
        print(f"Analyzing cluster: {cluster_name}")
        
        # Initialize unified analyzer
        print("Initializing unified analyzer...")
        analyzer = UnifiedClusterAnalyzer(
            cluster_name=cluster_name,
            offline_data=offline_data
        )
        
        # Perform comprehensive analysis
        print("Performing comprehensive analysis...")
        results = analyzer.run_comprehensive_analysis()
        
        # Generate timestamp for output files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate outputs based on format choice
        if args.format in ['json', 'both']:
            print("Generating JSON report...")
            json_filename = f"eks_analysis_{cluster_name}_{timestamp}.json"
            json_path = os.path.join(args.output_dir, json_filename)
            
            with open(json_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"✓ JSON report saved: {json_path}")
        
        if args.format in ['pdf', 'both']:
            print("Generating PDF report...")
            pdf_generator = PDFGenerator()
            pdf_data = pdf_generator.generate_report(results, cluster_name)
            
            pdf_filename = f"eks_analysis_{cluster_name}_{timestamp}.pdf"
            pdf_path = os.path.join(args.output_dir, pdf_filename)
            
            with open(pdf_path, 'wb') as f:
                f.write(pdf_data)
            
            print(f"✓ PDF report saved: {pdf_path}")
        
        # Print summary
        print("-" * 50)
        print("ANALYSIS SUMMARY")
        print("-" * 50)
        
        # Security summary
        security = results.get('security_analysis', {})
        if security:
            total_checks = security.get('total_checks', 0)
            passed_checks = security.get('passed_checks', 0)
            failed_checks = security.get('failed_checks', 0)
            
            print(f"Security Checks: {passed_checks}/{total_checks} passed ({failed_checks} failed)")
            
            if failed_checks > 0:
                print("Failed security checks:")
                for check in security.get('checks', []):
                    if check.get('status') == 'FAIL':
                        print(f"  ✗ {check.get('title', 'Unknown check')} ({check.get('severity', 'MEDIUM')})")
        
        # Health summary
        health = results.get('health_analysis', {})
        if health:
            cluster_info = health.get('cluster_info', {})
            print(f"Cluster Status: {cluster_info.get('status', 'Unknown')}")
            print(f"Kubernetes Version: {cluster_info.get('version', 'Unknown')}")
            
            node_analysis = health.get('node_analysis', {})
            if node_analysis:
                print(f"Total Nodes: {node_analysis.get('total_nodes', 0)}")
                print(f"Node Groups: {len(node_analysis.get('node_groups', []))}")
        
        # Recommendations
        recommendations = security.get('recommendations', [])
        if recommendations:
            print(f"Recommendations: {len(recommendations)} generated")
            print("Top recommendations:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"  {i}. {rec.get('title', 'Unknown recommendation')} ({rec.get('priority', 'MEDIUM')})")
        
        print("-" * 50)
        print("Analysis completed successfully!")
        
    except FileNotFoundError:
        print(f"Error: Could not find file '{args.json_file}'")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
