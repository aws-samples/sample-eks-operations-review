#!/usr/bin/env python3
"""Test the enhanced analyzer"""
import json

# Test with offline data
with open('reports/eks_analysis_strands-cluster_20251127_1845.json', 'r') as f:
    offline_data = json.load(f)

from core.unified_analyzer import UnifiedClusterAnalyzer

print("Creating analyzer...")
analyzer = UnifiedClusterAnalyzer(
    cluster_name='strands-cluster',
    region='us-west-2',
    offline_data=offline_data
)

print("Running analysis...")
results = analyzer.run_comprehensive_analysis()

print(f"\nResults keys: {list(results.keys())}")
if 'enhanced_checks' in results:
    print(f"Enhanced checks: {results['enhanced_checks'].get('summary', {})}")
else:
    print("No enhanced checks found")

print("\nTest complete!")
