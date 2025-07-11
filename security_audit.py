#!/usr/bin/env python3
"""
Security audit script to verify all vulnerabilities are fixed
"""
import os
import re
import subprocess
import sys

def scan_file_for_issues(filepath):
    """Scan a single file for security issues"""
    issues = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Check for command injection patterns
            if 'subprocess.run(' in line and ('cmd' in line or '[' not in line):
                issues.append(f"Line {i}: Potential command injection - {line_stripped[:80]}")
            
            # Check for logging errors without handling
            if 'logger.error(' in line and 'raise' in lines[min(i, len(lines)-1)]:
                issues.append(f"Line {i}: Error logging without handling - {line_stripped[:80]}")
            
            # Check for open() without encoding
            if re.search(r"open\([^)]*\)", line) and 'encoding=' not in line:
                issues.append(f"Line {i}: Missing encoding parameter - {line_stripped[:80]}")
            
            # Check for csv module usage
            if 'import csv' in line and 'defusedcsv' not in line:
                issues.append(f"Line {i}: Using unsafe csv module - {line_stripped[:80]}")
            
            # Check for time.sleep
            if 'time.sleep(' in line:
                issues.append(f"Line {i}: Arbitrary sleep detected - {line_stripped[:80]}")
                
    except Exception as e:
        issues.append(f"Error reading file: {e}")
    
    return issues

def main():
    """Main audit function"""
    print("🔍 Starting comprehensive security audit...")
    
    # Files to audit based on previous scan results
    files_to_check = [
        'src/utils/kubernetes_client_secure.py',
        'src/utils/kubernetes_client.py', 
        'src/remediation/remediation_manager_secure.py',
        'src/analyzers/cluster_analyzer.py',
        'bedrock_agent.py',
        'src/utils/csv_generator.py',
        'app.py',
        'src/utils/report_generator.py'
    ]
    
    total_issues = 0
    
    for filepath in files_to_check:
        if os.path.exists(filepath):
            print(f"\n📁 Scanning {filepath}...")
            issues = scan_file_for_issues(filepath)
            
            if issues:
                print(f"❌ Found {len(issues)} issues:")
                for issue in issues:
                    print(f"  - {issue}")
                total_issues += len(issues)
            else:
                print("✅ No issues found")
        else:
            print(f"⚠️  File not found: {filepath}")
    
    print(f"\n📊 AUDIT SUMMARY:")
    print(f"Total issues found: {total_issues}")
    
    if total_issues == 0:
        print("🎉 ALL SECURITY ISSUES APPEAR TO BE FIXED!")
        return 0
    else:
        print("❌ Security issues still exist - manual review required")
        return 1

if __name__ == "__main__":
    sys.exit(main())