"""
Comprehensive Excel Generator - Enterprise-grade reports with ALL checks
Includes all 152 DORA checks, CIS, NIST, SOC2, PCI DSS, HIPAA, ISO 27001
"""
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List
import io

class ComprehensiveExcelGenerator:
    """Generate enterprise-grade Excel reports with ALL comprehensive checks"""
    
    def generate_report(self, analysis_results: Dict[str, Any], output_path: str):
        """Generate comprehensive Excel report with all checks"""
        
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            
            # 1. Executive Summary
            self._create_executive_summary(writer, analysis_results)
            
            # 2. ALL DORA Checks (152 checks)
            self._create_dora_checks_sheet(writer, analysis_results)
            
            # 3. ALL CIS EKS Benchmark Checks
            self._create_cis_checks_sheet(writer, analysis_results)
            
            # 4. ALL NIST CSF Checks
            self._create_nist_checks_sheet(writer, analysis_results)
            
            # 5. ALL SOC 2 Checks
            self._create_soc2_checks_sheet(writer, analysis_results)
            
            # 6. ALL PCI DSS Checks
            self._create_pci_checks_sheet(writer, analysis_results)
            
            # 7. ALL HIPAA Checks
            self._create_hipaa_checks_sheet(writer, analysis_results)
            
            # 8. ALL ISO 27001 Checks
            self._create_iso27001_checks_sheet(writer, analysis_results)
            
            # 9. ALL Checks Combined (300+ checks)
            self._create_all_checks_combined(writer, analysis_results)
            
            # 10. Failed Checks with Detailed Remediation
            self._create_failed_checks_detailed(writer, analysis_results)
            
            # 11. Comprehensive Recommendations
            self._create_comprehensive_recommendations(writer, analysis_results)
            
            # 12. HardenEKS Detailed Analysis
            self._create_hardeneks_detailed(writer, analysis_results)
            
            # 13. Commands Executed
            self._create_commands_sheet(writer, analysis_results)
    
    def _create_dora_checks_sheet(self, writer, results):
        """Create sheet with ALL 152 DORA checks"""
        dora_checks = []
        
        # Get DORA analysis results
        dora_analysis = results.get('dora_analysis', {})
        detailed_results = dora_analysis.get('detailed_results', [])
        
        # If no results, create template with all 152 checks
        if not detailed_results:
            detailed_results = self._get_all_dora_check_definitions()
        
        for check in detailed_results:
            commands_str = '\n'.join([cmd.get('command', '') for cmd in check.get('commands_executed', [])])
            observations_str = '\n'.join([f"[{obs.get('severity', 'INFO')}] {obs.get('text', '')}" 
                                         for obs in check.get('observations', [])])
            steps_str = '\n'.join([f"{i+1}. {step}" for i, step in enumerate(check.get('recommendation', {}).get('steps', []))])
            rec_commands = '\n'.join(check.get('recommendation', {}).get('commands', []))
            
            dora_checks.append({
                'Check ID': check.get('check_id', 'N/A'),
                'Title': check.get('title', 'N/A'),
                'Category': check.get('category', 'N/A'),
                'DORA Article': check.get('dora_article', 'N/A'),
                'Severity': check.get('severity', 'N/A'),
                'Status': check.get('status', 'NOT_RUN'),
                'Commands Executed': commands_str,
                'Observations': observations_str,
                'Reasoning': check.get('reasoning', 'N/A'),
                'Business Impact': check.get('recommendation', {}).get('business_impact', 'N/A'),
                'Remediation Steps': steps_str,
                'Remediation Commands': rec_commands,
                'Verification Commands': '\n'.join(check.get('recommendation', {}).get('verification', [])),
                'Effort': check.get('recommendation', {}).get('effort', 'N/A'),
                'Risk': check.get('recommendation', {}).get('risk', 'N/A'),
                'Documentation': '\n'.join(check.get('recommendation', {}).get('documentation_links', []))
            })
        
        df = pd.DataFrame(dora_checks)
        df.to_excel(writer, sheet_name='DORA All 152 Checks', index=False)
        self._format_sheet(writer.sheets['DORA All 152 Checks'])
    
    def _get_all_dora_check_definitions(self):
        """Get all 152 DORA check definitions"""
        from core.dora_comprehensive_analyzer import DORAComprehensiveAnalyzer
        analyzer = DORAComprehensiveAnalyzer()
        return analyzer.get_all_dora_checks()
    
    def _create_cis_checks_sheet(self, writer, results):
        """Create sheet with ALL CIS EKS Benchmark checks"""
        from core.check_definitions import ComprehensiveCheckDefinitions
        
        cis_checks = []
        cis_analysis = results.get('cis_analysis', {})
        detailed_results = cis_analysis.get('detailed_results', [])
        
        # Get all CIS check definitions
        all_checks = ComprehensiveCheckDefinitions.get_cis_eks_checks()
        
        for check_def in all_checks:
            # Find matching result
            result = next((r for r in detailed_results if r.get('check_id') == check_def['check_id']), None)
            
            if result:
                commands_str = '\n'.join([cmd.get('command', '') for cmd in result.get('commands_executed', [])])
                observations_str = '\n'.join([f"[{obs.get('severity', 'INFO')}] {obs.get('text', '')}" 
                                             for obs in result.get('observations', [])])
            else:
                commands_str = '\n'.join([cmd['command'] for cmd in check_def.get('commands', [])])
                observations_str = 'Not executed'
            
            rec = check_def.get('recommendation_template', {})
            
            cis_checks.append({
                'Check ID': check_def['check_id'],
                'Title': check_def['title'],
                'Category': check_def['category'],
                'Severity': check_def['severity'],
                'Status': result.get('status', 'NOT_RUN') if result else 'NOT_RUN',
                'Commands Executed': commands_str,
                'Observations': observations_str,
                'Reasoning': result.get('reasoning', 'Not executed') if result else 'Not executed',
                'Business Impact': rec.get('business_impact', 'N/A'),
                'Remediation Steps': '\n'.join([f"{i+1}. {step}" for i, step in enumerate(rec.get('steps', []))]),
                'Remediation Commands': '\n'.join(rec.get('commands', [])),
                'Verification': '\n'.join(rec.get('verification', [])),
                'Effort': rec.get('effort', 'N/A'),
                'Risk': rec.get('risk', 'N/A'),
                'Documentation': '\n'.join(rec.get('documentation_links', []))
            })
        
        df = pd.DataFrame(cis_checks)
        df.to_excel(writer, sheet_name='CIS EKS All Checks', index=False)
        self._format_sheet(writer.sheets['CIS EKS All Checks'])
    
    def _create_all_checks_combined(self, writer, results):
        """Create sheet with ALL 300+ checks from all frameworks"""
        all_checks = []
        
        # Collect from all frameworks
        for framework_key in ['dora_analysis', 'cis_analysis', 'nist_analysis', 
                              'soc2_analysis', 'pci_analysis', 'hipaa_analysis', 
                              'iso27001_analysis']:
            framework_data = results.get(framework_key, {})
            framework_name = framework_data.get('framework', framework_key.replace('_analysis', '').upper())
            detailed_results = framework_data.get('detailed_results', [])
            
            for check in detailed_results:
                commands_str = '\n'.join([cmd.get('command', '') for cmd in check.get('commands_executed', [])])
                observations_str = '\n'.join([f"[{obs.get('severity', 'INFO')}] {obs.get('text', '')}" 
                                             for obs in check.get('observations', [])])
                
                all_checks.append({
                    'Framework': framework_name,
                    'Check ID': check.get('check_id', 'N/A'),
                    'Title': check.get('title', 'N/A'),
                    'Category': check.get('category', 'N/A'),
                    'Severity': check.get('severity', 'N/A'),
                    'Status': check.get('status', 'NOT_RUN'),
                    'Commands Executed': commands_str,
                    'Observations': observations_str,
                    'Reasoning': check.get('reasoning', 'N/A'),
                    'Business Impact': check.get('recommendation', {}).get('business_impact', 'N/A'),
                    'Remediation': check.get('recommendation', {}).get('description', 'N/A'),
                    'Effort': check.get('recommendation', {}).get('effort', 'N/A'),
                    'Risk': check.get('recommendation', {}).get('risk', 'N/A')
                })
        
        df = pd.DataFrame(all_checks)
        df.to_excel(writer, sheet_name='All 300+ Checks', index=False)
        self._format_sheet(writer.sheets['All 300+ Checks'])
    
    def _create_failed_checks_detailed(self, writer, results):
        """Create detailed sheet for all failed checks"""
        failed_checks = []
        
        for framework_key in ['dora_analysis', 'cis_analysis', 'nist_analysis', 
                              'soc2_analysis', 'pci_analysis', 'hipaa_analysis', 
                              'iso27001_analysis']:
            framework_data = results.get(framework_key, {})
            framework_name = framework_data.get('framework', framework_key.replace('_analysis', '').upper())
            detailed_results = framework_data.get('detailed_results', [])
            
            for check in detailed_results:
                if check.get('status', '').upper() in ['FAILED', 'FAIL']:
                    rec = check.get('recommendation', {})
                    
                    failed_checks.append({
                        'Framework': framework_name,
                        'Check ID': check.get('check_id', 'N/A'),
                        'Title': check.get('title', 'N/A'),
                        'Severity': check.get('severity', 'N/A'),
                        'Category': check.get('category', 'N/A'),
                        'Why It Failed': check.get('reasoning', 'N/A'),
                        'Business Impact': rec.get('business_impact', 'N/A'),
                        'Risk': rec.get('risk', 'N/A'),
                        'Remediation Description': rec.get('description', 'N/A'),
                        'Step 1': rec.get('steps', [''])[0] if rec.get('steps') else '',
                        'Step 2': rec.get('steps', ['', ''])[1] if len(rec.get('steps', [])) > 1 else '',
                        'Step 3': rec.get('steps', ['', '', ''])[2] if len(rec.get('steps', [])) > 2 else '',
                        'Command 1': rec.get('commands', [''])[0] if rec.get('commands') else '',
                        'Command 2': rec.get('commands', ['', ''])[1] if len(rec.get('commands', [])) > 1 else '',
                        'Verification': '\n'.join(rec.get('verification', [])),
                        'Effort': rec.get('effort', 'N/A'),
                        'Documentation': '\n'.join(rec.get('documentation_links', []))
                    })
        
        df = pd.DataFrame(failed_checks)
        df.to_excel(writer, sheet_name='Failed Checks Detailed', index=False)
        self._format_sheet(writer.sheets['Failed Checks Detailed'])
    
    def _create_comprehensive_recommendations(self, writer, results):
        """Create comprehensive recommendations sheet"""
        obs_analysis = results.get('observation_analysis', {})
        recommendations = []
        
        # Get prioritized recommendations
        prioritized = obs_analysis.get('prioritized_recommendations', [])
        
        for rec in prioritized:
            recommendations.append({
                'Priority': rec.get('priority', 'N/A'),
                'Check ID': rec.get('check_id', 'N/A'),
                'Title': rec.get('title', 'N/A'),
                'Severity': rec.get('severity', 'N/A'),
                'Business Impact': rec.get('business_impact', 'N/A'),
                'Effort': rec.get('effort', 'N/A'),
                'Estimated Time': rec.get('estimated_time', 'N/A'),
                'Quick Fix Commands': '\n'.join(rec.get('quick_fix', []))
            })
        
        df = pd.DataFrame(recommendations)
        df.to_excel(writer, sheet_name='Prioritized Recommendations', index=False)
        self._format_sheet(writer.sheets['Prioritized Recommendations'])
    
    def _create_hardeneks_detailed(self, writer, results):
        """Create detailed HardenEKS analysis sheet"""
        hardeneks_data = results.get('hardeneks_analysis', {})
        checks = hardeneks_data.get('checks', [])
        
        hardeneks_checks = []
        for check in checks:
            hardeneks_checks.append({
                'Check ID': check.get('id', 'N/A'),
                'Title': check.get('title', 'N/A'),
                'Category': check.get('category', 'N/A'),
                'Severity': check.get('severity', 'N/A'),
                'Status': check.get('status', 'N/A'),
                'Description': check.get('description', 'N/A'),
                'Finding': check.get('finding', 'N/A'),
                'Recommendation': check.get('recommendation', 'N/A'),
                'AWS Best Practice': check.get('aws_best_practice', 'N/A'),
                'Documentation': check.get('documentation_link', 'N/A')
            })
        
        df = pd.DataFrame(hardeneks_checks)
        df.to_excel(writer, sheet_name='HardenEKS Detailed', index=False)
        self._format_sheet(writer.sheets['HardenEKS Detailed'])
    
    def _create_commands_sheet(self, writer, results):
        """Create sheet with all commands executed"""
        commands = []
        
        for framework_key in ['dora_analysis', 'cis_analysis', 'nist_analysis', 
                              'soc2_analysis', 'pci_analysis', 'hipaa_analysis', 
                              'iso27001_analysis']:
            framework_data = results.get(framework_key, {})
            detailed_results = framework_data.get('detailed_results', [])
            
            for check in detailed_results:
                for cmd in check.get('commands_executed', []):
                    commands.append({
                        'Check ID': check.get('check_id', 'N/A'),
                        'Check Title': check.get('title', 'N/A'),
                        'Command': cmd.get('command', 'N/A'),
                        'Description': cmd.get('description', 'N/A'),
                        'Timestamp': cmd.get('timestamp', 'N/A'),
                        'Output Summary': str(cmd.get('output', ''))[:200]
                    })
        
        df = pd.DataFrame(commands)
        df.to_excel(writer, sheet_name='Commands Executed', index=False)
        self._format_sheet(writer.sheets['Commands Executed'])
    
    def _create_executive_summary(self, writer, results):
        """Create executive summary sheet"""
        overall = results.get('overall_metrics', {})
        
        summary_data = {
            'Metric': [
                'Total Checks Executed',
                'Checks Passed',
                'Checks Failed',
                'Overall Compliance %',
                'Risk Level',
                'Frameworks Assessed',
                'Analysis Date'
            ],
            'Value': [
                overall.get('total_checks_across_all_frameworks', 0),
                overall.get('total_passed', 0),
                overall.get('total_failed', 0),
                f"{overall.get('overall_compliance_percentage', 0):.1f}%",
                overall.get('risk_level', 'UNKNOWN'),
                overall.get('frameworks_assessed', 7),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ]
        }
        
        df = pd.DataFrame(summary_data)
        df.to_excel(writer, sheet_name='Executive Summary', index=False)
        self._format_sheet(writer.sheets['Executive Summary'])
    
    def _create_nist_checks_sheet(self, writer, results):
        """Create NIST checks sheet"""
        self._create_framework_sheet(writer, results, 'nist_analysis', 'NIST CSF All Checks')
    
    def _create_soc2_checks_sheet(self, writer, results):
        """Create SOC2 checks sheet"""
        self._create_framework_sheet(writer, results, 'soc2_analysis', 'SOC2 All Checks')
    
    def _create_pci_checks_sheet(self, writer, results):
        """Create PCI DSS checks sheet"""
        self._create_framework_sheet(writer, results, 'pci_analysis', 'PCI DSS All Checks')
    
    def _create_hipaa_checks_sheet(self, writer, results):
        """Create HIPAA checks sheet"""
        self._create_framework_sheet(writer, results, 'hipaa_analysis', 'HIPAA All Checks')
    
    def _create_iso27001_checks_sheet(self, writer, results):
        """Create ISO 27001 checks sheet"""
        self._create_framework_sheet(writer, results, 'iso27001_analysis', 'ISO27001 All Checks')
    
    def _create_framework_sheet(self, writer, results, framework_key, sheet_name):
        """Generic method to create framework-specific sheet"""
        framework_data = results.get(framework_key, {})
        detailed_results = framework_data.get('detailed_results', [])
        
        checks = []
        for check in detailed_results:
            commands_str = '\n'.join([cmd.get('command', '') for cmd in check.get('commands_executed', [])])
            observations_str = '\n'.join([f"[{obs.get('severity', 'INFO')}] {obs.get('text', '')}" 
                                         for obs in check.get('observations', [])])
            
            checks.append({
                'Check ID': check.get('check_id', 'N/A'),
                'Title': check.get('title', 'N/A'),
                'Category': check.get('category', 'N/A'),
                'Severity': check.get('severity', 'N/A'),
                'Status': check.get('status', 'NOT_RUN'),
                'Commands': commands_str,
                'Observations': observations_str,
                'Reasoning': check.get('reasoning', 'N/A'),
                'Recommendation': check.get('recommendation', {}).get('description', 'N/A'),
                'Business Impact': check.get('recommendation', {}).get('business_impact', 'N/A')
            })
        
        df = pd.DataFrame(checks)
        df.to_excel(writer, sheet_name=sheet_name, index=False)
        self._format_sheet(writer.sheets[sheet_name])
    
    def _format_sheet(self, worksheet):
        """Format worksheet for better readability"""
        from openpyxl.styles import Font, PatternFill, Alignment
        
        # Header formatting
        header_fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
        header_font = Font(bold=True, color="FFFFFF")
        
        for cell in worksheet[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        
        # Auto-adjust column widths
        for column in worksheet.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)
            worksheet.column_dimensions[column_letter].width = adjusted_width
