import os
import logging
from datetime import datetime
from fpdf import FPDF

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        pass

    def generate_report(self, cluster_details=None, analysis_results=None, inputs=None, kb_insights=None):
        """Generate a PDF report using FPDF"""
        try:
            # Create output directory if it doesn't exist
            output_dir = "reports"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            # Generate a filename with timestamp
            cluster_name = cluster_details.get('cluster', {}).get('name', 'unknown') if cluster_details else 'unknown'
            filename = f"eks_review_report_{cluster_name}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
            filepath = os.path.join(output_dir, filename)
            
            # Create PDF object
            pdf = FPDF()
            pdf.add_page()
            
            # Set font
            pdf.set_font("Arial", "B", 16)
            
            # Title
            pdf.cell(0, 10, "EKS Operational Review Report", 0, 1, "C")
            pdf.ln(10)
            
            # Cluster info
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, f"Cluster: {cluster_name}", 0, 1)
            pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}", 0, 1)
            pdf.ln(10)
            
            # Summary
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Summary", 0, 1)
            pdf.ln(5)
            
            pdf.set_font("Arial", "", 12)
            if analysis_results:
                pdf.cell(0, 10, f"HardenEKS Score: {analysis_results.get('hardeneks_score', 0)}%", 0, 1)
                pdf.cell(0, 10, f"High Priority Issues: {len(analysis_results.get('high_priority', []))}", 0, 1)
                pdf.cell(0, 10, f"Medium Priority Issues: {len(analysis_results.get('medium_priority', []))}", 0, 1)
                pdf.cell(0, 10, f"Low Priority Issues: {len(analysis_results.get('low_priority', []))}", 0, 1)
            pdf.ln(10)
            
            # Findings
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Findings", 0, 1)
            pdf.ln(5)
            
            if analysis_results:
                # High priority
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, "High Priority:", 0, 1)
                pdf.set_font("Arial", "", 10)
                
                for finding in analysis_results.get('high_priority', []):
                    pdf.multi_cell(0, 10, f"- {finding.get('title', 'Unknown')}: {finding.get('description', 'No description')}")
                pdf.ln(5)
                
                # Medium priority
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, "Medium Priority:", 0, 1)
                pdf.set_font("Arial", "", 10)
                
                for finding in analysis_results.get('medium_priority', []):
                    pdf.multi_cell(0, 10, f"- {finding.get('title', 'Unknown')}: {finding.get('description', 'No description')}")
                pdf.ln(5)
                
                # Low priority
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, "Low Priority:", 0, 1)
                pdf.set_font("Arial", "", 10)
                
                for finding in analysis_results.get('low_priority', []):
                    pdf.multi_cell(0, 10, f"- {finding.get('title', 'Unknown')}: {finding.get('description', 'No description')}")
                pdf.ln(5)
            
            # Recommendations
            pdf.add_page()
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Recommendations", 0, 1)
            pdf.ln(5)
            
            if analysis_results:
                pdf.set_font("Arial", "", 10)
                for finding in analysis_results.get('high_priority', []):
                    if 'action_items' in finding:
                        pdf.set_font("Arial", "B", 10)
                        pdf.cell(0, 10, f"{finding.get('title', 'Unknown')}:", 0, 1)
                        pdf.set_font("Arial", "", 10)
                        
                        for item in finding['action_items']:
                            pdf.multi_cell(0, 10, f"- {item}")
                        pdf.ln(5)
            
            # Output the PDF
            pdf.output(filepath)
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            # Fall back to simple text report
            from src.utils.simple_report_generator import ReportGenerator as SimpleReportGenerator
            simple_generator = SimpleReportGenerator()
            return simple_generator.generate_report(cluster_details, analysis_results, inputs, kb_insights)