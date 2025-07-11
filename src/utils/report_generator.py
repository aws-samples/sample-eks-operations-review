import logging
import os
import re
from datetime import datetime
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_styles()
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal attacks."""
        if not isinstance(filename, str):
            filename = str(filename)
        # Remove path separators and dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        # Limit length and remove leading/trailing dots and spaces
        sanitized = sanitized.strip('. ')[:50]
        return sanitized if sanitized else 'unknown'
    
    def _secure_filepath(self, directory: str, filename: str) -> Path:
        """Create a secure filepath preventing directory traversal."""
        # Convert to Path objects for secure handling
        base_dir = Path(directory).resolve()
        file_path = base_dir / filename
        
        # Ensure the resolved path is within the base directory
        try:
            file_path.resolve().relative_to(base_dir)
        except ValueError:
            raise ValueError("Invalid file path - potential directory traversal")
        
        return file_path
    
    def _sanitize_log_input(self, text: str) -> str:
        """Sanitize input for logging to prevent log injection."""
        if not isinstance(text, str):
            return str(text)
        # Remove newlines and control characters
        sanitized = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', '', text)
        return sanitized[:200]  # Limit length

    def _setup_styles(self):
        """Setup custom styles for the report"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#232F3E')  # AWS dark blue
        ))
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceBefore=12,
            spaceAfter=6,
            textColor=colors.HexColor('#232F3E')  # AWS dark blue
        ))
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=10,
            spaceAfter=6,
            textColor=colors.HexColor('#527FFF')  # AWS blue
        ))
        self.styles.add(ParagraphStyle(
            name='BulletPoint',
            parent=self.styles['Normal'],
            leftIndent=20,
            firstLineIndent=0,
            spaceBefore=5,
            spaceAfter=5
        ))
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#D13212'),  # AWS red
            fontSize=12,
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#FF9900'),  # AWS orange
            fontSize=12,
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            textColor=colors.HexColor('#1D8102'),  # AWS green
            fontSize=12,
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='TableHeader',
            parent=self.styles['Normal'],
            fontSize=10,
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            textColor=colors.white
        ))
        self.styles.add(ParagraphStyle(
            name='TableCell',
            parent=self.styles['Normal'],
            fontSize=9,
            alignment=TA_LEFT
        ))
        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.gray,
            alignment=TA_CENTER
        ))
        self.styles.add(ParagraphStyle(
            name='Caption',
            parent=self.styles['Normal'],
            fontSize=10,
            alignment=TA_CENTER,
            fontName='Helvetica-Oblique'
        ))

    def generate_report(self, inputs, cluster_details, analysis_results, kb_insights=None):
        """Generate comprehensive PDF report with secure file handling"""
        try:
            # Create output directory if it doesn't exist
            output_dir = "reports"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir, mode=0o755)
                
            # Sanitize cluster name for filename
            cluster_name = self._sanitize_filename(cluster_details.get('cluster', {}).get('name', 'unknown'))
            timestamp = datetime.now().strftime('%Y%m%d_%H%M')
            filename = f"eks_review_report_{cluster_name}_{timestamp}.pdf"
            
            # Validate and secure the filepath
            filepath = self._secure_filepath(output_dir, filename)
            filepath_str = str(filepath)
            
            doc = SimpleDocTemplate(
                filepath_str,
                pagesize=A4,
                rightMargin=50,
                leftMargin=50,
                topMargin=50,
                bottomMargin=50
            )

            story = []
            
            # Cover Page
            self._add_cover_page(story, cluster_details)
            story.append(PageBreak())
            
            # Table of Contents
            self._add_table_of_contents(story)
            story.append(PageBreak())
            
            # Executive Summary with visualizations
            self._add_executive_summary(story, cluster_details, analysis_results)
            story.append(PageBreak())
            
            # Cluster Information
            self._add_cluster_info(story, cluster_details)
            story.append(PageBreak())
            
            # Detailed Findings
            self._add_detailed_findings(story, analysis_results)
            story.append(PageBreak())
            
            # Recommendations
            self._add_recommendations(story, analysis_results)
            story.append(PageBreak())
            
            # Best Practices References
            self._add_references(story)
            
            # Add KB insights if available
            if kb_insights:
                story.append(PageBreak())
                self._add_kb_insights(story, kb_insights)
            
            # Add footer to all pages
            def add_page_number(canvas, doc):
                canvas.saveState()
                canvas.setFont('Helvetica', 8)
                canvas.setFillColor(colors.gray)
                footer_text = f"EKS Operational Review Report - Generated on {datetime.now().strftime('%Y-%m-%d')} - Page {doc.page}"
                canvas.drawCentredString(doc.pagesize[0]/2, 20, footer_text)
                canvas.restoreState()
            
            # Build the PDF with page numbers
            doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
            return filepath_str
            
        except Exception as e:
            sanitized_error = self._sanitize_log_input(str(e))
            logger.warning(f"Error generating report: {sanitized_error}")
            raise
            
    def _add_cover_page(self, story, cluster_details):
        """Add a professional cover page"""
        # Add AWS logo or custom logo if available
        # For now we'll just use text with AWS styling
        
        # Title with large font
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("EKS Operational Review", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Cluster name
        cluster_name = self._sanitize_log_input(cluster_details.get('cluster', {}).get('name', 'Unknown'))
        story.append(Paragraph(f"Cluster: {cluster_name}", 
                              ParagraphStyle(
                                  name='ClusterName',
                                  parent=self.styles['CustomHeading1'],
                                  fontSize=18,
                                  alignment=TA_CENTER
                              )))
        story.append(Spacer(1, 0.25*inch))
        
        # Date
        story.append(Paragraph(f"Report Date: {datetime.now().strftime('%B %d, %Y')}", 
                              ParagraphStyle(
                                  name='ReportDate',
                                  parent=self.styles['Normal'],
                                  fontSize=14,
                                  alignment=TA_CENTER
                              )))
        
        story.append(Spacer(1, 2*inch))
        
        # Confidentiality notice
        story.append(Paragraph("CONFIDENTIAL", 
                              ParagraphStyle(
                                  name='Confidential',
                                  parent=self.styles['Normal'],
                                  fontSize=10,
                                  alignment=TA_CENTER,
                                  textColor=colors.gray
                              )))
        
    def _add_table_of_contents(self, story):
        """Add table of contents"""
        story.append(Paragraph("Table of Contents", self.styles['CustomHeading1']))
        story.append(Spacer(1, 0.2*inch))
        
        toc_items = [
            ("1. Executive Summary", "3"),
            ("2. Cluster Information", "4"),
            ("3. Detailed Findings", "5"),
            ("   3.1 High Priority Issues", "5"),
            ("   3.2 Medium Priority Issues", ""),
            ("   3.3 Low Priority Issues", ""),
            ("4. Recommendations", ""),
            ("5. References and Resources", "")
        ]
        
        # Create a table for TOC
        toc_data = [[item, page] for item, page in toc_items]
        toc_table = Table(toc_data, colWidths=[5*inch, 0.5*inch])
        toc_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('LINEBELOW', (0, -1), (-1, -1), 1, colors.black),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.lightgrey),
        ]))
        
        story.append(toc_table)
        
    def _add_kb_insights(self, story, kb_insights):
        """Add knowledge base insights to the report"""
        story.append(Paragraph("Knowledge Base Insights", self.styles['CustomHeading1']))
        story.append(Spacer(1, 0.1*inch))
        
        for pillar, fields in kb_insights.items():
            story.append(Paragraph(pillar, self.styles['CustomHeading2']))
            for field, insight in fields.items():
                story.append(Paragraph(field, 
                                      ParagraphStyle(
                                          name='InsightTitle',
                                          parent=self.styles['Normal'],
                                          fontSize=12,
                                          fontName='Helvetica-Bold'
                                      )))
                story.append(Paragraph(insight, self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
                    
    def _add_cluster_info(self, story, cluster_details):
        """Add cluster information section"""
        story.append(Paragraph("Cluster Information", self.styles['CustomHeading1']))
        story.append(Spacer(1, 0.1*inch))
        
        # Create a table for cluster information
        data = [
            ["Property", "Value"],
            ["Cluster Name", self._sanitize_log_input(cluster_details.get('cluster', {}).get('name', 'N/A'))],
            ["Kubernetes Version", self._sanitize_log_input(str(cluster_details.get('cluster', {}).get('version', 'N/A')))],
            ["Status", self._sanitize_log_input(str(cluster_details.get('cluster', {}).get('status', 'N/A')))],
            ["Platform Version", self._sanitize_log_input(str(cluster_details.get('cluster', {}).get('platform_version', 'N/A')))],
            ["Region", cluster_details.get('cluster', {}).get('region', 'N/A')],
            ["Created At", cluster_details.get('cluster', {}).get('created_at', 'N/A')]
        ]
        
        # Add nodegroup information if available
        if 'nodegroups' in cluster_details and cluster_details['nodegroups']:
            data.append(["Total Node Groups", str(len(cluster_details['nodegroups']))])
            
            # Count nodes by type
            on_demand_count = 0
            spot_count = 0
            for ng in cluster_details['nodegroups']:
                if ng.get('capacityType') == 'ON_DEMAND':
                    on_demand_count += 1
                elif ng.get('capacityType') == 'SPOT':
                    spot_count += 1
            
            data.append(["On-Demand Node Groups", str(on_demand_count)])
            data.append(["Spot Node Groups", str(spot_count)])
        
        # Add networking information if available
        if 'networking' in cluster_details:
            net = cluster_details['networking']
            data.append(["VPC ID", net.get('vpc_id', 'N/A')])
            data.append(["Public Endpoint", "Enabled" if net.get('endpoint_access', {}).get('public', False) else "Disabled"])
            data.append(["Private Endpoint", "Enabled" if net.get('endpoint_access', {}).get('private', False) else "Disabled"])
        
        # Create the table
        table = Table(data, colWidths=[2*inch, 3*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#232F3E')),  # AWS dark blue header
            ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
            ('ALIGN', (0, 0), (1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (1, 0), 8),
            ('BACKGROUND', (0, 1), (1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('TOPPADDING', (0, 1), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.2*inch))
        
        # Add node group details in a separate table if available
        if 'nodegroups' in cluster_details and cluster_details['nodegroups']:
            story.append(Paragraph("Node Group Details", self.styles['CustomHeading2']))
            story.append(Spacer(1, 0.1*inch))
            
            ng_data = [["Name", "Instance Type", "Capacity Type", "Min Size", "Max Size", "Desired Size"]]
            
            for ng in cluster_details['nodegroups']:
                ng_data.append([
                    ng.get('name', 'N/A'),
                    ng.get('instanceType', 'N/A'),
                    ng.get('capacityType', 'N/A'),
                    str(ng.get('minSize', 'N/A')),
                    str(ng.get('maxSize', 'N/A')),
                    str(ng.get('desiredSize', 'N/A'))
                ])
            
            ng_table = Table(ng_data, colWidths=[1.5*inch, 1*inch, 1*inch, 0.7*inch, 0.7*inch, 0.7*inch])
            ng_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#527FFF')),  # AWS blue header
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 1), (0, -1), 'LEFT'),
                ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('TOPPADDING', (0, 1), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
            ]))
            
            story.append(ng_table)
        
        story.append(Spacer(1, 0.2*inch))

    def _add_executive_summary(self, story, cluster_details, analysis_results):
        """Add executive summary section with visualizations"""
        story.append(Paragraph("Executive Summary", self.styles['CustomHeading1']))
        story.append(Spacer(1, 0.1*inch))
        
        # Count applicable findings
        applicable_high = 0
        applicable_medium = 0
        applicable_low = 0
        
        for finding in analysis_results['high_priority']:
            if self._is_finding_applicable(finding, analysis_results):
                applicable_high += 1
                
        for finding in analysis_results['medium_priority']:
            if self._is_finding_applicable(finding, analysis_results):
                applicable_medium += 1
                
        for finding in analysis_results['low_priority']:
            if self._is_finding_applicable(finding, analysis_results):
                applicable_low += 1
        
        # Summary text
        summary = f"""This report provides a comprehensive analysis of the EKS cluster "{cluster_details['cluster']['name']}" 
        based on AWS best practices and industry standards. The analysis was completed on {datetime.now().strftime('%B %d, %Y at %H:%M')}.
        
        The review identified {applicable_high} high priority issues, {applicable_medium} medium priority issues, 
        and {applicable_low} low priority issues that should be addressed to improve the cluster's security, reliability, 
        performance, and operational excellence.
        """
        story.append(Paragraph(summary, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Create a findings summary table
        story.append(Paragraph("Findings Summary", self.styles['CustomHeading2']))
        story.append(Spacer(1, 0.1*inch))
        
        # Count findings by category
        categories = {}
        for priority in ['high_priority', 'medium_priority', 'low_priority']:
            for finding in analysis_results[priority]:
                # Skip findings that are not applicable
                if not self._is_finding_applicable(finding, analysis_results):
                    continue
                    
                category = finding.get('category', 'Other')
                if category not in categories:
                    categories[category] = {'high': 0, 'medium': 0, 'low': 0}
                
                if priority == 'high_priority':
                    categories[category]['high'] += 1
                elif priority == 'medium_priority':
                    categories[category]['medium'] += 1
                else:
                    categories[category]['low'] += 1
        
        # Create table data
        table_data = [["Category", "High", "Medium", "Low", "Total"]]
        
        for category, counts in sorted(categories.items()):
            total = counts['high'] + counts['medium'] + counts['low']
            table_data.append([
                category,
                str(counts['high']),
                str(counts['medium']),
                str(counts['low']),
                str(total)
            ])
        
        # Add totals row
        high_total = sum(c['high'] for c in categories.values())
        medium_total = sum(c['medium'] for c in categories.values())
        low_total = sum(c['low'] for c in categories.values())
        grand_total = high_total + medium_total + low_total
        
        table_data.append([
            "Total",
            str(high_total),
            str(medium_total),
            str(low_total),
            str(grand_total)
        ])
        
        # Create and style the table
        findings_table = Table(table_data, colWidths=[2*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232F3E')),  # AWS dark blue header
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -2), colors.white),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#F2F3F3')),  # Light gray for totals
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('TEXTCOLOR', (1, 1), (1, -2), colors.red),  # High priority in red
            ('TEXTCOLOR', (2, 1), (2, -2), colors.orange),  # Medium priority in orange
            ('TEXTCOLOR', (3, 1), (3, -2), colors.green),  # Low priority in green
        ]))
        
        story.append(findings_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Add pie chart for findings distribution only if there are findings
        if grand_total > 0:
            story.append(Paragraph("Findings Distribution", self.styles['CustomHeading2']))
            story.append(Spacer(1, 0.1*inch))
            
            # Create a drawing for the pie chart
            drawing = Drawing(500, 300)
            
            # Create pie chart
            pie = Pie()
            pie.x = 200
            pie.y = 75
            pie.width = 180
            pie.height = 180
            pie.data = [high_total, medium_total, low_total]
            pie.labels = ['High', 'Medium', 'Low']
            pie.slices.strokeWidth = 1.0
            pie.sideLabels = True
            pie.simpleLabels = False
            pie.labels = ['High Priority', 'Medium Priority', 'Low Priority']
            
            # Set colors for pie slices
            pie.slices[0].fillColor = colors.red
            pie.slices[1].fillColor = colors.orange
            pie.slices[2].fillColor = colors.green
            
            drawing.add(pie)
            story.append(drawing)
            
            # Add caption for the chart
            story.append(Paragraph("Figure 1: Distribution of findings by priority level", self.styles['Caption']))
            story.append(Spacer(1, 0.2*inch))
        else:
            story.append(Paragraph("No applicable findings to display in chart.", self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        # Add key recommendations section
        story.append(Paragraph("Key Recommendations", self.styles['CustomHeading2']))
        story.append(Spacer(1, 0.1*inch))
        
        # Get top 5 applicable high priority findings
        applicable_findings = [f for f in analysis_results['high_priority'] if self._is_finding_applicable(f, analysis_results)]
        top_findings = applicable_findings[:5] if applicable_findings else []
        
        if top_findings:
            for i, finding in enumerate(top_findings):
                story.append(Paragraph(f"{i+1}. {finding.get('title', 'N/A')}", self.styles['RiskHigh']))
                story.append(Paragraph(f"   {finding.get('description', 'N/A')}", self.styles['Normal']))
                story.append(Spacer(1, 0.05*inch))
        else:
            story.append(Paragraph("No high priority findings identified.", self.styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))

    def _add_detailed_findings(self, story, analysis_results):
        """Add detailed findings to the report with improved formatting."""
        story.append(Paragraph("Detailed Findings", self.styles['CustomHeading1']))
        story.append(Spacer(1, 0.1*inch))
        
        # Introduction text
        intro = """This section provides detailed information about all identified issues, categorized by priority level. 
        Each finding includes a description of the issue, its potential impact, and recommended action items to address it."""
        story.append(Paragraph(intro, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        priority_levels = [
            ('high_priority', 'High Priority', self.styles['RiskHigh'], colors.HexColor('#FFEBE6')),  # Light red background
            ('medium_priority', 'Medium Priority', self.styles['RiskMedium'], colors.HexColor('#FFF8E6')),  # Light orange background
            ('low_priority', 'Low Priority', self.styles['RiskLow'], colors.HexColor('#E6F5E6'))  # Light green background
        ]

        for priority_key, priority_title, priority_style, bg_color in priority_levels:
            if analysis_results.get(priority_key):
                story.append(Paragraph(priority_title, self.styles['CustomHeading2']))
                story.append(Spacer(1, 0.1*inch))
                
                # Group findings by category
                findings_by_category = {}
                for finding in analysis_results[priority_key]:
                    # Check if the finding is applicable to the current cluster
                    if not self._is_finding_applicable(finding, analysis_results):
                        continue
                        
                    category = finding.get('category', 'Other')
                    if category not in findings_by_category:
                        findings_by_category[category] = []
                    findings_by_category[category].append(finding)
                
                # Process each category
                for category, findings in sorted(findings_by_category.items()):
                    story.append(Paragraph(f"{category}", 
                                          ParagraphStyle(
                                              name=f"{category}Title",
                                              parent=self.styles['CustomHeading2'],
                                              fontSize=14,
                                              spaceBefore=10,
                                              spaceAfter=5
                                          )))
                    
                    # Process each finding in the category
                    for i, finding in enumerate(findings):
                        # Create a table for each finding
                        data = [
                            [Paragraph(f"<b>Finding {i+1}:</b> {finding.get('title', 'N/A')}", priority_style)]
                        ]
                        
                        # Description row
                        data.append([Paragraph(f"<b>Description:</b> {finding.get('description', 'N/A')}", self.styles['Normal'])])
                        
                        # Impact row
                        data.append([Paragraph(f"<b>Impact:</b> {finding.get('impact', 'N/A')}", self.styles['Normal'])])
                        
                        # Action items
                        if finding.get('action_items'):
                            action_items_text = "<b>Action Items:</b><br/>"
                            for item in finding['action_items']:
                                action_items_text += f"• {item}<br/>"
                            data.append([Paragraph(action_items_text, self.styles['Normal'])])
                        
                        # Reference row
                        if finding.get('reference'):
                            data.append([Paragraph(f"<b>Reference:</b> <link href='{finding['reference']}'><font color='blue'>{finding['reference']}</font></link>", self.styles['Normal'])])
                        
                        # Create and style the table
                        finding_table = Table(data, colWidths=[5.5*inch])
                        finding_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, 0), bg_color),  # Header row with priority color
                            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                            ('BOX', (0, 0), (-1, -1), 1, colors.lightgrey),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                            ('TOPPADDING', (0, 0), (-1, -1), 6),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                        ]))
                        
                        story.append(finding_table)
                        story.append(Spacer(1, 0.15*inch))
                
                # If no findings for this category after filtering
                if not findings_by_category:
                    story.append(Paragraph(f"No applicable {priority_title.lower()} issues were identified.", self.styles['Normal']))
                
                story.append(Spacer(1, 0.2*inch))
            else:
                # If no findings for this priority
                story.append(Paragraph(priority_title, self.styles['CustomHeading2']))
                story.append(Paragraph(f"No {priority_title.lower()} issues were identified.", self.styles['Normal']))
                story.append(Spacer(1, 0.2*inch))

    def _add_recommendations(self, story, analysis_results):
        """Add recommendations section with improved formatting"""
        story.append(Paragraph("Recommendations", self.styles['CustomHeading1']))
        story.append(Spacer(1, 0.1*inch))
        
        # Introduction text
        intro = """This section provides a consolidated list of recommendations to address the identified issues. 
        The recommendations are divided into two categories: cluster-specific recommendations that address actual issues 
        in your cluster, and general best practices that may be applied to improve your EKS environment."""
        story.append(Paragraph(intro, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Extract recommendations from findings
        cluster_specific_recommendations = {}
        general_best_practices = {}
        
        # Directly add HardenEKS findings to cluster-specific recommendations
        # This ensures they always appear in the report
        hardeneks_categories = ['IAM', 'Pod Security', 'Network Security', 'Runtime Security', 
                               'Detective Controls', 'Infrastructure Security', 'Data Security']
        
        # Process all findings and categorize them
        for priority_key in ['high_priority', 'medium_priority', 'low_priority']:
            for finding in analysis_results.get(priority_key, []):
                category = finding.get('category', 'Other')
                
                # Force HardenEKS findings into cluster-specific recommendations
                if category in hardeneks_categories:
                    if category not in cluster_specific_recommendations:
                        cluster_specific_recommendations[category] = []
                    
                    # Use action items as recommendations
                    if finding.get('action_items'):
                        priority = 'High' if priority_key == 'high_priority' else 'Medium' if priority_key == 'medium_priority' else 'Low'
                        for item in finding['action_items']:
                            cluster_specific_recommendations[category].append({
                                'text': item,
                                'priority': priority,
                                'title': finding.get('title', 'N/A'),
                                'reference': finding.get('reference', '')
                            })
                else:
                    # For other findings, check if they're applicable
                    is_applicable = self._is_finding_applicable(finding, analysis_results)
                    
                    # Select the appropriate recommendations dictionary
                    target_dict = cluster_specific_recommendations if is_applicable else general_best_practices
                    
                    if category not in target_dict:
                        target_dict[category] = []
                    
                    # Use action items as recommendations
                    if finding.get('action_items'):
                        priority = 'High' if priority_key == 'high_priority' else 'Medium' if priority_key == 'medium_priority' else 'Low'
                        for item in finding['action_items']:
                            target_dict[category].append({
                                'text': item,
                                'priority': priority,
                                'title': finding.get('title', 'N/A'),
                                'reference': finding.get('reference', '')
                            })
        
        # Add cluster-specific recommendations section
        if cluster_specific_recommendations:
            story.append(Paragraph("Cluster-Specific Recommendations", self.styles['CustomHeading2']))
            story.append(Paragraph("These recommendations address actual issues detected in your cluster and should be prioritized.", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            self._add_recommendation_tables(story, cluster_specific_recommendations)
        else:
            story.append(Paragraph("Cluster-Specific Recommendations", self.styles['CustomHeading2']))
            story.append(Paragraph("No cluster-specific issues were detected that require immediate attention.", self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        # Add general best practices section
        if general_best_practices:
            story.append(Paragraph("General Best Practices", self.styles['CustomHeading2']))
            story.append(Paragraph("These recommendations are general best practices that may improve your EKS environment, even though they may not address specific issues in your current cluster.", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            self._add_recommendation_tables(story, general_best_practices)
        
        # Add implementation roadmap
        story.append(Paragraph("Implementation Roadmap", self.styles['CustomHeading2']))
        story.append(Spacer(1, 0.1*inch))
        
        roadmap_text = """<b>Short-term (0-30 days):</b><br/>
        • Address all cluster-specific high-priority security and compliance issues<br/>
        • Implement critical patches and updates<br/>
        • Establish monitoring for critical components<br/><br/>
        
        <b>Medium-term (30-90 days):</b><br/>
        • Address cluster-specific medium-priority findings<br/>
        • Implement automation for routine tasks<br/>
        • Enhance logging and monitoring capabilities<br/><br/>
        
        <b>Long-term (90+ days):</b><br/>
        • Address remaining findings and general best practices<br/>
        • Implement continuous improvement processes<br/>
        • Establish regular review cycles for EKS best practices
        """
        
        story.append(Paragraph(roadmap_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
    
    def _add_recommendation_tables(self, story, recommendations_by_category):
        """Helper method to add recommendation tables by category"""
        # Create a table for each category
        for category, recommendations in sorted(recommendations_by_category.items()):
            story.append(Paragraph(category, self.styles['CustomHeading2']))
            story.append(Spacer(1, 0.1*inch))
            
            # Table data
            data = [["Priority", "Recommendation", "Related Finding"]]
            
            # Add recommendations to table
            for rec in recommendations:
                priority_text = "High" if rec['priority'] == 'High' else "Medium"
                priority_color = colors.red if rec['priority'] == 'High' else colors.orange
                
                data.append([
                    Paragraph(f"<font color='{priority_color}'>{priority_text}</font>", self.styles['TableCell']),
                    Paragraph(rec['text'], self.styles['TableCell']),
                    Paragraph(rec['title'], self.styles['TableCell'])
                ])
            
            # Create and style the table
            rec_table = Table(data, colWidths=[0.8*inch, 3.2*inch, 2*inch])
            rec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#232F3E')),  # AWS dark blue header
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 1), (0, -1), 'CENTER'),
                ('ALIGN', (1, 1), (1, -1), 'LEFT'),
                ('ALIGN', (2, 1), (2, -1), 'LEFT'),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ]))
            
            story.append(rec_table)
            story.append(Spacer(1, 0.2*inch))
            
        # Add implementation roadmap
        story.append(Paragraph("Implementation Roadmap", self.styles['CustomHeading2']))
        story.append(Spacer(1, 0.1*inch))
        
        roadmap_text = """<b>Short-term (0-30 days):</b><br/>
        • Address all high-priority security and compliance issues<br/>
        • Implement critical patches and updates<br/>
        • Establish monitoring for critical components<br/><br/>
        
        <b>Medium-term (30-90 days):</b><br/>
        • Address medium-priority findings<br/>
        • Implement automation for routine tasks<br/>
        • Enhance logging and monitoring capabilities<br/><br/>
        
        <b>Long-term (90+ days):</b><br/>
        • Address remaining low-priority findings<br/>
        • Implement continuous improvement processes<br/>
        • Establish regular review cycles for EKS best practices
        """
        
        story.append(Paragraph(roadmap_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

    def _is_finding_applicable(self, finding, analysis_results):
        """
        Check if a finding is applicable to the current cluster
        
        Args:
            finding: The finding to check
            analysis_results: Analysis results containing cluster details
            
        Returns:
            True if the finding is applicable, False otherwise
        """
        # Get the finding title and category
        title = finding.get('title', '')
        category = finding.get('category', '')
        
        # For HardenEKS findings, check if they're in the failed_checks list
        if 'failed_checks' in analysis_results:
            for failed_check in analysis_results.get('failed_checks', []):
                check_name = failed_check.get('check', '')
                
                # Check for exact or partial matches
                if (check_name and title and 
                    (check_name in title or title in check_name or
                     check_name.lower() in title.lower() or title.lower() in check_name.lower())):
                    return True
        
        # For findings from best_practices_analyzer, consider them applicable
        # These are based on actual cluster analysis, not just general recommendations
        if category in ['Security', 'Networking', 'Cost Optimization', 'Reliability', 
                       'Performance', 'Operations', 'Operational Excellence', 'Compliance']:
            return True
            
        # For HardenEKS findings, consider them applicable
        # These categories are specific to HardenEKS
        if category in ['IAM', 'Pod Security', 'Network Security', 'Runtime Security', 
                       'Detective Controls', 'Infrastructure Security', 'Data Security']:
            return True
        
        # For other findings, assume they're general best practices
        return False
    
    def _add_references(self, story):
        """Add comprehensive references section with improved formatting"""
        story.append(Paragraph("References and Resources", self.styles['CustomHeading1']))
        story.append(Spacer(1, 0.1*inch))
        
        # Introduction text
        intro = """This section provides links to official documentation and resources that can help you implement 
        the recommendations in this report and further improve your EKS environment."""
        story.append(Paragraph(intro, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        references = {
            "EKS Documentation": [
                ("EKS User Guide", "https://docs.aws.amazon.com/eks/latest/userguide/"),
                ("EKS Workshop", "https://www.eksworkshop.com/"),
                ("EKS Blueprints", "https://aws.github.io/aws-eks-blueprints/"),
                ("EKS Best Practices", "https://aws.github.io/aws-eks-best-practices/")
            ],
            "Security": [
                ("Security Best Practices", "https://docs.aws.amazon.com/eks/latest/userguide/security.html"),
                ("IAM Authentication", "https://docs.aws.amazon.com/eks/latest/userguide/security-iam.html"),
                ("Pod Security Standards", "https://docs.aws.amazon.com/eks/latest/userguide/pod-security-standards.html"),
                ("Network Policies", "https://docs.aws.amazon.com/eks/latest/userguide/network-policies.html"),
                ("Secrets Encryption", "https://docs.aws.amazon.com/eks/latest/userguide/enable-secrets-encryption.html")
            ],
            "Networking": [
                ("VPC CNI", "https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html"),
                ("Load Balancing", "https://docs.aws.amazon.com/eks/latest/userguide/network-load-balancing.html"),
                ("Service Mesh", "https://docs.aws.amazon.com/app-mesh/latest/userguide/getting-started-kubernetes.html"),
                ("IP Address Management", "https://aws.github.io/aws-eks-best-practices/networking/prefix-mode/"),
                ("Security Groups for Pods", "https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html")
            ],
            "Operations": [
                ("Cluster Updates", "https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html"),
                ("Logging & Monitoring", "https://docs.aws.amazon.com/eks/latest/userguide/logging-monitoring.html"),
                ("Cost Optimization", "https://aws.github.io/aws-eks-best-practices/cost_optimization/"),
                ("Scalability", "https://docs.aws.amazon.com/eks/latest/userguide/autoscaling.html"),
                ("Managed Node Groups", "https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html"),
                ("Karpenter", "https://karpenter.sh/docs/")
            ],
            "Reliability": [
                ("Multi-AZ Deployment", "https://aws.github.io/aws-eks-best-practices/reliability/docs/dataplane/"),
                ("Pod Disruption Budgets", "https://kubernetes.io/docs/tasks/run-application/configure-pdb/"),
                ("Topology Spread Constraints", "https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/"),
                ("Backup and Restore", "https://aws.amazon.com/blogs/containers/backup-and-restore-your-amazon-eks-cluster-resources-using-velero/")
            ],
            "Additional Resources": [
                ("Kubernetes Docs", "https://kubernetes.io/docs/home/"),
                ("CNCF Cloud Native Trail Map", "https://landscape.cncf.io/"),
                ("AWS Containers Blog", "https://aws.amazon.com/blogs/containers/"),
                ("AWS Solutions Library", "https://aws.amazon.com/solutions/"),
                ("EKS News", "https://eks.news/")
            ]
        }
        
        # Create a two-column layout for references
        for category, links in references.items():
            story.append(Paragraph(category, self.styles['CustomHeading2']))
            story.append(Spacer(1, 0.05*inch))
            
            # Create table data for references
            ref_data = []
            for title, url in links:
                ref_data.append([
                    Paragraph(f"• {title}", self.styles['TableCell']),
                    Paragraph(f"<link href='{url}'><font color='blue'>{url}</font></link>", self.styles['TableCell'])
                ])
            
            # Create and style the table
            ref_table = Table(ref_data, colWidths=[1.5*inch, 4*inch])
            ref_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ]))
            
            story.append(ref_table)
            story.append(Spacer(1, 0.15*inch))
        
        # Add disclaimer
        story.append(Spacer(1, 0.2*inch))
        disclaimer = """<i>Disclaimer: The recommendations in this report are based on AWS best practices and industry standards 
        at the time of generation. Always refer to the latest AWS documentation for the most up-to-date guidance.</i>"""
        story.append(Paragraph(disclaimer, self.styles['Footer']))
        story.append(Spacer(1, 0.1*inch))

    

    
