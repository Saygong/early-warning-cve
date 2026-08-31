"""
PDF Report Generator for CVE Early Warning System.
Generates professional PDF reports with company logo and vulnerability data.
"""

import os
from datetime import datetime
from dotenv import load_dotenv
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_RIGHT

load_dotenv()

LOOKBACK_DAYS = os.getenv('LOOKBACK_DAYS', 'unspecified')

# PDF styling constants
BRAND_COLOR = HexColor('#003D82')
ACCENT_COLOR = HexColor('#FF6B35')
LIGHT_GRAY = HexColor('#F5F5F5')
DARK_GRAY = HexColor('#333333')
LOGO_PATH = os.getenv('IMAGE_PATH', '').strip()


def write_pdf(filename, rows):
    """Generate a professional PDF report with CVE data.
    
    Args:
        filename (str): Output PDF file path
        rows (list): List of CVE data rows, each row is a list with:
                     [vendor, product, cve_id, date, cvss, epss, description, ...]
    """
    doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=BRAND_COLOR,
        spaceAfter=10,
        spaceBefore=10,
        fontName='Helvetica-Bold'
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        alignment=TA_JUSTIFY,
        leading=12
    )
    
    # ===== COVER PAGE =====
    # Create a two-column layout: logo on left, title on right
    logo_cell = None
    if LOGO_PATH and os.path.exists(LOGO_PATH):
        try:
            # Load logo with specific dimensions
            logo_cell = Image(LOGO_PATH, width=1.4*inch, height=1.4*inch)
            print(f'[*] Logo loaded from: {LOGO_PATH}')
        except Exception as e:
            print(f'[!] Could not load logo from {LOGO_PATH}: {e}')
    
    # Right column with title and subtitle
    title_style_right = ParagraphStyle(
        'TitleRight',
        parent=styles['Heading1'],
        fontSize=32,
        textColor=BRAND_COLOR,
        spaceAfter=12,
        alignment=TA_RIGHT,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style_right = ParagraphStyle(
        'SubtitleRight',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=DARK_GRAY,
        spaceAfter=0,
        alignment=TA_RIGHT,
        fontName='Helvetica'
    )
    
    title_text = Paragraph('CVE Report', title_style_right)
    subtitle_text = Paragraph('Early Warning System', subtitle_style_right)
    
    # Build right column content
    right_content = [title_text, Spacer(1, 0.1*inch), subtitle_text]
    
    # Create header table with logo and title - use fixed row height to prevent stretching
    header_data = [[logo_cell or Spacer(1.4*inch, 1.4*inch), Spacer(0.2*inch, 0), right_content]]
    header_table = Table(header_data, colWidths=[1.8*inch, 0.2*inch, 3.8*inch], rowHeights=[1.6*inch])
    header_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('ALIGN', (2, 0), (2, 0), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    
    story.append(header_table)
    story.append(Spacer(1, 0.3*inch))
    
    today = datetime.now().strftime('%d %B %Y')
    story.append(Paragraph(f'Generated on {today}', normal_style))
    
    
    story.append(Spacer(1, 0.4*inch))
    
    # ===== EXECUTIVE SUMMARY - SAME PAGE =====
    story.append(Paragraph('Executive Summary', heading_style))
    story.append(Spacer(1, 0.1*inch))
    
    summary_text = f"""
    This report presents critical and high-severity CVEs discovered in the last {LOOKBACK_DAYS} days 
    across monitored products. A total of <b>{len(rows)} vulnerabilities</b> were identified.
    <br/><br/>
    Each entry includes:
    <br/>• <b>Vendor</b> and <b>Product</b> information
    <br/>• Unique <b>CVE ID</b> representing the vulnerability
    <br/>• <b>Publication date</b>
    <br/>• Severity score based on <b>CVSS v3.1</b> ranking system
    <br/>• Probability score of exploitation (<b>EPSS</b>)
    <br/>• <b>Technical description</b>
    """
    
    ai_integration = os.getenv('USE_COPILOT', '').strip()
    if ai_integration.lower() in ('1', 'true', 'yes'):
        summary_text += """<br/>• Business impact analysis (<b>BIA</b>)
    <br/>• <b>Remediation</b> recommendations"""
    
    story.append(Paragraph(summary_text, normal_style))
    story.append(Spacer(1, 0.4*inch))
    
    # ===== DATA - ELEGANT SUBSECTION FORMAT =====
    
    story.append(Paragraph('Vulnerability Details', heading_style))
    story.append(Spacer(1, 0.15*inch))

    if rows:
        # Create elegant subsection for each vulnerability
        vuln_subsection_style = ParagraphStyle(
            'VulnSubsection',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=BRAND_COLOR,
            spaceAfter=6,
            spaceBefore=12,
            fontName='Helvetica-Bold',
            leftIndent=0.1*inch,
            borderPadding=6,
        )
        
        vuln_details_style = ParagraphStyle(
            'VulnDetails',
            parent=styles['Normal'],
            fontSize=9.5,
            alignment=TA_JUSTIFY,
            leading=11,
            leftIndent=0.2*inch,
        )
        
        vuln_label_style = ParagraphStyle(
            'VulnLabel',
            parent=styles['Normal'],
            fontSize=8,
            textColor=BRAND_COLOR,
            fontName='Helvetica-Bold',
            leftIndent=0.2*inch,
            spaceAfter=2,
        )
        
        for idx, row in enumerate(rows, 1):
            # Subsection title with CVE ID and product info
            cve_title = f"{row[2]} • {row[0]} {row[1]}"
            story.append(Paragraph(cve_title, vuln_subsection_style))
            
            # Quick info line: Date, CVSS, EPSS
            quick_info = f"<b>Published:</b> {row[3]} | <b>CVSS:</b> {row[4] if row[4] else 'N/A'} | <b>EPSS:</b> {row[5] if row[5] else 'N/A'}"
            story.append(Paragraph(quick_info, vuln_label_style))
            story.append(Spacer(1, 0.05*inch))
            
            # Description
            story.append(Paragraph("<b>Description:</b>", vuln_label_style))
            story.append(Paragraph(row[6], vuln_details_style))
            story.append(Spacer(1, 0.08*inch))
            
            # Business Impact and Remediation (if AI integration enabled)
            if ai_integration.lower() in ('1', 'true', 'yes'):
                story.append(Paragraph("<b>Business Impact:</b>", vuln_label_style))
                story.append(Paragraph(row[7], vuln_details_style))
                story.append(Spacer(1, 0.08*inch))
                
                story.append(Paragraph("<b>Remediation:</b>", vuln_label_style))
                story.append(Paragraph(row[8], vuln_details_style))
                story.append(Spacer(1, 0.08*inch))
            
            # Separator line between vulnerabilities (except for the last one)
            if idx < len(rows):
                sep_data = [['_' * 100]]
                sep_table = Table(sep_data, colWidths=[7.5*inch])
                sep_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('TEXTCOLOR', (0, 0), (-1, -1), LIGHT_GRAY),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 2),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ]))
                story.append(sep_table)
                story.append(Spacer(1, 0.05*inch))
    else:
        story.append(Paragraph('No vulnerabilities found in the specified period.', normal_style))
    
    # ===== FOOTER PAGE =====
    
    story.append(Spacer(1, 2*inch))
    footer_text = """
    <b>Early Warning CVE System</b><br/>
    <br/>
    <i>This report is generated automatically and contains information from the OpenCVE public database.
    <br/>
    For more information, visit: https://www.opencve.io</i>
    <br/><br/>
    """
    story.append(Paragraph(footer_text, normal_style))
    
    # Build PDF
    doc.build(story)
    print(f'[*] PDF report generated: {filename}')
