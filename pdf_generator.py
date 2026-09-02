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
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT

load_dotenv()

LOOKBACK_DAYS = os.getenv('LOOKBACK_DAYS', 'unspecified')
COMPANY_NAME = str(os.getenv('COMPANY_NAME', 'unspecified'))
REPORT_TITLE = os.getenv('REPORT_TITLE', 'CVE Bulletin').strip()

# PDF styling constants
BRAND_COLOR = HexColor('#003D82')
ACCENT_COLOR = HexColor('#FF6B35')
LIGHT_GRAY = HexColor('#F5F5F5')
DARK_GRAY = HexColor('#333333')
LOGO_PATH = os.getenv('IMAGE_PATH', '').strip()

def add_header(canvas, doc):
    canvas.saveState()
    page_width, page_height = A4
    margin = doc.leftMargin if doc is not None else 0.5 * inch
    right_margin = doc.rightMargin if doc is not None else 0.5 * inch
    header_x = margin
    header_y = page_height - 0.25 * inch
    header_width = page_width - margin - right_margin
    header_height = 0.94 * inch
    quarter_width = header_width / 4
    header_bottom = header_y - header_height

    canvas.setStrokeColor(BRAND_COLOR)
    canvas.setLineWidth(0.8)
    canvas.rect(header_x, header_bottom, header_width, header_height)
    for quarter in (1, 3):
        canvas.line(
            header_x + quarter * quarter_width,
            header_bottom,
            header_x + quarter * quarter_width,
            header_y,
        )

    if LOGO_PATH and os.path.exists(LOGO_PATH):
        try:
            canvas.drawImage(
                ImageReader(LOGO_PATH),
                header_x + 0.12 * inch,
                header_bottom + 0.08 * inch,
                width=quarter_width - 0.24 * inch,
                height=header_height - 0.16 * inch,
                preserveAspectRatio=True,
                anchor='c',
                mask='auto',
            )
        except Exception as e:
            print(f'[!] Could not load logo from {LOGO_PATH}: {e}')

    central_x = header_x + quarter_width
    central_center = central_x + quarter_width
    canvas.setFillColor(BRAND_COLOR)
    canvas.setFont('Helvetica-Bold', 20)
    canvas.drawCentredString(central_center, header_y - 0.35 * inch, 'Early Warning System')
    canvas.setFillColor(DARK_GRAY)
    canvas.setFont('Helvetica', 14)
    canvas.drawCentredString(central_center, header_y - 0.65 * inch, REPORT_TITLE)

    info_x = header_x + 3 * quarter_width + 0.08 * inch
    info_y = header_y - 0.14 * inch
    canvas.setFillColor(DARK_GRAY)
    canvas.setFont('Helvetica', 9)
    for line in (
        'Classificazione: Confidenziale',
        f'Doc: {REPORT_TITLE}',
        f'Data: {datetime.now().strftime("%d/%m/%Y")}',
        f'Pagina: {canvas.getPageNumber()} di {getattr(canvas, "page_count", "?")}',
    ):
        canvas.drawString(info_x, info_y, line)
        info_y -= 0.20 * inch
    canvas.restoreState()

def add_vertical_label(canvas, doc):
    canvas.saveState()
    canvas.translate(0.50 * inch, 1.15 * inch)
    canvas.rotate(90)
    canvas.setFillColor(DARK_GRAY)
    canvas.setFont('Helvetica', 7)
    canvas.drawString(0, 0, 'Early Warning Bulletin - Confidential information')
    canvas.restoreState()

def draw_page(canvas, doc):
    add_header(canvas, doc)
    add_vertical_label(canvas, doc)

class NumberedCanvas(pdf_canvas.Canvas):
    def __init__(self, *args, **kwargs):
        pdf_canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.page_count = page_count
            draw_page(self, None)
            pdf_canvas.Canvas.showPage(self)
        pdf_canvas.Canvas.save(self)

def write_pdf(filename, rows):
    """Generate a professional PDF report with CVE data.
    
    Args:
        filename (str): Output PDF file path
        rows (list): List of CVE data rows, each row is a list with:
                     [vendor, product, cve_id, date, cvss, epss, description, ...]
    """
    doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=1.35*inch, bottomMargin=0.5*inch)

    doc.title = COMPANY_NAME + " | Weekly Early Warning Report"


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
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=26,
        textColor=BRAND_COLOR,
        spaceAfter=12,
        alignment=TA_LEFT,
        fontName='Helvetica-Bold'
    )
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=DARK_GRAY,
        spaceAfter=0,
        alignment=TA_LEFT,
        fontName='Helvetica'
    )
    story.append(Paragraph(REPORT_TITLE, title_style))
    story.append(Paragraph('Early Warning System', subtitle_style))
    story.append(Spacer(1, 0.25*inch))
    
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
    doc.build(story, canvasmaker=NumberedCanvas)

    print(f'[*] PDF report generated: {filename}')
