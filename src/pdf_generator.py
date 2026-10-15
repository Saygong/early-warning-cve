"""
PDF Report Generator for CVE Early Warning System.
Generates professional PDF reports with company logo and vulnerability data.
"""

import os
import re
from xml.sax.saxutils import escape
from datetime import datetime, timedelta
from urllib.parse import urlsplit
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
        'Classification: Confidential',
        f'Doc: {REPORT_TITLE}',
        f'Date: {datetime.now().strftime("%d/%m/%Y")}',
        f'Page: {canvas.getPageNumber()} of {getattr(canvas, "page_count", "?")}',
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


def escape_attribute(value):
    """Escape text for use in an HTML-style attribute in a ReportLab paragraph."""
    return escape(value).replace('"', '&quot;')


def format_cited_text(text, bibliography):
    """Replace source URLs in AI text with numbered inline citations."""
    citation_markup = {}
    token_index = 0

    def make_citation(url, label=None):
        nonlocal token_index
        url = url.rstrip('.,;:!?')
        if url not in bibliography:
            bibliography[url] = len(bibliography) + 1
        token = f'CITATIONTOKEN{token_index}END'
        token_index += 1
        number = bibliography[url]
        link = f'<link href="{escape_attribute(url)}">[{number}]</link>'
        citation_markup[token] = f'{escape(label)} {link}' if label else link
        return token

    text = str(text or '')
    citation_pattern = re.compile(
        r'\[([^\]]+)\]\((https?://[^)\s]+)\)|\[?(https?://[^\s<>\[\]()]+)\]?'
    )
    text = citation_pattern.sub(
        lambda match: make_citation(match.group(2), match.group(1))
        if match.group(2) else make_citation(match.group(3)),
        text,
    )
    text = escape(text)
    for token, markup in citation_markup.items():
        text = text.replace(token, markup)
    return text

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
    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        topMargin=1.35*inch,
        bottomMargin=0.5*inch,
        leftMargin=0.5*inch,
        rightMargin=0.5*inch,
    )

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

    sub_normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=8,
        alignment=TA_JUSTIFY,
        leading=10
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
    
    cve_count = sum(
        len(row.get('vulnerabilities', [])) if isinstance(row, dict) else 1
        for row in rows
    )
    today = datetime.now().strftime('%d %B %Y')
    sixdays_ago = (datetime.now() - timedelta(days=6)).strftime('%d %B %Y')
    story.append(
        Paragraph(
            f'<i>This report is based on data collected between {sixdays_ago} and {today}.</i>',
            normal_style
        )
    )
    story.append(Paragraph(f'Report generated on {today}', sub_normal_style))
    
    
    story.append(Spacer(1, 0.4*inch))
    
    # ===== EXECUTIVE SUMMARY - SAME PAGE =====
    story.append(Paragraph('Executive Summary', heading_style))
    story.append(Spacer(1, 0.1*inch))
    
    summary_text = f"""
    This report presents critical and high-severity CVEs discovered in the last {LOOKBACK_DAYS} days 
    across monitored products. A total of <b>{cve_count} CVEs</b> were identified in <b>{len(rows)} groups</b>.
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
        # Create an entry for each related vulnerability group.
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

        group_title_style = ParagraphStyle(
            'GroupTitle',
            parent=styles['Heading2'],
            fontSize=15,
            textColor=BRAND_COLOR,
            spaceBefore=14,
            spaceAfter=3,
            fontName='Helvetica-Bold',
        )
        group_subtitle_style = ParagraphStyle(
            'GroupSubtitle',
            parent=styles['Heading3'],
            fontSize=10.5,
            textColor=DARK_GRAY,
            spaceAfter=7,
            fontName='Helvetica-Oblique',
        )
        grouping_reason_style = ParagraphStyle(
            'GroupingReason',
            parent=styles['Normal'],
            fontSize=8,
            textColor=DARK_GRAY,
            leading=10,
            spaceAfter=6,
        )
        table_header_style = ParagraphStyle(
            'VulnerabilityTableHeader',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7.5,
            textColor=HexColor('#FFFFFF'),
            leading=9,
        )
        table_cell_style = ParagraphStyle(
            'VulnerabilityTableCell',
            parent=styles['Normal'],
            fontSize=7.5,
            leading=9,
            wordWrap='CJK',
        )
        chapter_style = ParagraphStyle(
            'GroupChapter',
            parent=styles['Heading3'],
            fontSize=10,
            textColor=BRAND_COLOR,
            spaceBefore=8,
            spaceAfter=3,
            fontName='Helvetica-Bold',
        )
        bibliography = {}
        
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
            if isinstance(row, dict):
                vulnerabilities = row.get('vulnerabilities', [])
                business_impact = row.get('business_impact', 'N/A')
                remediation = row.get('remediation', 'N/A')
                grouping_reason = row.get('grouping_reason', 'Grouping reason unavailable.')
                group_title = row.get('group_title')
            else:
                vulnerabilities = [{
                    'vendor_name': row[0],
                    'product_name': row[1],
                    'cve_id': row[2],
                    'created_at': row[3],
                    'cvss': row[4],
                    'epss': row[5],
                    'description': row[6],
                }]
                business_impact = row[7] if len(row) > 7 else 'N/A'
                remediation = row[8] if len(row) > 8 else 'N/A'
                grouping_reason = 'Grouping reason unavailable.'
                group_title = None

            products = list(dict.fromkeys(
                ' '.join(part for part in (
                    vulnerability.get('vendor_name', ''),
                    vulnerability.get('product_name', ''),
                ) if part).strip()
                for vulnerability in vulnerabilities
            ))
            products = [product for product in products if product]
            tool_title = '; '.join(products) or 'Affected product unavailable'
            group_title = group_title or 'Related vulnerabilities'
            story.append(Paragraph(escape(tool_title), group_title_style))
            story.append(Paragraph(escape(str(group_title)), group_subtitle_style))
            story.append(Paragraph(
                f'<b>Grouping reason:</b> {escape(str(grouping_reason))}',
                grouping_reason_style,
            ))

            table_data = [[
                Paragraph('CVE code', table_header_style),
                Paragraph('Published date', table_header_style),
                Paragraph('CVSS', table_header_style),
                Paragraph('EPSS', table_header_style),
                Paragraph('Description', table_header_style),
            ]]
            for vulnerability in vulnerabilities:
                table_data.append([
                    Paragraph(escape(str(vulnerability.get('cve_id') or 'N/A')), table_cell_style),
                    Paragraph(escape(str(vulnerability.get('created_at') or 'N/A')), table_cell_style),
                    Paragraph(escape(str(vulnerability.get('cvss') if vulnerability.get('cvss') is not None else 'N/A')), table_cell_style),
                    Paragraph(escape(str(vulnerability.get('epss') if vulnerability.get('epss') is not None else 'N/A')), table_cell_style),
                    Paragraph(escape(str(vulnerability.get('description') or 'N/A')), table_cell_style),
                ])

            fixed_widths = [1.05*inch, 0.8*inch, 0.48*inch, 0.48*inch]
            column_widths = fixed_widths + [doc.width - sum(fixed_widths)]
            vulnerability_table = Table(
                table_data,
                colWidths=column_widths,
                repeatRows=1,
                hAlign='LEFT',
            )
            vulnerability_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), BRAND_COLOR),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#FFFFFF')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#FFFFFF'), LIGHT_GRAY]),
                ('GRID', (0, 0), (-1, -1), 0.35, HexColor('#B8C2CC')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(vulnerability_table)
            story.append(Spacer(1, 0.08*inch))

            if ai_integration.lower() in ('1', 'true', 'yes'):
                story.append(Paragraph('Business Impact Analysis', chapter_style))
                story.append(Paragraph(format_cited_text(business_impact, bibliography) or 'N/A', vuln_details_style))
                story.append(Spacer(1, 0.08*inch))
                story.append(Paragraph('Remediation', chapter_style))
                story.append(Paragraph(format_cited_text(remediation, bibliography) or 'N/A', vuln_details_style))
                story.append(Spacer(1, 0.08*inch))
            
            # Separator line between groups.
            if idx < len(rows) - 1:
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

        if bibliography:
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph('Sitografia e bibliografia', heading_style))
            bibliography_style = ParagraphStyle(
                'BibliographyEntry',
                parent=styles['Normal'],
                fontSize=8,
                leading=10,
                wordWrap='CJK',
                spaceAfter=4,
            )
            for url, number in bibliography.items():
                host = urlsplit(url).netloc or url
                story.append(Paragraph(
                    f'<b>[{number}] {escape(host)}</b><br/>'
                    f'<link href="{escape_attribute(url)}">{escape(url)}</link>',
                    bibliography_style,
                ))
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
