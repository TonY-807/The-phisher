import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.units import inch

def get_reports_dir():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "reports")

def generate_phishing_report(result_data, output_dir=None):
    """
    Generates a professional PDF report for a scanned URL.
    
    Args:
        result_data (dict): Dictionary containing analysis results.
        output_dir (str): Directory to save the generated PDF. Defaults to 'reports'.
        
    Returns:
        str: Absolute path to the generated PDF file.
    """
    if output_dir is None:
        output_dir = get_reports_dir()
        
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"phishing_report_{timestamp}.pdf"
    filepath = os.path.join(output_dir, filename)
    
    # Setup document
    doc = SimpleDocTemplate(filepath, pagesize=letter,
                            rightMargin=72, leftMargin=72,
                            topMargin=72, bottomMargin=72)
    
    styles = getSampleStyleSheet()
    
    # Custom styles defining professional formatting
    title_style = ParagraphStyle(
        'MainTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=20,
        textColor=colors.HexColor('#0f172a'),
        alignment=1 # Center alignment
    )
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=15,
        textColor=colors.HexColor('#64748b'),
        alignment=1 # Center alignment
    )
    
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceBefore=15,
        spaceAfter=10,
        textColor=colors.HexColor('#1e293b'),
        borderPadding=(0, 0, 4, 0)
    )
    
    normal_style = styles['Normal']
    normal_style.fontSize = 11
    normal_style.leading = 14
    
    # List to hold PDF elements
    flowables = []
    
    # 1. Header & Title (Company/Project name at the top)
    flowables.append(Paragraph("<b>PhishGuard Project</b>", subtitle_style))
    flowables.append(Spacer(1, 0.1 * inch))
    flowables.append(Paragraph("Phishing Detection Report", title_style))
    
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    input_type = result_data.get('type', 'URL')
    input_value = result_data.get('input_data', result_data.get('url', 'Unknown'))
    flowables.append(Paragraph(f"<b>{input_type} Analyzed:</b> {input_value}", normal_style))
    flowables.append(Paragraph(f"<b>Date & Time of Scan:</b> {scan_time}", normal_style))
    flowables.append(Spacer(1, 0.3 * inch))
    
    # 2. Final Verdict & Score
    verdict = result_data['classification']
    score = result_data['score']
    
    # Color-code the verdict text
    verdict_color = colors.HexColor('#10b981') # Safe - Green
    if verdict == "Suspicious":
        verdict_color = colors.HexColor('#f59e0b') # Orange
    elif verdict == "Phishing":
        verdict_color = colors.HexColor('#ef4444') # Red
        
    verdict_style = ParagraphStyle(
        'Verdict',
        parent=styles['Heading2'],
        fontSize=18,
        textColor=verdict_color,
        spaceAfter=10
    )
    
    flowables.append(Paragraph("Overview", heading_style))
    flowables.append(Paragraph(f"Final Verdict: <b>{verdict.upper()}</b>", verdict_style))
    flowables.append(Paragraph(f"<b>Risk Score:</b> {score}%", normal_style))
    flowables.append(Spacer(1, 0.25 * inch))
    
    # 3. Detailed Analysis Results
    flowables.append(Paragraph("Detailed Analysis Results", heading_style))
    
    # Extract structural details securely
    details = result_data.get('details', [])
    bullet_items = []
    
    for detail in details:
        check_name = detail.get('check', 'Unknown Check')
        result_val = detail.get('result', 'N/A')
        # Formatting individual check items
        bullet_items.append(ListItem(Paragraph(f"<b>{check_name}:</b> {result_val}", normal_style)))
        
    if bullet_items:
        flowables.append(ListFlowable(bullet_items, bulletType='bullet', leftIndent=15, spaceBefore=5))
    flowables.append(Spacer(1, 0.25 * inch))
    
    # 4. Recommendations
    flowables.append(Paragraph("Recommendations", heading_style))
    recommendations = []
    
    if verdict == "Safe":
        recommendations = [
            "The URL appears to be safe and free of typical phishing indicators.",
            "You may safely proceed to browse this website normally.",
            "Always remain vigilant for unexpected login prompts or changes in site behavior."
        ]
    elif verdict == "Suspicious":
        recommendations = [
            "Exercise caution when browsing this website.",
            "Avoid entering any sensitive information such as credentials or credit card numbers.",
            "Double-check the domain name for subtle misspellings (e.g., g00gle.com instead of google.com)."
        ]
    else:
        recommendations = [
            "Do NOT enter any personal information, passwords, or financial details.",
            "Close the page immediately and block the URL if possible.",
            "If you received this link via email, report the email as a phishing attempt.",
            "Run a malware scan if you downloaded any files from this site."
        ]
        
    rec_bullets = [ListItem(Paragraph(rec, normal_style)) for rec in recommendations]
    flowables.append(ListFlowable(rec_bullets, bulletType='bullet', leftIndent=15, spaceBefore=5))
    
    flowables.append(Spacer(1, 0.5 * inch))
    
    # 5. Footer Requirements ("Generated by Phishing Detection Tool")
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Italic'],
        fontSize=10,
        textColor=colors.HexColor('#94a3b8'),
        alignment=1 # Center alignment for footer
    )
    flowables.append(Spacer(1, 1 * inch))
    flowables.append(Paragraph("Generated by Phishing Detection Tool", footer_style))
    
    # Build PDF and save output
    doc.build(flowables)
    
    return filepath
