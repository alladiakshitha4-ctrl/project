import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT

def generate_pdf_report(scan, user, features):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                             rightMargin=2*cm, leftMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    # Custom styles
    title_style = ParagraphStyle('Title', parent=styles['Title'],
                                  fontSize=24, textColor=colors.HexColor('#00d4ff'),
                                  spaceAfter=6, alignment=TA_CENTER)
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'],
                                     fontSize=11, textColor=colors.HexColor('#a0aec0'),
                                     alignment=TA_CENTER, spaceAfter=20)
    heading_style = ParagraphStyle('Heading', parent=styles['Heading2'],
                                    fontSize=14, textColor=colors.HexColor('#00d4ff'),
                                    spaceBefore=15, spaceAfter=8)
    body_style = ParagraphStyle('Body', parent=styles['Normal'],
                                 fontSize=10, textColor=colors.HexColor('#2d3748'),
                                 spaceAfter=6)

    story = []

    # Header
    story.append(Paragraph("🛡️ PHISHGUARD AI", title_style))
    story.append(Paragraph("Security Scan Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#00d4ff')))
    story.append(Spacer(1, 0.5*cm))

    # Meta info table
    verdict_color = colors.HexColor('#e53e3e') if scan.verdict == 'PHISHING' else (
        colors.HexColor('#d69e2e') if scan.verdict == 'SUSPICIOUS' else colors.HexColor('#38a169'))

    meta_data = [
        ['Report ID', f'PG-{scan.id:06d}', 'Generated', datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')],
        ['Analyst', user.username, 'Scan Date', scan.timestamp.strftime('%Y-%m-%d %H:%M UTC')],
    ]
    meta_table = Table(meta_data, colWidths=[3*cm, 7*cm, 3*cm, 5*cm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f7fafc')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2d3748')),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#edf2f7'), colors.HexColor('#f7fafc')]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5*cm))

    # Verdict banner
    story.append(Paragraph("SCAN VERDICT", heading_style))
    verdict_data = [
        ['TARGET URL', scan.url],
        ['VERDICT', scan.verdict],
        ['RISK SCORE', f'{scan.risk_score:.1f} / 100'],
    ]
    verdict_table = Table(verdict_data, colWidths=[5*cm, 13*cm])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#2d3748')),
        ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#f7fafc')),
        ('BACKGROUND', (1, 1), (1, 1), verdict_color),
        ('BACKGROUND', (1, 2), (1, 2), colors.HexColor('#f7fafc')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
        ('TEXTCOLOR', (1, 1), (1, 1), colors.white),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('PADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 0.5*cm))

    # Feature analysis
    story.append(Paragraph("FEATURE ANALYSIS", heading_style))
    feat_data = [['Feature', 'Value', 'Risk Level']]
    feature_rows = [
        ('HTTPS Enabled', str(features.get('has_https', False)),
         'LOW' if features.get('has_https') else 'HIGH'),
        ('IP Address in URL', str(features.get('has_ip', False)),
         'HIGH' if features.get('has_ip') else 'LOW'),
        ('URL Length', str(features.get('url_length', 0)),
         'HIGH' if features.get('url_length', 0) > 100 else 'LOW'),
        ('Suspicious Keywords', str(features.get('keyword_count', 0)),
         'HIGH' if features.get('keyword_count', 0) > 2 else 'MEDIUM' if features.get('keyword_count', 0) > 0 else 'LOW'),
        ('Suspicious TLD', str(features.get('has_suspicious_tld', False)),
         'HIGH' if features.get('has_suspicious_tld') else 'LOW'),
        ('Brand Impersonation', str(features.get('has_brand_impersonation', False)),
         'HIGH' if features.get('has_brand_impersonation') else 'LOW'),
        ('Domain Entropy', str(features.get('domain_entropy', 0)),
         'HIGH' if features.get('domain_entropy', 0) > 3.5 else 'LOW'),
        ('Subdomain Count', str(features.get('subdomain_count', 0)),
         'HIGH' if features.get('subdomain_count', 0) > 2 else 'LOW'),
    ]
    for row in feature_rows:
        feat_data.append(list(row))

    risk_colors_map = {'HIGH': colors.HexColor('#fed7d7'), 'MEDIUM': colors.HexColor('#fefcbf'), 'LOW': colors.HexColor('#c6f6d5')}
    feat_table = Table(feat_data, colWidths=[7*cm, 5*cm, 5*cm])
    style_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f7fafc'), colors.white]),
    ]
    for i, (_, _, risk) in enumerate(feature_rows, start=1):
        style_cmds.append(('BACKGROUND', (2, i), (2, i), risk_colors_map.get(risk, colors.white)))
    feat_table.setStyle(TableStyle(style_cmds))
    story.append(feat_table)
    story.append(Spacer(1, 0.5*cm))

    # Recommendations
    story.append(Paragraph("SECURITY RECOMMENDATIONS", heading_style))
    recs = features.get('recommendations', [])
    if not recs:
        recs = ['No specific recommendations available.']
    for rec in recs:
        story.append(Paragraph(f"• {rec}", body_style))

    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph("This report was generated by PhishGuard AI. For security research purposes only.",
                            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                                           textColor=colors.HexColor('#a0aec0'), alignment=TA_CENTER)))

    doc.build(story)
    buffer.seek(0)
    return buffer
