import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class ApexReportGenerator:
    PALETTE = {
        "CRITICAL": colors.HexColor('#DC2626'), # Crimson Red
        "HIGH":     colors.HexColor('#EA580C'), # Dark Orange
        "MEDIUM":   colors.HexColor('#D97706'), # Amber
        "LOW":      colors.HexColor('#059669'), # Emerald Green
        "NEUTRAL":  colors.HexColor('#0F172A'), # Dark Slate
    }

    def __init__(self, filename, forensic_data, score, severity):
        self.filename = filename
        self.data = forensic_data
        self.score = score
        self.severity = severity
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()

    def setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='ApexTitle',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0F172A'),
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#1E293B'),
            fontName='Helvetica-Bold',
            spaceBefore=10,
            spaceAfter=4
        ))

    def build_pdf(self):
        doc = SimpleDocTemplate(
            self.filename,
            pagesize=letter,
            rightMargin=36, leftMargin=36,
            topMargin=36, bottomMargin=36
        )
        story = []

        # --- PAGE 1: EXECUTIVE COVER & DASHBOARD ---
        story.append(Paragraph("APEX FORENSIC INVESTIGATION REPORT", self.styles['ApexTitle']))
        story.append(Paragraph("Automated Phishing Executive Examiner", self.styles['Normal']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0284C7'), spaceBefore=8, spaceAfter=12))

        # Metadata & Severity Paragraph Styling
        badge_color_hex = {
            "CRITICAL": "#DC2626",
            "HIGH": "#EA580C",
            "MEDIUM": "#D97706",
            "LOW": "#059669"
        }.get(self.severity, "#0F172A")

        severity_p = Paragraph(
            f"<font color='white'><b>&nbsp;{self.severity} ({self.score}/100)&nbsp;</b></font>", 
            ParagraphStyle(
                name='BadgeP',
                fontName='Helvetica-Bold',
                fontSize=10,
                leading=12,
                backColor=colors.HexColor(badge_color_hex),
                borderColor=colors.HexColor(badge_color_hex),
                borderPadding=4,
                borderRadius=3
            )
        )

        meta_data = [
            ["Subject:", Paragraph(str(self.data.get("subject", "N/A")), self.styles['Normal']), "Risk Assessment:"],
            ["Sender:", Paragraph(str(self.data.get("from_address", "N/A")), self.styles['Normal']), severity_p],
            ["Recipient:", Paragraph(str(self.data.get("to_address", "N/A")), self.styles['Normal']), ""]
        ]
        
        t = Table(meta_data, colWidths=[80, 260, 150])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#334155')),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t)
        story.append(Spacer(1, 15))

        story.append(Paragraph("Executive Summary & Risk Overview", self.styles['SectionHeader']))
        exec_summary_text = (
            f"APEX completed automated forensic triage on the target email. "
            f"The computed risk score is <b>{self.score}/100</b>, classifying the message under the <b>{self.severity}</b> tier. "
            f"Total extracted URLs: {len(self.data.get('urls', []))}. Total attachments: {len(self.data.get('attachments', []))}."
        )
        story.append(Paragraph(exec_summary_text, self.styles['Normal']))
        story.append(PageBreak())

        # --- PAGE 2: EXTRACTED ARTIFACTS & IOC TABLE ---
        story.append(Paragraph("Extracted Artifacts & Indicators of Compromise (IOCs)", self.styles['SectionHeader']))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#94A3B8'), spaceBefore=4, spaceAfter=10))

        story.append(Paragraph("<b>Embedded Hyperlinks (Defanged):</b>", self.styles['Normal']))
        story.append(Spacer(1, 4))

        urls = self.data.get("urls", [])
        if urls:
            url_rows = [["Original URL", "Defanged Representation"]]
            for u in urls[:10]:
                url_rows.append([u["original"][:50], u["defanged"][:50]])
            url_table = Table(url_rows, colWidths=[240, 250])
            url_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(url_table)
        else:
            story.append(Paragraph("No URLs detected in the email body.", self.styles['Normal']))

        story.append(Spacer(1, 15))
        story.append(Paragraph("<b>Attachment Forensic Analysis:</b>", self.styles['Normal']))
        story.append(Spacer(1, 4))

        attachments = self.data.get("attachments", [])
        if attachments:
            att_rows = [["Filename", "SHA-256 Hash", "Executable?"]]
            for att in attachments:
                att_rows.append([att["filename"], att["sha256"][:24] + "...", str(att["is_executable"])])
            att_table = Table(att_rows, colWidths=[150, 260, 80])
            att_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(att_table)
        else:
            story.append(Paragraph("No attachments detected.", self.styles['Normal']))

        story.append(PageBreak())

        # --- PAGE 3: REMEDIATION & RECOMMENDATIONS ---
        story.append(Paragraph("Strategic Recommendations & Remediation Playbook", self.styles['SectionHeader']))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#94A3B8'), spaceBefore=4, spaceAfter=10))
        
        remedy_text = (
            "<b>Recommended Incident Response Steps:</b><br/>"
            "1. <b>Isolate Endpoint:</b> If any user interacted with or executed attachments from this email, isolate the device immediately.<br/>"
            "2. <b>Revoke Sessions:</b> Force a reset of user credentials and active token sessions if credentials were submitted.<br/>"
            "3. <b>Email Gateway Block:</b> Add extracted sender domains and IOC file hashes to your secure email gateway (SEG) blocklist.<br/>"
            "4. <b>Tenant Purge:</b> Run automated message purge commands across Exchange Online or M365 to remove copies from user mailboxes."
        )
        story.append(Paragraph(remedy_text, self.styles['Normal']))

        doc.build(story)
        return self.filename
