from io import BytesIO
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def build_pdf_report(profile: Dict[str, Any], top_5: List[Dict[str, Any]]) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        spaceAfter=12,
        textColor=colors.HexColor("#1F2937"),
    )
    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        spaceBefore=10,
        spaceAfter=6,
        textColor=colors.HexColor("#111827"),
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        spaceAfter=4,
        textColor=colors.HexColor("#374151"),
    )

    story = []
    org_name = profile.get("organisation", "Organisation")
    service_name = profile.get("service", "Service")
    exposure = profile.get("exposure", "Unknown")
    importance = profile.get("importance", "Unknown")

    story.append(Paragraph("VulnWise - Vulnerability Report", title_style))
    story.append(Paragraph(f"Organisation: {org_name}", body_style))
    story.append(Paragraph(f"Service: {service_name}", body_style))
    story.append(Paragraph(f"Exposure: {exposure}", body_style))
    story.append(Paragraph(f"Importance: {importance}", body_style))
    story.append(Spacer(1, 10))

    if not top_5:
        story.append(Paragraph("No actionable vulnerabilities matched the selected profile.", body_style))
    else:
        story.append(Paragraph("Top Actionable Vulnerabilities", heading_style))
        for index, item in enumerate(top_5, start=1):
            risk_score = item.get("risk_score", 0)
            priority = item.get("priority", "Low")
            cve = item.get("cve_id", "N/A")
            matched_tech = item.get("matched_tech", "Unknown technology")
            description = item.get("description", "No description available.")
            summary = (
                f"{index}. {cve} | {matched_tech} | {priority} | Score: {risk_score}/100"
            )
            story.append(Paragraph(summary, body_style))
            story.append(Paragraph(f"Description: {description}", body_style))

            score_breakdown = item.get("score_breakdown", {})
            if score_breakdown:
                table_data = [["Factor", "Detail"]]
                for factor, detail in score_breakdown.items():
                    table_data.append([factor, detail])
                table = Table(table_data, colWidths=[180, 300])
                table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E7EB")),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
                            ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ]
                    )
                )
                story.append(table)
            story.append(Spacer(1, 10))

    doc.build(story)
    return buffer.getvalue()
