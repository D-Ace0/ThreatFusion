from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import Analysis


def pdf_report(analysis: Analysis) -> bytes:
    """Escape all indicator/provider text; never create clickable suspicious links."""
    output = BytesIO()
    styles = getSampleStyleSheet()
    styles["BodyText"].fontSize = 9
    styles["BodyText"].leading = 13
    styles["BodyText"].wordWrap = "CJK"

    def paragraph(value, style="BodyText"):
        return Paragraph(escape(str(value)), styles[style])

    s = analysis.score
    story = [
        paragraph(
            "THREATFUSION / SIMULATED DEMO"
            if analysis.mode == "demo"
            else "THREATFUSION / Intelligence report",
            "Title",
        ),
        paragraph(f"{analysis.mode.upper()} | {analysis.created_at.isoformat()}"),
        paragraph(
            "FICTIONAL FIXTURE DATA. No live provider lookup or maliciousness verdict."
            if analysis.mode == "demo"
            else "Existing provider intelligence. This heuristic is not a safety verdict."
        ),
        Spacer(1, 12),
        paragraph(analysis.ioc.value, "Heading2"),
        paragraph(f"Type: {analysis.ioc.type.value} | Analysis: {analysis.id}"),
        Spacer(1, 12),
    ]
    metrics = [
        ["Risk / 100", "Confidence", "Coverage", "Freshness"],
        [
            str(s.risk) if s.risk is not None else "Unknown",
            f"{s.confidence}%",
            f"{s.coverage}%",
            f"{s.freshness}%",
        ],
    ]
    table = Table(metrics, colWidths=[1.65 * inch] * 4)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14283d")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#edf5fa")),
                ("PADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story += [
        table,
        Spacer(1, 12),
        paragraph(s.methodology),
        paragraph(
            "Synthetic fixtures are not real intelligence. Low scores and missing records do not establish safety."
        ),
        paragraph("Explainable contributions", "Heading2"),
    ]
    for c in s.contributions:
        story.append(paragraph(f"{c.source}: +{c.points:g}. {c.reason}"))
    story.append(paragraph("Source evidence and availability", "Heading2"))
    for r in analysis.results:
        story += [
            paragraph(
                f"{r.source} / {r.status} / {'cached' if r.cached else 'fresh retrieval'}",
                "Heading3",
            ),
            paragraph(
                f"Retrieved: {r.retrieved_at.isoformat()} | Attempts: {r.attempts} | {r.message}"
            ),
        ]
        for e in r.evidence:
            story += [
                paragraph(f"{e.metric}: {e.value:g} | {e.description}"),
                paragraph(f"Observed: {e.observed_at.isoformat() if e.observed_at else 'Unknown'}"),
                paragraph(f"Source: {e.source_url}"),
                Spacer(1, 5),
            ]

    def footer(canvas, doc):
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#526578"))
        canvas.drawString(
            40, 25, "ThreatFusion | Unvalidated heuristic triage | Handle as sensitive"
        )
        canvas.drawRightString(572, 25, f"Page {doc.page}")

    SimpleDocTemplate(
        output,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=45,
        title="ThreatFusion Intelligence Report",
    ).build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
