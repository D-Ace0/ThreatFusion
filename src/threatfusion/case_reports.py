import csv
from io import BytesIO, StringIO
from xml.sax.saxutils import escape

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer

from .case_models import Case


def csv_report(case: Case) -> bytes:
    def safe(value):
        text = str(value)
        return (
            "'" + text
            if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n"))
            else text
        )

    output = StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "indicator",
            "type",
            "public",
            "occurrences",
            "priority",
            "disposition",
            "note",
            "source_lines",
            "local_context",
            "reputation_mode",
            "risk",
            "coverage",
            "next_steps",
        ]
    )
    for item in case.indicators:
        writer.writerow(
            [
                safe(v)
                for v in [
                    item.ioc.value,
                    item.ioc.type.value,
                    item.ioc.public,
                    item.occurrences,
                    item.priority,
                    item.disposition,
                    item.note,
                    ",".join(str(o.line) for o in item.observations),
                    "; ".join(item.tags),
                    item.analysis.mode if item.analysis else "not enriched",
                    item.analysis.score.risk if item.analysis else "unknown",
                    item.analysis.score.coverage if item.analysis else 0,
                    "; ".join(item.next_steps),
                ]
            ]
        )
    return output.getvalue().encode("utf-8-sig")


def case_pdf(case: Case) -> bytes:
    output = BytesIO()
    styles = getSampleStyleSheet()
    styles["BodyText"].fontSize, styles["BodyText"].leading = 9, 13
    styles["BodyText"].wordWrap = "CJK"

    def p(value, style="BodyText"):
        return Paragraph(escape(str(value)), styles[style])

    counts = {
        key: sum(i.disposition == key for i in case.indicators)
        for key in ("unreviewed", "investigate", "expected", "escalate")
    }
    story = [
        p("THREATFUSION / Investigation brief", "Title"),
        p(case.title, "Heading1"),
        p(
            "SYNTHETIC TRAINING CASE: fictional events and demo intelligence."
            if case.synthetic
            else "Imported local evidence; enrichment mode is shown per indicator."
        ),
        p(
            f"Source: {case.source_name} | {case.line_count} lines | {len(case.indicators)} unique indicators"
        ),
        p(f"Input SHA256: {case.input_sha256}"),
        p(f"Created: {case.created_at.isoformat()} | Updated: {case.updated_at.isoformat()}"),
        p("Analyst decisions: " + ", ".join(f"{k}: {v}" for k, v in counts.items())),
        p(
            "Review priorities are unvalidated workflow hints, not automatic verdicts. Co-occurrence and keywords do not establish maliciousness."
        ),
        Spacer(1, 12),
    ]
    for warning in case.warnings:
        story.append(p(warning))
    by_id = {i.id: i for i in case.indicators}
    for item in case.indicators:
        story += [
            KeepTogether(
                [
                    p(item.ioc.value, "Heading2"),
                    p(
                        f"{item.ioc.type.value} | {item.occurrences} sightings | Priority: {item.priority} | Decision: {item.disposition}"
                    ),
                ]
            ),
            p("Analyst note: " + (item.note or "Not reviewed")),
        ]
        for reason in item.reasons:
            story.append(p("Why review: " + reason))
        if item.analysis:
            s = item.analysis.score
            story.append(
                p(
                    f"Enrichment {item.analysis.mode.upper()}: risk {s.risk if s.risk is not None else 'unknown'} | coverage {s.coverage}% | confidence {s.confidence}% | freshness {s.freshness}%"
                )
            )
            for result in item.analysis.results:
                story.append(
                    p(
                        f"{result.source}: {result.status}; retrieved {result.retrieved_at.isoformat()}"
                    )
                )
                for e in result.evidence:
                    story.append(
                        p(
                            f"{e.metric}={e.value:g}; observed {e.observed_at.isoformat() if e.observed_at else 'unknown'}; source {e.source_url}"
                        )
                    )
        for o in item.observations[:3]:
            story.append(p(f"Line {o.line}: {o.excerpt}"))
        neighbors = [
            by_id[e.target if e.source == item.id else e.source].ioc.value
            for e in case.relationships
            if item.id in (e.source, e.target)
        ]
        if neighbors:
            story.append(p("Related in this source: " + ", ".join(dict.fromkeys(neighbors))))
        for step in item.next_steps:
            story.append(p("Next: " + step))
        story.append(Spacer(1, 8))
    story.append(p("Activity log", "Heading1"))
    for entry in case.audit:
        story.append(p(f"{entry.at.isoformat()} | {entry.action} | {entry.detail}"))

    def footer(canvas, doc):
        canvas.setFont("Helvetica", 8)
        canvas.drawString(40, 25, "ThreatFusion | Sensitive case data | Human review required")
        canvas.drawRightString(572, 25, f"Page {doc.page}")

    SimpleDocTemplate(output, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=45).build(
        story, onFirstPage=footer, onLaterPages=footer
    )
    return output.getvalue()
