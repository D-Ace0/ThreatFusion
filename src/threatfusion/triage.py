"""Explain review priorities using local context and explicitly separated reputation."""

from .case_models import Case
from .models import IOCType


def prioritize(case: Case) -> Case:
    connected = {i.id: set() for i in case.indicators}
    for edge in case.relationships:
        connected[edge.source].add(edge.target)
        connected[edge.target].add(edge.source)
    for item in case.indicators:
        reasons = []
        priority = "context"
        if not item.ioc.public:
            reasons.append(
                "Non-public/reserved indicator: retained for local context; external lookup blocked"
            )
        if item.tags:
            priority = "review"
            reasons.append(
                "Local source contains: " + ", ".join(item.tags) + "; keywords alone are not proof"
            )
        if item.occurrences > 1:
            reasons.append(
                f"Appears {item.occurrences} times in the imported text; repetition is not maliciousness"
            )
        if len(item.tags) >= 2 and item.occurrences >= 2:
            priority = "high"
            reasons.append(
                "Multiple local activity types across repeated sightings: review the combined sequence first"
            )
        positive = []
        if item.analysis:
            simulated = item.analysis.mode == "demo"
            for result in item.analysis.results:
                positive.extend(e.source for e in result.evidence if e.value > 0)
            if positive:
                priority = "high"
                reasons.append(
                    ("SIMULATED fixture signals" if simulated else "Provider signals to review")
                    + ": "
                    + ", ".join(sorted(set(positive)))
                )
            elif item.analysis.score.risk == 0:
                reasons.append(
                    "Available providers returned no positive signal; this does not establish safety"
                )
            if item.analysis.score.coverage < 100:
                reasons.append(
                    f"Provider coverage {item.analysis.score.coverage}%; missing sources remain a gap"
                )
        else:
            reasons.append("Not enriched: no reputation claim is available")
        neighbors = connected[item.id]
        if neighbors:
            reasons.append(f"Connected to {len(neighbors)} other case indicators by source context")
        steps = []
        if "authentication failure" in item.tags:
            steps.append(
                "Check account, host, and authentication timestamps; distinguish user error from repeated abuse"
            )
        if "execution context" in item.tags:
            steps.append(
                "Review the process tree and command line in endpoint telemetry; do not execute the sample"
            )
        if "download context" in item.tags:
            steps.append(
                "Identify the originating message/process and downloaded file hash using existing logs"
            )
        if "blocked event" in item.tags:
            steps.append(
                "Confirm the control blocked the event and check whether any related activity was allowed"
            )
        if not steps:
            steps.append(
                "Compare the source line with the asset owner's expected activity and record your finding"
            )
        if item.ioc.type == IOCType.url:
            steps.append(
                "Review URL text locally; enrich the hostname separately if full-URL disclosure is inappropriate"
            )
        if item.ioc.public and not item.analysis:
            steps.append(
                "Optionally enrich this indicator; full URLs require separate disclosure consent"
            )
        item.priority, item.reasons, item.next_steps = priority, reasons, steps
    case.indicators.sort(
        key=lambda item: (
            {"high": 0, "review": 1, "context": 2}[item.priority],
            -item.occurrences,
            item.ioc.value,
        )
    )
    return case
