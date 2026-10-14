from .models import Contribution, ProviderResult, Score, utcnow


def score(results: list[ProviderResult]) -> Score:
    """Fixed weights deliberately do not renormalize when sources are missing."""
    eligible = [r for r in results if r.status != "unsupported"]
    usable = [r for r in eligible if r.status == "ok" and r.evidence]
    evidence = [e for r in usable for e in r.evidence]
    coverage = round(100 * len(usable) / len(eligible)) if eligible else 0
    ages = [
        max(0, (utcnow() - e.observed_at).total_seconds() / 86400)
        for e in evidence
        if e.observed_at
    ]
    freshness = (
        round(sum(max(0, 1 - age / 90) for age in ages) / len(evidence) * 100) if evidence else 0
    )
    contributions = []
    for e in evidence:
        if e.metric == "detections":
            points = min(60, 60 * e.value / max(e.total or 1, 1))
            reason = f"{e.value:g}/{e.total} malicious engines x 60-point ceiling"
        elif e.metric == "abuse_confidence":
            points = min(30, e.value * 0.3)
            reason = f"Provider abuse score {e.value:g}/100 x 30-point ceiling"
        else:
            points = min(10, e.value * 2)
            reason = f"{e.value:g} community pulses x 2, capped at 10"
        contributions.append(Contribution(source=e.source, points=round(points, 2), reason=reason))
    risk = min(100, round(sum(c.points for c in contributions))) if evidence else None
    label = (
        "unknown"
        if risk is None
        else "high"
        if risk >= 60
        else "elevated"
        if risk >= 30
        else "low signal"
    )
    # Correlated sources and absent observations limit this completeness proxy.
    confidence = round(coverage * (0.4 + 0.6 * freshness / 100) * min(1, len(usable) / 2))
    return Score(
        risk=risk,
        label=label,
        confidence=confidence,
        coverage=coverage,
        freshness=freshness,
        contributions=contributions,
    )
