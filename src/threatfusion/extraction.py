"""Bounded local text extraction; never visits, resolves, or executes input."""

import hashlib
import re
from collections import defaultdict
from itertools import combinations
from urllib.parse import urlsplit
from uuid import uuid4

from .case_models import AuditEntry, Case, CaseIndicator, Observation, Relationship
from .models import IOCType
from .validation import validate

MAX_TEXT = 200_000
MAX_INDICATORS = 200
MAX_LINES = 10_000
MAX_OBSERVATIONS = 12

URL = re.compile(r'(?i)\bhttps?://[^\s<>"\',]+')
HASH = re.compile(r"(?i)\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?i)(?<![\w:])[a-f0-9:]*:[a-f0-9:.]+(?![\w:])")
DOMAIN = re.compile(
    r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?![\w.-])"
)
TAGS = {
    "authentication failure": re.compile(
        r"(?i)failed? (?:login|password|auth)|authentication fail|invalid password"
    ),
    "blocked event": re.compile(r"(?i)\b(?:deny|denied|blocked|reject|rejected)\b"),
    "download context": re.compile(r"(?i)\b(?:download|downloaded|attachment|payload)\b"),
    "execution context": re.compile(r"(?i)\b(?:powershell|rundll32|wscript|mshta|cmd\.exe)\b"),
}


def refang(text: str) -> str:
    return re.sub(r"(?i)\bhxxp(s?)://", r"http\1://", text.replace("[.]", ".").replace("(.)", "."))


def identifier(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:20]


def extract_case(title: str, source_name: str, text: str, synthetic: bool = False) -> Case:
    if not text.strip() or len(text) > MAX_TEXT:
        raise ValueError(f"Provide 1-{MAX_TEXT:,} characters of text")
    if "\x00" in text:
        raise ValueError(
            "Binary files are not supported; import text logs, CSV, JSON, or email text"
        )
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError(f"At most {MAX_LINES:,} lines per case")
    indicators = {}
    edges = defaultdict(lambda: {"count": 0, "lines": []})
    truncated = False

    def add(value, line_number, excerpt, tags):
        nonlocal truncated
        try:
            ioc = validate(value)
        except ValueError:
            return None
        key = identifier(ioc.value)
        if key not in indicators:
            if len(indicators) >= MAX_INDICATORS:
                truncated = True
                return None
            indicators[key] = CaseIndicator(id=key, ioc=ioc)
        item = indicators[key]
        item.occurrences += 1
        item.tags = sorted(set(item.tags) | set(tags))
        if len(item.observations) < MAX_OBSERVATIONS and not any(
            o.line == line_number for o in item.observations
        ):
            item.observations.append(Observation(line=line_number, excerpt=excerpt, tags=tags))
        return key

    def connect(left, right, kind, line_number):
        if not left or not right or left == right:
            return
        a, b = (left, right) if kind == "url_host" else tuple(sorted((left, right)))
        edge = edges[(a, b, kind)]
        edge["count"] += 1
        if len(edge["lines"]) < 12 and line_number not in edge["lines"]:
            edge["lines"].append(line_number)

    for number, original in enumerate(lines, 1):
        line = refang(original)
        tags = [tag for tag, pattern in TAGS.items() if pattern.search(line)]
        excerpt = original[:500]
        seen_spans = []
        line_ids = set()
        for pattern in (URL, HASH, IPV4, IPV6, DOMAIN):
            for match in pattern.finditer(line):
                if any(start <= match.start() < end for start, end in seen_spans):
                    continue
                value = match.group().rstrip(".;}")
                for ending, opening in ((")", "("), ("]", "[")):
                    while value.endswith(ending) and value.count(ending) > value.count(opening):
                        value = value[:-1]
                if pattern == DOMAIN and value.lower().endswith(
                    (".exe", ".dll", ".log", ".txt", ".csv", ".json", ".ps1")
                ):
                    continue
                key = add(value, number, excerpt, tags)
                if not key:
                    continue
                seen_spans.append(match.span())
                line_ids.add(key)
                if indicators[key].ioc.type == IOCType.url:
                    host = urlsplit(indicators[key].ioc.value).hostname
                    host_key = add(host, number, excerpt, tags)
                    if host_key:
                        line_ids.add(host_key)
                        connect(key, host_key, "url_host", number)
        # Relationships mean co-occurrence only, not attribution or causality.
        for left, right in combinations(sorted(line_ids)[:20], 2):
            connect(left, right, "same_line", number)
    if not indicators:
        raise ValueError("No supported indicators found in this text")
    relationships = [
        Relationship(source=a, target=b, kind=kind, **data) for (a, b, kind), data in edges.items()
    ]
    warnings = [
        "Extraction and local keyword tags are heuristics; review original context. Relationships do not prove causality."
    ]
    if truncated:
        warnings.append(
            f"Only the first {MAX_INDICATORS} unique indicators were retained; split the input to review the rest."
        )
    if any(len(line) > 500 for line in lines):
        warnings.append(
            "Displayed source excerpts are limited to 500 characters; keep the original file for full context."
        )
    return Case(
        id=str(uuid4()),
        title=title,
        source_name=source_name,
        synthetic=synthetic,
        line_count=len(lines),
        input_sha256=hashlib.sha256(text.encode()).hexdigest(),
        indicators=list(indicators.values()),
        relationships=relationships,
        warnings=warnings,
        audit=[AuditEntry(action="import", detail="Local extraction only; no external queries")],
    )
