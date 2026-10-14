# ThreatFusion roadmap

The requested local portfolio MVP is implemented and tested. The work below is intentionally open; none of it is claimed as already implemented.

## Verification priorities

| Priority | Remaining work | Acceptance criteria |
| --- | --- | --- |
| High | Live-provider compatibility | With account-owner credentials and approved public fixtures, verify each provider's actual response fields, entitlements, timestamps, and quota behavior. Never use confidential URLs. Keep this opt-in and outside normal CI. |
| High | Score evaluation | Define a labeled evaluation dataset and methodology; measure false positives/negatives and source correlation. Keep current scores labeled unvalidated until evidence supports stronger claims. |
| Medium | Automated dashboard regression | Add browser tests for analysis, authentication, history, report downloads, errors, and responsive layouts. Current browser checks are manual. |
| Medium | Reproducible dependencies | Add a maintained dependency lock and update process, plus dependency vulnerability auditing. Current dependencies use bounded version ranges. |

## Before hosting the application publicly

- Bound upstream response reads while streaming; the current provider size check happens after download. Inbound chunked/body limits are now implemented.
- Add inbound rate limits, per-account provider budgets, deduplication of simultaneous identical cache misses, and durable quota coordination for multiple workers. Current serialization/cooldowns are process-local and react to provider responses.
- Define the deployment threat model, TLS reverse-proxy configuration, user authentication/authorization, and operational monitoring. The current API key grants single-user access and deletion privileges.
- Define retention, backups, file permissions, and encryption appropriate to the data being handled. SQLite and exported reports are not encrypted by the application.
- Add a supported deployment package, health/readiness checks, and an operational recovery guide. Docker is not currently provided.

Publishing this repository as a portfolio does not require deploying the application as a public service.

## Product enhancements

- Richer cross-case search, case merging, per-analysis deletion, and structured CSV column mapping. Local text import, case groups, per-case deletion, IOC filtering, findings, and progress/cancellation are now implemented.
- Time comparisons, richer provider context, and related-indicator views with source attribution preserved.
- STIX/TAXII interoperability and additional providers after defining normalized schemas and scoring semantics.

## Already available

IOC validation for seven types; three async provider adapters; privacy guards; source-attributed evidence; explainable heuristic risk with separate quality metrics; bounded retries and 429 cooldowns; SQLite cache/history; FastAPI; Typer/Rich CLI; functional local dashboard and API explorer; JSON/PDF reports; synthetic demo fixtures; mocked tests; and CI configuration.

## Investigation workflow shipped

Local text/log/CSV/JSON/email-text extraction and deduplication; defanged IOC parsing; source-line provenance; occurrence counts; co-occurrence and URL-host relationships; context-based review priorities and next steps; optional selected batch enrichment with cancellation; analyst dispositions/notes; case activity history; case deletion; CSV/JSON/PDF investigation exports; CLI import/report commands; and a dedicated case dashboard. All remain human-reviewed heuristics.
