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

- Enforce request-body size limits while streaming, including chunked requests; the current app checks Content-Length. Bound upstream response reads while streaming; the current size check happens after download.
- Add inbound rate limits, per-account provider budgets, deduplication of simultaneous identical cache misses, and durable quota coordination for multiple workers. Current serialization/cooldowns are process-local and react to provider responses.
- Define the deployment threat model, TLS reverse-proxy configuration, user authentication/authorization, and operational monitoring. The current API key grants single-user access and deletion privileges.
- Define retention, backups, file permissions, and encryption appropriate to the data being handled. SQLite and exported reports are not encrypted by the application.
- Add a supported deployment package, health/readiness checks, and an operational recovery guide. Docker is not currently provided.

Publishing this repository as a portfolio does not require deploying the application as a public service.

## Product enhancements

- Bulk CSV/JSON import with per-IOC results, cancellation, progress, and disclosure consent.
- Search/filter/pagination in dashboard history, per-analysis deletion, notes, and investigations grouped into cases. The API already supports paginated history.
- Time comparisons, richer provider context, and related-indicator views with source attribution preserved.
- STIX/TAXII interoperability and additional providers after defining normalized schemas and scoring semantics.

## Already available

IOC validation for seven types; three async provider adapters; privacy guards; source-attributed evidence; explainable heuristic risk with separate quality metrics; bounded retries and 429 cooldowns; SQLite cache/history; FastAPI; Typer/Rich CLI; functional local dashboard and API explorer; JSON/PDF reports; synthetic demo fixtures; mocked tests; and CI configuration.
