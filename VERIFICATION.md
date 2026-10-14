# Verification record

Verified locally on **2026-10-14**, Windows, Python **3.12.14**.

- Repeated installation and all 89 tests successfully in the owner's Python 3.11 environment on Windows after setup.
- **89 tests passed**, **97.28% statement coverage**, exceeding the CI threshold of 85%.
- Ruff static checks and formatting checks passed.
- Dashboard and documentation JavaScript syntax checks passed.
- Python 3.11 syntax compatibility checked; other Python/OS combinations are configured in CI but were not run locally.
- FastAPI mocked integration tests exercised analysis, history, retrieval, JSON/PDF export, schema, local documentation, authentication, CSRF Origin checks, and request size rejection.
- CLI tests exercised validation, demo, analysis, exports, history, deletion, and non-loopback binding guard.
- HTTPX mocked tests exercised all three normalized adapters, transport retries, authentication failures, malformed payloads, 429 retry/cooldown, URL identifiers, unsupported types, missing credentials, and disclosure policy.
- Browser demo verified an investigation with score 76, source evidence, explanations, quality metrics, and saved history.
- Sample PDF was rendered and visually inspected: one page, legible tables/evidence/timestamps, no clipping. Sample JSON matches that PDF analysis.
- Built a wheel and smoke-tested it independently of the source checkout: packaged assets, fixture analysis, API routes, and PDF export passed.
- Final browser checks confirmed PDF download and the local API explorer's successful health request.

Examples are in `examples/`: dashboard preview, synthetic report PDF, and matching JSON.

The initial verification was offline. On 2026-10-14, an owner-authorized VirusTotal live lookup for public IP `8.8.8.8` succeeded and returned 0/92 malicious detections. The documentation address `203.0.113.42` remained blocked in live mode with unknown risk. No suspicious URLs were submitted and no samples were executed. Credentials are stored only in ignored local configuration. AbuseIPDB/OTX live behavior and other VirusTotal IOC types remain unverified.

The installed Starlette version emits one deprecation warning about its HTTPX-based TestClient. Tests still pass. This is a test-client compatibility notice, not a failed runtime check.

Selected tested dependency versions:

```text
fastapi 0.143.1       uvicorn 0.54.0       httpx 0.28.1
pydantic 2.14.1      pydantic-settings 2.16.0
typer 0.27.3         rich 14.3.4          reportlab 4.5.1
idna 3.20            pytest 9.1.1         pytest-asyncio 1.4.0
pytest-cov 7.1.0     ruff 0.17.0          pypdf 6.20.1
```

Heuristic scores have **not** been benchmarked, calibrated, or validated against a labeled threat dataset. Code coverage is not evidence of detection accuracy.

## Demo clarity correction

Demo results now display prominent fictional-data labels in the dashboard, CLI, and PDF exports; historical demo entries remain explicitly simulated when the running app is in live mode. The fictional fixture score for `203.0.113.42` is not a VirusTotal reputation claim. Rechecked all 89 mocked tests after this change: 97.30% coverage.
