# Security and privacy

ThreatFusion is a local defensive portfolio tool. It never executes or downloads samples, scans targets, visits indicators, resolves DNS, posts URLs for analysis, or uploads files. The live clients only read existing records from fixed HTTPS provider origins. TLS verification stays enabled and redirects/proxy environment inheritance are disabled.

Default demo mode has no network calls. In live mode non-global/reserved/multicast IPs and reserved/local domain suffixes are blocked. URL disclosure requires explicit per-request consent; private URL hosts remain blocked. This guard runs before cache and plugin invocation. DNS rebinding is not relevant to indicator fetching because fetching never occurs, but a domain name can still disclose internal information. Syntax and suffix checks cannot identify every confidential hostname.

API keys come from environment/.env and are represented as secrets in configuration. Keep `.env`, databases, backups, and reports out of public repositories. Do not log provider request URLs/headers; they may contain IOCs or keys. The default server disables access logs. Application errors omit upstream body/exception details. No external fonts, scripts, telemetry, or dashboard asset requests are needed.

The dashboard treats all IOC/provider data as text, not HTML. PDF content is XML-escaped. SQLite queries are parameterized. API mutation requests with a foreign Origin are rejected; there is no permissive CORS. Optional `X-API-Key` protects data/operations. Use TLS and an authenticated reverse proxy with request-size/rate limits for anything beyond local testing. Directly starting Uvicorn bypasses the CLI's non-loopback guard: the deployer must configure authentication. Reverse-proxy header policy must be configured explicitly.

The in-process limiter and provider timeouts bound routine upstream work but are not a comprehensive denial-of-service defense. DB history has no automatic retention. Use the clear-history command or DELETE endpoint to clear all cached and saved analyses. This is logical deletion with vacuum/checkpoint, not a guarantee against forensic recovery or copies. Apply OS permissions and encrypted storage as needed.

Trusted third-party plugin code can access process secrets and bypass network intentions internally. Review plugins before registering them. Provider subscriptions may restrict use, sharing, or retention; verify the terms applicable to your account.

Scores are unvalidated, source intelligence can be wrong or stale, and community associations can be benign context. Human review is required. Do not connect this heuristic directly to automated blocking, incident severity decisions, or legal attribution.

To report a vulnerability in your fork, contact its maintainer privately. Do not include real secrets, private indicators, or active malicious links in public issues; use reserved fixtures and mocked responses.

Case imports are local-only and do not trigger enrichment. Selected live enrichment filters non-public IOCs and full URLs lacking explicit consent. Source excerpts, filenames, and analyst notes are untrusted text and never executed. Case data and audit records remain in plaintext SQLite; exports may contain source context. Deleting a case is logical deletion and does not erase separate IOC cache/history or backups. CSV formula prefixes are neutralized. Case deletion is rejected during active enrichment. Import size limits are enforced on actual request bytes, including chunked transfer.
