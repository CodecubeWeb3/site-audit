# Assumptions and Limitations

- **Consent handling:** Active and intrusive modules are disabled unless a signed consent file (`.auth/active-scan-consent.json`) is available. The current implementation validates only the presence of configuration; signature verification is expected to be handled manually by the operator.
- **CAA/WHOIS lookups:** The DNS module exposes interfaces for CAA and WHOIS resolution. Default builds do not perform external network lookups; operators must provide resolvers that respect rate limits and legal requirements.
- **Headless capture:** The headless/browser capture module is not yet implemented. Future work will integrate a Playwright-based collector restricted to passive mode.
- **OSINT integrations:** External OSINT services (Shodan, VirusTotal, crt.sh, etc.) require API credentials and are intentionally stubbed out of the default CLI to avoid unauthorized queries.
- **TLS CT lookups:** Certificate Transparency queries are not performed automatically. Placeholder hooks exist for future integration once consent and API endpoints are defined.
- **Reporting redaction:** PII redaction defaults to enabled. Operators opting into `--retain-pii` or equivalent configuration accept responsibility for handling sensitive data.
- **CI network access:** Continuous integration executes only local unit tests and linting; it does not perform network scans or call third-party APIs.
