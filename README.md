# site-audit

`site-audit` is a consent-first web reconnaissance toolkit written in Go. It provides a command-line interface and reusable packages for performing passive web audits, generating DMCA evidence packs, and exporting machine-readable artifacts.

## Features

- **Passive crawler** with robots.txt awareness, sitemap discovery, link graph generation, and offline mirroring.
- **HTTP header analysis** covering common security, caching, and protocol configuration checks.
- **TLS inspection** collecting certificate chains, cipher information, and mixed-content indicators.
- **DNS profiling** including MX/SPF/DMARC extraction and pluggable CAA/WHOIS resolvers.
- **Technology fingerprinting** for frameworks, CMS hints, SPA routers, and source maps.
- **DMCA evidence packaging** producing signed manifests and ZIP archives of supplied artifacts.
- **HTML/JSON reporting** with redaction defaults and artifact directory management.

## Quick Start

1. Install Go 1.22 or newer.
2. Clone the repository and change into the project directory.
3. Build the CLI:

```bash
go build ./cmd/site-audit
```

4. Create a configuration file (JSON or YAML). An example is shown below.
5. Run the passive audit:

```bash
./site-audit audit --config config.yaml --output artifacts
```

The command generates `artifacts/run.json` and `artifacts/report.html` along with crawler mirrors and module outputs. Active or intrusive modules remain disabled unless explicit signed consent is added (see `.auth` directory instructions).

## Configuration

The CLI accepts either JSON or YAML configuration files. Minimal example:

```yaml
mode: passive
targets:
  - url: https://example.com
    allowedHosts:
      - example.com
http:
  userAgent: site-audit/0.1
crawler:
  maxDepth: 2
  maxPages: 25
reporting:
  outputDir: artifacts
```

For more options consult `core/config/config.go`.

## DMCA Evidence Packs

Use the `dmca` subcommand to bundle evidence files into a signed ZIP with manifest:

```bash
./site-audit dmca --complainant "Example Corp" \
  --file artifacts/mirror/example.com_index.html \
  --file artifacts/run.json
```

The pack is created under `artifacts/evidence/` with SHA-256 hashes recorded in `manifest.json`.

## Reporting

To re-render HTML reports from an existing run:

```bash
./site-audit report --run artifacts/run.json --output artifacts/report.html
```

## Development

Run the full test suite and vetting tools before submitting changes:

```bash
go test ./...
go vet ./...
```

Additional instructions for contributors are available in [CONTRIBUTING.md](CONTRIBUTING.md). Assumptions and limitations are documented in [ASSUMPTIONS.md](ASSUMPTIONS.md).

## License

This project is released under the [MIT License](LICENSE).
