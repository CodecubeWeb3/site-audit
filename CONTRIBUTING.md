# Contributing

Thank you for your interest in contributing to **site-audit**. The project emphasises consent-first security practices and expects contributors to follow the same principles.

## Development Workflow

1. Fork the repository and create a feature branch from `feat/site-audit-mvp`.
2. Ensure your changes remain in passive mode unless an authenticated consent file is provided.
3. Run the required checks:
   - `go test ./...`
   - `go vet ./...`
   - `golangci-lint run`
4. Update `session-log.md` with a short summary of the work performed and tests executed.
5. Submit a pull request referencing relevant issues or tasks.

## Coding Guidelines

- Follow idiomatic Go style and run `gofmt` before committing.
- Avoid adding active or intrusive behaviour to CI workflows or default command paths.
- Keep modules decoupled and favour dependency injection for network-facing logic.
- Provide tests for new packages or behaviours wherever practical.

## Reporting Issues

Use the GitHub issue tracker to report bugs or request enhancements. Include reproduction steps, configuration snippets, and relevant log output where possible.

## Security

This project does not accept vulnerability reports through the issue tracker. Please contact the maintainers privately for responsible disclosure.
