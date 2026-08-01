# Contributing to Gateway

Thank you for your interest in contributing to Gateway!

## Development Workflow

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/aidanhopper/gateway.git
   cd gateway
   ```

2. Build the project locally:
   ```bash
   make build
   ```

3. Run the test suite:
   ```bash
   make test
   ```

## Pull Request Guidelines

- Ensure all existing and new unit tests pass (`go test ./...`).
- Keep commit messages clear and follow Conventional Commits (e.g., `feat(api): add feature`, `fix(serve): resolve bug`).
- Ensure no emojis are introduced into documentation or commit messages.
- Open a pull request against the `main` branch.

## Code of Conduct

Please treat all contributors and maintainers with respect and professionalism.
