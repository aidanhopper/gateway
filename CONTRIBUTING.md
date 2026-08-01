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

## Commit Message Guidelines

All commit messages MUST follow the **Conventional Commits 1.0.0** specification along with the following mandatory formatting constraints:

### Structural Format
```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Formatting Rules & Constraints
- **All Lowercase**: The subject line (`<type>[scope]: <description>`) MUST be written entirely in lowercase.
- **Subject Line Length Limit**: The subject line MUST NOT exceed **50 characters**.
- **Body Line Length Limit**: Lines in the commit body MUST NOT exceed **72 characters** per line.
- **No Emojis**: Commit messages MUST NOT contain any emojis.

### Commit Types
- `feat`: Introduces a new feature (correlates with MINOR in SemVer)
- `fix`: Patches a bug (correlates with PATCH in SemVer)
- `refactor`: Code changes that neither fix a bug nor add a feature
- `test`: Adding or updating test cases
- `docs`: Documentation-only changes
- `chore`: Maintenance, dependency, or tooling updates
- `ci`: CI pipeline and workflow updates
- `perf`: Performance improvements
- `build`: Changes affecting build system or dependencies

### Breaking Changes
- Append `!` after the type/scope (e.g., `feat(api)!: drop legacy endpoint`), or include a `BREAKING CHANGE:` footer.

### Examples
- `feat(api): add serve mount parameter`
- `fix(serve): resolve listener cleanup deadlock`
- `docs: update deployment guidelines`
- `feat(cli)!: remove deprecated listen flag`

## Pull Request Guidelines

- Ensure all existing and new unit tests pass (`make test` or `go test ./...`).
- Strictly adhere to the Conventional Commits guidelines above.
- Ensure no emojis are introduced into documentation or commit messages.
- Open a pull request against the `main` branch.

## Code of Conduct

Please treat all contributors and maintainers with respect and professionalism.
