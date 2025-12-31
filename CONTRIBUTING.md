# Contributing to WAF Detector

First off, thank you for considering contributing to WAF Detector! It's people like you that make this tool better for everyone.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps to reproduce the problem**
* **Provide specific examples to demonstrate the steps**
* **Describe the behavior you observed and what behavior you expected**
* **Include logs and error messages**
* **Specify your environment** (OS, Go version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a detailed description of the suggested enhancement**
* **Explain why this enhancement would be useful**
* **List some examples of how it would be used**

### Adding WAF Signatures

To add a new WAF signature:

1. Add the signature to `signatures/signatures.go`
2. Include detection patterns for headers, cookies, and response bodies
3. Test against real WAF instances when possible
4. Document the detection method

### Pull Requests

* Fill in the required template
* Follow the Go coding style
* Include appropriate test cases
* Update documentation as needed
* End all files with a newline
* Ensure all tests pass
* Update CHANGELOG.md

## Development Setup

```bash
# Clone the repository
git clone https://github.com/ahmedtouahria/waf-detector.git
cd waf-detector

# Install dependencies
go mod download

# Run tests
make test

# Run linter
make lint

# Build
make build
```

## Style Guide

### Go Code Style

* Follow the official [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
* Run `gofmt` before committing
* Use meaningful variable names
* Add comments for exported functions
* Keep functions focused and small
* Use error handling, don't panic

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests after the first line

Example:
```
Add support for custom WAF signatures

- Implement signature loading from external files
- Add validation for custom signatures
- Update documentation

Closes #123
```

## Testing

* Write unit tests for new functionality
* Ensure all tests pass before submitting PR
* Aim for high test coverage
* Include both positive and negative test cases

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific package tests
go test ./scanner -v
```

## Release Process

Releases are automated through GitHub Actions when a new tag is pushed:

```bash
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.

Thank you for contributing! 🎉
