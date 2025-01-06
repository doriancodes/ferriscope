# Contributing

## Getting Started

1. Fork the repository
2. Create a new branch:
```bash
git checkout -b feature/your-feature-name
```

## Development Workflow

### Code Style
- Follow Rust style guidelines
- Use `cargo fmt` before committing
- Run `cargo clippy` to check for common mistakes
- Add comments for complex logic
- Write documentation for public APIs

### Testing
1. Add tests for new features
2. Ensure all tests pass:
```bash
cargo test
```
3. Add integration tests when appropriate
4. Test on multiple platforms if possible

### Commit Guidelines
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- feat: New feature
- fix: Bug fix
- docs: Documentation
- style: Formatting
- refactor: Code restructuring
- test: Adding tests
- chore: Maintenance

Example:
```
feat(capture): add support for VLAN filtering

Implements VLAN tag filtering in packet capture module.
Includes unit tests and documentation updates.

Closes #123
```

## Pull Request Process

1. Update documentation
2. Add tests for new features
3. Ensure CI passes
4. Request review
5. Address feedback

## Bug Reports

Include:
- Ferriscope version
- OS and version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs
- Sample capture (if possible)
