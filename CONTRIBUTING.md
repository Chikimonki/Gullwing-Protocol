# Contributing to Gullwing Protocol

## Welcome!

PRs are welcome. This document explains the workflow.

## Getting Started

1. Fork the repo
2. Clone your fork
3. Create a feature branch
4. Make your changes
5. Run tests
6. Submit PR

## Test Gates

Before submitting a PR, ensure:

```bash
# Run all tests
./scripts/run-ultimate-suite.sh

# Run security checks
./security-pipeline.sh /usr/bin/ls
Coding Conventions
LuaJIT for orchestration

Zig for compute kernels

Python for tooling

Clear variable names

Comments for complex logic

PR Requirements
□ Tests pass
□ Documentation updated
□ No new dependencies without discussion
□ Code follows existing patterns
License
By contributing, you agree your code will be MIT licensed.
