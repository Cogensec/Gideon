---
title: Contributing
description: How to contribute to Gideon.
---

# Contributing to Gideon 🤝

First off, thank you for considering contributing to Gideon! It's people like you that make Gideon such a great tool for the defensive security community.

## Code of Conduct

Gideon follows a strict **Defensive-Only** mandate. We do not accept contributions that:
- Implement offensive capabilities (exploit generation, malware, etc.).
- Facilitate unauthorized access to systems.
- Provide instructions for malicious activities.

## How Can I Contribute?

### Reporting Bugs
If you find a bug, please open an issue on GitHub. Include:
- A clear description of the issue.
- Steps to reproduce.
- Your environment details (OS, Bun version).

### Suggesting Enhancements
Have an idea for a new skill or security connector? Open a "Feature Request" issue to discuss it with the community.

### Pull Requests
1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests!
3. Ensure the test suite passes (`bun test`).
4. Run the typechecker (`bun run typecheck`).
5. Link your PR to a relevant issue.

---

## Technical Standards

- **Language**: TypeScript (Strict Mode).
- **Runtime**: Bun.
- **UI**: Ink (React for terminal).
- **Style**: Clear, typed, and well-documented.

---

## License

By contributing to Gideon, you agree that your contributions will be licensed under its [MIT License](/docs/community/license).
