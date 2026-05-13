# Contributing to Azure Environment Review Tool

First off, thank you for considering contributing to this tool! It's people like you that make it a better resource for the security community.

## How Can I Contribute?

### Reporting Bugs
- Use the GitHub Issues to report bugs.
- Describe the exact steps to reproduce the issue.
- Include information about your environment (Node.js version, OS).

### Suggesting Enhancements
- Open a GitHub Issue with the tag "enhancement".
- Clearly explain how the feature would work and why it would be useful.

### Pull Requests
1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Project Structure

- `src/agents/`: Specialized AI agent instructions.
- `src/models/`: Database schemas.
- `src/routes/`: API endpoint definitions.
- `src/services/`: Core business logic and engines.
- `src/utils/`: Shared utilities and Azure clients.
- `public/`: Frontend assets.

## Style Guide

- Use PascalCase for model names.
- Use camelCase for variables and function names.
- Maintain consistent indentation (2 spaces).
- Write descriptive commit messages.

## Developing Locally

Refer to the [README.md](./README.md) for setup instructions. You can use `npm run dev` to start the server with auto-reload.

If you are adding new security checks, look at `src/services/findingEngine.js` for examples of deterministic rules.
