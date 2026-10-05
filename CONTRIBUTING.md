# Contributing to Agent Security CLI 🛡️

Thank you for your interest in contributing to **Agent Security CLI**! We welcome contributions from developers, security researchers, and AI architects worldwide.

## Before you begin

### Sign our Contributor License Agreement

Contributions to this project must be accompanied by a
[Contributor License Agreement](https://cla.developers.google.com/about) (CLA).
You (or your employer) retain the copyright to your contribution; this simply
gives us permission to use and redistribute your contributions as part of the
project.

If you or your current employer have already signed the Google CLA (even if it
was for a different project), you probably don't need to do it again.

Visit <https://cla.developers.google.com/> to see your current agreements or to
sign a new one.

### Review our Community Guidelines

This project follows [Google's Open Source Community
Guidelines](https://opensource.google/conduct/).

---

## 🧭 How to Contribute

There are many ways to contribute:
* **Add new security rules & AST checks** (e.g. new STRIDE patterns, MCP vulnerabilities, LangGraph / CrewAI / Semantic Kernel integrations).
* **Improve prompt guard evaluation datasets** for red-teaming.
* **Report bugs or suggest features** via [GitHub Issues](https://github.com/RaviManjunatha/agent-security-cli/issues).
* **Improve documentation & architecture guides**.

---

## 🛠️ Local Development Setup

### 1. Fork & Clone
```bash
git clone https://github.com/RaviManjunatha/agent-security-cli.git
cd agent-security-cli
```

### 2. Create a Virtual Environment
```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install with Development Dependencies
```bash
pip install -e ".[dev]"
```

---

## 🧪 Running Tests

We maintain 100% pass rates across all test suites:

```bash
# Run full pytest test suite
pytest tests/ -v

# Run with test coverage
pytest --cov=src/agent_security tests/
```

---

## 🚀 Adding a New Security Check / Engine

All security inspection engines reside in `src/agent_security/core/`:

1. **Create or edit engine:** `src/agent_security/core/<engine_name>.py`.
2. **Implement CLI subcommand:** Wire the engine into `src/agent_security/cli.py`.
3. **Write comprehensive unit tests:** Add test cases in `tests/test_<engine_name>.py`.
4. **Update Documentation:** Document the new check in `README.md`.

---

## 📦 Pull Request Guidelines

1. Create a descriptive feature branch: `git checkout -b feat/my-new-security-check`.
2. Ensure all tests pass: `pytest tests/ -v`.
3. Format code with standard Python typing (`typing`, Pydantic v2).
4. Submit a Pull Request targeting the `main` branch.
5. Link any relevant issue numbers (e.g., `Fixes #12`).

---

## 📜 Code of Conduct

Please review and adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) during all project interactions.
