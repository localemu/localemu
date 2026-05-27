# Contributing to LocalEmu

Thank you for considering a contribution. The detailed contributor guide
lives at [`docs/CONTRIBUTING.md`](./docs/CONTRIBUTING.md), with deeper
references for the dev environment and for testing:

- [Contributor guide](./docs/CONTRIBUTING.md): coding style, PR
  expectations, sign-off, license header.
- [Development environment setup](./docs/development-environment-setup/README.md):
  Python venv, Docker, the editable pip install, how to run a local
  LocalEmu against the source tree.
- [Testing](./docs/testing/README.md): unit tests, integration tests,
  end-to-end tests.

Quick-start for a first contribution:

```bash
git clone https://github.com/localemu/localemu.git
cd localemu
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[runtime,test,dev]"
# pick an issue with the "good first issue" label, branch, code, test, PR
pytest tests/unit -q   # 24,928 unit tests; runs in a few minutes
```

For security issues, please do **not** open a public GitHub issue.
See [SECURITY.md](./SECURITY.md) for the disclosure address and process.
