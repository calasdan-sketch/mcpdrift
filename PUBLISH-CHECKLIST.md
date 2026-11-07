# Publish checklist (nothing here has been run for you)

**Version to release: 0.3.0.** The code already says 0.3.0 everywhere and the CHANGELOG heading says "(unreleased)". PyPI has only 0.1.0 (checked 2026-11-07), so this release jumps over 0.2.0, which was never published. It is **not drop-in compatible** with 0.1.0 (still pre-1.0, so a minor bump is fine):
- `check` now fails on any finding of `low` or worse by default (0.1 failed on any drift; version-only bumps no longer fail).
- It lists the server three times per run, not once.
- Locks are version 2. A 0.1 lock still works but reports a few things as "added" the first time; re-snapshot after reading `mcpdrift scan`.

## Before you publish

1. Check the CI file on GitHub: push this branch to a throwaway branch and look at the Actions tab. The Windows and macOS jobs have never run. If Windows fails, that is useful news, not a reason to hide it.
2. In a fresh folder: `python -m venv v && v/bin/pip install pytest ruff build twine && v/bin/pip install -e . && v/bin/pytest -q && v/bin/ruff check .`
3. Build and check: `python -m build` then `twine check dist/*` (both must say PASSED).
4. Install the built wheel into a new empty venv (not editable) and run `mcpdrift --version` and `mcpdrift demo`. You should see `0.3.0`, a CRITICAL finding, and "6 drift finding(s)".
5. Read the top of `README.md`: the "Version note" box says PyPI still carries 0.1.0. **Delete that box after the release is live**, and check `pip install mcpdrift` then shows 0.3.0.
6. Decide the author line: it says `Dan Calas` with no email. Change `authors` in `pyproject.toml` if you want an email or the company name (Calas Automations Inc.).

## Publish (costs nothing; needs a PyPI account and API token)

```
python -m build
twine upload dist/*
git tag v0.3.0
git push origin expert-2 --tags
```

Prefer PyPI "trusted publishing" over a long-lived token if you set up a workflow later (not built).

## After

- `pip index versions mcpdrift` should list 0.3.0.
- The GitHub Action in `action.yml` installs from the repo itself, so tag or pin the commit people should use.
- Mention in the release notes that Windows has not been run.
