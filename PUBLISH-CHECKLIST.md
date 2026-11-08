# Publish checklist (nothing here has been run for you)

**Version to release: 0.3.0.** The code says 0.3.0 everywhere and the CHANGELOG heading says "(unreleased)". PyPI has only 0.1.0 (checked 2026-11-08), so this release jumps over 0.2.0, which was never published. It is **not drop-in compatible** with 0.1.0 (still pre-1.0, so a minor bump is fine):
- `check` now fails on any finding of `low` or worse by default (0.1 failed on any drift; version-only bumps no longer fail).
- It lists the server three times per run, not once.
- Locks are version 2. A 0.1 lock still works (tested): the first `check` shows one harmless `info` line. Do not run 0.1.0 against a lock made by 0.3.0.

The author line is already "Calas Automations Inc." (no email) in the package, the licence and the Action. Nothing to decide there unless you want to add an email.

## Before you publish

1. Push this branch to a throwaway branch on GitHub and look at the Actions tab. The Windows and macOS jobs have never run. If Windows fails, that is useful news, not a reason to hide it.
2. In a fresh folder: `python -m venv v && v/bin/pip install pytest hypothesis ruff build twine && v/bin/pip install -e . && v/bin/pytest -q && v/bin/ruff check .` (all tests pass; ruff says "All checks passed").
3. Build and check: `python -m build` then `twine check dist/*` (both must say PASSED).
4. Prove the author: `unzip -p dist/mcpdrift-0.3.0-py3-none-any.whl mcpdrift-0.3.0.dist-info/METADATA | grep -E "^(Author|Maintainer)"` must print `Calas Automations Inc.` twice.
5. Install the built wheel into a new empty venv (not editable) and run `mcpdrift --version` and `mcpdrift demo`. You should see `0.3.0`, a CRITICAL finding, and "6 drift finding(s)".
6. Optional but cheap: `python bench/mutation_sanity.py` (takes a few minutes; every line should say "killed").
7. Read the top of `README.md`: the "Version note" box says PyPI still carries 0.1.0. **Delete that box after the release is live**, then check `pip install mcpdrift` shows 0.3.0.

## Publish (costs nothing; you are signed in to PyPI yourself)

```
python -m build
twine upload dist/*
git tag v0.3.0
git push origin expert-2 --tags
```

(Round 5 did not run any of these.) Prefer PyPI "trusted publishing" over a long-lived token if you set up a workflow later (not built).

## After

- `pip index versions mcpdrift` should list 0.3.0.
- The GitHub Action in `action.yml` installs from the repo itself, so tag or pin the commit people should use.
- Say in the release notes that Windows and macOS have not been run.
