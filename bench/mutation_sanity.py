"""Mutation-style sanity check: python bench/mutation_sanity.py  (needs pytest).

Copies src/ into a temporary folder, flips one key condition at a time and runs
the fast test files against the copy. A mutant that the tests do NOT notice is
"survived" and the script exits 1: either a test is missing or the condition is
dead code. A control run without any mutation must pass, and the first mutant's
failure proves the copy is the code actually under test.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TESTS = ["tests/test_risk.py", "tests/test_canon.py", "tests/test_normalize.py", "tests/test_review.py",
         "tests/test_round3.py", "tests/test_round5.py", "tests/test_render.py", "tests/test_sign.py"]

# (file, exact text that occurs once, replacement, what it breaks)
MUTANTS = [
    ("risk.py", "if _RANK[sev] > _RANK[self.severity]:", "if _RANK[sev] < _RANK[self.severity]:", "severity only goes up"),
    ("risk.py", 'out.append(("high", f"instruction aimed at the model: {m.group(0)[:60]!r}"))\n    else:',
     'out.append(("low", f"instruction aimed at the model: {m.group(0)[:60]!r}"))\n    else:', "injection marker grade"),
    ("risk.py", 'out.append(("high", f"steers other tools (shadowing): {m.group(0)[:60]!r}"))',
     'out.append(("low", f"steers other tools (shadowing): {m.group(0)[:60]!r}"))', "shadowing grade"),
    ("risk.py", "if len(text) > MAX_TEXT:", "if len(text) > MAX_TEXT * 10:", "over-long text is flagged"),
    ("risk.py", "|\\b(always|also|additionally|silently)\\s+(bcc|", "|\\b(zzz|also|additionally|silently)\\s+(bcc|", "shadowing: always BCC"),
    ("cli.py", "rank(worst) >= rank(fail_on)", "rank(worst) > rank(fail_on)", "--fail-on is inclusive"),
    ("cli.py", "if l_seq < p_seq:", "if l_seq < p_seq - 1:", "rollback detection"),
    ("cli.py", "ver > LOCKFILE_VERSION", "ver > LOCKFILE_VERSION + 1", "newer lock refused"),
    ("cli.py", "raw.isascii() and raw.isdigit()", "raw.isdigit()", "SOURCE_DATE_EPOCH takes ASCII digits only"),
    ("canon.py", "        if k in out:\n            raise DuplicateKeyError(k)", "        if k in out and False:\n            raise DuplicateKeyError(k)", "repeated JSON keys refused"),
    ("canon.py", "def is_missing(value: Any) -> bool:\n    return value is _MISSING",
     "def is_missing(value: Any) -> bool:\n    return value is not _MISSING", "missing marker"),
    ("normalize.py", "_OPAQUE = {\"default\", \"const\", \"examples\", \"example\"}", "_OPAQUE = set()", "data under default/const kept raw"),
    ("render.py", "fails = fail_on != \"never\" and rank(a.severity) >= rank(fail_on)",
     "fails = rank(a.severity) >= rank(fail_on)", "junit never"),
    ("render.py", "t = _XML_BAD.sub(", "t = (lambda *_: t)(", "junit strips non-XML characters"),
]


def run_tests(src_root):
    env = dict(os.environ, PYTHONPATH=os.path.join(src_root, "src"), PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *TESTS],
                       cwd=ROOT, env=env, capture_output=True, text=True)
    return r.returncode, r.stdout[-300:]


def main():
    survived = []
    tmp = tempfile.mkdtemp(prefix="mutsan-")
    try:
        code, tail = run_tests(ROOT)
        print("control (no mutation):", "pass" if code == 0 else "FAIL\n" + tail)
        if code != 0:
            return 2
        for i, (fname, old, new, why) in enumerate(MUTANTS):
            work = os.path.join(tmp, f"m{i}")
            shutil.copytree(os.path.join(ROOT, "src"), os.path.join(work, "src"),
                            ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
            path = os.path.join(work, "src", "mcpdrift", fname)
            text = open(path, encoding="utf-8").read()
            if text.count(old) != 1:
                print(f"BAD MUTANT {i} ({why}): pattern occurs {text.count(old)} times")
                return 2
            open(path, "w", encoding="utf-8").write(text.replace(old, new))
            code, _ = run_tests(work)
            status = "killed" if code != 0 else "SURVIVED"
            print(f"{status:9} {fname}: {why}")
            if code == 0:
                survived.append(why)
            shutil.rmtree(work, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"{len(MUTANTS) - len(survived)}/{len(MUTANTS)} killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
