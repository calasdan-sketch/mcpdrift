"""Signed lockfiles using ``ssh-keygen -Y`` (OpenSSH >= 8.1).

No new Python dependency: it reuses the SSH key many developers already use
to sign git commits, and the same ``allowed_signers`` file format git uses.

What is signed is a short, canonical statement that is *recomputed from the
lockfile's surface* at verify time, never read from the lockfile itself:

    mcpdrift-lock v3
    server: <name>
    seq: <monotonic integer>
    snapshot_at: <timestamp>
    surface-sha256: <hex>

Editing any tool, description or schema, the sequence number or the
timestamp breaks the signature. ``seq`` lets CI reject a *rollback*: an
attacker replaying an older, validly signed lock (see ``check
--previous-lock``).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict

from .canon import sha256_of

NAMESPACE = "mcpdrift"


class SignError(RuntimeError):
    pass


def signing_payload(lock: Dict[str, Any]) -> bytes:
    surface = lock.get("surface")
    if not isinstance(surface, dict):
        raise SignError("lockfile has no surface to sign")
    server = str(lock.get("server") or "")
    stamp = str(lock.get("snapshot_at") or "")
    seq = lock.get("seq", 0)
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise SignError("lockfile seq must be a non-negative integer")
    for label, value in (("server name", server), ("snapshot_at", stamp)):
        if any(c in value for c in "\r\n"):
            raise SignError(f"{label} contains a newline")
    return (
        "mcpdrift-lock v3\n"
        f"server: {server}\n"
        f"seq: {seq}\n"
        f"snapshot_at: {stamp}\n"
        f"surface-sha256: {sha256_of(surface)}\n"
    ).encode("utf-8")


def _ssh_keygen() -> str:
    exe = shutil.which("ssh-keygen")
    if not exe:
        raise SignError("ssh-keygen not found (install OpenSSH 8.1+ to sign or verify lockfiles)")
    return exe


def _run(argv, data: bytes, timeout: float = 30.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
        )
    except subprocess.TimeoutExpired as e:
        raise SignError("ssh-keygen timed out (is the key passphrase-protected without an agent?)") from e


def sign_lock(lock: Dict[str, Any], key_path: str) -> str:
    """Return an armored SSH signature over the lock's signing payload."""
    exe = _ssh_keygen()
    if not os.path.exists(key_path):
        raise SignError(f"signing key not found: {key_path}")
    payload = signing_payload(lock)
    with tempfile.TemporaryDirectory(prefix="mcpdrift-sign-") as tmp:
        msg = os.path.join(tmp, "payload")
        with open(msg, "wb") as fh:
            fh.write(payload)
        proc = _run([exe, "-Y", "sign", "-q", "-f", key_path, "-n", NAMESPACE, msg], b"")
        if proc.returncode != 0:
            raise SignError("ssh-keygen sign failed: " + proc.stderr.decode("utf-8", "replace").strip())
        with open(msg + ".sig", "r", encoding="ascii") as fh:
            return fh.read()


def verify_lock(lock: Dict[str, Any], signature: str, allowed_signers: str, identity: str) -> str:
    """Verify ``signature`` for the lock; returns ssh-keygen's success line."""
    exe = _ssh_keygen()
    if not os.path.exists(allowed_signers):
        raise SignError(f"allowed signers file not found: {allowed_signers}")
    if not identity or any(c in identity for c in "\r\n"):
        raise SignError("a signer identity is required (e.g. the email in allowed_signers)")
    payload = signing_payload(lock)
    with tempfile.TemporaryDirectory(prefix="mcpdrift-verify-") as tmp:
        sig = os.path.join(tmp, "lock.sig")
        with open(sig, "w", encoding="ascii", newline="\n") as fh:
            fh.write(signature)
        proc = _run(
            [exe, "-Y", "verify", "-f", allowed_signers, "-I", identity, "-n", NAMESPACE, "-s", sig],
            payload,
        )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()
        raise SignError("lockfile signature is NOT valid: " + (detail or "verification failed"))
    return proc.stdout.decode("utf-8", "replace").strip() or "Good signature"
