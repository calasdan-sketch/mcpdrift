"""Signed lockfiles via ssh-keygen -Y."""
import json
import shutil
import subprocess

import pytest

from mcpdrift.cli import main

pytestmark = pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs OpenSSH ssh-keygen")

LISTING = {"initialize": {"serverInfo": {"name": "s", "version": "1"}},
           "tools": [{"name": "t", "description": "ok", "inputSchema": {"type": "object"}}]}


@pytest.fixture
def setup(tmp_path):
    key = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "dev@example.com", "-f", str(key)], check=True)
    signers = tmp_path / "allowed_signers"
    signers.write_text("dev@example.com " + (tmp_path / "key.pub").read_text().split(" ", 2)[0] + " "
                       + (tmp_path / "key.pub").read_text().split(" ", 2)[1] + "\n")
    listing = tmp_path / "listing.json"
    listing.write_text(json.dumps(LISTING))
    lock = tmp_path / "mcp.lock.json"
    assert main(["snapshot", "--from-file", str(listing), "--out", str(lock), "--sign-key", str(key)]) == 0
    return tmp_path, key, signers, listing, lock


def test_sign_and_verify_roundtrip(setup):
    tmp, key, signers, listing, lock = setup
    assert (tmp / "mcp.lock.json.sig").exists()
    assert main(["verify", "--lock", str(lock), "--allowed-signers", str(signers), "--identity", "dev@example.com"]) == 0
    assert main(["check", "--from-file", str(listing), "--lock", str(lock),
                 "--allowed-signers", str(signers), "--identity", "dev@example.com"]) == 0


def test_tampered_lock_fails_verification(setup):
    tmp, key, signers, listing, lock = setup
    data = json.loads(lock.read_text())
    data["surface"]["tools"]["t"]["description"] = "evil"
    # attacker also fixes up the recorded digest so the integrity check passes
    from mcpdrift.canon import surface_digests
    data["digests"] = surface_digests(data["surface"])
    lock.write_text(json.dumps(data))
    assert main(["verify", "--lock", str(lock), "--allowed-signers", str(signers), "--identity", "dev@example.com"]) == 3
    assert main(["check", "--from-file", str(listing), "--lock", str(lock),
                 "--allowed-signers", str(signers), "--identity", "dev@example.com"]) == 3


def test_wrong_identity_fails(setup):
    tmp, key, signers, listing, lock = setup
    assert main(["verify", "--lock", str(lock), "--allowed-signers", str(signers), "--identity", "eve@example.com"]) == 3


def test_missing_signature_fails(setup):
    tmp, key, signers, listing, lock = setup
    (tmp / "mcp.lock.json.sig").unlink()
    assert main(["verify", "--lock", str(lock), "--allowed-signers", str(signers), "--identity", "dev@example.com"]) == 3


def test_snapshot_at_change_keeps_signature_valid(setup):
    tmp, key, signers, listing, lock = setup
    data = json.loads(lock.read_text())
    data["snapshot_at"] = "1999-01-01T00:00:00+00:00"
    lock.write_text(json.dumps(data))
    assert main(["verify", "--lock", str(lock), "--allowed-signers", str(signers), "--identity", "dev@example.com"]) == 0
