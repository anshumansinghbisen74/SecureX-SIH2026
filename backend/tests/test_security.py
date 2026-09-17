import base64
import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import jwt
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_securex.db"
os.environ["DEMO_SEED_ENABLED"] = "true"
TEST_PASSWORD = secrets.token_urlsafe(18)
os.environ["DEMO_ADMIN_PASSWORD"] = TEST_PASSWORD
os.environ["DEMO_INVESTIGATOR_PASSWORD"] = TEST_PASSWORD
os.environ["DEMO_OFFICER_PASSWORD"] = TEST_PASSWORD
os.environ["DEMO_VIEWER_PASSWORD"] = TEST_PASSWORD

from fastapi.testclient import TestClient
from app.main import _jwt_secret, app, settings


client_context = TestClient(app)
client_context.__enter__()
client = client_context
created_case_number = None


def login(email, password):
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_refresh_token_rotation():
    response = client.post("/auth/login", json={"email": "viewer@securex.local", "password": TEST_PASSWORD})
    assert response.status_code == 200
    first = response.json()
    rotated = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != first["refresh_token"]
    assert client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]}).status_code == 401


def test_login_and_case_creation():
    global created_case_number
    headers = login("investigator@securex.local", TEST_PASSWORD)
    case_number = f"CASE-TEST-{uuid.uuid4().hex[:12]}"
    created_case_number = case_number
    response = client.post("/cases", headers=headers, json={"case_number": case_number, "title": "Evidence test"})
    assert response.status_code == 201
    assert response.json()["case_number"] == case_number


def test_upload_encrypt_and_verify(tmp_path):
    headers = login("investigator@securex.local", TEST_PASSWORD)
    cases = client.get("/cases", headers=headers).json()
    case = next(x for x in cases if x["case_number"] == created_case_number)
    response = client.post("/documents/upload", headers=headers, data={"case_id": case["id"]}, files={"file": ("report.txt", b"CASE-102 forensic evidence Section 302 12 March 2026", "text/plain")})
    assert response.status_code == 201
    doc_id = response.json()["id"]
    encrypted = Path(settings.storage_path, f"{doc_id}.v1.enc").read_bytes()
    assert encrypted != b"CASE-102 forensic evidence Section 302 12 March 2026"
    verified = client.get(f"/documents/{doc_id}/verify", headers=headers)
    assert verified.json()["status"] == "VERIFIED"
    path = Path(settings.storage_path, f"{doc_id}.v1.enc")
    original = path.read_bytes()
    path.write_bytes(original + b"tamper")
    assert client.get(f"/documents/{doc_id}/verify", headers=headers).json()["status"] == "TAMPER DETECTED"
    path.write_bytes(original)

    client_key = X25519PrivateKey.generate()
    client_public = client_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    viewer_headers = login("viewer@securex.local", TEST_PASSWORD)
    denied = client.post(
        f"/documents/{doc_id}/key-release",
        headers=viewer_headers,
        json={"client_public_key": base64.b64encode(client_public).decode()},
    )
    assert denied.status_code == 403
    released = client.post(
        f"/documents/{doc_id}/key-release",
        headers=headers,
        json={"client_public_key": base64.b64encode(client_public).decode()},
    )
    assert released.status_code == 200
    envelope = released.json()
    assert not any(key.lower().endswith("-dek") for key in released.headers)
    server_public = X25519PublicKey.from_public_bytes(base64.b64decode(envelope["server_public_key"]))
    shared = client_key.exchange(server_public)
    envelope_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(envelope["salt"]),
        info=f"securex-key-release:{doc_id}".encode(),
    ).derive(shared)
    encrypted_dek = base64.b64decode(envelope["ciphertext"])
    dek = AESGCM(envelope_key).decrypt(
        base64.b64decode(envelope["nonce"]),
        encrypted_dek,
        doc_id.encode(),
    )
    downloaded = client.get(
        f"/documents/{doc_id}/download",
        headers={**headers, "X-SecureX-Release-Token": envelope["release_token"]},
    )
    assert downloaded.status_code == 200
    clear = AESGCM(dek).decrypt(
        base64.b64decode(downloaded.headers["x-securex-nonce"]),
        downloaded.content,
        None,
    )
    assert clear == b"CASE-102 forensic evidence Section 302 12 March 2026"


def test_public_registration_cannot_escalate_role():
    response = client.post(
        "/auth/register",
        json={
            "email": f"viewer-{uuid.uuid4().hex}@securex.local",
            "full_name": "Unprivileged User",
            "password": secrets.token_urlsafe(18),
            "role": "ADMIN",
        },
    )
    assert response.status_code == 201
    assert response.json()["role"] == "VIEWER"


def test_expired_access_token_cannot_release_key():
    expired = jwt.encode(
        {
            "sub": "missing-user",
            "role": "INVESTIGATOR",
            "type": "access",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        },
        _jwt_secret(),
        algorithm="HS256",
    )
    response = client.post(
        "/documents/not-a-document/key-release",
        headers={"Authorization": f"Bearer {expired}"},
        json={"client_public_key": base64.b64encode(secrets.token_bytes(32)).decode()},
    )
    assert response.status_code == 401


def test_audit_chain_tampering_is_detected():
    with sqlite3.connect("test_securex.db") as connection:
        connection.execute("UPDATE audit_events SET event_hash = ? WHERE id = (SELECT id FROM audit_events LIMIT 1)", ("0" * 64,))
        connection.commit()
    headers = login("investigator@securex.local", TEST_PASSWORD)
    result = client.get("/audit/verify-chain", headers=headers)
    assert result.status_code == 200
    assert result.json()["status"] == "TAMPER DETECTED"
