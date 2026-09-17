# Secure'X

Secure'X is a runnable SIH prototype for secure investigation-document lifecycle management. It uses a FastAPI backend, AES-256-GCM envelope encryption, Argon2id password hashing, JWT authentication, case/document authorization, local encrypted storage, deterministic local document analysis, hash-chained audit events, a Solidity proof registry, and a Flutter Material 3 client.

## Repository

```text
securex/
├── backend/       FastAPI API, SQLAlchemy models, crypto and tests
├── frontend/      Flutter Android/web/desktop client
├── blockchain/    Hardhat project and SecureXRegistry.sol
└── docker-compose.yml
```

## Prerequisites

Python 3.11+, Flutter 3.35+, Node.js 20+. Docker Desktop is optional. PostgreSQL is supported through `DATABASE_URL`; SQLite is the default for a zero-install local demo.

## Run the backend

```powershell
cd C:\Users\anshu\securex\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API and OpenAPI UI are available at `http://127.0.0.1:8000/docs`. Production startup does not create accounts automatically. For a disposable local demo only, set `DEMO_SEED_ENABLED=true` in an untracked `.env` file; replace the generated demo passwords before any network exposure.

## Run the Flutter client

```powershell
cd C:\Users\anshu\securex\frontend
flutter pub get
flutter run -d chrome --dart-define=SECUREX_API=http://127.0.0.1:8000
```

For Android emulator use `http://10.0.2.2:8000` as the API value. The client uses real API responses for login, cases, documents, uploads, verification, and audit events.

## Run the local blockchain

```powershell
cd C:\Users\anshu\securex\blockchain
npm install --legacy-peer-deps
npm test
npm run node
# in another terminal
npm run deploy
```

Copy the deployed address into an untracked environment file as `CONTRACT_ADDRESS`, and use a disposable local Hardhat account private key only for the local demo as `BLOCKCHAIN_PRIVATE_KEY`. Never commit either value or use a Hardhat key on a real network. Then call `POST /documents/{id}/blockchain` with an investigator/admin token. The contract stores only a document identifier hash, encrypted-file SHA-256, event type, timestamp, and registrar address.

## SIH demo

1. Sign in as the investigator.
2. Create `CASE-102`.
3. Upload a PDF/TXT/JPG/PNG/DOCX. The backend validates type and size, performs local extraction, encrypts the bytes with a fresh AES-256-GCM DEK, wraps the DEK with the master key, and stores only ciphertext.
4. Open the document action. The client performs an authenticated X25519 key exchange, receives only an encrypted DEK envelope, downloads ciphertext after backend authorization, decrypts AES-GCM in memory, and renders supported text/image content temporarily without writing plaintext to disk.
5. For the tamper demo, append bytes to the corresponding `.enc` file under `backend/storage`, then verify again to receive `TAMPER DETECTED`.
6. Start Hardhat, deploy the registry, configure the backend, and register the proof.
7. Use `POST /documents/{id}/access` to issue a scoped, expiring or one-time grant to the officer. The backend checks role, case membership, grant expiry, and one-time usage before key release.
8. Inspect `/documents/{id}/audit` to show hash-chained lifecycle events.

## Security model

- Passwords are Argon2id hashes; passwords and JWT secrets are never logged.
- Every upload gets a random 256-bit DEK and 96-bit nonce. AES-GCM authentication protects ciphertext integrity.
- The DEK is wrapped separately with a deployment master key. Key release uses an authenticated X25519 + HKDF + AES-GCM envelope bound to the document and client ephemeral public key; plaintext DEKs are never sent in HTTP headers.
- Plaintext is read only during the upload request for analysis/encryption; storage contains ciphertext.
- Backend authorization is enforced for every protected route.
- Audit event hashes chain to the preceding event hash.
- Blockchain registration is optional but real when configured; no document content is put on-chain.
- SQLite is a local development default. Set `DATABASE_URL` to a PostgreSQL URL for deployment. Production requires explicit `JWT_SECRET` and `MASTER_KEY_B64`; development fallbacks are process-local and are not suitable for persisted data.

## Tests

```powershell
cd backend
$env:PYTHONPATH='.'
python -m pytest -q

cd ..\blockchain
npm test

cd ..\frontend
flutter analyze
flutter build apk --debug
```

## Provider configuration and remaining deployment requirements

The analyzer uses `LocalDeterministicProvider` by default. Set `LLM_PROVIDER=llm`, `LLM_ENDPOINT`, `LLM_API_KEY`, and `LLM_MODEL` for an OpenAI-compatible `/chat/completions` provider. Responses are explicitly marked non-authoritative and failures fall back to the local provider. No API key or live LLM endpoint is configured in this development environment; mocked provider tests are included.

Set `TESSERACT_CMD` to an installed executable path, or put `tesseract` on `PATH`. The OCR adapter was exercised with a generated PNG and Tesseract 5.5.3, and reports `ocr: false` safely when unavailable.

`KEY_PROVIDER=development` uses the existing AES-GCM-wrapped DEK format. Production can use `KEY_PROVIDER=aws_kms` with `AWS_KMS_KEY_ID`, `AWS_KMS_REGION`, and AWS credentials supplied by the runtime identity/secret manager; credentials are never embedded in the repository. The provider calls AWS KMS `Decrypt` and never persists plaintext DEKs. Authorization is evaluated before the provider is called.

PostgreSQL is supported with `postgresql+psycopg://...`; Alembic is the schema authority and runtime `create_all()` is disabled for PostgreSQL. This machine has no Docker and the attempted PostgreSQL installer did not produce a runnable local cluster, so a live PostgreSQL test remains blocked by the environment rather than by the application code.

## Refresh tokens and migrations

The backend exposes `POST /auth/refresh` with a refresh token and rotates it on every successful use. Only a SHA-256 hash of each refresh token is stored, and the previous token is revoked. `POST /auth/logout` revokes the supplied refresh token.

For a PostgreSQL or clean SQLite deployment, apply the schema with:

```powershell
cd backend
alembic upgrade head
```

The runtime uses `create_all()` only for SQLite development startup; PostgreSQL deployments must run Alembic migrations as part of release setup.
