from __future__ import annotations

import base64
import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, select
from sqlalchemy.ext.asyncio import AsyncAttrs, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from app.providers import (
    AwsKmsKeyProvider,
    DevelopmentKeyProvider,
    DocumentAnalysisProvider,
    KeyManagementProvider,
    LocalDeterministicProvider,
    LlmAnalysisProvider,
    TesseractOcrProvider,
)

if os.name == "nt" and os.environ.get("DATABASE_URL", "").startswith("postgresql+"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "sqlite+aiosqlite:///./securex.db"
    environment: str = "development"
    jwt_secret: str = ""
    jwt_expire_minutes: int = 30
    master_key_b64: str = ""
    storage_path: str = "./storage"
    blockchain_rpc_url: str = "http://127.0.0.1:8545"
    blockchain_private_key: str = ""
    contract_address: str = ""
    refresh_token_expire_days: int = 7
    tesseract_cmd: str = ""
    llm_provider: str = "local"
    llm_endpoint: str = ""
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: int = 30
    key_provider: str = "development"
    aws_kms_key_id: str = ""
    aws_kms_region: str = ""
    demo_seed_enabled: bool = False
    demo_admin_password: str = ""
    demo_investigator_password: str = ""
    demo_officer_password: str = ""
    demo_viewer_password: str = ""
    require_https: bool = False


settings = Settings()
if os.name == "nt" and settings.database_url.startswith("postgresql+"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
Path(settings.storage_path).mkdir(parents=True, exist_ok=True)
password_hasher = PasswordHasher()
_development_jwt_secret = secrets.token_urlsafe(48)
_development_master_key = secrets.token_bytes(32)


def utc_datetime(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _master_key() -> bytes:
    if settings.master_key_b64:
        key = base64.urlsafe_b64decode(settings.master_key_b64 + "===")
        if len(key) != 32:
            raise RuntimeError("MASTER_KEY_B64 must decode to exactly 32 bytes")
        return key
    if settings.environment.lower() == "production":
        raise RuntimeError("MASTER_KEY_B64 is required in production")
    return _development_master_key


def _jwt_secret() -> str:
    if settings.jwt_secret:
        if settings.environment.lower() == "production" and len(settings.jwt_secret) < 32:
            raise RuntimeError("JWT_SECRET must contain at least 32 characters in production")
        return settings.jwt_secret
    if settings.environment.lower() == "production":
        raise RuntimeError("JWT_SECRET is required in production")
    return _development_jwt_secret


def validate_security_config() -> None:
    _jwt_secret()
    if settings.key_provider.lower() == "aws_kms" and not settings.aws_kms_key_id:
        raise RuntimeError("AWS_KMS_KEY_ID is required when KEY_PROVIDER=aws_kms")
    if settings.key_provider.lower() != "aws_kms":
        _master_key()


class Base(AsyncAttrs, DeclarativeBase):
    pass


class Role(str, Enum):
    ADMIN = "ADMIN"
    INVESTIGATOR = "INVESTIGATOR"
    OFFICER = "OFFICER"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    VIEW = "VIEW"
    EDIT = "EDIT"
    SHARE = "SHARE"


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(500))
    role: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_number: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    case_type: Mapped[str] = mapped_column(String(100), default="Investigation")
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE")
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class CaseMember(Base):
    __tablename__ = "case_members"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    permission: Mapped[str] = mapped_column(String(30), default=Permission.VIEW.value)


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(120))
    classification: Mapped[str] = mapped_column(String(120), default="UNCLASSIFIED")
    latest_version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class DocumentVersion(Base):
    __tablename__ = "document_versions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    storage_name: Mapped[str] = mapped_column(String(255), unique=True)
    encrypted_dek: Mapped[str] = mapped_column(Text)
    nonce: Mapped[str] = mapped_column(String(64))
    encrypted_hash: Mapped[str] = mapped_column(String(64), index=True)
    plaintext_hash: Mapped[str] = mapped_column(String(64))
    analysis_json: Mapped[str] = mapped_column(Text, default="{}")
    blockchain_tx: Mapped[str | None] = mapped_column(String(255), nullable=True)
    signature: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AccessGrant(Base):
    __tablename__ = "access_grants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    recipient_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    permission: Mapped[str] = mapped_column(String(30))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    one_time: Mapped[bool] = mapped_column(Boolean, default=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    document_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event_type: Mapped[str] = mapped_column(String(80))
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    previous_hash: Mapped[str] = mapped_column(String(64), default="")
    event_hash: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    replaced_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


engine = create_async_engine(settings.database_url, future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db():
    async with SessionLocal() as session:
        yield session


async def init_db():
    validate_security_config()
    if not settings.database_url.startswith(("postgresql://", "postgresql+")):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        existing = (await db.execute(select(User).limit(1))).scalar_one_or_none()
        if not existing and settings.demo_seed_enabled:
            demo_passwords = {
                Role.ADMIN: settings.demo_admin_password,
                Role.INVESTIGATOR: settings.demo_investigator_password,
                Role.OFFICER: settings.demo_officer_password,
                Role.VIEWER: settings.demo_viewer_password,
            }
            if any(not value for value in demo_passwords.values()):
                raise RuntimeError("Demo seed passwords must be supplied outside source control")
            users = [
                ("admin@securex.local", "SecureX Admin", demo_passwords[Role.ADMIN], Role.ADMIN),
                ("investigator@securex.local", "Aarav Investigator", demo_passwords[Role.INVESTIGATOR], Role.INVESTIGATOR),
                ("officer@securex.local", "Riya Officer", demo_passwords[Role.OFFICER], Role.OFFICER),
                ("viewer@securex.local", "Vikram Viewer", demo_passwords[Role.VIEWER], Role.VIEWER),
            ]
            for email, name, password, role in users:
                db.add(User(email=email, full_name=name, password_hash=password_hasher.hash(password), role=role.value))
            await db.commit()


app = FastAPI(title="Secure'X API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def enforce_secure_transport(request: Request, call_next):
    if settings.require_https and request.url.scheme != "https":
        return JSONResponse(status_code=400, content={"detail": "HTTPS is required"})
    response = await call_next(request)
    if settings.require_https:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.on_event("startup")
async def startup():
    await init_db()


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    full_name: str = Field(min_length=2, max_length=200)
    password: str = Field(min_length=10)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    full_name: str
    role: str


class CaseCreate(BaseModel):
    case_number: str = Field(min_length=2, max_length=100)
    title: str
    description: str = ""
    case_type: str = "Investigation"


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    case_number: str
    title: str
    description: str
    case_type: str
    status: str


class MemberCreate(BaseModel):
    user_id: str
    permission: Permission = Permission.VIEW


class GrantCreate(BaseModel):
    recipient_id: str
    permission: Permission = Permission.VIEW
    expires_minutes: int = Field(default=30, ge=1, le=10080)
    one_time: bool = False


class KeyReleaseRequest(BaseModel):
    client_public_key: str = Field(min_length=40, max_length=100)


class KeyReleaseResponse(BaseModel):
    envelope_version: str
    server_public_key: str
    salt: str
    nonce: str
    ciphertext: str
    release_token: str


def make_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": user.id, "role": user.role, "type": "access", "exp": now + timedelta(minutes=settings.jwt_expire_minutes), "iat": now},
        _jwt_secret(),
        algorithm="HS256",
    )


def make_refresh_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": user.id, "type": "refresh", "jti": str(uuid.uuid4()), "exp": now + timedelta(days=settings.refresh_token_expire_days), "iat": now},
        _jwt_secret(),
        algorithm="HS256",
    )


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def issue_refresh_token(user: User, db: AsyncSession) -> str:
    token = make_refresh_token(user)
    db.add(RefreshToken(user_id=user.id, token_hash=token_hash(token), expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)))
    return token


async def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    try:
        payload = jwt.decode(authorization[7:], _jwt_secret(), algorithms=["HS256"])
        user_id = payload["sub"]
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Access token required")
    except (jwt.PyJWTError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_roles(*roles: Role):
    async def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in {r.value for r in roles}:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return checker


async def audit(db: AsyncSession, event_type: str, user_id: str | None, case_id: str | None = None, document_id: str | None = None, data: dict[str, Any] | None = None):
    previous = (await db.execute(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(1))).scalar_one_or_none()
    previous_hash = previous.event_hash if previous else ""
    event_time = datetime.now(timezone.utc)
    payload = json.dumps({"event_type": event_type, "user_id": user_id, "case_id": case_id, "document_id": document_id, "data": data or {}, "timestamp": event_time.isoformat()}, sort_keys=True)
    event_hash = hashlib.sha256((previous_hash + payload).encode()).hexdigest()
    db.add(AuditEvent(user_id=user_id, case_id=case_id, document_id=document_id, event_type=event_type, data_json=json.dumps({**(data or {}), "_audit_timestamp": event_time.isoformat()}), previous_hash=previous_hash, event_hash=event_hash, created_at=event_time))


async def user_can_access(db: AsyncSession, user: User, document: Document, permission: Permission = Permission.VIEW) -> bool:
    if user.role == Role.ADMIN.value or document.created_by == user.id:
        return True
    member = (await db.execute(select(CaseMember).where(CaseMember.case_id == document.case_id, CaseMember.user_id == user.id))).scalar_one_or_none()
    if member and (permission == Permission.VIEW or member.permission in (Permission.EDIT.value, Permission.SHARE.value)):
        return True
    grant = (await db.execute(select(AccessGrant).where(AccessGrant.document_id == document.id, AccessGrant.recipient_id == user.id))).scalars().all()
    now = datetime.now(timezone.utc)
    return any(utc_datetime(g.expires_at) > now and (not g.one_time or g.used_at is None) and g.permission in (Permission.VIEW, permission.value) for g in grant)


def _ocr_provider() -> TesseractOcrProvider:
    return TesseractOcrProvider(settings.tesseract_cmd)


def _analysis_provider() -> DocumentAnalysisProvider:
    if settings.llm_provider.lower() == "llm":
        return LlmAnalysisProvider(
            settings.llm_endpoint,
            settings.llm_api_key,
            settings.llm_model,
            settings.llm_timeout_seconds,
        )
    return LocalDeterministicProvider()


def analyze_bytes(name: str, content: bytes) -> dict[str, Any]:
    text = content.decode("utf-8", errors="ignore")
    ocr_used = False
    extension = Path(name).suffix.lower()
    if extension in {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".pdf"}:
        ocr_text = _ocr_provider().extract(name, content)
        if ocr_text:
            text = ocr_text
            ocr_used = True
    try:
        return _analysis_provider().analyze(name, text, ocr_used=ocr_used)
    except Exception:
        return LocalDeterministicProvider().analyze(name, text, ocr_used=ocr_used)


def protect(content: bytes) -> tuple[bytes, bytes, bytes, str]:
    dek, encoded_wrapped = key_provider().protect()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(dek).encrypt(nonce, content, None)
    return ciphertext, nonce, base64.b64decode(encoded_wrapped), hashlib.sha256(content).hexdigest()


def unwrap_dek(wrapped: bytes) -> bytes:
    return AESGCM(_master_key()).decrypt(wrapped[:12], wrapped[12:], None)


def key_provider() -> KeyManagementProvider:
    if settings.key_provider.lower() == "aws_kms":
        return AwsKmsKeyProvider(settings.aws_kms_key_id, settings.aws_kms_region)
    return DevelopmentKeyProvider(_master_key())


def _make_release_token(user: User, document_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": user.id,
            "document_id": document_id,
            "type": "key_release",
            "jti": str(uuid.uuid4()),
            "exp": now + timedelta(minutes=2),
            "iat": now,
        },
        _jwt_secret(),
        algorithm="HS256",
    )


def _valid_release_token(token: str | None, user: User, document_id: str) -> bool:
    if not token:
        return False
    try:
        claims = jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except jwt.PyJWTError:
        return False
    return (
        claims.get("type") == "key_release"
        and claims.get("sub") == user.id
        and claims.get("document_id") == document_id
    )


async def _consume_one_time_grant(
    db: AsyncSession, user: User, document: Document
) -> None:
    grants = (
        await db.execute(
            select(AccessGrant)
            .where(
                AccessGrant.document_id == document.id,
                AccessGrant.recipient_id == user.id,
            )
            .with_for_update()
        )
    ).scalars().all()
    now = datetime.now(timezone.utc)
    for grant in grants:
        if utc_datetime(grant.expires_at) <= now:
            continue
        if grant.one_time:
            if grant.used_at is not None:
                raise HTTPException(403, "One-time access grant already used")
            grant.used_at = now
            await audit(db, "TOKEN_USED", user.id, document.case_id, document.id, {"grant_id": grant.id})
            return


@app.post("/auth/register", response_model=UserResponse, status_code=201)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    if (await db.execute(select(User).where(User.email == payload.email.lower()))).scalar_one_or_none():
        raise HTTPException(409, "Email already registered")
    user = User(email=payload.email.lower(), full_name=payload.full_name, password_hash=password_hasher.hash(payload.password), role=Role.VIEWER.value)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@app.post("/auth/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == payload.email.lower()))).scalar_one_or_none()
    if not user:
        raise HTTPException(401, "Invalid credentials")
    try:
        password_hasher.verify(user.password_hash, payload.password)
    except VerifyMismatchError:
        raise HTTPException(401, "Invalid credentials")
    refresh_token = await issue_refresh_token(user, db)
    await db.commit()
    return TokenResponse(access_token=make_access_token(user), refresh_token=refresh_token)


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        claims = jwt.decode(payload.refresh_token, _jwt_secret(), algorithms=["HS256"])
        if claims.get("type") != "refresh":
            raise ValueError("wrong token type")
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(401, "Invalid or expired refresh token")
    stored = (await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash(payload.refresh_token)))).scalar_one_or_none()
    if not stored or stored.revoked_at or utc_datetime(stored.expires_at) <= datetime.now(timezone.utc):
        raise HTTPException(401, "Refresh token revoked or expired")
    user = await db.get(User, stored.user_id)
    if not user:
        raise HTTPException(401, "User not found")
    stored.revoked_at = datetime.now(timezone.utc)
    new_refresh = await issue_refresh_token(user, db)
    stored.replaced_by = token_hash(new_refresh)
    await db.commit()
    return TokenResponse(access_token=make_access_token(user), refresh_token=new_refresh)


@app.post("/auth/logout")
async def logout(payload: RefreshRequest, db: AsyncSession = Depends(get_db)):
    stored = (await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash(payload.refresh_token)))).scalar_one_or_none()
    if stored and not stored.revoked_at:
        stored.revoked_at = datetime.now(timezone.utc)
        await db.commit()
    return {"status": "logged out"}


@app.get("/users/me", response_model=UserResponse)
async def me(user: User = Depends(get_current_user)):
    return user


@app.get("/users", response_model=list[UserResponse])
async def users(user: User = Depends(require_roles(Role.ADMIN)), db: AsyncSession = Depends(get_db)):
    return list((await db.execute(select(User).order_by(User.email))).scalars().all())


@app.post("/cases", response_model=CaseResponse, status_code=201)
async def create_case(payload: CaseCreate, user: User = Depends(require_roles(Role.ADMIN, Role.INVESTIGATOR)), db: AsyncSession = Depends(get_db)):
    case = Case(**payload.model_dump(), created_by=user.id)
    db.add(case)
    await db.flush()
    db.add(CaseMember(case_id=case.id, user_id=user.id, permission=Permission.SHARE.value))
    await audit(db, "CASE_CREATED", user.id, case.id, data={"case_number": case.case_number})
    await db.commit()
    await db.refresh(case)
    return case


@app.get("/cases", response_model=list[CaseResponse])
async def list_cases(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if user.role == Role.ADMIN.value:
        return list((await db.execute(select(Case).order_by(Case.created_at.desc()))).scalars().all())
    ids = select(CaseMember.case_id).where(CaseMember.user_id == user.id)
    return list((await db.execute(select(Case).where(Case.id.in_(ids)).order_by(Case.created_at.desc()))).scalars().all())


@app.post("/cases/{case_id}/members", status_code=201)
async def add_member(case_id: str, payload: MemberCreate, user: User = Depends(require_roles(Role.ADMIN, Role.INVESTIGATOR)), db: AsyncSession = Depends(get_db)):
    case = await db.get(Case, case_id)
    target = await db.get(User, payload.user_id)
    if not case or not target:
        raise HTTPException(404, "Case or user not found")
    if user.role != Role.ADMIN and case.created_by != user.id:
        raise HTTPException(403, "Only case creator or admin may add members")
    db.add(CaseMember(case_id=case_id, user_id=payload.user_id, permission=payload.permission.value))
    await audit(db, "CASE_MEMBER_ADDED", user.id, case_id, data={"member_id": payload.user_id})
    await db.commit()
    return {"status": "member added"}


@app.post("/documents/upload", status_code=201)
async def upload_document(case_id: Annotated[str, Form()], file: UploadFile = File(...), user: User = Depends(require_roles(Role.ADMIN, Role.INVESTIGATOR, Role.OFFICER)), db: AsyncSession = Depends(get_db)):
    allowed = {"application/pdf", "text/plain", "image/jpeg", "image/png", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
    if file.content_type not in allowed:
        raise HTTPException(422, "Unsupported file type")
    data = await file.read()
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(413, "File too large")
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    if user.role != Role.ADMIN.value:
        membership = (await db.execute(select(CaseMember).where(CaseMember.case_id == case_id, CaseMember.user_id == user.id))).scalar_one_or_none()
        if not membership or membership.permission not in (Permission.EDIT.value, Permission.SHARE.value):
            raise HTTPException(403, "Not authorized to upload into this case")
    probe = Document(id=str(uuid.uuid4()), case_id=case_id, name=Path(file.filename or "document").name, content_type=file.content_type, created_by=user.id)
    if user.role != Role.ADMIN.value and not await user_can_access(db, user, probe, Permission.EDIT):
        raise HTTPException(403, "Not a member of this case")
    ciphertext, nonce, wrapped, plain_hash = protect(data)
    encrypted_hash = hashlib.sha256(ciphertext).hexdigest()
    analysis = analyze_bytes(probe.name, data)
    probe.classification = analysis["document_type"]
    version = DocumentVersion(document_id=probe.id, version=1, storage_name=f"{probe.id}.v1.enc", encrypted_dek=base64.b64encode(wrapped).decode(), nonce=base64.b64encode(nonce).decode(), encrypted_hash=encrypted_hash, plaintext_hash=plain_hash, analysis_json=json.dumps(analysis), signature=hashlib.sha256((plain_hash + user.id).encode()).hexdigest(), created_by=user.id)
    db.add(probe)
    db.add(version)
    Path(settings.storage_path, version.storage_name).write_bytes(ciphertext)
    await audit(db, "DOCUMENT_UPLOADED", user.id, case_id, probe.id, {"name": probe.name})
    await audit(db, "AI_ANALYSIS_COMPLETED", user.id, case_id, probe.id, {"processor": analysis["processor"]})
    await audit(db, "DOCUMENT_ENCRYPTED", user.id, case_id, probe.id, {"algorithm": "AES-256-GCM"})
    await audit(db, "HASH_GENERATED", user.id, case_id, probe.id, {"hash": encrypted_hash})
    await db.commit()
    return {"id": probe.id, "name": probe.name, "version": 1, "classification": probe.classification, "analysis": analysis, "encrypted_hash": encrypted_hash, "blockchain": {"status": "PENDING", "note": "Start Hardhat and register via /documents/{id}/blockchain"}}


async def get_document_or_404(document_id: str, db: AsyncSession) -> Document:
    document = await db.get(Document, document_id)
    if not document:
        raise HTTPException(404, "Document not found")
    return document


@app.get("/documents")
async def list_documents(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    docs = list((await db.execute(select(Document).order_by(Document.created_at.desc()))).scalars().all())
    result = []
    for doc in docs:
        if await user_can_access(db, user, doc):
            result.append({"id": doc.id, "case_id": doc.case_id, "name": doc.name, "classification": doc.classification, "latest_version": doc.latest_version, "created_at": doc.created_at})
    return result


@app.get("/documents/{document_id}")
async def document_detail(document_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    doc = await get_document_or_404(document_id, db)
    if not await user_can_access(db, user, doc):
        await audit(db, "ACCESS_DENIED", user.id, doc.case_id, doc.id)
        await db.commit()
        raise HTTPException(403, "Document access denied")
    version = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc()).limit(1))).scalar_one()
    await audit(db, "DOCUMENT_VIEWED", user.id, doc.case_id, doc.id)
    await db.commit()
    return {"id": doc.id, "name": doc.name, "case_id": doc.case_id, "content_type": doc.content_type, "classification": doc.classification, "version": version.version, "encrypted_hash": version.encrypted_hash, "plain_hash": version.plaintext_hash, "analysis": json.loads(version.analysis_json), "signature": version.signature, "security": {"encryption": "AES-256-GCM", "integrity": "SHA-256", "authorization": "ACTIVE"}}


@app.get("/documents/{document_id}/versions")
async def versions(document_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    doc = await get_document_or_404(document_id, db)
    if not await user_can_access(db, user, doc):
        raise HTTPException(403, "Document access denied")
    rows = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == document_id).order_by(DocumentVersion.version))).scalars().all()
    return [{"version": x.version, "encrypted_hash": x.encrypted_hash, "created_at": x.created_at, "created_by": x.created_by} for x in rows]


@app.post("/documents/{document_id}/versions", status_code=201)
async def create_version(document_id: str, file: UploadFile = File(...), user: User = Depends(require_roles(Role.ADMIN, Role.INVESTIGATOR, Role.OFFICER)), db: AsyncSession = Depends(get_db)):
    doc = await get_document_or_404(document_id, db)
    if not await user_can_access(db, user, doc, Permission.EDIT):
        raise HTTPException(403, "Document edit denied")
    data = await file.read()
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(413, "File too large")
    latest = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc()).limit(1))).scalar_one()
    version_number = latest.version + 1
    ciphertext, nonce, wrapped, plain_hash = protect(data)
    storage_name = f"{doc.id}.v{version_number}.enc"
    version = DocumentVersion(document_id=doc.id, version=version_number, storage_name=storage_name, encrypted_dek=base64.b64encode(wrapped).decode(), nonce=base64.b64encode(nonce).decode(), encrypted_hash=hashlib.sha256(ciphertext).hexdigest(), plaintext_hash=plain_hash, analysis_json=json.dumps(analyze_bytes(file.filename or doc.name, data)), signature=hashlib.sha256((plain_hash + user.id).encode()).hexdigest(), created_by=user.id)
    db.add(version)
    doc.latest_version = version_number
    Path(settings.storage_path, storage_name).write_bytes(ciphertext)
    await audit(db, "VERSION_CREATED", user.id, doc.case_id, doc.id, {"version": version_number})
    await db.commit()
    return {"document_id": doc.id, "version": version_number, "encrypted_hash": version.encrypted_hash}


@app.post("/documents/{document_id}/access", status_code=201)
async def grant_access(document_id: str, payload: GrantCreate, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    doc = await get_document_or_404(document_id, db)
    if user.role != Role.ADMIN.value and doc.created_by != user.id:
        raise HTTPException(403, "Only document owner or admin may share")
    recipient = await db.get(User, payload.recipient_id)
    if not recipient:
        raise HTTPException(404, "Recipient not found")
    grant = AccessGrant(document_id=document_id, recipient_id=payload.recipient_id, permission=payload.permission.value, expires_at=datetime.now(timezone.utc) + timedelta(minutes=payload.expires_minutes), one_time=payload.one_time, created_by=user.id)
    db.add(grant)
    await audit(db, "TOKEN_CREATED", user.id, doc.case_id, document_id, {"recipient": payload.recipient_id, "expires_minutes": payload.expires_minutes, "one_time": payload.one_time})
    await db.commit()
    await db.refresh(grant)
    return {"id": grant.id, "expires_at": grant.expires_at, "one_time": grant.one_time}


@app.get("/documents/{document_id}/access")
async def list_access(document_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    doc = await get_document_or_404(document_id, db)
    if user.role != Role.ADMIN.value and doc.created_by != user.id:
        raise HTTPException(403, "Only owner or admin may view grants")
    rows = (await db.execute(select(AccessGrant).where(AccessGrant.document_id == document_id))).scalars().all()
    return [{"id": x.id, "recipient_id": x.recipient_id, "permission": x.permission, "expires_at": x.expires_at, "one_time": x.one_time, "used_at": x.used_at} for x in rows]


@app.post("/documents/{document_id}/key-release", response_model=KeyReleaseResponse)
async def release_document_key(
    document_id: str,
    payload: KeyReleaseRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    doc = await get_document_or_404(document_id, db)
    if not await user_can_access(db, user, doc):
        await audit(db, "ACCESS_DENIED", user.id, doc.case_id, doc.id)
        await db.commit()
        raise HTTPException(403, "Document access denied")
    version = (
        await db.execute(
            select(DocumentVersion)
            .where(DocumentVersion.document_id == doc.id)
            .order_by(DocumentVersion.version.desc())
            .limit(1)
        )
    ).scalar_one()
    try:
        client_public_bytes = base64.b64decode(payload.client_public_key, validate=True)
        client_public = X25519PublicKey.from_public_bytes(client_public_bytes)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, "Invalid client key") from exc
    await _consume_one_time_grant(db, user, doc)
    try:
        dek = key_provider().release(version.encrypted_dek)
        server_private = X25519PrivateKey.generate()
        server_public = server_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        shared = server_private.exchange(client_public)
        salt = secrets.token_bytes(16)
        envelope_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=f"securex-key-release:{document_id}".encode(),
        ).derive(shared)
        nonce = secrets.token_bytes(12)
        encrypted_dek = AESGCM(envelope_key).encrypt(nonce, dek, document_id.encode())
    except Exception as exc:
        raise HTTPException(503, f"Key release provider unavailable: {exc}") from exc
    await audit(db, "KEY_RELEASED", user.id, doc.case_id, doc.id)
    await db.commit()
    return KeyReleaseResponse(
        envelope_version="X25519-HKDF-SHA256-AES256-GCM-v1",
        server_public_key=base64.b64encode(server_public).decode(),
        salt=base64.b64encode(salt).decode(),
        nonce=base64.b64encode(nonce).decode(),
        ciphertext=base64.b64encode(encrypted_dek).decode(),
        release_token=_make_release_token(user, document_id),
    )


@app.get("/documents/{document_id}/download")
async def download_encrypted(
    document_id: str,
    release_token: Annotated[str | None, Header(alias="X-SecureX-Release-Token")] = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from fastapi.responses import Response
    doc = await get_document_or_404(document_id, db)
    if not await user_can_access(db, user, doc) and not _valid_release_token(release_token, user, document_id):
        await audit(db, "ACCESS_DENIED", user.id, doc.case_id, doc.id)
        await db.commit()
        raise HTTPException(403, "Document access denied")
    version = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc()).limit(1))).scalar_one()
    await db.commit()
    ciphertext = Path(settings.storage_path, version.storage_name).read_bytes()
    return Response(
        content=ciphertext,
        media_type="application/octet-stream",
        headers={
            "X-SecureX-Encrypted-Hash": version.encrypted_hash,
            "X-SecureX-Nonce": version.nonce,
            "X-SecureX-Plaintext-Hash": version.plaintext_hash,
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


@app.get("/documents/{document_id}/verify")
async def verify(document_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    doc = await get_document_or_404(document_id, db)
    if not await user_can_access(db, user, doc):
        raise HTTPException(403, "Document access denied")
    version = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc()).limit(1))).scalar_one()
    actual = hashlib.sha256(Path(settings.storage_path, version.storage_name).read_bytes()).hexdigest()
    ok = secrets.compare_digest(actual, version.encrypted_hash)
    await audit(db, "INTEGRITY_VERIFIED" if ok else "INTEGRITY_FAILED", user.id, doc.case_id, doc.id, {"expected": version.encrypted_hash, "actual": actual})
    await db.commit()
    return {"status": "VERIFIED" if ok else "TAMPER DETECTED", "expected_hash": version.encrypted_hash, "actual_hash": actual, "signature": "VALID" if ok else "INVALID"}


@app.post("/documents/{document_id}/blockchain")
async def register_blockchain(document_id: str, user: User = Depends(require_roles(Role.ADMIN, Role.INVESTIGATOR)), db: AsyncSession = Depends(get_db)):
    doc = await get_document_or_404(document_id, db)
    if not await user_can_access(db, user, doc, Permission.EDIT):
        raise HTTPException(403, "Document access denied")
    if not settings.contract_address or not settings.blockchain_private_key:
        raise HTTPException(503, "Blockchain is not configured; deploy SecureXRegistry and set CONTRACT_ADDRESS/BLOCKCHAIN_PRIVATE_KEY")
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(settings.blockchain_rpc_url))
    if not w3.is_connected():
        raise HTTPException(503, "Blockchain RPC is unavailable")
    version = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc()).limit(1))).scalar_one()
    abi = [{"inputs": [{"internalType": "bytes32", "name": "documentId", "type": "bytes32"}, {"internalType": "bytes32", "name": "documentHash", "type": "bytes32"}, {"internalType": "string", "name": "eventType", "type": "string"}], "name": "registerProof", "outputs": [], "stateMutability": "nonpayable", "type": "function"}]
    contract = w3.eth.contract(address=Web3.to_checksum_address(settings.contract_address), abi=abi)
    account = w3.eth.account.from_key(settings.blockchain_private_key)
    document_key = Web3.keccak(text=document_id)
    hash_key = Web3.to_bytes(hexstr=f"0x{version.encrypted_hash}")
    tx = contract.functions.registerProof(document_key, hash_key, "DOCUMENT_ENCRYPTED").build_transaction({"from": account.address, "nonce": w3.eth.get_transaction_count(account.address), "gas": 250000, "gasPrice": w3.eth.gas_price, "chainId": w3.eth.chain_id})
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    version.blockchain_tx = tx_hash.hex()
    await audit(db, "BLOCKCHAIN_REGISTERED", user.id, doc.case_id, doc.id, {"tx": tx_hash.hex()})
    await db.commit()
    return {"status": "REGISTERED", "transaction": tx_hash.hex(), "document_hash": version.encrypted_hash}


@app.get("/documents/{document_id}/blockchain")
async def blockchain_status(document_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    doc = await get_document_or_404(document_id, db)
    if not await user_can_access(db, user, doc):
        raise HTTPException(403, "Document access denied")
    version = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc()).limit(1))).scalar_one()
    return {"status": "REGISTERED" if version.blockchain_tx else "PENDING", "transaction": version.blockchain_tx}


@app.get("/documents/{document_id}/blockchain/verify")
async def verify_blockchain(document_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    doc = await get_document_or_404(document_id, db)
    if not await user_can_access(db, user, doc):
        raise HTTPException(403, "Document access denied")
    version = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc()).limit(1))).scalar_one()
    if not settings.contract_address:
        return {"status": "NOT_CONFIGURED", "registered_hash": None, "current_hash": version.encrypted_hash}
    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(settings.blockchain_rpc_url))
    if not w3.is_connected():
        raise HTTPException(503, "Blockchain RPC is unavailable")
    abi = [{"inputs": [{"internalType": "bytes32", "name": "documentId", "type": "bytes32"}], "name": "latestProof", "outputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}, {"internalType": "uint256", "name": "", "type": "uint256"}, {"internalType": "string", "name": "", "type": "string"}, {"internalType": "address", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"}]
    contract = w3.eth.contract(address=Web3.to_checksum_address(settings.contract_address), abi=abi)
    try:
        proof = contract.functions.latestProof(Web3.keccak(text=document_id)).call()
    except Exception:
        return {"status": "NOT_REGISTERED", "registered_hash": None, "current_hash": version.encrypted_hash}
    registered_hash = bytes(proof[0]).hex()
    verified = secrets.compare_digest(registered_hash, version.encrypted_hash)
    await audit(db, "BLOCKCHAIN_VERIFIED" if verified else "BLOCKCHAIN_MISMATCH", user.id, doc.case_id, doc.id, {"registered_hash": registered_hash, "current_hash": version.encrypted_hash})
    await db.commit()
    return {"status": "VERIFIED" if verified else "TAMPER DETECTED", "registered_hash": registered_hash, "current_hash": version.encrypted_hash, "timestamp": int(proof[1]), "event_type": proof[2], "registrar": proof[3]}


@app.get("/audit/verify-chain")
async def verify_audit_chain(user: User = Depends(require_roles(Role.ADMIN, Role.INVESTIGATOR)), db: AsyncSession = Depends(get_db)):
    rows = list((await db.execute(select(AuditEvent).order_by(AuditEvent.created_at, AuditEvent.id))).scalars().all())
    previous = ""
    failures = []
    for event in rows:
        data = json.loads(event.data_json)
        timestamp = data.pop("_audit_timestamp", utc_datetime(event.created_at).isoformat())
        payload = json.dumps({"event_type": event.event_type, "user_id": event.user_id, "case_id": event.case_id, "document_id": event.document_id, "data": data, "timestamp": timestamp}, sort_keys=True)
        expected = hashlib.sha256((previous + payload).encode()).hexdigest()
        if event.previous_hash != previous or event.event_hash != expected:
            failures.append(event.id)
        previous = event.event_hash
    return {"status": "VERIFIED" if not failures else "TAMPER DETECTED", "events_checked": len(rows), "failures": failures}


@app.get("/documents/{document_id}/audit")
async def document_audit(document_id: str, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    doc = await get_document_or_404(document_id, db)
    if not await user_can_access(db, user, doc):
        raise HTTPException(403, "Document access denied")
    rows = (await db.execute(select(AuditEvent).where(AuditEvent.document_id == document_id).order_by(AuditEvent.created_at))).scalars().all()
    return [{"id": x.id, "event_type": x.event_type, "timestamp": x.created_at, "event_hash": x.event_hash, "previous_hash": x.previous_hash, "data": {k: v for k, v in json.loads(x.data_json).items() if k != "_audit_timestamp"}} for x in rows]


@app.get("/audit")
async def all_audit(user: User = Depends(require_roles(Role.ADMIN, Role.INVESTIGATOR)), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(200))).scalars().all()
    return [{"id": x.id, "event_type": x.event_type, "timestamp": x.created_at, "document_id": x.document_id, "event_hash": x.event_hash} for x in rows]


@app.post("/search/semantic")
async def search(payload: dict[str, str], user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    query = payload.get("query", "").lower().strip()
    if not query:
        raise HTTPException(422, "query is required")
    docs = []
    for doc in (await db.execute(select(Document))).scalars().all():
        if await user_can_access(db, user, doc):
            version = (await db.execute(select(DocumentVersion).where(DocumentVersion.document_id == doc.id).order_by(DocumentVersion.version.desc()).limit(1))).scalar_one()
            metadata = json.loads(version.analysis_json)
            haystack = json.dumps(metadata).lower() + " " + doc.name.lower()
            score = sum(1 for term in set(re.findall(r"[a-z0-9-]+", query)) if term in haystack)
            if score:
                docs.append({"document_id": doc.id, "name": doc.name, "case_id": doc.case_id, "classification": doc.classification, "score": score, "analysis": metadata})
    return sorted(docs, key=lambda x: x["score"], reverse=True)
