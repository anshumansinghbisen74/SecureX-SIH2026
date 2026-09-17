from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import httpx


class OcrProvider(ABC):
    @abstractmethod
    def extract(self, name: str, content: bytes) -> str | None:
        raise NotImplementedError


class TesseractOcrProvider(OcrProvider):
    def __init__(self, executable: str = "", timeout_seconds: int = 30):
        self.executable = executable or shutil.which("tesseract") or ""
        self.timeout_seconds = timeout_seconds

    def extract(self, name: str, content: bytes) -> str | None:
        if not self.executable:
            return None
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir, Path(name).name)
            source.write_bytes(content)
            try:
                result = subprocess.run(
                    [self.executable, str(source), "stdout"],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                return None
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        return None


class DocumentAnalysisProvider(ABC):
    @abstractmethod
    def analyze(self, name: str, text: str, *, ocr_used: bool) -> dict[str, Any]:
        raise NotImplementedError


class LocalDeterministicProvider(DocumentAnalysisProvider):
    def analyze(self, name: str, text: str, *, ocr_used: bool) -> dict[str, Any]:
        import re

        case_numbers = re.findall(r"\bCASE[-\s]?\d+\b", text, flags=re.I)
        dates = re.findall(
            r"\b(?:\d{1,2}[/-]){2}\d{2,4}\b|\b\d{1,2}\s+[A-Za-z]+\s+\d{4}\b",
            text,
        )
        legal = re.findall(r"\bSection\s+[A-Za-z0-9-]+\b", text, flags=re.I)
        keywords = [
            word
            for word in re.findall(r"[A-Za-z]{5,}", text.lower())
            if word not in {"which", "there", "their", "about"}
        ][:12]
        classification = (
            "Forensic Report"
            if any(term in text.lower() for term in ("forensic", "evidence", "exhibit"))
            else "Investigation Document"
        )
        return {
            "provider": "local-deterministic",
            "processor": "tesseract+deterministic-local-analyzer"
            if ocr_used
            else "deterministic-local-analyzer",
            "ocr": ocr_used,
            "document_type": classification,
            "case_numbers": sorted({item.upper().replace(" ", "-") for item in case_numbers}),
            "dates": dates[:20],
            "names_entities": [],
            "locations": [],
            "legal_sections": sorted(set(legal)),
            "evidence_references": [],
            "keywords": sorted(set(keywords)),
            "semantic_metadata": {"keywords": sorted(set(keywords)), "entities": []},
            "summary": f"Local analysis completed for {name}; extracted {len(text.split())} words.",
            "authoritative": False,
        }


class LlmAnalysisProvider(DocumentAnalysisProvider):
    def __init__(self, endpoint: str, api_key: str, model: str, timeout_seconds: int = 30):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def analyze(self, name: str, text: str, *, ocr_used: bool) -> dict[str, Any]:
        if not self.endpoint or not self.api_key:
            raise RuntimeError("LLM provider is not configured")
        prompt = (
            "Analyze this legal/investigation document. Return JSON only with keys "
            "document_type, case_numbers, names_entities, dates, locations, "
            "legal_sections, evidence_references, keywords, semantic_metadata, summary. "
            "Do not provide legal advice; extracted fields are non-authoritative. "
            f"Filename: {name}\nDocument text:\n{text[:120000]}"
        )
        response = httpx.post(
            f"{self.endpoint}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": "You are a document metadata extraction service."},
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        content = payload["choices"][0]["message"]["content"]
        result = json.loads(content) if isinstance(content, str) else content
        if not isinstance(result, dict):
            raise ValueError("LLM response was not a JSON object")
        result.update(
            {
                "provider": "llm",
                "processor": f"llm:{self.model}",
                "ocr": ocr_used,
                "authoritative": False,
            }
        )
        return result


class KeyManagementProvider(ABC):
    @abstractmethod
    def protect(self, dek: bytes | None = None) -> tuple[bytes, str]:
        raise NotImplementedError

    @abstractmethod
    def release(self, encrypted_dek: str) -> bytes:
        raise NotImplementedError


class DevelopmentKeyProvider(KeyManagementProvider):
    def __init__(self, master_key: bytes):
        self.master_key = master_key

    def protect(self, dek: bytes | None = None) -> tuple[bytes, str]:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets

        plaintext = dek or AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        wrapped = nonce + AESGCM(self.master_key).encrypt(nonce, plaintext, None)
        return plaintext, base64.b64encode(wrapped).decode()

    def release(self, encrypted_dek: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        wrapped = base64.b64decode(encrypted_dek)
        return AESGCM(self.master_key).decrypt(wrapped[:12], wrapped[12:], None)


class AwsKmsKeyProvider(KeyManagementProvider):
    def __init__(self, key_id: str, region: str):
        self.key_id = key_id
        self.region = region

    def protect(self, dek: bytes | None = None) -> tuple[bytes, str]:
        if dek is not None:
            raise RuntimeError("AWS KMS provider must generate document data keys")
        if not self.key_id:
            raise RuntimeError("AWS_KMS_KEY_ID is not configured")
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("boto3 is required for AWS KMS key release") from exc
        client = boto3.client("kms", region_name=self.region or None)
        response = client.generate_data_key(KeyId=self.key_id, KeySpec="AES_256")
        return response["Plaintext"], base64.b64encode(response["CiphertextBlob"]).decode()

    def release(self, encrypted_dek: str) -> bytes:
        if not self.key_id:
            raise RuntimeError("AWS_KMS_KEY_ID is not configured")
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("boto3 is required for AWS KMS key release") from exc
        client = boto3.client("kms", region_name=self.region or None)
        response = client.decrypt(
            KeyId=self.key_id,
            CiphertextBlob=base64.b64decode(encrypted_dek),
            EncryptionAlgorithm="SYMMETRIC_DEFAULT",
        )
        return response["Plaintext"]
