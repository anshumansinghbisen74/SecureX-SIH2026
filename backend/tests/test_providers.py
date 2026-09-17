import base64
import json
from pathlib import Path

import pytest

from app.providers import (
    AwsKmsKeyProvider,
    DevelopmentKeyProvider,
    LocalDeterministicProvider,
    LlmAnalysisProvider,
    TesseractOcrProvider,
)


def test_local_provider_extracts_investigation_metadata():
    result = LocalDeterministicProvider().analyze(
        "report.txt",
        "CASE-404 Evidence exhibit Section 302 12 March 2026",
        ocr_used=False,
    )
    assert result["case_numbers"] == ["CASE-404"]
    assert result["legal_sections"] == ["Section 302"]
    assert result["authoritative"] is False


def test_tesseract_available_real_execution(tmp_path):
    executable = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    if not Path(executable).exists():
        pytest.skip("Tesseract is not installed")
    image = tmp_path / "sample.png"
    from PIL import Image, ImageDraw

    canvas = Image.new("RGB", (1000, 220), "white")
    ImageDraw.Draw(canvas).text((30, 70), "CASE-404 EVIDENCE SECTION 302", fill="black")
    canvas.save(image)
    text = TesseractOcrProvider(executable).extract(image.name, image.read_bytes())
    assert text and "CASE-404" in text.upper()


def test_tesseract_unavailable_is_safe():
    assert TesseractOcrProvider(r"C:\does-not-exist\tesseract.exe").extract("x.png", b"") is None


def test_invalid_document_is_rejected_by_provider_boundary():
    assert TesseractOcrProvider("").extract("x.png", b"not-an-image") is None


def test_llm_provider_parses_mocked_response(monkeypatch):
    class MockResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "document_type": "Evidence Report",
                                    "case_numbers": ["CASE-404"],
                                    "names_entities": ["Example Person"],
                                    "dates": [],
                                    "locations": ["Delhi"],
                                    "legal_sections": ["Section 302"],
                                    "evidence_references": ["Exhibit A"],
                                    "keywords": ["evidence"],
                                    "semantic_metadata": {"keywords": ["evidence"]},
                                    "summary": "Extracted summary",
                                }
                            )
                        }
                    }
                ]
            }

    monkeypatch.setattr("app.providers.httpx.post", lambda *args, **kwargs: MockResponse())
    result = LlmAnalysisProvider("https://llm.example", "test-key", "test-model").analyze(
        "report.txt", "CASE-404", ocr_used=False
    )
    assert result["provider"] == "llm"
    assert result["case_numbers"] == ["CASE-404"]


def test_llm_provider_failure_is_explicit():
    with pytest.raises(RuntimeError):
        LlmAnalysisProvider("", "", "test-model").analyze("x.txt", "text", ocr_used=False)


def test_analysis_pipeline_falls_back_when_llm_fails(monkeypatch):
    import app.main as main

    class BrokenProvider:
        def analyze(self, *args, **kwargs):
            raise RuntimeError("provider unavailable")

    monkeypatch.setattr(main, "_analysis_provider", lambda: BrokenProvider())
    result = main.analyze_bytes("report.txt", b"CASE-404 evidence Section 302")
    assert result["provider"] == "local-deterministic"
    assert result["case_numbers"] == ["CASE-404"]


def test_development_key_provider_round_trip():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import secrets

    master = secrets.token_bytes(32)
    dek = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    wrapped = nonce + AESGCM(master).encrypt(nonce, dek, None)
    encoded = base64.b64encode(wrapped).decode()
    assert DevelopmentKeyProvider(master).release(encoded) == dek


def test_aws_kms_provider_uses_kms_without_logging_plaintext(monkeypatch):
    class MockKms:
        def decrypt(self, **kwargs):
            assert kwargs["KeyId"] == "alias/securex"
            return {"Plaintext": b"released-dek"}

    monkeypatch.setattr("boto3.client", lambda *args, **kwargs: MockKms())
    assert AwsKmsKeyProvider("alias/securex", "local").release(
        base64.b64encode(b"ciphertext").decode()
    ) == b"released-dek"


def test_aws_kms_provider_failure_is_explicit(monkeypatch):
    class BrokenKms:
        def decrypt(self, **kwargs):
            raise RuntimeError("kms unavailable")

    monkeypatch.setattr("boto3.client", lambda *args, **kwargs: BrokenKms())
    with pytest.raises(RuntimeError, match="kms unavailable"):
        AwsKmsKeyProvider("alias/securex", "local").release(
            base64.b64encode(b"ciphertext").decode()
        )
