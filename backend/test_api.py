
import io

import pymupdf
import pytest
from fastapi.testclient import TestClient
from PIL import Image

import main
from services.document_intelligence import DocumentIntelligence
from services.risk_assessment import RiskAssessment


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Keep test uploads separate from real user uploads.
    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path)

    with TestClient(main.app) as test_client:
        yield test_client


def make_image(image_format="PNG"):
    buffer = io.BytesIO()
    image = Image.new("RGB", (120, 80), "white")
    image.save(buffer, format=image_format)
    return buffer.getvalue()


def make_pdf(text="ScamScan automated test document"):
    buffer = io.BytesIO()

    document = pymupdf.open()
    page = document.new_page()
    page.insert_text((72, 72), text)
    document.save(buffer)
    document.close()

    return buffer.getvalue()


def test_root_endpoint(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "running"


def test_health_endpoint(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_system_info(client):
    response = client.get("/api/system/info")

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "operational"
    assert ".pdf" in data["supported_formats"]
    assert data["maximum_file_size_mb"] == 15


def test_cors_allows_production_preview(client):
    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:4173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.headers.get(
        "access-control-allow-origin"
    ) == "http://localhost:4173"


def test_upload_valid_png(client):
    response = client.post(
        "/api/upload",
        files={
            "file": (
                "sample.png",
                make_image("PNG"),
                "image/png",
            )
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "uploaded"


def test_upload_valid_pdf(client):
    response = client.post(
        "/api/upload",
        files={
            "file": (
                "sample.pdf",
                make_pdf(),
                "application/pdf",
            )
        },
    )

    assert response.status_code == 200
    assert response.json()["file_type"] == ".pdf"


def test_reject_unsupported_extension(client):
    response = client.post(
        "/api/upload",
        files={
            "file": (
                "sample.txt",
                b"ordinary text",
                "text/plain",
            )
        },
    )

    assert response.status_code == 400


def test_reject_empty_file(client):
    response = client.post(
        "/api/upload",
        files={
            "file": (
                "empty.png",
                b"",
                "image/png",
            )
        },
    )

    assert response.status_code == 400


def test_reject_mismatched_content_type(client):
    response = client.post(
        "/api/upload",
        files={
            "file": (
                "sample.png",
                make_image("PNG"),
                "image/jpeg",
            )
        },
    )

    assert response.status_code == 400


def test_reject_invalid_file_signature(client):
    response = client.post(
        "/api/upload",
        files={
            "file": (
                "fake.png",
                b"not really a png file",
                "image/png",
            )
        },
    )

    assert response.status_code == 400


def test_reject_file_over_15_mb(client):
    oversized_content = (
        b"\x89PNG\r\n\x1a\n"
        + b"x" * (main.MAX_FILE_SIZE)
    )

    response = client.post(
        "/api/upload",
        files={
            "file": (
                "oversized.png",
                oversized_content,
                "image/png",
            )
        },
    )

    assert response.status_code == 413


def test_ocr_valid_png(client, monkeypatch):
    # Mock OCR so the test does not depend on Tesseract.
    monkeypatch.setattr(
        main,
        "extract_image_text",
        lambda content: "Sample academic document",
    )

    response = client.post(
        "/api/ocr",
        files={
            "file": (
                "sample.png",
                make_image("PNG"),
                "image/png",
            )
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert response.json()["extracted_text"] == (
        "Sample academic document"
    )


def test_analyze_valid_png(client, monkeypatch):
    monkeypatch.setattr(
        main,
        "extract_image_text",
        lambda content: (
            "University Marksheet\n"
            "Student Name: Aryan Gupta\n"
            "Date: 2026-05-15\n"
            "Roll Number: 24CS1015"
        ),
    )

    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "sample.png",
                make_image("PNG"),
                "image/png",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "completed"
    assert data["intelligence_analysis"] is not None
    assert data["image_forensics"]["status"] == "completed"
    assert "risk_score" in data["risk_assessment"]


def test_analyze_valid_pdf(client):
    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "sample.pdf",
                make_pdf(),
                "application/pdf",
            )
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "completed"
    assert data["document_extraction"]["document_type"] == "PDF"
    assert data["pdf_forensics"]["status"] == "completed"


def test_reject_scanned_pdf_without_text(client):
    # This PDF has a page but no embedded text.
    buffer = io.BytesIO()
    document = pymupdf.open()
    document.new_page()
    document.save(buffer)
    document.close()

    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "blank.pdf",
                buffer.getvalue(),
                "application/pdf",
            )
        },
    )

    assert response.status_code == 422
    assert "Scanned PDF OCR support" in response.json()["detail"]


def test_document_intelligence_empty_text():
    result = DocumentIntelligence.analyze("")

    assert result["status"] == "completed"
    assert result["document_type"] == "unknown"
    assert result["text_statistics"]["word_count"] == 0


def test_risk_score_is_bounded():
    result = RiskAssessment.assess(
        intelligence_analysis=None,
        forensic_findings=[
            {"code": f"TEST_{i}", "severity": "high"}
            for i in range(10)
        ],
    )

    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] == "high"
    assert "not a fraud probability" in (
    " ".join(result["limitations"])
)


def test_image_forensics_rejects_invalid_image():
    from services.image_forensics import ImageForensics

    with pytest.raises(ValueError):
        ImageForensics.analyze(
            b"not an image",
            filename="broken.png",
        )


def test_pdf_forensics_rejects_invalid_pdf():
    from services.pdf_forensics import PDFForensics

    with pytest.raises(ValueError):
        PDFForensics.analyze(
            b"not a PDF",
            filename="broken.pdf",
        )


def test_analyze_valid_jpeg(client, monkeypatch):
    monkeypatch.setattr(
        main,
        "extract_image_text",
        lambda content: "Sample JPEG document",
    )

    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "sample.jpg",
                make_image("JPEG"),
                "image/jpeg",
            )
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["image_forensics"]["status"] == "completed"
    assert data["image_forensics"]["ela_analysis"]["available"]


def test_analyze_valid_webp(client, monkeypatch):
    monkeypatch.setattr(
        main,
        "extract_image_text",
        lambda content: "Sample WEBP document",
    )

    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "sample.webp",
                make_image("WEBP"),
                "image/webp",
            )
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["image_forensics"]["status"] == "completed"


def test_reject_corrupted_pdf_during_analysis(client):
    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "corrupted.pdf",
                b"%PDF-1.7\nthis is not a valid PDF structure",
                "application/pdf",
            )
        },
    )

    assert response.status_code == 422


def test_reject_pdf_over_page_limit(client):
    buffer = io.BytesIO()
    document = pymupdf.open()

    for _ in range(main.MAX_PDF_PAGES + 1):
        document.new_page()

    document.save(buffer)
    document.close()

    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "large_pages.pdf",
                buffer.getvalue(),
                "application/pdf",
            )
        },
    )

    assert response.status_code == 422
    assert "page processing limit" in response.json()["detail"]


def test_reject_image_over_pixel_limit(client, monkeypatch):
    from services.image_forensics import ImageForensics

    monkeypatch.setattr(
        main,
        "extract_image_text",
        lambda content: "Sample image text",
    )

    monkeypatch.setattr(
        ImageForensics,
        "MAX_IMAGE_PIXELS",
        100,
    )

    large_image = io.BytesIO()
    Image.new("RGB", (20, 20), "white").save(
        large_image,
        format="PNG",
    )

    response = client.post(
        "/api/analyze",
        files={
            "file": (
                "large_dimensions.png",
                large_image.getvalue(),
                "image/png",
            )
        },
    )

    assert response.status_code == 422
    assert "pixel limit" in response.json()["detail"]
