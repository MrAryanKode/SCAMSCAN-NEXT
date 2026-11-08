from datetime import datetime, timezone
from pathlib import Path
import io
import uuid

import pymupdf
import pytesseract
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image

from services.document_intelligence import DocumentIntelligence
from services.risk_assessment import RiskAssessment
from services.pdf_forensics import PDFForensics
from services.image_forensics import ImageForensics


# ==================================================
# 1. APPLICATION CONFIGURATION
# ==================================================

app = FastAPI(
    title="ScamScan 2.0 API",
    description="Digital Trust & Document Forensics API",
    version="2.3.0",
)

# Tesseract OCR executable location on the development machine.
pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_FILE_SIZE = 15 * 1024 * 1024
MAX_PDF_PAGES = 50

ALLOWED_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".pdf": "application/pdf",
}


# ==================================================
# 2. CORS CONFIGURATION
# ==================================================


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
        "http://localhost:4174",
        "http://127.0.0.1:4174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# ==================================================
# 3. FILE VALIDATION
# ==================================================

def validate_file_signature(extension: str, content: bytes) -> bool:
    """Check whether file bytes match the declared format."""
    signatures = {
        ".jpg": content.startswith(b"\xff\xd8\xff"),
        ".jpeg": content.startswith(b"\xff\xd8\xff"),
        ".png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        ".webp": (
            content.startswith(b"RIFF")
            and content[8:12] == b"WEBP"
        ),
        ".pdf": content.startswith(b"%PDF-"),
    }
    return signatures.get(extension, False)


async def read_validated_upload(file: UploadFile):
    """Read and validate an uploaded document."""
    filename = file.filename or ""
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format.",
        )

    if file.content_type != ALLOWED_TYPES[extension]:
        raise HTTPException(
            status_code=400,
            detail="File extension and content type do not match.",
        )

    content = await file.read(MAX_FILE_SIZE + 1)

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty.",
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 15 MB limit.",
        )

    if not validate_file_signature(extension, content[:16]):
        raise HTTPException(
            status_code=400,
            detail="File content does not match its format.",
        )

    return content, extension


# ==================================================
# 4. TEXT EXTRACTION SERVICES
# ==================================================

def extract_image_text(content: bytes) -> str:
    """Extract text from a supported image using Tesseract OCR."""
    with Image.open(io.BytesIO(content)) as image:
        image.load()

        if image.format not in ("JPEG", "PNG", "WEBP"):
            raise ValueError("Unsupported image format.")

        text = pytesseract.image_to_string(image, lang="eng")

    return text.strip()


def extract_pdf_text(content: bytes) -> list[dict]:
    """Extract embedded text from every page of a PDF."""
    extracted_pages = []

    with pymupdf.open(stream=content, filetype="pdf") as document:
        if document.page_count > MAX_PDF_PAGES:
            raise ValueError(
                f"PDF exceeds the {MAX_PDF_PAGES}-page processing limit."
            )

        for page_number, page in enumerate(document):
            page_text = page.get_text("text").strip()
            extracted_pages.append({
                "page": page_number + 1,
                "text": page_text,
            })

    return extracted_pages


def process_document(content: bytes, extension: str) -> dict:
    """Select the appropriate text extraction engine."""
    if extension == ".pdf":
        pages = extract_pdf_text(content)
        combined_text = "\n".join(
            page["text"] for page in pages
        )

        return {
            "document_type": "PDF",
            "pages": pages,
            "total_pages": len(pages),
            "extracted_text": combined_text,
        }

    extracted_text = extract_image_text(content)

    return {
        "document_type": "IMAGE",
        "pages": None,
        "total_pages": 1,
        "extracted_text": extracted_text,
    }


# ==================================================
# 5. ROOT ENDPOINT
# ==================================================

@app.get("/")
async def root():
    return {
        "project": "ScamScan 2.0",
        "message": "Digital Trust & Document Forensics API",
        "status": "running",
        "version": "2.3.0",
    }


# ==================================================
# 6. HEALTH CHECK
# ==================================================

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.3.0",
    }


# ==================================================
# 7. DOCUMENT UPLOAD ENDPOINT
# ==================================================

@app.post("/api/upload")
async def upload_document(file: UploadFile = File(...)):
    file_path = None

    try:
        content, extension = await read_validated_upload(file)

        scan_id = str(uuid.uuid4())
        safe_filename = f"{scan_id}{extension}"
        file_path = UPLOAD_DIR / safe_filename
        file_path.write_bytes(content)

        return {
            "message": "Document uploaded successfully.",
            "scan_id": scan_id,
            "filename": file.filename,
            "file_type": extension,
            "file_size_bytes": len(content),
            "status": "uploaded",
        }

    except HTTPException:
        if file_path:
            file_path.unlink(missing_ok=True)
        raise

    except Exception:
        if file_path:
            file_path.unlink(missing_ok=True)

        raise HTTPException(
            status_code=500,
            detail="Document upload failed.",
        )

    finally:
        await file.close()


# ==================================================
# 8. OCR EXTRACTION ENDPOINT
# ==================================================

@app.post("/api/ocr")
async def extract_document_text(file: UploadFile = File(...)):
    try:
        content, extension = await read_validated_upload(file)
        result = process_document(content, extension)

        return {
            "filename": file.filename,
            **result,
            "character_count": len(result["extracted_text"]),
            "status": "completed",
        }

    except HTTPException:
        raise

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        )

    except Exception:
        raise HTTPException(
            status_code=422,
            detail="Document text extraction failed.",
        )

    finally:
        await file.close()


# ==================================================
# 9. DOCUMENT INTELLIGENCE + FORENSICS + RISK
# ==================================================

@app.post("/api/analyze")
async def analyze_document(file: UploadFile = File(...)):
    try:
        # Step 1: Read and validate the uploaded document.
        content, extension = await read_validated_upload(file)

        # Step 2: Extract text from the image or PDF.
        extraction = process_document(content, extension)
        extracted_text = extraction["extracted_text"]

        # A PDF without embedded text still needs scanned-PDF OCR support.
        # Keep the existing PDF behaviour until that feature is implemented.
        if extension == ".pdf" and not extracted_text.strip():
            raise HTTPException(
                status_code=422,
                detail=(
                    "No readable text found. "
                    "Scanned PDF OCR support is not implemented yet."
                ),
            )

        # Images can still receive forensic analysis when OCR finds no text.
        # In that case, text-based intelligence is explicitly unavailable.
        intelligence = (
            DocumentIntelligence.analyze(extracted_text)
            if extracted_text.strip()
            else None
        )

        # Step 4: Run the appropriate forensic engine.
        pdf_forensics = None
        image_forensics = None
        forensic_findings = []

        if extension == ".pdf":
            pdf_forensics = PDFForensics.analyze(
                file_bytes=content,
                filename=file.filename or "document.pdf",
            )
            forensic_findings = pdf_forensics.get("findings", [])

        elif extension in {".jpg", ".jpeg", ".png", ".webp"}:
            image_forensics = ImageForensics.analyze(
                file_bytes=content,
                filename=file.filename or "image",
            )
            forensic_findings = image_forensics.get("findings", [])

        # Step 5: Assess document intelligence and forensic findings together.
        risk_assessment = RiskAssessment.assess(
            intelligence_analysis=intelligence,
            forensic_findings=forensic_findings,
            file_metadata={
                "filename": file.filename,
                "extension": extension,
                "file_size_bytes": len(content),
                "page_count": extraction["total_pages"],
            },
        )

        # Step 6: Return all analysis modules to the frontend.
        return {
            "scan_id": str(uuid.uuid4()),
            "filename": file.filename,
            "file_type": extension,
            "file_size_bytes": len(content),
            "document_extraction": {
                "document_type": extraction["document_type"],
                "total_pages": extraction["total_pages"],
                "character_count": len(extracted_text),
                "text_available": bool(extracted_text.strip()),
            },
            "intelligence_analysis": intelligence,
            "pdf_forensics": pdf_forensics,
            "image_forensics": image_forensics,
            "risk_assessment": risk_assessment,
            "status": "completed",
        }

    except HTTPException:
        raise

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        )

    except Exception:
        raise HTTPException(
            status_code=422,
            detail="Document intelligence, forensics and risk analysis failed.",
        )

    finally:
        await file.close()


# ==================================================
# 10. APPLICATION INFORMATION
# ==================================================

@app.get("/api/system/info")
async def system_info():
    return {
        "project": "ScamScan 2.0",
        "modules": {
            "document_upload": "available",
            "ocr_extraction": "available",
            "pdf_extraction": "available",
            "document_intelligence": "available",
            "risk_assessment": "available",
            "pdf_forensics": "available",
            "image_forensics": "available",
        },
        "supported_formats": list(ALLOWED_TYPES.keys()),
        "maximum_file_size_mb": 15,
        "maximum_pdf_pages": MAX_PDF_PAGES,
        "status": "operational",
    }
