
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from PIL import Image
import pytesseract
import pymupdf
import io

# --------------------------------------------------
# 1. APPLICATION CONFIGURATION
# --------------------------------------------------

app = FastAPI(
    title="ScamScan 2.0 API",
    description="AI-Powered Digital Trust & Document Forensics",
    version="2.0.0"
)

# Tesseract installation path
pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

# Upload configuration
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_FILE_SIZE = 15 * 1024 * 1024

ALLOWED_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".pdf": "application/pdf"
}

# --------------------------------------------------
# 2. CORS CONFIGURATION
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------
# 3. FILE VALIDATION
# --------------------------------------------------

def validate_file_signature(extension, content):
    signatures = {
        ".jpg": content.startswith(b"\xff\xd8\xff"),
        ".jpeg": content.startswith(b"\xff\xd8\xff"),
        ".png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        ".webp": (
            content.startswith(b"RIFF")
            and content[8:12] == b"WEBP"
        ),
        ".pdf": content.startswith(b"%PDF-")
    }

    return signatures.get(extension, False)

# --------------------------------------------------
# 4. ROOT ENDPOINT
# --------------------------------------------------

@app.get("/")
async def root():
    return {
        "project": "ScamScan 2.0",
        "message": "Digital Trust & Document Forensics API",
        "status": "running"
    }

# --------------------------------------------------
# 5. HEALTH CHECK
# --------------------------------------------------

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0"
    }

# --------------------------------------------------
# 6. DOCUMENT UPLOAD
# --------------------------------------------------

@app.post("/api/upload")
async def upload_document(file: UploadFile = File(...)):

    extension = Path(file.filename or "").suffix.lower()

    if extension not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format."
        )

    if file.content_type != ALLOWED_TYPES[extension]:
        raise HTTPException(
            status_code=400,
            detail="File extension and content type do not match."
        )

    scan_id = str(uuid4())
    safe_filename = f"{scan_id}{extension}"
    file_path = UPLOAD_DIR / safe_filename

    total_size = 0
    first_chunk = b""

    try:
        with file_path.open("wb") as output:

            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                if not first_chunk:
                    first_chunk = chunk[:16]

                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds the 15 MB limit."
                    )

                output.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty."
            )

        if not validate_file_signature(extension, first_chunk):
            raise HTTPException(
                status_code=400,
                detail="Invalid file signature."
            )

        return {
            "message": "Document uploaded successfully.",
            "scan_id": scan_id,
            "filename": file.filename,
            "file_type": extension,
            "file_size_bytes": total_size,
            "status": "uploaded"
        }

    except Exception:
        file_path.unlink(missing_ok=True)
        raise

    finally:
        await file.close()

# --------------------------------------------------
# 7. OCR TEXT EXTRACTION
# --------------------------------------------------

def extract_image_text(content):
    image = Image.open(io.BytesIO(content))
    image.load()

    if image.format not in ("JPEG", "PNG", "WEBP"):
        raise ValueError("Unsupported image format.")

    text = pytesseract.image_to_string(
        image,
        lang="eng"
    )

    return text.strip()

def extract_pdf_text(content):
    extracted_pages = []

    with pymupdf.open(
        stream=content,
        filetype="pdf"
    ) as document:

        if document.page_count > 50:
            raise ValueError("PDF exceeds the 50-page limit.")

        for page_number, page in enumerate(document):
            page_text = page.get_text("text")

            extracted_pages.append({
                "page": page_number + 1,
                "text": page_text.strip()
            })

    return extracted_pages

# --------------------------------------------------
# 8. OCR API ENDPOINT
# --------------------------------------------------

@app.post("/api/ocr")
async def extract_document_text(file: UploadFile = File(...)):

    extension = Path(file.filename or "").suffix.lower()

    if extension not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format."
        )

    if file.content_type != ALLOWED_TYPES[extension]:
        raise HTTPException(
            status_code=400,
            detail="File extension and content type do not match."
        )

    content = await file.read(MAX_FILE_SIZE + 1)
    await file.close()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty."
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 15 MB limit."
        )

    if not validate_file_signature(extension, content[:16]):
        raise HTTPException(
            status_code=400,
            detail="Invalid file signature."
        )

    try:
        if extension == ".pdf":
            pages = extract_pdf_text(content)

            return {
                "filename": file.filename,
                "document_type": "PDF",
                "pages": pages,
                "total_pages": len(pages),
                "status": "completed"
            }

        extracted_text = extract_image_text(content)

        return {
            "filename": file.filename,
            "document_type": "IMAGE",
            "extracted_text": extracted_text,
            "character_count": len(extracted_text),
            "status": "completed"
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=422,
            detail=f"Document processing failed: {str(error)}"
        )
