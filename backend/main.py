from datetime import datetime, timezone

from pathlib import Path

import io

import uuid
import difflib
import re as regex



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

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"



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





# ==================================================
# 10. DOCUMENT-TO-DOCUMENT COMPARISON
# ==================================================

def _normalise_comparison_value(value):
    """Normalize values only for comparison; preserve originals in the report."""
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return str(round(float(value), 2))
    return " ".join(str(value).casefold().split())


def _compare_value_lists(values_a, values_b, category):
    """Compare extracted list values without claiming semantic identity."""
    a = list(values_a or [])
    b = list(values_b or [])
    norm_a = {_normalise_comparison_value(v): v for v in a}
    norm_b = {_normalise_comparison_value(v): v for v in b}
    matched_keys = set(norm_a) & set(norm_b)
    only_a_keys = set(norm_a) - set(norm_b)
    only_b_keys = set(norm_b) - set(norm_a)
    return {
        "category": category,
        "matched": [norm_a[k] for k in sorted(matched_keys)],
        "only_in_document_a": [norm_a[k] for k in sorted(only_a_keys)],
        "only_in_document_b": [norm_b[k] for k in sorted(only_b_keys)],
        "status": "different" if only_a_keys or only_b_keys else "matched",
    }


def _financial_rows(analysis):
    info = (analysis or {}).get("extracted_information") or {}
    details = info.get("financial_details") or {}
    rows = details.get("all_rows") or []
    if rows:
        return rows
    # Fallback for non-ITR documents: preserve extracted amount strings.
    return [{"key": f"amount_{i}", "label": f"Amount {i + 1}", "value": v}
            for i, v in enumerate(info.get("amounts") or [])]


def _compare_financial_rows(analysis_a, analysis_b):
    rows_a = _financial_rows(analysis_a)
    rows_b = _financial_rows(analysis_b)
    map_a = {str(row.get("key", row.get("label", i))): row for i, row in enumerate(rows_a)}
    map_b = {str(row.get("key", row.get("label", i))): row for i, row in enumerate(rows_b)}
    result = []
    for key in sorted(set(map_a) | set(map_b)):
        left, right = map_a.get(key), map_b.get(key)
        if left is None:
            status = "added"
        elif right is None:
            status = "removed"
        elif _normalise_comparison_value(left.get("value")) == _normalise_comparison_value(right.get("value")):
            status = "matched"
        else:
            status = "changed"
        result.append({
            "key": key,
            "label": (right or left).get("label", key),
            "document_a": left.get("value") if left else None,
            "document_b": right.get("value") if right else None,
            "currency_a": left.get("currency") if left else None,
            "currency_b": right.get("currency") if right else None,
            "status": status,
        })
    return result


def compare_document_content(text_a, text_b, filename_a, filename_b):
    """Build a field-level and line-level comparison from two extracted texts."""
    analysis_a = DocumentIntelligence.analyze(text_a) if text_a.strip() else None
    analysis_b = DocumentIntelligence.analyze(text_b) if text_b.strip() else None
    if not analysis_a or not analysis_b:
        raise ValueError("Both documents must contain extractable text for comparison.")

    info_a = analysis_a.get("extracted_information", {})
    info_b = analysis_b.get("extracted_information", {})
    fields = [
        _compare_value_lists(info_a.get("names"), info_b.get("names"), "names"),
        _compare_value_lists(info_a.get("dates"), info_b.get("dates"), "dates"),
        _compare_value_lists(info_a.get("reference_numbers"), info_b.get("reference_numbers"), "reference_numbers"),
        _compare_value_lists(info_a.get("roll_numbers"), info_b.get("roll_numbers"), "roll_numbers"),
    ]
    financial = _compare_financial_rows(analysis_a, analysis_b)
    lines_a = [line.strip() for line in text_a.splitlines() if line.strip()]
    lines_b = [line.strip() for line in text_b.splitlines() if line.strip()]
    text_diff = list(difflib.unified_diff(
        lines_a, lines_b, fromfile=filename_a, tofile=filename_b,
        lineterm="", n=1
    ))
    changed_count = sum(1 for row in financial if row["status"] != "matched")
    changed_count += sum(len(item["only_in_document_a"]) + len(item["only_in_document_b"]) for item in fields)
    matched_count = sum(1 for row in financial if row["status"] == "matched")
    matched_count += sum(len(item["matched"]) for item in fields)
    return {
        "comparison_id": str(uuid.uuid4()),
        "documents": {
            "document_a": {"filename": filename_a, "document_type": analysis_a.get("document_type")},
            "document_b": {"filename": filename_b, "document_type": analysis_b.get("document_type")},
        },
        "document_type_match": analysis_a.get("document_type") == analysis_b.get("document_type"),
        "field_comparisons": fields,
        "financial_comparison": financial,
        "text_diff": text_diff[:500],
        "summary": {
            "matched_items": matched_count,
            "differences_found": changed_count,
            "financial_fields_compared": len(financial),
            "text_diff_lines": len(text_diff),
            "status": "differences_found" if changed_count or text_diff else "no_differences_detected",
        },
        "interpretation": "Differences are review indicators only. They do not establish alteration, fraud, or document authenticity.",
        "limitations": [
            "Comparison depends on OCR/PDF text extraction quality and layout.",
            "Line-level text differences may be caused by formatting or OCR variation.",
            "Metadata and pixel-level image comparison are not included in this endpoint.",
            "Scanned PDF OCR is not implemented in the current extraction pipeline.",
        ],
        "status": "completed",
    }


@app.post("/api/compare")
async def compare_documents(
    file_a: UploadFile = File(...),
    file_b: UploadFile = File(...),
):
    """Compare two supported documents. Send multipart fields file_a and file_b."""
    try:
        content_a, extension_a = await read_validated_upload(file_a)
        content_b, extension_b = await read_validated_upload(file_b)
        extraction_a = process_document(content_a, extension_a)
        extraction_b = process_document(content_b, extension_b)
        text_a = extraction_a["extracted_text"]
        text_b = extraction_b["extracted_text"]
        if not text_a.strip() or not text_b.strip():
            raise HTTPException(
                status_code=422,
                detail="Both documents must contain readable text. Scanned PDF OCR is not currently supported.",
            )
        return compare_document_content(
            text_a, text_b,
            file_a.filename or "document_a",
            file_b.filename or "document_b",
        )
    except HTTPException:
        raise
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))
    except Exception:
        raise HTTPException(status_code=422, detail="Document comparison failed. Check both files and try again.")
    finally:
        await file_a.close()
        await file_b.close()


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
            "document_comparison": "available",

        },

        "supported_formats": list(ALLOWED_TYPES.keys()),

        "maximum_file_size_mb": 15,

        "maximum_pdf_pages": MAX_PDF_PAGES,

        "status": "operational",

    }
