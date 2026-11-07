
"""
SCAMSCAN-NEXT: PDF Forensics Service

Features:
1. PDF metadata extraction
2. Creation and modification date analysis
3. PDF version and internal object count
4. Page dimensions and orientation
5. Embedded image detection
6. Links and annotations detection
7. Embedded attachment detection
8. Encryption detection
9. PDF title and filename mismatch detection

Important:
These are review indicators, not proof of fraud.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import PurePath
from typing import Any, Dict, List, Optional
import re

# Modern PyMuPDF import (avoids deprecated fitz warning)
import pymupdf as fitz


class PDFForensics:
    """Metadata and structural analysis for PDF documents."""

    METADATA_FIELDS = (
        "title",
        "author",
        "subject",
        "keywords",
        "creator",
        "producer",
        "creationDate",
        "modDate",
        "format",
        "encryption",
    )

    @staticmethod
    def _clean_text(value: Any) -> Optional[str]:
        """Remove unnecessary spaces and handle empty metadata."""
        if value is None:
            return None

        cleaned = str(value).strip()
        return cleaned or None

    @staticmethod
    def _parse_pdf_date(value: Optional[str]) -> Optional[str]:
        """Convert common PDF dates into readable format."""
        if not value:
            return None

        match = re.search(
            r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?",
            value.strip(),
        )

        if not match:
            return value.strip()

        year, month, day, hour, minute, second = [
            part or "00" for part in match.groups()
        ]

        try:
            parsed = datetime(
                int(year),
                int(month),
                int(day or "01"),
                int(hour),
                int(minute),
                int(second),
            )
            return parsed.isoformat()

        except ValueError:
            return value.strip()

    @staticmethod
    def _page_dimensions(page: fitz.Page) -> Dict[str, Any]:
        """Extract page dimensions and orientation."""
        rect = page.rect

        width = round(float(rect.width), 2)
        height = round(float(rect.height), 2)

        if abs(width - height) < 1:
            orientation = "square"
        elif width > height:
            orientation = "landscape"
        else:
            orientation = "portrait"

        return {
            "width_points": width,
            "height_points": height,
            "orientation": orientation,
            "rotation": int(page.rotation),
        }

    @staticmethod
    def _count_annotations(page: fitz.Page) -> int:
        """Count PDF annotations safely."""
        try:
            count = 0
            annotation = page.first_annot

            while annotation is not None:
                count += 1
                annotation = annotation.next

            return count

        except Exception:
            return 0

    @staticmethod
    def _collect_embedded_files(
        document: fitz.Document,
    ) -> List[Dict[str, Any]]:
        """Extract details of files attached inside the PDF."""
        attachments = []

        try:
            for name in document.embfile_names():

                try:
                    info = document.embfile_info(name)

                    attachments.append({
                        "name": str(name),
                        "size_bytes": int(
                            info.get("size", 0) or 0
                        ),
                        "description": PDFForensics._clean_text(
                            info.get("desc")
                        ),
                    })

                except Exception:
                    attachments.append({
                        "name": str(name),
                        "size_bytes": None,
                    })

        except Exception:
            pass

        return attachments

    @classmethod
    def _collect_metadata(
        cls,
        document: fitz.Document,
    ) -> Dict[str, Any]:
        """Extract standard PDF metadata."""
        raw = document.metadata or {}
        metadata = {}

        for field in cls.METADATA_FIELDS:

            value = cls._clean_text(raw.get(field))

            if field in ("creationDate", "modDate"):
                metadata[field] = cls._parse_pdf_date(value)
            else:
                metadata[field] = value

        return metadata

    @staticmethod
    def _normalized_filename(
        value: Optional[str],
    ) -> Optional[str]:
        """Normalize filenames for comparison."""
        if not value:
            return None

        return PurePath(value.strip()).stem.casefold()

    @classmethod
    def _build_findings(
        cls,
        metadata: Dict[str, Any],
        filename: str,
        page_count: int,
        embedded_files: List[Dict[str, Any]],
        is_encrypted: bool,
    ) -> List[Dict[str, Any]]:
        """Generate explainable PDF review indicators."""

        findings = []

        # Check missing creation date.
        if not metadata.get("creationDate"):

            findings.append({
                "code": "PDF_CREATION_DATE_MISSING",
                "severity": "info",
                "title": "PDF creation date is unavailable",
                "evidence": {
                    "creation_date": None
                },
                "explanation": (
                    "The PDF does not expose a readable creation date."
                ),
            })

        # Check missing PDF producer.
        if not metadata.get("producer"):

            findings.append({
                "code": "PDF_PRODUCER_MISSING",
                "severity": "info",
                "title": "PDF producer is unavailable",
                "evidence": {
                    "producer": None
                },
                "explanation": (
                    "The software generating this PDF is not identified."
                ),
            })

        # Compare creation and modification dates.
        creation = metadata.get("creationDate")
        modification = metadata.get("modDate")

        if creation and modification and creation != modification:

            findings.append({
                "code": "PDF_MODIFICATION_DATE_DIFFERS",
                "severity": "info",
                "title": "Creation and modification dates differ",
                "evidence": {
                    "creation_date": creation,
                    "modification_date": modification,
                },
                "explanation": (
                    "The PDF modification date differs from its "
                    "creation date. Normal editing can cause this."
                ),
            })

        # Compare embedded title with uploaded filename.
        title = metadata.get("title")

        title_stem = cls._normalized_filename(title)
        filename_stem = cls._normalized_filename(filename)

        if (
            title_stem
            and filename_stem
            and title_stem != filename_stem
        ):

            findings.append({
                "code": "PDF_TITLE_FILENAME_MISMATCH",
                "severity": "info",
                "title": "PDF title differs from uploaded filename",
                "evidence": {
                    "pdf_title": title,
                    "uploaded_filename": filename,
                },
                "explanation": (
                    "The embedded PDF title differs from the "
                    "uploaded filename. This may happen when a "
                    "document is renamed or reused."
                ),
            })

        # Check embedded attachments.
        if embedded_files:

            findings.append({
                "code": "PDF_EMBEDDED_FILES_PRESENT",
                "severity": "review",
                "title": "PDF contains embedded attachments",
                "evidence": {
                    "attachments": embedded_files
                },
                "explanation": (
                    "Review attached files if they are unexpected."
                ),
            })

        # Check encryption.
        if is_encrypted:

            findings.append({
                "code": "PDF_ENCRYPTED",
                "severity": "info",
                "title": "PDF encryption is enabled",
                "evidence": {
                    "is_encrypted": True
                },
                "explanation": (
                    "PDF encryption is common and is not "
                    "itself suspicious."
                ),
            })

        # Check empty PDF.
        if page_count == 0:

            findings.append({
                "code": "PDF_HAS_NO_PAGES",
                "severity": "review",
                "title": "PDF contains no readable pages",
                "evidence": {
                    "page_count": 0
                },
                "explanation": (
                    "No pages could be enumerated in this PDF."
                ),
            })

        return findings

    @classmethod
    def analyze(
        cls,
        file_bytes: bytes,
        filename: str = "document.pdf",
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze PDF bytes and return JSON-serializable results."""

        # Validate input.
        if not isinstance(file_bytes, (bytes, bytearray)):
            raise TypeError(
                "file_bytes must be bytes or bytearray"
            )

        if not file_bytes:
            raise ValueError("The uploaded PDF is empty")

        if not bytes(file_bytes).startswith(b"%PDF-"):
            raise ValueError(
                "The uploaded file does not have a valid PDF header"
            )

        document = None

        try:
            # Open PDF directly from memory.
            document = fitz.open(
                stream=bytes(file_bytes),
                filetype="pdf",
            )

            is_encrypted = bool(document.is_encrypted)

            # Handle password-protected PDFs.
            if is_encrypted:

                if not password:

                    return {
                        "status": "password_required",
                        "filename": filename,
                        "metadata": {},
                        "structure": {
                            "is_encrypted": True,
                            "requires_password": True,
                            "page_count": None,
                        },
                        "findings": [{
                            "code": "PDF_PASSWORD_REQUIRED",
                            "severity": "info",
                            "title": "Password required for PDF analysis",
                            "evidence": {},
                            "explanation": (
                                "Provide the PDF password before "
                                "page-level analysis."
                            ),
                        }],
                        "limitations": [
                            "Page-level structure was not inspected "
                            "because the PDF is password-protected."
                        ],
                    }

                if not document.authenticate(password):
                    raise ValueError(
                        "The supplied PDF password is incorrect"
                    )

            # Extract metadata.
            metadata = cls._collect_metadata(document)

            pages = []

            total_images = 0
            total_links = 0
            total_annotations = 0

            # Analyze each page.
            for page_index in range(document.page_count):

                page = document.load_page(page_index)

                try:
                    image_count = len(
                        page.get_images(full=True)
                    )
                except Exception:
                    image_count = 0

                try:
                    link_count = len(page.get_links())
                except Exception:
                    link_count = 0

                annotation_count = cls._count_annotations(page)

                total_images += image_count
                total_links += link_count
                total_annotations += annotation_count

                pages.append({
                    "page_number": page_index + 1,
                    **cls._page_dimensions(page),
                    "image_count": image_count,
                    "link_count": link_count,
                    "annotation_count": annotation_count,
                    "text_character_count": len(
                        page.get_text("text") or ""
                    ),
                })

            # Extract embedded attachments.
            embedded_files = cls._collect_embedded_files(
                document
            )

            # Count internal PDF objects.
            try:
                xref_count = int(document.xref_length())
            except Exception:
                xref_count = None

            # Get PDF version from metadata first.
            pdf_version = metadata.get("format")

            if not pdf_version:
                pdf_version = cls._clean_text(
                    getattr(document, "pdf_version", None)
                )

            structure = {
                "page_count": int(document.page_count),
                "is_encrypted": is_encrypted,
                "requires_password": False,
                "is_repaired": bool(
                    getattr(document, "is_repaired", False)
                ),
                "pdf_version": pdf_version,
                "xref_object_count": xref_count,
                "total_image_references": total_images,
                "total_links": total_links,
                "total_annotations": total_annotations,
                "embedded_files": embedded_files,
                "pages": pages,
            }

            # Generate review indicators.
            findings = cls._build_findings(
                metadata=metadata,
                filename=filename,
                page_count=document.page_count,
                embedded_files=embedded_files,
                is_encrypted=is_encrypted,
            )

            # Return complete analysis.
            return {
                "status": "completed",
                "filename": filename,
                "metadata": metadata,
                "structure": structure,
                "findings": findings,
                "summary": {
                    "finding_count": len(findings),
                    "page_count": int(document.page_count),
                    "embedded_file_count": len(embedded_files),
                    "image_reference_count": total_images,
                },
                "analysis_method": (
                    "pymupdf_metadata_and_structure"
                ),
                "limitations": [
                    "Metadata can be missing, edited, or rewritten "
                    "by legitimate PDF software.",
                    "Different creation and modification dates do "
                    "not prove tampering.",
                    "A PDF title/filename mismatch can result from "
                    "ordinary renaming.",
                    "Image and link counts describe structure; "
                    "they are not fraud indicators by themselves.",
                    "This module does not verify digital signatures "
                    "or establish authenticity.",
                    "Visual image manipulation requires separate "
                    "image-forensics analysis.",
                ],
            }

        except (fitz.FileDataError, fitz.EmptyFileError) as exc:

            raise ValueError(
                f"Unable to read PDF: {exc}"
            ) from exc

        finally:

            if document is not None:
                document.close()
