
"""
ScamScan 2.0 - Image Forensics Engine

Capabilities:
- Image properties and EXIF metadata extraction.
- SHA-256 file fingerprinting.
- JPEG Error Level Analysis (ELA).
- PNG metadata inspection.
- PNG local high-frequency residual visualization.

Important:
These techniques provide review indicators only.
They do not prove manipulation, authenticity, or fraud.
"""

from __future__ import annotations

import base64
import hashlib
import io
from pathlib import PurePath
from typing import Any

import numpy as np
from PIL import (
    ExifTags,
    Image,
    ImageFilter,
    UnidentifiedImageError,
)


class ImageForensics:
    """Explainable metadata and image analysis engine."""

    SUPPORTED_FORMATS = {"JPEG", "PNG", "WEBP"}

    MAX_IMAGE_PIXELS = 40_000_000

    ELA_RECOMPRESSION_QUALITY = 90
    ELA_VISUALIZATION_SCALE = 10

    MAX_VISUALIZATION_DIMENSION = 1200

    # --------------------------------------------------
    # MAIN IMAGE ANALYSIS
    # --------------------------------------------------

    @classmethod
    def analyze(
        cls,
        file_bytes: bytes,
        filename: str = "image",
    ) -> dict[str, Any]:
        """Analyze an image and return JSON-serializable results."""

        if not file_bytes:
            raise ValueError("Image file is empty.")

        file_hash = hashlib.sha256(file_bytes).hexdigest()

        try:
            # First verify that the uploaded image is readable.
            with Image.open(
                io.BytesIO(file_bytes)
            ) as verification_image:

                verification_image.verify()

            # Reopen after verification.
            with Image.open(io.BytesIO(file_bytes)) as image:

                image_format = (image.format or "").upper()

                if image_format not in cls.SUPPORTED_FORMATS:
                    raise ValueError(
                        f"Unsupported image format: "
                        f"{image_format or 'unknown'}."
                    )

                width, height = image.size

                if width <= 0 or height <= 0:
                    raise ValueError("Invalid image dimensions.")

                if width * height > cls.MAX_IMAGE_PIXELS:
                    raise ValueError(
                        "Image exceeds the maximum pixel limit."
                    )

                # Extract image properties.
                properties = cls._get_image_properties(
                    image=image,
                    filename=filename,
                    file_size=len(file_bytes),
                )

                # Extract EXIF information.
                exif_analysis = cls._analyze_exif(image)

                findings: list[dict[str, Any]] = []

                # Report available software metadata as context.
                if exif_analysis.get("software"):

                    findings.append({
                        "code": "IMAGE_SOFTWARE_METADATA_PRESENT",
                        "severity": "info",
                        "title": "Image software metadata found",

                        "evidence": {
                            "software": exif_analysis["software"]
                        },

                        "explanation": (
                            "The image contains software metadata. "
                            "It may identify software that created or "
                            "processed the image, but does not establish "
                            "that the image was manipulated."
                        ),

                        "recommendation": (
                            "Record this metadata as context and compare "
                            "it with the document's provenance if relevant."
                        ),
                    })

                # PNG metadata inspection.
                png_metadata = None

                if image_format == "PNG":
                    png_metadata = cls._analyze_png_metadata(image)

                # JPEG ELA.
                ela_analysis = cls._analyze_ela(
                    image=image,
                    image_format=image_format,
                )

                # PNG residual analysis.
                png_analysis = None

                if image_format == "PNG":
                    png_analysis = cls._analyze_png(image)

                limitations = [
                    "EXIF metadata may be absent, stripped, or modified.",
                    "JPEG ELA is applicable only to JPEG images.",
                    "PNG residual analysis is not equivalent to JPEG ELA.",
                    "Image content, texture, compression and processing "
                    "can affect forensic measurements.",
                    "Visual differences are not a manipulation probability "
                    "or authenticity verdict.",
                    "A human reviewer should inspect the original image "
                    "and its context.",
                ]

                return {
                    "status": "completed",

                    "analysis_method": (
                        "pillow_metadata_jpeg_ela_png_residual"
                    ),

                    "file": {
                        "filename": PurePath(filename).name,
                        "sha256": file_hash,
                        "file_size_bytes": len(file_bytes),
                    },

                    "image_properties": properties,

                    "exif_analysis": exif_analysis,

                    "png_metadata": png_metadata,

                    "ela_analysis": ela_analysis,

                    "png_analysis": png_analysis,

                    "findings": findings,

                    "summary": {
                        "finding_count": len(findings),
                        "format": image_format,

                        "dimensions": {
                            "width": width,
                            "height": height,
                        },

                        "png_residual_analysis_available": (
                            png_analysis is not None
                            and png_analysis.get("available", False)
                        ),

                        "jpeg_ela_available": (
                            ela_analysis.get("available", False)
                        ),
                    },

                    "limitations": limitations,
                }

        except (
            UnidentifiedImageError,
            OSError,
        ) as error:

            raise ValueError(
                f"Unable to read image: {error}"
            ) from error

    # --------------------------------------------------
    # IMAGE PROPERTIES
    # --------------------------------------------------

    @staticmethod
    def _get_image_properties(
        image: Image.Image,
        filename: str,
        file_size: int,
    ) -> dict[str, Any]:

        return {
            "filename": PurePath(filename).name,

            "format": image.format,

            "width": image.width,

            "height": image.height,

            "aspect_ratio": round(
                image.width / image.height, 4
            ),

            "color_mode": image.mode,

            "file_size_bytes": file_size,

            "has_transparency": (
                "A" in image.getbands()
                or "transparency" in image.info
            ),
        }

    # --------------------------------------------------
    # SAFE METADATA CONVERSION
    # --------------------------------------------------

    @staticmethod
    def _safe_exif_value(
        value: Any,
    ) -> str | None:

        if value is None:
            return None

        if isinstance(value, bytes):
            value = value.decode(
                "utf-8",
                errors="replace",
            )

        return str(value)[:300]

    # --------------------------------------------------
    # EXIF ANALYSIS
    # --------------------------------------------------

    @classmethod
    def _analyze_exif(
        cls,
        image: Image.Image,
    ) -> dict[str, Any]:

        selected_names = {
            "Software",
            "DateTime",
            "DateTimeOriginal",
            "DateTimeDigitized",
            "Make",
            "Model",
            "Orientation",
        }

        selected: dict[str, str] = {}

        try:
            raw_exif = image.getexif()

            for tag_id, value in raw_exif.items():

                tag_name = ExifTags.TAGS.get(
                    tag_id,
                    str(tag_id),
                )

                if tag_name in selected_names:

                    safe_value = cls._safe_exif_value(value)

                    if safe_value is not None:
                        selected[tag_name] = safe_value

        except (
            AttributeError,
            OSError,
            ValueError,
            TypeError,
        ):
            selected = {}

        return {
            "metadata_present": bool(selected),

            "software": selected.get("Software"),

            "date_taken": (
                selected.get("DateTimeOriginal")
                or selected.get("DateTimeDigitized")
                or selected.get("DateTime")
            ),

            "camera_make": selected.get("Make"),

            "camera_model": selected.get("Model"),

            "selected_tags": selected,
        }

    # --------------------------------------------------
    # PNG METADATA ANALYSIS
    # --------------------------------------------------

    @classmethod
    def _analyze_png_metadata(
        cls,
        image: Image.Image,
    ) -> dict[str, Any]:
        """
        Inspect metadata exposed by Pillow for PNG images.

        Metadata presence is contextual information,
        not evidence of image manipulation.
        """

        info = getattr(image, "info", {}) or {}

        metadata_keys = sorted(
            str(key) for key in info.keys()
        )

        recognized_metadata = [
            key for key in metadata_keys
            if key.lower() in {
                "gamma",
                "dpi",
                "srgb",
                "icc_profile",
                "transparency",
                "background",
                "exif",
                "xml",
                "software",
                "creation_time",
                "author",
                "description",
                "copyright",
            }
        ]

        return {
            "metadata_present": bool(metadata_keys),

            "metadata_key_count": len(metadata_keys),

            "metadata_keys": metadata_keys,

            "recognized_metadata_fields": recognized_metadata,

            "analysis_note": (
                "PNG metadata fields exposed by Pillow were inspected. "
                "Their presence or absence does not establish authenticity."
            ),
        }

    # --------------------------------------------------
    # JPEG ERROR LEVEL ANALYSIS
    # --------------------------------------------------

    @classmethod
    def _analyze_ela(
        cls,
        image: Image.Image,
        image_format: str,
    ) -> dict[str, Any]:

        if image_format != "JPEG":

            return {
                "available": False,

                "reason": (
                    "JPEG ELA is not applicable to this image format. "
                    "PNG uses separate residual analysis."
                    if image_format == "PNG"
                    else "ELA currently supports JPEG images only."
                ),
            }

        try:
            original = image.convert("RGB")

            recompressed_buffer = io.BytesIO()

            original.save(
                recompressed_buffer,
                format="JPEG",
                quality=cls.ELA_RECOMPRESSION_QUALITY,
                optimize=False,
            )

            recompressed_buffer.seek(0)

            with Image.open(
                recompressed_buffer
            ) as recompressed_image:

                recompressed = recompressed_image.convert("RGB")

            original_array = np.asarray(
                original,
                dtype=np.int16,
            )

            recompressed_array = np.asarray(
                recompressed,
                dtype=np.int16,
            )

            difference = np.abs(
                original_array - recompressed_array
            )

            mean_difference = float(
                np.mean(difference)
            )

            max_difference = int(
                np.max(difference)
            )

            visualization = np.clip(
                difference * cls.ELA_VISUALIZATION_SCALE,
                0,
                255,
            ).astype(np.uint8)

            visualization_image = Image.fromarray(
                visualization,
                mode="RGB",
            )

            visualization_image.thumbnail((
                cls.MAX_VISUALIZATION_DIMENSION,
                cls.MAX_VISUALIZATION_DIMENSION,
            ))

            output_buffer = io.BytesIO()

            visualization_image.save(
                output_buffer,
                format="PNG",
                optimize=True,
            )

            encoded_preview = base64.b64encode(
                output_buffer.getvalue()
            ).decode("ascii")

            return {
                "available": True,

                "method": "jpeg_recompression_difference",

                "recompression_quality": (
                    cls.ELA_RECOMPRESSION_QUALITY
                ),

                "visualization_scale": (
                    cls.ELA_VISUALIZATION_SCALE
                ),

                "mean_difference": round(
                    mean_difference, 4
                ),

                "max_difference": max_difference,

                "visualization": {
                    "mime_type": "image/png",

                    "encoding": "base64",

                    "data": encoded_preview,

                    "width": visualization_image.width,

                    "height": visualization_image.height,
                },

                "analysis_note": (
                    "The visualization amplifies pixel differences "
                    "after JPEG recompression. Bright regions are not "
                    "proof of editing; content, prior compression and "
                    "processing can affect them."
                ),
            }

        except (
            OSError,
            ValueError,
            TypeError,
        ) as error:

            return {
                "available": False,

                "reason": (
                    f"ELA analysis could not be completed: {error}"
                ),
            }

    # --------------------------------------------------
    # PNG LOCAL RESIDUAL ANALYSIS
    # --------------------------------------------------

    @classmethod
    def _analyze_png(
        cls,
        image: Image.Image,
    ) -> dict[str, Any]:
        """
        Calculate local high-frequency pixel residuals.

        This creates a visualization of local texture differences.
        It is NOT PNG ELA and does NOT identify edited regions reliably.
        """

        try:
            # Convert to grayscale for residual analysis.
            original = image.convert("L")

            # Limit processing size to reduce memory usage.
            original.thumbnail((
                cls.MAX_VISUALIZATION_DIMENSION,
                cls.MAX_VISUALIZATION_DIMENSION,
            ))

            # Apply a small blur to estimate local image structure.
            blurred = original.filter(
                ImageFilter.BoxBlur(radius=1)
            )

            original_array = np.asarray(
                original,
                dtype=np.float32,
            )

            blurred_array = np.asarray(
                blurred,
                dtype=np.float32,
            )

            # Absolute high-frequency residual.
            residual = np.abs(
                original_array - blurred_array
            )

            mean_residual = float(
                np.mean(residual)
            )

            p95_residual = float(
                np.percentile(residual, 95)
            )

            p99_residual = float(
                np.percentile(residual, 99)
            )

            max_residual = float(
                np.max(residual)
            )

            # Normalize only for visualization.
            # This is not a risk score or manipulation threshold.
            scale_reference = max(
                p99_residual,
                1.0,
            )

            visualization = np.clip(
                (residual / scale_reference) * 255,
                0,
                255,
            ).astype(np.uint8)

            visualization_image = Image.fromarray(
                visualization,
                mode="L",
            )

            output_buffer = io.BytesIO()

            visualization_image.save(
                output_buffer,
                format="PNG",
                optimize=True,
            )

            encoded_preview = base64.b64encode(
                output_buffer.getvalue()
            ).decode("ascii")

            return {
                "available": True,

                "method": "png_local_high_frequency_residual",

                "analysis_dimensions": {
                    "width": original.width,
                    "height": original.height,
                },

                "metrics": {
                    "mean_residual": round(
                        mean_residual, 4
                    ),

                    "p95_residual": round(
                        p95_residual, 4
                    ),

                    "p99_residual": round(
                        p99_residual, 4
                    ),

                    "max_residual": round(
                        max_residual, 4
                    ),
                },

                "visualization": {
                    "mime_type": "image/png",

                    "encoding": "base64",

                    "data": encoded_preview,

                    "width": visualization_image.width,

                    "height": visualization_image.height,
                },

                "analysis_note": (
                    "This visualization shows local high-frequency "
                    "pixel residuals. Bright regions can correspond "
                    "to edges, text, fine texture or noise. They are "
                    "not evidence of manipulation by themselves."
                ),

                "limitations": [
                    "PNG is lossless, so JPEG-style ELA is not applicable.",
                    "Natural image edges and text produce strong residuals.",
                    "Resizing and image content affect residual measurements.",
                    "This method does not identify copy-paste edits or prove tampering.",
                    "No manipulation probability is calculated.",
                ],
            }

        except (
            OSError,
            ValueError,
            TypeError,
        ) as error:

            return {
                "available": False,

                "reason": (
                    f"PNG residual analysis could not be completed: {error}"
                ),
            }
