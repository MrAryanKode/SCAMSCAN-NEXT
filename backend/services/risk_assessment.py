
from typing import Any


class RiskAssessment:
    """
    Explainable, rule-based risk indicator engine for ScamScan 2.0.

    The score represents review priority based on available indicators.
    It is not a probability of fraud and is not an authenticity verdict.
    """

    EXPECTED_FIELDS = {
        "identity": ["names", "dates", "reference_numbers"],
        "financial": ["dates", "amounts", "reference_numbers"],
        "academic": ["names", "dates", "reference_numbers"],
        "legal": ["names", "dates", "reference_numbers"],
        "travel": ["names", "dates", "reference_numbers"],
        "employment": ["names", "dates"],
        "medical": ["names", "dates"],
        "government": ["names", "dates", "reference_numbers"],
        "unknown": [],
    }

    MAX_SCORE = 100

    @staticmethod
    def _finding(
        code: str,
        title: str,
        severity: str,
        points: int,
        evidence: Any,
        explanation: str,
        recommendation: str,
    ) -> dict[str, Any]:
        return {
            "code": code,
            "title": title,
            "severity": severity,
            "points": points,
            "evidence": evidence,
            "explanation": explanation,
            "recommendation": recommendation,
        }

    @staticmethod
    def _first_available(
        mapping: dict[str, Any],
        keys: tuple[str, ...],
    ) -> Any:
        """Return the first non-None value from compatible engine field names."""
        for key in keys:
            value = mapping.get(key)
            if value is not None:
                return value
        return None

    @classmethod
    def _financial_evidence(
        cls,
        financial: dict[str, Any],
    ) -> dict[str, Any]:
        """Normalize financial results from different engine versions."""

        calculated_total = cls._first_available(
            financial,
            (
                "calculated_component_total",
                "calculated_subtotal_plus_tax",
                "calculated_total",
            ),
        )

        declared_total = cls._first_available(
            financial,
            ("declared_total", "total_amount_paid"),
        )

        difference = financial.get("difference")

        if difference is None:
            if isinstance(calculated_total, (int, float)) and isinstance(
                declared_total, (int, float)
            ):
                difference = round(
                    abs(calculated_total - declared_total),
                    2,
                )

        return {
            "components": financial.get("components", {}),
            "calculated_total": calculated_total,
            "declared_total": declared_total,
            "difference": difference,
            "source_financial_status": financial.get("status"),
        }

    @classmethod
    def assess(
        cls,
        intelligence_analysis: dict[str, Any] | None,
        forensic_findings: list[dict[str, Any]] | None = None,
        file_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Assess supplied analysis results and return a transparent score.

        Missing text intelligence is not automatically treated as fraud
        or incomplete analysis.
        """

        analysis = intelligence_analysis or {}

        extracted = analysis.get("extracted_information") or {}
        document_type = analysis.get("document_type", "unknown")
        financial = analysis.get("financial_analysis") or {}
        statistics = analysis.get("text_statistics") or {}

        findings: list[dict[str, Any]] = []
        limitations: list[str] = []

        if not isinstance(extracted, dict):
            extracted = {}

        if not isinstance(financial, dict):
            financial = {}

        if not isinstance(statistics, dict):
            statistics = {}

        # Check whether text-based intelligence was actually performed.
        text_analysis_available = intelligence_analysis is not None

        # Do not penalize documents simply because OCR found no text.
        expected_fields = (
            cls.EXPECTED_FIELDS.get(document_type, [])
            if text_analysis_available
            else []
        )

        missing_fields = [
            field
            for field in expected_fields
            if not extracted.get(field)
        ]

        if missing_fields:
            findings.append(
                cls._finding(
                    code="EXPECTED_FIELDS_NOT_EXTRACTED",
                    title="Some expected fields were not extracted",
                    severity="low",
                    points=min(15, len(missing_fields) * 5),
                    evidence={
                        "document_type": document_type,
                        "missing_fields": missing_fields,
                    },
                    explanation=(
                        "The text extraction stage did not find some commonly "
                        "expected fields for this document category. They may "
                        "be absent, placed in an unusual layout, or missed by OCR."
                    ),
                    recommendation=(
                        "Review the original document and OCR output. Do not "
                        "treat missing extracted fields alone as proof of tampering."
                    ),
                )
            )

        # Only classify unknown document types when text analysis exists.
        if text_analysis_available and document_type == "unknown":
            findings.append(
                cls._finding(
                    code="DOCUMENT_TYPE_UNCERTAIN",
                    title="Document category could not be identified",
                    severity="low",
                    points=10,
                    evidence={
                        "document_type": document_type,
                    },
                    explanation=(
                        "The available text did not match the supported "
                        "document classification patterns."
                    ),
                    recommendation=(
                        "Confirm the document type and review the extracted "
                        "text manually."
                    ),
                )
            )

        # Missing text intelligence is not an incomplete analysis error.
        if (
            text_analysis_available
            and str(analysis.get("status", "")).lower() != "completed"
        ):
            findings.append(
                cls._finding(
                    code="ANALYSIS_INCOMPLETE",
                    title="Document analysis is incomplete",
                    severity="medium",
                    points=20,
                    evidence={
                        "analysis_status": analysis.get("status", "missing"),
                    },
                    explanation=(
                        "The intelligence analysis did not report a completed status."
                    ),
                    recommendation=(
                        "Retry analysis and verify that the file was processed successfully."
                    ),
                )
            )

        word_count = statistics.get("word_count")

        if (
            text_analysis_available
            and isinstance(word_count, (int, float))
            and word_count < 10
        ):
            findings.append(
                cls._finding(
                    code="LOW_TEXT_CONTENT",
                    title="Very little readable text was extracted",
                    severity="medium",
                    points=15,
                    evidence={
                        "word_count": word_count,
                    },
                    explanation=(
                        "A low word count may indicate a scan, image-only page, "
                        "poor OCR, or a document with little text."
                    ),
                    recommendation=(
                        "Inspect the original pages and consider a clearer "
                        "scan or OCR review."
                    ),
                )
            )

        # Financial consistency checks.
        if financial.get("status") == "requires_verification":
            evidence = cls._financial_evidence(financial)

            findings.append(
                cls._finding(
                    code="FINANCIAL_TOTAL_MISMATCH",
                    title="Financial values do not reconcile",
                    severity="high",
                    points=35,
                    evidence=evidence,
                    explanation=financial.get(
                        "comparison",
                        "The extracted financial components differ from "
                        "the declared total.",
                    ),
                    recommendation=(
                        "Recheck the original figures, tax lines, discounts "
                        "and OCR text before drawing a conclusion."
                    ),
                )
            )

        elif financial.get("status") == "insufficient_data":
            findings.append(
                cls._finding(
                    code="FINANCIAL_CHECK_INSUFFICIENT_DATA",
                    title="Financial consistency could not be checked",
                    severity="info",
                    points=0,
                    evidence={
                        "message": financial.get(
                            "message",
                            "Required values were not available.",
                        )
                    },
                    explanation=(
                        "The required labelled financial values were not "
                        "all extracted."
                    ),
                    recommendation=(
                        "Review the source document manually; no arithmetic "
                        "conclusion is available."
                    ),
                )
            )

        # Process findings supplied by PDF or image forensic engines.
        supplied_forensics = forensic_findings or []

        severity_points = {
            "info": 0,
            "low": 5,
            "medium": 15,
            "high": 30,
        }

        for item in supplied_forensics:
            if not isinstance(item, dict):
                continue

            severity = str(
                item.get("severity", "info")
            ).lower()

            if severity not in severity_points:
                severity = "info"

            findings.append(
                cls._finding(
                    code=str(
                        item.get("code", "FORENSIC_INDICATOR")
                    ),
                    title=str(
                        item.get(
                            "title",
                            "Forensic indicator reported",
                        )
                    ),
                    severity=severity,
                    points=severity_points[severity],
                    evidence=item.get("evidence"),
                    explanation=str(
                        item.get(
                            "explanation",
                            "A forensic module reported an indicator for review.",
                        )
                    ),
                    recommendation=str(
                        item.get(
                            "recommendation",
                            "Review the original file and supporting evidence.",
                        )
                    ),
                )
            )

        # Calculate the review-priority score.
        raw_score = sum(
            item["points"] for item in findings
        )

        score = min(cls.MAX_SCORE, raw_score)

        if score >= 60:
            level = "high"
        elif score >= 30:
            level = "medium"
        elif score > 0:
            level = "low"
        else:
            level = "no_flagged_indicators"

        # Clearly disclose unavailable text analysis.
        if not text_analysis_available:
            limitations.append(
                "Text-based document intelligence was not run because "
                "no readable text was extracted. The risk score does "
                "not assess document content."
            )

        if not supplied_forensics:
            limitations.append(
                "No actionable image/PDF forensic findings were reported "
                "by the available forensic modules."
            )

        limitations.extend(
            [
                "The score is a rule-based review-priority indicator, "
                "not a fraud probability.",
                "A high score does not prove manipulation; a low score "
                "does not prove authenticity.",
                "OCR errors, document layout and legitimate variations "
                "can produce false alerts.",
                "Verify important documents with the issuing organization "
                "or an authorized professional.",
            ]
        )

        return {
            "risk_score": score,
            "risk_level": level,
            "assessment_status": "completed",
            "document_type": document_type,
            "finding_count": len(findings),
            "findings": findings,
            "score_explanation": (
                "The score is the capped sum of points assigned to the "
                "listed review indicators. Each finding includes its "
                "evidence and reason."
            ),
            "limitations": limitations,
            "verdict": (
                "No authenticity or fraud verdict is made by this engine."
            ),
        }
