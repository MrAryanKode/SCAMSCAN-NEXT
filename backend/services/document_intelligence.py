import re
from datetime import datetime
from typing import Any


class DocumentIntelligence:
    """
    Rule-based document intelligence for ScamScan 2.0.

    This module classifies common document families, extracts clearly
    labelled information, and reports basic consistency indicators.
    It does not determine whether a document is genuine or fraudulent.
    """

    DOCUMENT_PATTERNS = {
        "identity": [
            r"\bpassport\b", r"\bdriving licence\b", r"\bdriver'?s license\b",
            r"\bidentity card\b", r"\bid card\b", r"\baadhaar\b",
            r"\bdate of birth\b", r"\bplace of birth\b",
        ],
        "financial": [
            r"\binvoice\b", r"\btax invoice\b", r"\bbill to\b",
            r"\bsubtotal\b", r"\bgrand total\b", r"\breceipt\b",
            r"\bpayment received\b", r"\bbank statement\b",
            r"\baccount summary\b", r"\bopening balance\b",
            r"\bclosing balance\b", r"\btransaction id\b",
        ],
        "academic": [
            r"\bmarksheet\b", r"\bmark sheet\b", r"\btranscript\b",
            r"\bdegree\b", r"\bdiploma\b", r"\buniversity\b",
            r"\bsemester\b", r"\bgrade point\b", r"\bcertificate of",
            r"\bregistration number\b",
        ],
        "legal": [
            r"\bagreement\b", r"\bcontract\b", r"\baffidavit\b",
            r"\bdeed\b", r"\bwhereas\b", r"\bterms and conditions\b",
            r"\bparty of the first part\b", r"\bnotary\b",
        ],
        "travel": [
            r"\bflight\b", r"\bpnr\b", r"\bairline\b",
            r"\bdeparture\b", r"\barrival\b", r"\bboarding pass\b",
            r"\bpassenger\b", r"\bhotel booking\b", r"\bcheck-in\b",
            r"\bcheck-out\b", r"\bitinerary\b",
        ],
        "employment": [
            r"\boffer letter\b", r"\bappointment letter\b",
            r"\bexperience letter\b", r"\bsalary slip\b",
            r"\bpayslip\b", r"\bpay slip\b", r"\bemployment\b",
            r"\bdesignation\b", r"\bjoining date\b",
        ],
        "medical": [
            r"\bmedical report\b", r"\bprescription\b",
            r"\blaboratory report\b", r"\blab report\b",
            r"\bpatient\b", r"\bdiagnosis\b", r"\btest result\b",
            r"\bdoctor\b", r"\bhospital\b",
        ],
        "government": [
            r"\bgovernment of\b", r"\bincome tax\b",
            r"\btax return\b", r"\bpan\b", r"\bcertificate number\b",
            r"\bapplication form\b", r"\bdepartment of\b",
            r"\bmunicipal\b", r"\bbirth certificate\b",
        ],
    }

    DATE_PATTERNS = [
        r"\b\d{4}-\d{1,2}-\d{1,2}\b",
        r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
        r"\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}\b",
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b",
    ]

    DATE_FORMATS = [
        "%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y",
        "%d-%m-%y", "%d/%m/%y", "%d %b %Y",
        "%d %B %Y", "%b %d %Y", "%B %d %Y",
        "%b %d, %Y", "%B %d, %Y",
    ]

    NAME_LABELS = [
        "passenger name", "name of passenger", "traveller name",
        "traveler name", "customer name", "patient name",
        "employee name", "student name", "candidate name",
        "applicant name", "account holder", "issued to",
        "name",
    ]

    REFERENCE_LABELS = [
        "invoice number", "invoice no", "receipt number",
        "receipt no", "transaction id", "transaction reference",
        "booking reference", "booking id", "pnr", "ticket number",
        "document number", "certificate number", "application number",
        "reference number", "registration number", "policy number",
        "order id", "order number",
    ]

    AMOUNT_LABELS = [
        "grand total", "total amount", "amount paid", "net amount",
        "subtotal", "total", "fare", "price", "amount", "charges",
        "salary", "gross pay", "net pay", "balance",
    ]

    CURRENCY_PATTERN = re.compile(
        r"(?:₹\s*|INR\s*|Rs\.?\s*|USD\s*\$?\s*|\$\s*|EUR\s*€?\s*|€\s*)"
        r"([0-9][0-9,]*(?:\.\d{1,2})?)",
        re.IGNORECASE,
    )

    GENERIC_VALUES = {
        "number", "no", "name", "id", "date", "amount", "details",
        "customer", "passenger", "student", "employee", "patient",
        "reference", "invoice", "ticket", "document",
    }

    @staticmethod
    def normalize_text(text: str) -> str:
        """Normalize OCR/PDF text without changing its meaning."""
        if not isinstance(text, str):
            return ""
        text = text.replace("\x00", " ").replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    @classmethod
    def classify_document(cls, text: str) -> dict[str, Any]:
        """Classify by keyword evidence; return unknown when evidence is absent."""
        normalized = text.lower()
        scores = {}

        for document_type, patterns in cls.DOCUMENT_PATTERNS.items():
            matched = [pattern for pattern in patterns if re.search(pattern, normalized)]
            scores[document_type] = {
                "score": len(matched),
                "matched_indicators": matched,
            }

        if not scores or max(item["score"] for item in scores.values()) == 0:
            return {
                "document_type": "unknown",
                "classification_method": "keyword_matching",
                "matched_indicators": [],
                "classification_scores": scores,
            }

        # Stable ordering makes ties deterministic.
        best_type = max(scores, key=lambda key: scores[key]["score"])
        return {
            "document_type": best_type,
            "classification_method": "keyword_matching",
            "matched_indicators": scores[best_type]["matched_indicators"],
            "classification_scores": scores,
        }

    @classmethod
    def extract_dates(cls, text: str) -> list[str]:
        found = set()
        for pattern in cls.DATE_PATTERNS:
            for match in re.findall(pattern, text, flags=re.IGNORECASE):
                cleaned = re.sub(r"\s+", " ", match.strip())
                for date_format in cls.DATE_FORMATS:
                    try:
                        parsed = datetime.strptime(cleaned, date_format)
                        found.add(parsed.strftime("%Y-%m-%d"))
                        break
                    except ValueError:
                        continue
        return sorted(found)

    @classmethod
    def extract_travel_passenger_names(cls, text: str) -> list[str]:
        """Extract passenger names from common multi-line ticket tables."""
        lines = [line.strip() for line in text.splitlines()]
        names = set()

        # Ticket tables often place the title/first name and surname on
        # separate lines, followed by passenger type (Adult/Child/Infant).
        for index, line in enumerate(lines):
            title_match = re.fullmatch(
                r"(?:Mr|Mrs|Ms|Miss|Master)\.?\s+([A-Za-z][A-Za-z'-]*)",
                line,
                flags=re.IGNORECASE,
            )
            if not title_match:
                continue

            first_part = title_match.group(1)
            if index + 1 >= len(lines):
                continue

            next_line = lines[index + 1]
            surname_match = re.fullmatch(
                r"([A-Za-z][A-Za-z .'-]{1,60})",
                next_line,
            )
            if not surname_match:
                continue

            # Avoid joining a title/name to unrelated table headings.
            if next_line.lower() in {
                "adult", "child", "infant", "passenger", "delivered",
                "economy", "regular", "na", "status",
            }:
                continue

            full_name = re.sub(r"\s+", " ", f"{first_part} {next_line}").strip()
            if len(full_name) <= 80:
                names.add(full_name)

        return sorted(names)

    @classmethod
    def extract_names(cls, text: str) -> list[str]:
        names = set(cls.extract_travel_passenger_names(text))
        for line in text.splitlines():
            cleaned = line.strip()
            for label in cls.NAME_LABELS:
                match = re.search(
                    rf"^\s*{re.escape(label)}\s*[:#-]\s*(.+?)\s*$",
                    cleaned,
                    flags=re.IGNORECASE,
                )
                if not match:
                    continue

                candidate = match.group(1).strip(" \t:,-")
                if (
                    candidate.lower() in cls.GENERIC_VALUES
                    or not 2 < len(candidate) < 81
                    or re.search(r"\d", candidate)
                ):
                    continue
                names.add(candidate)
                break
        return sorted(names)

    @classmethod
    def extract_reference_numbers(cls, text: str) -> list[str]:
        references = set()
        lines = [line.strip() for line in text.splitlines()]
        for index, line in enumerate(lines):
            for label in cls.REFERENCE_LABELS:
                match = re.search(
                    rf"\b{re.escape(label)}\b\s*[:#-]?\s*([A-Z0-9][A-Z0-9./_-]{{2,}})",
                    line,
                    flags=re.IGNORECASE,
                )
                value = match.group(1) if match else None

                # PDF table extraction may put a column heading (e.g. PNR)
                # on one line and its value on the next line.
                if value is None and re.fullmatch(
                    rf"{re.escape(label)}\s*[:#-]?", line, flags=re.IGNORECASE
                ) and index + 1 < len(lines):
                    next_line = lines[index + 1]
                    next_match = re.match(
                        r"^([A-Z0-9][A-Z0-9./_-]{2,})$",
                        next_line,
                        flags=re.IGNORECASE,
                    )
                    if next_match:
                        value = next_match.group(1)

                if value:
                    value = value.strip(" .,:;")
                    if value.lower() not in cls.GENERIC_VALUES and re.search(r"\d", value):
                        references.add(value.upper())
        return sorted(references)

    @classmethod
    def extract_flight_fare_data(cls, text: str) -> dict[str, float] | None:
        """
        Extract IRCTC-style flight fare components.

        PDF text extraction can return the fare labels first and the
        right-aligned amount column later. This isolates the fare section
        and reads the final five amount-like values before the next section.
        """
        start = re.search(r"\bFare Details\b", text, flags=re.IGNORECASE)
        if not start:
            return None

        following_section = re.search(
            r"As per Government guidelines",
            text[start.end():],
            flags=re.IGNORECASE,
        )
        if not following_section:
            return None

        fare_section = text[start.end():start.end() + following_section.start()]
        number_pattern = re.compile(
            r"(?<![A-Za-z0-9/.-])"
            r"(?:\d{1,3}(?:,\d{3})+|\d+)"
            r"(?:\.\d{1,2})?"
            r"(?![A-Za-z0-9/.-])"
        )

        values = []
        for match in number_pattern.finditer(fare_section):
            try:
                values.append(float(match.group(0).replace(",", "")))
            except ValueError:
                continue

        if len(values) < 5:
            return None

        labels = [
            "Base Fare",
            "Other Fees and Taxes",
            "Convenience Fee",
            "Additional Payment",
            "Total Amount Paid",
        ]
        return dict(zip(labels, values[-5:]))

    @classmethod
    def extract_amounts(cls, text: str, document_type: str = "unknown") -> list[str]:
        """Extract labelled amounts, using a fare-table parser for flight tickets."""
        if document_type == "travel":
            fare_data = cls.extract_flight_fare_data(text)
            if fare_data:
                return [f"INR {value:,.2f}" for value in fare_data.values()]

        amounts = set()
        for line in text.splitlines():
            if not re.search(
                r"\b(?:grand total|total amount|amount paid|net amount|subtotal|"
                r"total|fare|price|amount|charges|salary|gross pay|net pay|balance)\b",
                line,
                flags=re.IGNORECASE,
            ):
                continue

            for match in cls.CURRENCY_PATTERN.finditer(line):
                amounts.add(re.sub(r"\s+", " ", match.group(0).strip()))
        return sorted(amounts)

    @classmethod
    def analyze_financial_consistency(cls, text: str, document_type: str) -> dict[str, Any]:
        """
        Compare extracted totals for flight tickets and common invoices.
        This is an arithmetic check, not an authenticity determination.
        """
        if document_type == "travel":
            fare_data = cls.extract_flight_fare_data(text)
            if not fare_data:
                return {
                    "status": "insufficient_data",
                    "message": "Could not reliably isolate all five flight fare values.",
                    "components": {},
                    "checks": [],
                }

            component_sum = round(
                fare_data["Base Fare"]
                + fare_data["Other Fees and Taxes"]
                + fare_data["Convenience Fee"]
                + fare_data["Additional Payment"],
                2,
            )
            declared_total = fare_data["Total Amount Paid"]
            difference = round(component_sum - declared_total, 2)
            consistent = abs(difference) < 0.01

            return {
                "status": "consistent" if consistent else "requires_verification",
                "components": fare_data,
                "calculated_component_total": component_sum,
                "declared_total": declared_total,
                "difference": abs(difference),
                "comparison": (
                    "Flight fare components match the declared total."
                    if consistent
                    else "Flight fare component sum differs from the declared total."
                ),
                "checks": [{
                    "name": "flight_fare_components_equal_total",
                    "passed": consistent,
                    "evidence": {
                        "base_fare": fare_data["Base Fare"],
                        "other_fees_and_taxes": fare_data["Other Fees and Taxes"],
                        "convenience_fee": fare_data["Convenience Fee"],
                        "additional_payment": fare_data["Additional Payment"],
                        "calculated_total": component_sum,
                        "declared_total": declared_total,
                    },
                }],
                "limitation": "Only values isolated from the fare section were compared; this does not establish ticket authenticity.",
            }

        if document_type != "financial":
            return {
                "status": "not_applicable",
                "message": "Financial arithmetic check is not applicable to this document category.",
                "checks": [],
            }

        values = {}
        for line in text.splitlines():
            label_match = re.search(
                r"\b(subtotal|tax|gst|grand total|total amount|total)\b",
                line,
                flags=re.IGNORECASE,
            )
            if not label_match:
                continue
            amounts = cls.CURRENCY_PATTERN.findall(line)
            if not amounts:
                continue
            try:
                values[label_match.group(1).lower()] = float(amounts[-1].replace(",", ""))
            except ValueError:
                continue

        subtotal = values.get("subtotal")
        tax = values.get("tax", values.get("gst"))
        total = values.get("grand total", values.get("total amount", values.get("total")))

        if subtotal is None or tax is None or total is None:
            return {
                "status": "insufficient_data",
                "message": "A labelled subtotal, tax and total were not all found. No arithmetic conclusion was made.",
                "components": values,
                "checks": [],
            }

        calculated = round(subtotal + tax, 2)
        difference = round(calculated - total, 2)
        consistent = abs(difference) < 0.01

        return {
            "status": "consistent" if consistent else "requires_verification",
            "components": values,
            "calculated_subtotal_plus_tax": calculated,
            "declared_total": total,
            "difference": abs(difference),
            "comparison": (
                "Subtotal plus tax matches the declared total."
                if consistent
                else "Subtotal plus tax differs from the declared total."
            ),
            "checks": [{
                "name": "subtotal_plus_tax_equals_total",
                "passed": consistent,
                "evidence": {
                    "subtotal": subtotal,
                    "tax": tax,
                    "calculated": calculated,
                    "declared_total": total,
                },
            }],
            "limitation": "Only the extracted labelled values were compared; this does not establish document authenticity.",
        }

    @classmethod
    def analyze(cls, text: str) -> dict[str, Any]:
        """Run classification, extraction and conservative consistency checks."""
        normalized_text = cls.normalize_text(text)

        if not normalized_text:
            return {
                "document_type": "unknown",
                "classification": {
                    "document_type": "unknown",
                    "classification_method": "keyword_matching",
                    "matched_indicators": [],
                    "classification_scores": {},
                },
                "extracted_information": {
                    "names": [],
                    "dates": [],
                    "amounts": [],
                    "reference_numbers": [],
                },
                "missing_extraction_fields": [
                    "names", "dates", "amounts", "reference_numbers"
                ],
                "financial_analysis": {
                    "status": "insufficient_data",
                    "message": "No readable text was available for analysis.",
                    "checks": [],
                },
                "text_statistics": {"character_count": 0, "word_count": 0},
                "analysis_method": "rule_based_extraction",
                "status": "completed",
                "limitations": [
                    "No readable text was supplied.",
                    "No authenticity or fraud verdict can be made.",
                ],
            }

        classification = cls.classify_document(normalized_text)
        document_type = classification["document_type"]

        extracted_information = {
            "names": cls.extract_names(normalized_text),
            "dates": cls.extract_dates(normalized_text),
            "amounts": cls.extract_amounts(normalized_text, document_type),
            "reference_numbers": cls.extract_reference_numbers(normalized_text),
        }

        missing_fields = [
            field for field, values in extracted_information.items() if not values
        ]

        return {
            "document_type": document_type,
            "classification": classification,
            "extracted_information": extracted_information,
            "missing_extraction_fields": missing_fields,
            "financial_analysis": cls.analyze_financial_consistency(
                normalized_text, document_type
            ),
            "text_statistics": {
                "character_count": len(normalized_text),
                "word_count": len(normalized_text.split()),
            },
            "analysis_method": "rule_based_extraction",
            "status": "completed",
            "limitations": [
                "Classification is based on keyword matching and may be uncertain.",
                "Extraction depends on OCR/PDF text quality and document layout.",
                "Missing extracted fields do not prove that a document is invalid.",
                "Automated indicators do not establish whether a document is genuine or fraudulent.",
            ],
        }
