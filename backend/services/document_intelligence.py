
import re
from datetime import datetime
from typing import Any


class DocumentIntelligence:
    """Rule-based document intelligence for ScamScan 2.0."""

    DOCUMENT_PATTERNS = {
        "identity": [
            r"\bpassport\b", r"\bdriving licence\b",
            r"\bdriver'?s license\b", r"\bidentity card\b",
            r"\bid card\b", r"\baadhaar\b",
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
            r"\bsemester\b", r"\bgrade point\b",
            r"\bcertificate of", r"\bregistration number\b",
        ],
        "legal": [
            r"\bagreement\b", r"\bcontract\b", r"\baffidavit\b",
            r"\bdeed\b", r"\bwhereas\b", r"\bterms and conditions\b",
            r"\bparty of the first part\b", r"\bnotary\b",
        ],
        "travel": [
            r"\bflight\b", r"\bpnr\b", r"\bairline\b",
            r"\bdeparture\b", r"\barrival\b", r"\bboarding pass\b",
            r"\bpassenger\b", r"\bhotel booking\b",
            r"\bcheck-in\b", r"\bcheck-out\b", r"\bitinerary\b",
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
        "%m/%d/%Y", "%d-%m-%y", "%d/%m/%y",
        "%d %b %Y", "%d %B %Y", "%b %d %Y",
        "%B %d %Y", "%b %d, %Y", "%B %d, %Y",
    ]

    NAME_LABELS = [
        "passenger name", "name of passenger",
        "traveller name", "traveler name",
        "customer name", "patient name",
        "employee name", "student name",
        "candidate name", "applicant name",
        "account holder", "issued to",
        "client", "provider", "customer", "beneficiary", "recipient", "name",
    ]

    REFERENCE_LABELS = [
        "transaction reference", "booking reference", "reference",
        "registration number", "certificate number",
        "application number", "reference number",
        "reference no", "ref no", "transaction id",
        "invoice number", "invoice no",
        "receipt number", "receipt no",
        "booking id", "ticket number",
        "document number", "policy number",
        "order number", "order id",
        "roll number", "roll no",
        "enrollment number", "enrolment number",
        "enrollment no", "enrolment no",
        "student id", "student number",
        "exam seat number", "seat number", "pnr",
    ]

    GENERIC_VALUES = {
        "number", "no", "name", "id", "date", "amount",
        "details", "customer", "passenger", "student",
        "employee", "patient", "reference", "invoice",
        "ticket", "document", "adult", "child",
        "programme", "semester", "status",
    }

    CURRENCY_PATTERN = re.compile(
        r"(?:₹|INR|Rs\.?|USD|\$|EUR|€)\s*"
        r"([0-9][0-9.,]*)",
        re.IGNORECASE,
    )

    @staticmethod
    def parse_currency_number(raw_value: str) -> float | None:
        """Parse currency digits while tolerating common OCR separators."""
        value = re.sub(r"[^0-9.,]", "", raw_value)
        if not value or not re.search(r"\d", value):
            return None

        # OCR may read the thousands separator as a dot: 2.400.00.
        if value.count(".") > 1 and re.fullmatch(
            r"\d{1,3}(?:\.\d{3})+\.\d{2}", value
        ):
            value = value.replace(".", "", value.count(".") - 1)

        # Handle standard grouped values such as 2,400.00 and 1.234,56.
        if "," in value and "." in value:
            if value.rfind(".") > value.rfind(","):
                value = value.replace(",", "")
            else:
                value = value.replace(".", "").replace(",", ".")
        elif "," in value:
            parts = value.split(",")
            if len(parts) > 1 and len(parts[-1]) == 2:
                value = "".join(parts[:-1]) + "." + parts[-1]
            else:
                value = "".join(parts)
        elif value.count(".") == 1:
            left, right = value.split(".")
            if len(right) == 3 and len(left) <= 3:
                value = left + right
        elif value.count(".") > 1:
            parts = value.split(".")
            if len(parts[-1]) == 2:
                value = "".join(parts[:-1]) + "." + parts[-1]
            else:
                value = "".join(parts)

        try:
            return float(value)
        except ValueError:
            return None

    # --------------------------------------------------
    # TEXT NORMALIZATION
    # --------------------------------------------------

    @staticmethod
    def normalize_text(text: str) -> str:
        if not isinstance(text, str):
            return ""

        text = text.replace("\x00", " ")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)

        return text.strip()

    # --------------------------------------------------
    # DOCUMENT CLASSIFICATION
    # --------------------------------------------------

    @classmethod
    def classify_document(cls, text: str) -> dict[str, Any]:
        normalized = text.lower()
        scores = {}

        for document_type, patterns in cls.DOCUMENT_PATTERNS.items():
            matched = [
                pattern for pattern in patterns
                if re.search(pattern, normalized)
            ]

            scores[document_type] = {
                "score": len(matched),
                "matched_indicators": matched,
            }

        if not scores or max(
            item["score"] for item in scores.values()
        ) == 0:
            return {
                "document_type": "unknown",
                "classification_method": "keyword_matching",
                "matched_indicators": [],
                "classification_scores": scores,
            }

        best_type = max(
            scores, key=lambda key: scores[key]["score"]
        )

        return {
            "document_type": best_type,
            "classification_method": "keyword_matching",
            "matched_indicators": scores[best_type]["matched_indicators"],
            "classification_scores": scores,
        }

    # --------------------------------------------------
    # DATE EXTRACTION
    # --------------------------------------------------

    @classmethod
    def extract_dates(cls, text: str) -> list[str]:
        found = set()

        for pattern in cls.DATE_PATTERNS:
            for match in re.findall(
                pattern, text, flags=re.IGNORECASE
            ):
                cleaned = re.sub(r"\s+", " ", match.strip())

                for date_format in cls.DATE_FORMATS:
                    try:
                        parsed = datetime.strptime(
                            cleaned, date_format
                        )
                        found.add(parsed.strftime("%Y-%m-%d"))
                        break
                    except ValueError:
                        continue

        return sorted(found)

    # --------------------------------------------------
    # NAME VALIDATION
    # --------------------------------------------------

    @classmethod
    def is_valid_name(cls, candidate: str) -> bool:
        candidate = candidate.strip(" \t:,-.")

        if not 2 < len(candidate) < 81:
            return False

        if candidate.lower() in cls.GENERIC_VALUES:
            return False

        if re.search(r"\d", candidate):
            return False

        if re.search(
            r"\b(date|number|amount|address|gender|roll|"
            r"semester|programme|academic|year|credits|"
            r"marks|course|total)\b",
            candidate,
            re.IGNORECASE,
        ):
            return False

        if len(candidate.split()) > 6:
            return False

        return bool(re.fullmatch(
            r"[A-Za-z][A-Za-z .'-]*", candidate
        ))

    # --------------------------------------------------
    # TRAVEL PASSENGER NAME EXTRACTION
    # --------------------------------------------------

    @classmethod
    def extract_travel_passenger_names(
        cls, text: str
    ) -> list[str]:

        lines = [line.strip() for line in text.splitlines()]
        names = set()

        for index, line in enumerate(lines):
            title_match = re.fullmatch(
                r"(?:Mr|Mrs|Ms|Miss|Master)\.?\s+"
                r"([A-Za-z][A-Za-z'-]*)",
                line,
                flags=re.IGNORECASE,
            )

            if not title_match or index + 1 >= len(lines):
                continue

            first_part = title_match.group(1)
            next_line = lines[index + 1]

            if next_line.lower() in {
                "adult", "child", "infant", "passenger",
                "delivered", "economy", "regular", "na",
                "status",
            }:
                continue

            if re.fullmatch(
                r"[A-Za-z][A-Za-z .'-]{1,60}", next_line
            ):
                full_name = f"{first_part} {next_line}"

                if cls.is_valid_name(full_name):
                    names.add(full_name)

        return sorted(names)

    # --------------------------------------------------
    # IMPROVED NAME EXTRACTION
    # --------------------------------------------------

    @classmethod
    def extract_names(cls, text: str) -> list[str]:
        names = set(cls.extract_travel_passenger_names(text))
        lines = [line.strip() for line in text.splitlines()]

        for index, line in enumerate(lines):
            for label in sorted(cls.NAME_LABELS, key=len, reverse=True):
                pattern = (
                    rf"^\s*{re.escape(label)}\s*[:#-]?\s*(.*?)\s*$"
                )

                match = re.match(
                    pattern, line, flags=re.IGNORECASE
                )

                if not match:
                    continue

                candidate = match.group(1).strip(" \t:,-")
                # Remove explanatory parentheticals after extracted names.
                candidate = re.split(r"\s*\(", candidate, maxsplit=1)[0]
                candidate = candidate.strip(" \t:,-.")


                if not candidate:
                    for next_index in range(
                        index + 1, min(index + 5, len(lines))
                    ):
                        possible = lines[next_index]

                        if not possible:
                            continue

                        if possible.lower() in cls.GENERIC_VALUES:
                            continue

                        possible = re.split(r"\s*\(", possible, maxsplit=1)[0]
                        possible = possible.strip(" \t:,-.")
                        if cls.is_valid_name(possible):
                            candidate = possible
                            break

                        break

                if cls.is_valid_name(candidate):
                    names.add(candidate)

        # Academic marksheet layout.
        academic_pattern = re.compile(
            r"^\s*([A-Za-z][A-Za-z .'-]{1,60}?)"
            r"\s+Academic\s+Year\s*:",
            re.IGNORECASE,
        )

        # Name followed by Date of Issue.
        issue_pattern = re.compile(
            r"^\s*([A-Za-z][A-Za-z .'-]{1,60}?)"
            r"\s+Date\s+of\s+Issue\s*:",
            re.IGNORECASE,
        )

        for line in lines:
            for pattern in (academic_pattern, issue_pattern):
                match = pattern.search(line)

                if match:
                    candidate = match.group(1).strip()

                    if cls.is_valid_name(candidate):
                        names.add(candidate)

        return sorted(names)

    # --------------------------------------------------
    # ROLL NUMBER EXTRACTION
    # --------------------------------------------------

    @classmethod
    def extract_roll_numbers(cls, text: str) -> list[str]:
        has_roll_label = bool(re.search(
            r"\broll\s*(?:number|no\.?)\b",
            text,
            re.IGNORECASE,
        ))

        if not has_roll_label:
            return []

        academic_id_pattern = re.compile(
            r"(?<![A-Z0-9])"
            r"(?:\d{2,4}[A-Z]{2,4}\d{3,8}|"
            r"[A-Z]{2,4}\d{5,12})"
            r"(?![A-Z0-9])",
            re.IGNORECASE,
        )

        roll_numbers = {
            match.group(0).upper()
            for match in academic_id_pattern.finditer(text)
        }

        return sorted(roll_numbers)

    # --------------------------------------------------
    # REFERENCE NUMBER EXTRACTION
    # --------------------------------------------------

    @classmethod
    def extract_reference_numbers(cls, text: str) -> list[str]:
        references = set()
        lines = [line.strip() for line in text.splitlines()]

        labels = sorted(
            cls.REFERENCE_LABELS, key=len, reverse=True
        )

        for index, line in enumerate(lines):
            for label in labels:

                # Support spaces, dots and OCR-separated labels.
                label_regex = re.escape(label).replace(
                    r"\ ", r"[\s.]+"
                )

                match = re.search(
                    rf"\b{label_regex}\b\.?\s*[:#-]?\s*"
                    r"([A-Z0-9][A-Z0-9./_-]{2,})",
                    line,
                    flags=re.IGNORECASE,
                )

                value = match.group(1) if match else None

                # Handle labels whose values are on the next line.
                if value is None:
                    label_match = re.fullmatch(
                        rf"{label_regex}\.?\s*[:#-]?",
                        line,
                        flags=re.IGNORECASE,
                    )

                    if label_match:
                        for next_index in range(
                            index + 1, min(index + 5, len(lines))
                        ):
                            next_line = lines[next_index]

                            if not next_line:
                                continue

                            next_match = re.fullmatch(
                                r"([A-Z0-9][A-Z0-9./_-]{2,})",
                                next_line,
                                flags=re.IGNORECASE,
                            )

                            if next_match:
                                value = next_match.group(1)

                            break

                if value:
                    value = value.strip(" .,:;")

                    if (
                        value.lower() not in cls.GENERIC_VALUES
                        and re.search(r"\d", value)
                    ):
                        references.add(value.upper())

                    break

        return sorted(references)

    # --------------------------------------------------
    # FLIGHT FARE EXTRACTION
    # --------------------------------------------------

    @classmethod
    def extract_flight_fare_data(
        cls, text: str
    ) -> dict[str, float] | None:

        start = re.search(
            r"\bFare Details\b", text, flags=re.IGNORECASE
        )

        if not start:
            return None

        following_section = re.search(
            r"As per Government guidelines",
            text[start.end():],
            flags=re.IGNORECASE,
        )

        if not following_section:
            return None

        fare_section = text[
            start.end():
            start.end() + following_section.start()
        ]

        number_pattern = re.compile(
            r"(?<![A-Za-z0-9/.-])"
            r"(?:\d{1,3}(?:,\d{3})+|\d+)"
            r"(?:\.\d{1,2})?"
            r"(?![A-Za-z0-9/.-])"
        )

        values = []

        for match in number_pattern.finditer(fare_section):
            try:
                values.append(
                    float(match.group(0).replace(",", ""))
                )
            except ValueError:
                continue

        if len(values) < 5:
            return None

        labels = [
            "Base Fare", "Other Fees and Taxes",
            "Convenience Fee", "Additional Payment",
            "Total Amount Paid",
        ]

        return dict(zip(labels, values[-5:]))

    # --------------------------------------------------
    # AMOUNT EXTRACTION
    # --------------------------------------------------

    @classmethod
    def extract_amounts(
        cls, text: str, document_type: str = "unknown"
    ) -> list[str]:

        if document_type == "travel":
            fare_data = cls.extract_flight_fare_data(text)

            if fare_data:
                return [
                    f"INR {value:,.2f}"
                    for value in fare_data.values()
                ]

        amounts = set()

        for line in text.splitlines():
            if not re.search(
                r"\b(?:grand total|total amount|amount paid|"
                r"net amount|subtotal|total|fare|price|amount|"
                r"charges|salary|gross pay|net pay|balance)\b",
                line,
                flags=re.IGNORECASE,
            ):
                continue

            for match in cls.CURRENCY_PATTERN.finditer(line):
                parsed = cls.parse_currency_number(match.group(1))
                if parsed is None:
                    continue

                prefix = match.group(0)[:-len(match.group(1))].strip()
                if prefix in {"₹", "Rs", "Rs.", "INR"}:
                    prefix = "INR"
                elif prefix == "$" or prefix.upper() == "USD":
                    prefix = "USD"
                elif prefix == "€" or prefix.upper() == "EUR":
                    prefix = "EUR"
                else:
                    prefix = prefix.upper()

                amounts.add(f"{prefix} {parsed:,.2f}")

        return sorted(amounts)

    # --------------------------------------------------
    # FINANCIAL CONSISTENCY ANALYSIS
    # --------------------------------------------------

    @classmethod
    def analyze_financial_consistency(
        cls, text: str, document_type: str
    ) -> dict[str, Any]:

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
                "status": (
                    "consistent" if consistent
                    else "requires_verification"
                ),
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
                "limitation": (
                    "Only values isolated from the fare section were compared; "
                    "this does not establish ticket authenticity."
                ),
            }

        if document_type != "financial":
            return {
                "status": "not_applicable",
                "message": (
                    "Financial arithmetic check is not applicable "
                    "to this document category."
                ),
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

            amounts = [
                cls.parse_currency_number(match.group(1))
                for match in cls.CURRENCY_PATTERN.finditer(line)
            ]
            amounts = [amount for amount in amounts if amount is not None]

            if not amounts:
                continue

            values[label_match.group(1).lower()] = amounts[-1]

        subtotal = values.get("subtotal")
        tax = values.get("tax", values.get("gst"))
        total = values.get(
            "grand total",
            values.get("total amount", values.get("total")),
        )

        if subtotal is None or tax is None or total is None:
            return {
                "status": "insufficient_data",
                "message": (
                    "A labelled subtotal, tax and total were not all found. "
                    "No arithmetic conclusion was made."
                ),
                "components": values,
                "checks": [],
            }

        calculated = round(subtotal + tax, 2)
        difference = round(calculated - total, 2)
        consistent = abs(difference) < 0.01

        return {
            "status": (
                "consistent" if consistent
                else "requires_verification"
            ),
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
            "limitation": (
                "Only the extracted labelled values were compared; "
                "this does not establish document authenticity."
            ),
        }

    # --------------------------------------------------
    # MAIN ANALYSIS PIPELINE
    # --------------------------------------------------

    @classmethod
    def analyze(cls, text: str) -> dict[str, Any]:

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
                    "roll_numbers": [],
                },
                "missing_extraction_fields": [
                    "names", "dates", "amounts",
                    "reference_numbers", "roll_numbers",
                ],
                "financial_analysis": {
                    "status": "insufficient_data",
                    "message": "No readable text was available for analysis.",
                    "checks": [],
                },
                "text_statistics": {
                    "character_count": 0,
                    "word_count": 0,
                },
                "analysis_method": "rule_based_extraction",
                "status": "completed",
                "limitations": [
                    "No readable text was supplied.",
                    "No authenticity or fraud verdict can be made.",
                ],
            }

        classification = cls.classify_document(normalized_text)
        document_type = classification["document_type"]

        names = cls.extract_names(normalized_text)
        dates = cls.extract_dates(normalized_text)
        amounts = cls.extract_amounts(normalized_text, document_type)
        roll_numbers = cls.extract_roll_numbers(normalized_text)
        references = cls.extract_reference_numbers(normalized_text)

        # Preserve roll numbers in reference_numbers for
        # compatibility with existing API consumers.
        all_references = sorted(
            set(references).union(roll_numbers)
        )

        extracted_information = {
            "names": names,
            "dates": dates,
            "amounts": amounts,
            "reference_numbers": all_references,
            "roll_numbers": roll_numbers,
        }

        missing_fields = [
            field
            for field, values in extracted_information.items()
            if not values
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
