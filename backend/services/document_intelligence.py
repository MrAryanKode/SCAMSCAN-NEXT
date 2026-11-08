
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
        # Indian tax and government documents commonly use 06-Jul-2026.
        r"\b\d{1,2}[-\s](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[-\s]\d{4}\b",
        r"\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}\b",
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}\b",
    ]

    DATE_FORMATS = [
        "%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y",
        "%m/%d/%Y", "%d-%m-%y", "%d/%m/%y",
        "%d-%b-%Y", "%d-%B-%Y", "%d %b %Y", "%d %B %Y", "%b %d %Y",
        "%B %d %Y", "%b %d, %Y", "%B %d, %Y",
    ]

    NAME_LABELS = [
        "passenger name", "name of passenger",
        "traveller name", "traveler name",
        "customer name", "patient name",
        "employee name", "student name",
        "candidate name", "applicant name",
        "account holder", "issued to", "verified by", "verified and signed by",
        "signed by", "deponent", "applicant", "client", "provider",
        "customer", "beneficiary", "recipient", "name",
    ]

    REFERENCE_LABELS = [
        "acknowledgement number", "acknowledgment number",
        "e-filing acknowledgement number", "e-filing acknowledgment number",
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

        # Government forms often identify a second person in a verifier/signatory
        # line rather than in another plain "Name" field.
        verifier_pattern = re.compile(
            r"\b(?:and\s+)?(?:verified|signed|attested)\s+by\s+"
            r"([A-Za-z][A-Za-z .'-]{2,60}?)"
            r"(?=\s+(?:having\s+PAN|on\s+|using\s+|through\s+|"
            r"generated\s+through)\b|[,;]|$)",
            re.IGNORECASE,
        )
        for match in verifier_pattern.finditer(text):
            candidate = match.group(1).strip(" \\t:,-.")
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

        # Income-tax acknowledgements may identify a separate verifier.
        # Preserve that person's name as an extracted name as well.
        for index, line in enumerate(lines):
            verifier_match = re.search(
                r"veri(?:f|ﬁ)ed\s+by\s*[:,-]?\s*(.*)$",
                line,
                flags=re.IGNORECASE,
            )
            if not verifier_match:
                continue

            candidate = verifier_match.group(1).strip(" \t:,-.")
            if not candidate:
                for next_line in lines[index + 1:index + 4]:
                    possible = next_line.strip(" \t:,-.")
                    if not possible:
                        continue
                    # OCR can split a date across lines; don't mistake it for a name.
                    if re.search(r"\d", possible):
                        continue
                    candidate = possible
                    break

            candidate = re.split(
                r"\s+(?:having\s+PAN|on|using)\\b",
                candidate,
                maxsplit=1,
                flags=re.IGNORECASE,
            )[0].strip(" \t:,-.")
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

    # ITR acknowledgement labels are matched as complete labels. The row
    # number and value are read from following lines, never treated as money.
    ITR_FINANCIAL_LABELS = [
        ("current_year_business_loss", "Current Year business loss, if any", "additional"),
        ("total_income", "Total Income", "primary"),
        ("book_profit_mat", "Book Profit under MAT, where applicable", "additional"),
        ("adjusted_total_income_amt", "Adjusted Total Income under AMT, where applicable", "additional"),
        ("net_tax_payable", "Net tax payable", "primary"),
        ("interest_and_fee_payable", "Interest and Fee Payable", "primary"),
        ("total_tax_interest_fee_payable", "Total tax, interest and Fee payable", "primary"),
        ("taxes_paid", "Taxes Paid", "primary"),
        ("tax_payable_refundable", "(+) Tax Payable /(-) Refundable", "primary"),
        ("accreted_income_115td", "Accreted Income as per section 115TD", "additional"),
        ("additional_tax_115td", "Additional Tax payable u/s 115TD", "additional"),
        ("interest_115te", "Interest payable u/s 115TE", "additional"),
        ("additional_tax_interest_payable", "Additional Tax and interest payable", "additional"),
        ("tax_and_interest_paid", "Tax and interest paid", "additional"),
        ("tax_payable_refundable_115td", "(+) Tax Payable /(-) Refundable", "additional"),
    ]

    @classmethod
    def extract_itr_financial_rows(cls, text: str) -> list[dict[str, Any]]:
        """Extract labelled ITR figures with row IDs and section provenance.

        Values are preserved as printed. This method does not reconcile or
        silently correct arithmetic inconsistencies in the source document.
        """
        lines = [line.strip() for line in text.splitlines()]
        rows: list[dict[str, Any]] = []
        seen_occurrences: dict[str, int] = {}
        table_section = "Income and tax details"

        # A value must be a complete numeric line. This prevents unrelated
        # numbers in surrounding prose from being picked up.
        value_re = re.compile(r"^\s*(?:\(\s*([+-])\s*\)|([+-]))?\s*"
                              r"(\d[\d,]*(?:\.\d{1,2})?)\s*$")
        row_id_re = re.compile(r"^(?:\d{1,2}[A-Z]?|[A-Z]\d{1,2})$", re.I)

        def parse_value(raw: str, sign: str | None) -> float | None:
            value = cls.parse_currency_number(raw)
            if value is None:
                return None
            return -value if sign == "-" else value

        for index, line in enumerate(lines):
            if re.fullmatch(r"Accreted Income and Tax Detail", line, re.I):
                table_section = "Accreted income and tax detail"
                continue

            for key, label, group in cls.ITR_FINANCIAL_LABELS:
                # Exact label match, optionally followed by a value on same line.
                if not re.match(rf"^{re.escape(label)}(?:\s|$)", line, re.I):
                    continue

                remainder = line[len(label):].strip(" :\t")
                row_number = None
                value = None

                same_line = value_re.fullmatch(remainder) if remainder else None
                if same_line:
                    value = parse_value(same_line.group(3), same_line.group(1) or same_line.group(2))
                else:
                    # Look only a short distance ahead. Skip one explicit row ID.
                    look = [v for v in lines[index + 1:index + 4] if v]
                    if look and row_id_re.fullmatch(look[0]):
                        row_number = look[0]
                        look = look[1:]
                    if look:
                        candidate = value_re.fullmatch(look[0])
                        if candidate:
                            value = parse_value(candidate.group(3), candidate.group(1) or candidate.group(2))

                if value is None:
                    continue

                seen_occurrences[key] = seen_occurrences.get(key, 0) + 1
                occurrence = seen_occurrences[key]
                actual_group = group
                # The second repeated tax-payable row belongs to the
                # accreted-income/115TD table, not the main tax summary.
                if key == "tax_payable_refundable" and occurrence > 1:
                    actual_group = "additional"

                rows.append({
                    "key": key if occurrence == 1 else f"{key}_{occurrence}",
                    "label": label,
                    "value": value,
                    "currency": "INR",
                    "formatted_value": f"INR {value:,.2f}",
                    "row_number": row_number,
                    "section": table_section,
                    "group": actual_group,
                    "is_zero": abs(value) < 0.000001,
                    "source_label": line,
                    "source_line_index": index,
                })
                break

        return rows

    @classmethod
    def extract_amounts(
        cls, text: str, document_type: str = "unknown"
    ) -> list[str]:
        """Return concise, non-zero primary figures for legacy UI consumers."""
        if document_type == "travel":
            fare_data = cls.extract_flight_fare_data(text)
            if fare_data:
                return [f"INR {value:,.2f}" for value in fare_data.values()]

        if document_type == "government" and re.search(
            r"\b(?:income tax return|ITR acknowledgement|acknowledgement number)\b",
            text, re.I
        ):
            rows = cls.extract_itr_financial_rows(text)
            return [
                f"{row['label']}: {row['formatted_value']}"
                for row in rows
                if row["group"] == "primary" and not row["is_zero"]
            ]

        amounts = set()
        for line in text.splitlines():
            if not re.search(
                r"\b(?:grand total|total amount|amount paid|net amount|"
                r"subtotal|total|fare|price|amount|charges|salary|"
                r"gross pay|net pay|balance)\b",
                line, flags=re.IGNORECASE
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

        # Rich, label-aware financial rows for the detailed report UI.
        # Keep the existing "amounts" list for backward compatibility.
        if document_type == "government" and re.search(
            r"\b(?:income tax return|ITR acknowledgement|acknowledgement number)\b",
            normalized_text, re.IGNORECASE
        ):
            financial_rows = cls.extract_itr_financial_rows(normalized_text)
            extracted_information["financial_details"] = {
                "primary": [row for row in financial_rows if row["group"] == "primary"],
                "additional": [row for row in financial_rows if row["group"] == "additional"],
                "all_rows": financial_rows,
                "note": "Values are transcribed from labelled source rows; arithmetic has not been silently corrected.",
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
