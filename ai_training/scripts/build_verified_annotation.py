
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DOC_DIR = ROOT / "ai_training/dataset/processed/SCS-INV-0001"
OCR_FILE = DOC_DIR / "ocr_output.json"
OUTPUT_FILE = DOC_DIR / "verified_annotation.json"


def normalize(word):
    return re.sub(r"^[^\w₹]+|[^\w₹]+$", "", word).casefold()


def main():
    if not OCR_FILE.exists():
        raise FileNotFoundError(f"OCR file not found: {OCR_FILE}")

    with OCR_FILE.open("r", encoding="utf-8") as file:
        ocr = json.load(file)

    words = ocr["words"]
    boxes = ocr["boxes"]

    if len(words) != len(boxes):
        raise ValueError("OCR words and bounding boxes do not match.")

    normalized = [normalize(word) for word in words]
    tags = ["O"] * len(words)

    # These phrases are manually reviewed entity spans.
    entities = {
        "PERSON_NAME": ["Rahul", "Sharma"],
        "DOCUMENT_NUMBER": ["INV-2026-001"],
        "DATE": ["06/11/2026"],
        "ADDRESS": ["Surat", "Gujarat", "India"]
    }

    # Financial values are explicitly labelled.
    amounts = ["10000", "1000", "11000", "1980", "12980"]

    def assign_span(tokens, label):
        target = [normalize(token) for token in tokens]
        size = len(target)

        for start in range(len(normalized) - size + 1):
            if normalized[start:start + size] == target:
                for offset in range(size):
                    prefix = "B" if offset == 0 else "I"
                    tags[start + offset] = f"{prefix}-{label}"
                return True

        print(f"[REVIEW REQUIRED] Not found: {' '.join(tokens)}")
        return False

    for label, phrase in entities.items():
        assign_span(phrase, label)

    for amount in amounts:
        assign_span([amount], "AMOUNT")

    # INR is a currency entity wherever OCR recognizes it.
    for index, word in enumerate(normalized):
        if word == "inr":
            tags[index] = "B-CURRENCY"

    annotation = {
        "document_id": "SCS-INV-0001",
        "document_type": "financial",
        "source": "synthetic",
        "annotation_method": "human_reviewed_entity_spans_with_ocr_boxes",
        "pages": [
            {
                "page_number": 1,
                "image_path": "processed/SCS-INV-0001/page_1.png",
                "words": words,
                "boxes": boxes,
                "ner_tags": tags
            }
        ]
    }

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(annotation, file, indent=2, ensure_ascii=False)

    print("=" * 55)
    print("SCAMSCAN VERIFIED ANNOTATION BUILDER")
    print("=" * 55)
    print(f"OCR tokens: {len(words)}")
    print(f"Bounding boxes: {len(boxes)}")
    print(f"Entity-labelled tokens: {sum(tag != 'O' for tag in tags)}")
    print(f"Output: {OUTPUT_FILE}")
    print("\n[SUCCESS] Annotation generated!")
    print("[INFO] Review entity labels before model training.")


if __name__ == "__main__":
    main()
