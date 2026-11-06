
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

ANNOTATION_FILE = (
    ROOT / "ai_training/dataset/processed/"
    "SCS-INV-0001/verified_annotation.json"
)

SCHEMA_FILE = ROOT / "ai_training/configs/document_schema.json"


def main():
    with ANNOTATION_FILE.open("r", encoding="utf-8") as file:
        annotation = json.load(file)

    with SCHEMA_FILE.open("r", encoding="utf-8") as file:
        schema = json.load(file)

    allowed_types = schema["document_types"]
    allowed_labels = set(schema["entity_labels"])

    errors = []

    if annotation["document_type"] not in allowed_types:
        errors.append("Unsupported document type")

    for page in annotation["pages"]:
        words = page["words"]
        boxes = page["boxes"]
        tags = page["ner_tags"]

        if not (len(words) == len(boxes) == len(tags)):
            errors.append("Word, box and tag counts do not match")
            continue

        for index, (word, box, tag) in enumerate(
            zip(words, boxes, tags)
        ):
            if not isinstance(word, str) or not word.strip():
                errors.append(f"Invalid word at token {index}")

            if not isinstance(box, list) or len(box) != 4:
                errors.append(f"Invalid bounding box at token {index}")
                continue

            if not all(
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and 0 <= value <= 1000
                for value in box
            ):
                errors.append(f"Invalid coordinates at token {index}")

            if tag != "O":
                if not isinstance(tag, str) or "-" not in tag:
                    errors.append(f"Invalid BIO tag at token {index}")
                    continue

                prefix, label = tag.split("-", 1)

                if prefix not in ("B", "I"):
                    errors.append(f"Invalid BIO prefix at token {index}")
                elif label not in allowed_labels:
                    errors.append(f"Unknown entity label at token {index}")

    print("=" * 55)
    print("VERIFIED ANNOTATION VALIDATION")
    print("=" * 55)

    if errors:
        for error in errors:
            print("[FAIL]", error)

        print(f"\nValidation errors: {len(errors)}")
    else:
        print("[PASS] Document category")
        print("[PASS] Words and bounding boxes")
        print("[PASS] BIO entity labels")
        print("[PASS] Coordinate ranges")
        print("\n[SUCCESS] Structural validation passed!")


if __name__ == "__main__":
    main()
