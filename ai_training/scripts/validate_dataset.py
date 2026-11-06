
import json
from pathlib import Path

# Find the project and dataset folders
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = PROJECT_ROOT / "ai_training" / "configs" / "document_schema.json"
ANNOTATION_DIR = PROJECT_ROOT / "ai_training" / "dataset" / "annotations"


def load_json(file_path):
    """Load a JSON file safely."""
    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def validate_annotation(annotation, schema, file_name):
    """Check one annotation file for common errors."""
    errors = []

    # Check document category
    document_type = annotation.get("document_type")
    allowed_types = schema["document_types"]

    if document_type not in allowed_types:
        errors.append(f"Invalid document type: {document_type}")

    # Check pages
    pages = annotation.get("pages", [])

    if not pages:
        errors.append("No pages found in annotation")

    allowed_labels = set(schema["entity_labels"])
    minimum = schema["bounding_box"]["minimum"]
    maximum = schema["bounding_box"]["maximum"]

    for page_number, page in enumerate(pages, start=1):
        words = page.get("words", [])
        boxes = page.get("boxes", [])
        tags = page.get("ner_tags", [])

        # All three lists must have equal lengths
        if not (len(words) == len(boxes) == len(tags)):
            errors.append(
                f"Page {page_number}: words, boxes and tags "
                "must have equal lengths"
            )
            continue

        # Validate every word, bounding box and entity tag
        for index, (word, box, tag) in enumerate(
            zip(words, boxes, tags)
        ):
            if not isinstance(word, str) or not word.strip():
                errors.append(
                    f"Page {page_number}, token {index}: invalid word"
                )

            if not isinstance(box, list) or len(box) != 4:
                errors.append(
                    f"Page {page_number}, token {index}: invalid box format"
                )
                continue

            if not all(
                isinstance(value, (int, float)) and
                not isinstance(value, bool) and
                minimum <= value <= maximum
                for value in box
            ):
                errors.append(
                    f"Page {page_number}, token {index}: "
                    "box coordinates must be between 0 and 1000"
                )
            elif box[0] > box[2] or box[1] > box[3]:
                errors.append(
                    f"Page {page_number}, token {index}: "
                    "invalid box coordinate order"
                )

            # Validate BIO entity tags
            if tag == "O":
                continue

            if not isinstance(tag, str) or "-" not in tag:
                errors.append(
                    f"Page {page_number}, token {index}: invalid tag {tag}"
                )
                continue

            prefix, label = tag.split("-", 1)

            if prefix not in ("B", "I"):
                errors.append(
                    f"Page {page_number}, token {index}: "
                    f"invalid BIO prefix {prefix}"
                )
            elif label not in allowed_labels:
                errors.append(
                    f"Page {page_number}, token {index}: "
                    f"unknown entity label {label}"
                )

    if errors:
        print(f"\n[FAIL] {file_name}")
        for error in errors:
            print(f"  - {error}")
        return False

    print(f"[PASS] {file_name}")
    return True


def main():
    print("=" * 55)
    print("       SCAMSCAN 2.0 DATASET VALIDATOR")
    print("=" * 55)

    # Check required files and folders
    if not CONFIG_FILE.exists():
        print("[ERROR] document_schema.json not found")
        return

    if not ANNOTATION_DIR.exists():
        print("[ERROR] Annotation directory not found")
        return

    schema = load_json(CONFIG_FILE)
    annotation_files = list(ANNOTATION_DIR.glob("*.json"))

    if not annotation_files:
        print("[WARNING] No annotation JSON files found")
        return

    passed = 0
    failed = 0

    for file_path in annotation_files:
        try:
            annotation = load_json(file_path)

            if validate_annotation(
                annotation, schema, file_path.name
            ):
                passed += 1
            else:
                failed += 1

        except json.JSONDecodeError as error:
            print(f"\n[FAIL] {file_path.name}: Invalid JSON")
            print(f"  - {error}")
            failed += 1

        except Exception as error:
            print(f"\n[ERROR] {file_path.name}: {error}")
            failed += 1

    print("\n" + "=" * 55)
    print(f"Total files : {passed + failed}")
    print(f"Passed      : {passed}")
    print(f"Failed      : {failed}")
    print("=" * 55)

    if failed == 0:
        print("DATASET VALIDATION SUCCESSFUL!")
    else:
        print("PLEASE FIX THE ERRORS BEFORE TRAINING.")


if __name__ == "__main__":
    main()
