
import json
from pathlib import Path

# --------------------------------------------------
# 1. Project paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

CONFIG_DIR = PROJECT_ROOT / "ai_training" / "configs"
ANNOTATION_DIR = PROJECT_ROOT / "ai_training" / "dataset" / "annotations"
OUTPUT_DIR = PROJECT_ROOT / "ai_training" / "dataset" / "processed"

SCHEMA_FILE = CONFIG_DIR / "document_schema.json"

OUTPUT_FILE = OUTPUT_DIR / "layoutlmv3_dataset.jsonl"
LABEL_MAP_FILE = CONFIG_DIR / "label_map.json"


# --------------------------------------------------
# 2. JSON utilities
# --------------------------------------------------

def load_json(path):
    """Read JSON data from a file."""
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_json(data, path):
    """Save data as formatted JSON."""
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)


# --------------------------------------------------
# 3. Generate entity label mappings
# --------------------------------------------------

def create_label_mapping(entity_labels):
    """Convert BIO labels into numerical IDs."""

    labels = ["O"]

    for entity in entity_labels:
        labels.append(f"B-{entity}")
        labels.append(f"I-{entity}")

    label_to_id = {
        label: index
        for index, label in enumerate(labels)
    }

    id_to_label = {
        str(index): label
        for label, index in label_to_id.items()
    }

    return label_to_id, id_to_label


# --------------------------------------------------
# 4. Process one annotated document
# --------------------------------------------------

def process_annotation(annotation, label_to_id, document_types):
    """Convert an annotation into model-ready page records."""

    document_id = annotation["document_id"]
    document_type = annotation["document_type"]

    if document_type not in document_types:
        raise ValueError(
            f"Unsupported document type: {document_type}"
        )

    processed_pages = []

    for page in annotation["pages"]:
        words = page["words"]
        boxes = page["boxes"]
        ner_tags = page["ner_tags"]

        # Ensure all token information matches
        if not (len(words) == len(boxes) == len(ner_tags)):
            raise ValueError(
                f"Token count mismatch in {document_id}"
            )

        # Convert text labels into numerical IDs
        ner_label_ids = []

        for tag in ner_tags:
            if tag not in label_to_id:
                raise ValueError(
                    f"Unknown entity label: {tag}"
                )

            ner_label_ids.append(label_to_id[tag])

        # Keep the image path relative to the project
        image_path = page["image_path"]

        processed_pages.append({
            "document_id": document_id,
            "document_type": document_type,
            "page_number": page["page_number"],
            "image_path": image_path,
            "words": words,
            "boxes": boxes,
            "ner_tags": ner_tags,
            "ner_label_ids": ner_label_ids
        })

    return processed_pages


# --------------------------------------------------
# 5. Main dataset preparation pipeline
# --------------------------------------------------

def main():
    print("=" * 60)
    print("       SCAMSCAN 2.0 AI DATASET PREPARATION")
    print("=" * 60)

    if not SCHEMA_FILE.exists():
        print("[ERROR] document_schema.json not found.")
        return

    if not ANNOTATION_DIR.exists():
        print("[ERROR] Annotation directory not found.")
        return

    schema = load_json(SCHEMA_FILE)

    # Create output directory if required
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Generate label mappings
    label_to_id, id_to_label = create_label_mapping(
        schema["entity_labels"]
    )

    save_json({
        "label_to_id": label_to_id,
        "id_to_label": id_to_label
    }, LABEL_MAP_FILE)

    print(f"[INFO] Entity labels: {len(label_to_id)}")

    # Find annotation files
    annotation_files = sorted(
        ANNOTATION_DIR.glob("*.json")
    )

    if not annotation_files:
        print("[WARNING] No annotation files found.")
        return

    all_pages = []
    successful_files = 0
    failed_files = 0

    for file_path in annotation_files:
        try:
            annotation = load_json(file_path)

            pages = process_annotation(
                annotation,
                label_to_id,
                schema["document_types"]
            )

            all_pages.extend(pages)
            successful_files += 1

            print(
                f"[PASS] {file_path.name}: "
                f"{len(pages)} page(s)"
            )

        except Exception as error:
            failed_files += 1
            print(f"[FAIL] {file_path.name}: {error}")

    # Save one JSON record per page
    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        for page in all_pages:
            file.write(
                json.dumps(page, ensure_ascii=False) + "\n"
            )

    # Final summary
    print("\n" + "=" * 60)
    print("DATASET PREPARATION SUMMARY")
    print("=" * 60)

    print(f"Annotation files : {len(annotation_files)}")
    print(f"Successful files : {successful_files}")
    print(f"Failed files     : {failed_files}")
    print(f"Processed pages  : {len(all_pages)}")
    print(f"Entity labels    : {len(label_to_id)}")

    print(f"\nDataset output: {OUTPUT_FILE}")
    print(f"Label mapping : {LABEL_MAP_FILE}")

    if failed_files == 0 and all_pages:
        print("\nDATASET PREPARATION SUCCESSFUL!")
    else:
        print("\nPLEASE CHECK THE ERRORS ABOVE.")


if __name__ == "__main__":
    main()
