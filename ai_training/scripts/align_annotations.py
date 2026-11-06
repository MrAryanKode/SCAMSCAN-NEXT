
import json
import re
from pathlib import Path
from difflib import SequenceMatcher


# --------------------------------------------------
# 1. Project paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DOCUMENT_DIR = (
    PROJECT_ROOT
    / "ai_training"
    / "dataset"
    / "processed"
    / "SCS-INV-0001"
)

ANNOTATION_FILE = (
    PROJECT_ROOT
    / "ai_training"
    / "dataset"
    / "annotations"
    / "sample_invoice_annotation.json"
)

OCR_FILE = DOCUMENT_DIR / "ocr_output.json"

OUTPUT_FILE = DOCUMENT_DIR / "aligned_annotation.json"


# --------------------------------------------------
# 2. Load JSON files
# --------------------------------------------------

def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_json(data, path):
    with path.open("w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False
        )


# --------------------------------------------------
# 3. Normalize words before matching
# --------------------------------------------------

def normalize_word(word):
    """Normalize text for case-insensitive matching."""

    word = str(word).strip().casefold()

    # Remove surrounding punctuation, preserve internal symbols
    word = re.sub(r"^[^\w₹]+|[^\w₹]+$", "", word)

    return word


# --------------------------------------------------
# 4. Match OCR tokens with manual annotations
# --------------------------------------------------

def align_tokens(ocr_words, annotation_words, annotation_tags):

    ocr_normalized = [
        normalize_word(word)
        for word in ocr_words
    ]

    annotation_normalized = [
        normalize_word(word)
        for word in annotation_words
    ]

    # Every OCR word starts with the default O label
    aligned_tags = ["O"] * len(ocr_words)

    matcher = SequenceMatcher(
        None,
        ocr_normalized,
        annotation_normalized,
        autojunk=False
    )

    matched = []
    unmatched_ocr = []
    unmatched_annotations = []

    matched_ocr_indices = set()
    matched_annotation_indices = set()

    for operation, i1, i2, j1, j2 in matcher.get_opcodes():

        if operation == "equal":
            for ocr_index, annotation_index in zip(
                range(i1, i2),
                range(j1, j2)
            ):
                aligned_tags[ocr_index] = annotation_tags[
                    annotation_index
                ]

                matched_ocr_indices.add(ocr_index)
                matched_annotation_indices.add(annotation_index)

                matched.append({
                    "ocr_word": ocr_words[ocr_index],
                    "annotation_word": annotation_words[
                        annotation_index
                    ],
                    "label": annotation_tags[annotation_index]
                })

        else:
            # Record OCR words without manual labels
            for index in range(i1, i2):
                unmatched_ocr.append(ocr_words[index])

            # Record manual annotation words not found by OCR
            for index in range(j1, j2):
                unmatched_annotations.append(
                    annotation_words[index]
                )

    return {
        "ner_tags": aligned_tags,
        "matched_tokens": matched,
        "unmatched_ocr_tokens": unmatched_ocr,
        "unmatched_annotation_tokens": unmatched_annotations
    }


# --------------------------------------------------
# 5. Main alignment pipeline
# --------------------------------------------------

def main():

    print("=" * 60)
    print("SCAMSCAN OCR-ANNOTATION ALIGNMENT")
    print("=" * 60)

    # Check required files
    for path in [OCR_FILE, ANNOTATION_FILE]:

        if not path.exists():
            print(f"[ERROR] File not found: {path}")
            return

    ocr_data = load_json(OCR_FILE)
    annotation_data = load_json(ANNOTATION_FILE)

    # Use the first annotated page for this sample
    annotation_page = annotation_data["pages"][0]

    ocr_words = ocr_data["words"]
    annotation_words = annotation_page["words"]
    annotation_tags = annotation_page["ner_tags"]

    if not (
        len(annotation_words) == len(annotation_tags)
    ):
        print("[ERROR] Annotation word/tag count mismatch.")
        return

    # Match OCR words with manually verified annotations
    result = align_tokens(
        ocr_words,
        annotation_words,
        annotation_tags
    )

    # Prepare aligned dataset record
    aligned_data = {
        "document_id": annotation_data["document_id"],
        "document_type": annotation_data["document_type"],
        "source": annotation_data["source"],
        "page_number": annotation_page["page_number"],
        "image_path": annotation_page["image_path"],
        "words": ocr_words,
        "boxes": ocr_data["boxes"],
        "confidences": ocr_data["confidences"],
        "ner_tags": result["ner_tags"],
        "alignment_report": {
            "matched_count": len(result["matched_tokens"]),
            "unmatched_ocr_count": len(
                result["unmatched_ocr_tokens"]
            ),
            "unmatched_annotation_count": len(
                result["unmatched_annotation_tokens"]
            ),
            "matched_tokens": result["matched_tokens"],
            "unmatched_ocr_tokens": result[
                "unmatched_ocr_tokens"
            ],
            "unmatched_annotation_tokens": result[
                "unmatched_annotation_tokens"
            ]
        }
    }

    # Save output
    save_json(aligned_data, OUTPUT_FILE)

    # Print report
    print(f"\nOCR words: {len(ocr_words)}")
    print(f"Manual annotation words: {len(annotation_words)}")

    print(
        f"Matched tokens: "
        f"{len(result['matched_tokens'])}"
    )

    print(
        f"Unmatched OCR tokens: "
        f"{len(result['unmatched_ocr_tokens'])}"
    )

    print(
        f"Unmatched annotation tokens: "
        f"{len(result['unmatched_annotation_tokens'])}"
    )

    print("\nMATCHED ENTITY TOKENS:")

    for item in result["matched_tokens"]:
        print(
            f"{item['ocr_word']:20} -> {item['label']}"
        )

    print("\nOUTPUT:")
    print(OUTPUT_FILE)

    print("\n[SUCCESS] Alignment completed!")


if __name__ == "__main__":
    main()
