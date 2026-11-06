
import json
from pathlib import Path

import torch
from PIL import Image
from transformers import LayoutLMv3Processor


# -----------------------------------------
# 1. Project paths
# -----------------------------------------

ROOT = Path(__file__).resolve().parents[2]

DOC_DIR = ROOT / "ai_training/dataset/processed/SCS-INV-0001"

IMAGE_FILE = DOC_DIR / "page_1.png"
ANNOTATION_FILE = DOC_DIR / "verified_annotation.json"

MODEL_NAME = "microsoft/layoutlmv3-base"


# -----------------------------------------
# 2. Load annotation and image
# -----------------------------------------

def load_data():
    with ANNOTATION_FILE.open("r", encoding="utf-8") as file:
        annotation = json.load(file)

    page = annotation["pages"][0]

    image = Image.open(IMAGE_FILE).convert("RGB")

    return image, page


# -----------------------------------------
# 3. Initialize processor
# -----------------------------------------

def initialize_processor():
    print("[INFO] Loading LayoutLMv3 processor...")

    processor = LayoutLMv3Processor.from_pretrained(
        MODEL_NAME,
        apply_ocr=False
    )

    return processor


# -----------------------------------------
# 4. Process document
# -----------------------------------------

def process_document(processor, image, page):

    encoded = processor(
        images=image,
        text=page["words"],
        boxes=page["boxes"],
        return_tensors="pt",
        truncation=True,
        padding="max_length",
        max_length=512
    )

    return encoded


# -----------------------------------------
# 5. Main execution
# -----------------------------------------

def main():

    print("=" * 60)
    print("SCAMSCAN LAYOUTLMv3 PROCESSOR TEST")
    print("=" * 60)

    if not IMAGE_FILE.exists() or not ANNOTATION_FILE.exists():
        raise FileNotFoundError("Image or annotation file missing.")

    image, page = load_data()

    processor = initialize_processor()

    encoded = process_document(
        processor,
        image,
        page
    )

    print("\n[PASS] Document image loaded")
    print("[PASS] OCR words loaded")
    print("[PASS] Bounding boxes loaded")

    print("\nMODEL INPUT INFORMATION")

    for key, value in encoded.items():
        print(f"{key}: {tuple(value.shape)}")

    if "pixel_values" in encoded:
        print(
            "\nImage tensor:",
            tuple(encoded["pixel_values"].shape)
        )

    if "input_ids" in encoded:
        print(
            "Token count:",
            encoded["input_ids"].shape[1]
        )

    print("\n[SUCCESS] LayoutLMv3 processor completed!")


if __name__ == "__main__":
    main()
