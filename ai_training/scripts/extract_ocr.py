
import json
from pathlib import Path

import pytesseract
from PIL import Image


# -----------------------------------------
# 1. Project configuration
# -----------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

IMAGE_PATH = (
    PROJECT_ROOT
    / "ai_training"
    / "dataset"
    / "processed"
    / "SCS-INV-0001"
    / "page_1.png"
)

OUTPUT_DIR = IMAGE_PATH.parent
OUTPUT_FILE = OUTPUT_DIR / "ocr_output.json"

TESSERACT_PATH = Path(
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

pytesseract.pytesseract.tesseract_cmd = str(
    TESSERACT_PATH
)


# -----------------------------------------
# 2. Extract OCR information
# -----------------------------------------

def extract_ocr(image_path):
    image = Image.open(image_path).convert("RGB")

    width, height = image.size

    data = pytesseract.image_to_data(
        image,
        output_type=pytesseract.Output.DICT,
        config="--oem 3 --psm 6"
    )

    words = []
    boxes = []
    confidences = []

    for index, text in enumerate(data["text"]):
        text = text.strip()

        if not text:
            continue

        confidence = float(data["conf"][index])

        if confidence < 0:
            continue

        x = data["left"][index]
        y = data["top"][index]
        w = data["width"][index]
        h = data["height"][index]

        # Normalize coordinates to 0-1000
        box = [
            round(x * 1000 / width),
            round(y * 1000 / height),
            round((x + w) * 1000 / width),
            round((y + h) * 1000 / height)
        ]

        words.append(text)
        boxes.append(box)
        confidences.append(round(confidence, 2))

    return {
        "image_width": width,
        "image_height": height,
        "words": words,
        "boxes": boxes,
        "confidences": confidences
    }


# -----------------------------------------
# 3. Main execution
# -----------------------------------------

def main():
    print("=" * 55)
    print("SCAMSCAN OCR EXTRACTION")
    print("=" * 55)

    if not IMAGE_PATH.exists():
        print("[ERROR] Invoice image not found.")
        return

    if not TESSERACT_PATH.exists():
        print("[ERROR] Tesseract executable not found.")
        return

    result = extract_ocr(IMAGE_PATH)

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            result,
            file,
            indent=2,
            ensure_ascii=False
        )

    print(f"Image dimensions: {result['image_width']} x {result['image_height']}")
    print(f"Extracted words: {len(result['words'])}")

    print("\nEXTRACTED TEXT:")

    print(" ".join(result["words"]))

    print("\n" + "=" * 55)
    print("[SUCCESS] OCR extraction completed!")
    print(f"Output: {OUTPUT_FILE}")
    print("=" * 55)


if __name__ == "__main__":
    main()
