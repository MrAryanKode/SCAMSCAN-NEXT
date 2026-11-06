
import json
from pathlib import Path

import torch
from PIL import Image
from transformers import (
    LayoutLMv3Processor,
    LayoutLMv3ForTokenClassification
)

ROOT = Path(__file__).resolve().parents[2]

DOC_DIR = ROOT / "ai_training/dataset/processed/SCS-INV-0001"
CONFIG_DIR = ROOT / "ai_training/configs"

IMAGE_FILE = DOC_DIR / "page_1.png"
ANNOTATION_FILE = DOC_DIR / "verified_annotation.json"
LABEL_FILE = CONFIG_DIR / "label_map.json"

MODEL_NAME = "microsoft/layoutlmv3-base"


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def main():
    print("=" * 60)
    print("SCAMSCAN LAYOUTLMv3 FORWARD PASS")
    print("=" * 60)

    annotation = load_json(ANNOTATION_FILE)
    label_data = load_json(LABEL_FILE)

    page = annotation["pages"][0]
    id_to_label = label_data["id_to_label"]

    image = Image.open(IMAGE_FILE).convert("RGB")

    device = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )

    print(f"\n[INFO] Device: {device}")

    processor = LayoutLMv3Processor.from_pretrained(
        MODEL_NAME,
        apply_ocr=False
    )

    model = LayoutLMv3ForTokenClassification.from_pretrained(
        MODEL_NAME,
        num_labels=len(label_data["label_to_id"]),
        id2label={
            int(key): value
            for key, value in id_to_label.items()
        },
        ignore_mismatched_sizes=True
    )

    model.to(device)
    model.eval()

    inputs = processor(
        images=image,
        text=page["words"],
        boxes=page["boxes"],
        return_tensors="pt",
        truncation=True,
        padding="max_length",
        max_length=512
    )

    inputs = {
        key: value.to(device)
        for key, value in inputs.items()
    }

    print("[INFO] Running model inference...")

    with torch.inference_mode():
        outputs = model(**inputs)

    predictions = torch.argmax(
        outputs.logits,
        dim=-1
    )

    print("\nMODEL OUTPUT")
    print(f"Logits shape: {tuple(outputs.logits.shape)}")
    print(f"Predictions shape: {tuple(predictions.shape)}")

    print("\nFIRST 20 OCR TOKEN PREDICTIONS")

    for index, word in enumerate(page["words"][:20]):
        label_id = predictions[0][index].item()
        label = id_to_label[str(label_id)]

        print(f"{word:22} -> {label}")

    print("\n[SUCCESS] LayoutLMv3 forward pass completed!")
    print("[INFO] These predictions are from an untrained custom head.")


if __name__ == "__main__":
    main()
