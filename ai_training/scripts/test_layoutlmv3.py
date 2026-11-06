
import torch
from transformers import (
    LayoutLMv3Config,
    LayoutLMv3ForTokenClassification
)

# -----------------------------------------
# 1. Model configuration
# -----------------------------------------

MODEL_NAME = "microsoft/layoutlmv3-base"

PROJECT_ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
LABEL_MAP_FILE = (
    PROJECT_ROOT / "ai_training" / "configs" / "label_map.json"
)


def load_label_mapping():
    """Load the entity labels created earlier."""
    import json

    with LABEL_MAP_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return data["label_to_id"], data["id_to_label"]


# -----------------------------------------
# 2. Check GPU availability
# -----------------------------------------

def get_device():
    if torch.cuda.is_available():
        device = torch.device("cuda")
        print("[SUCCESS] NVIDIA GPU detected")
        print(f"[GPU] {torch.cuda.get_device_name(0)}")
    else:
        device = torch.device("cpu")
        print("[WARNING] GPU unavailable. Using CPU.")

    return device


# -----------------------------------------
# 3. Initialize LayoutLMv3
# -----------------------------------------

def initialize_model(num_labels, id_to_label):
    print("\n[INFO] Initializing LayoutLMv3...")

    config = LayoutLMv3Config.from_pretrained(MODEL_NAME)

    config.num_labels = num_labels
    config.id2label = {
        int(index): label
        for index, label in id_to_label.items()
    }
    config.label2id = {
        label: index
        for index, label in config.id2label.items()
    }

    model = LayoutLMv3ForTokenClassification.from_pretrained(
        MODEL_NAME,
        config=config,
        ignore_mismatched_sizes=True
    )

    return model


# -----------------------------------------
# 4. Main verification
# -----------------------------------------

def main():
    print("=" * 60)
    print("       SCAMSCAN 2.0 - LAYOUTLMv3")
    print("=" * 60)

    if not LABEL_MAP_FILE.exists():
        print("[ERROR] label_map.json not found.")
        return

    label_to_id, id_to_label = load_label_mapping()

    device = get_device()

    model = initialize_model(
        num_labels=len(label_to_id),
        id_to_label=id_to_label
    )

    model.to(device)
    model.eval()

    total_parameters = sum(
        parameter.numel()
        for parameter in model.parameters()
    )

    trainable_parameters = sum(
        parameter.numel()
        for parameter in model.parameters()
        if parameter.requires_grad
    )

    print("\n" + "=" * 60)
    print("MODEL INFORMATION")
    print("=" * 60)

    print(f"Model          : {MODEL_NAME}")
    print(f"Device         : {device}")
    print(f"Entity labels  : {len(label_to_id)}")
    print(f"Total params   : {total_parameters:,}")
    print(f"Trainable      : {trainable_parameters:,}")

    print("\n[PASS] LayoutLMv3 initialized successfully!")
    print("[INFO] Model is ready for the next integration step.")

    if device.type == "cuda":
        print(
            f"[GPU MEMORY] "
            f"{torch.cuda.memory_allocated() / 1024**2:.2f} MB allocated"
        )


if __name__ == "__main__":
    main()
