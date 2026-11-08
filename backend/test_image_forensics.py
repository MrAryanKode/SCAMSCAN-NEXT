
from pathlib import Path
from services.image_forensics import ImageForensics

# Change this filename to test another image.
IMAGE_PATH = Path("test.jpg")

def main():
    if not IMAGE_PATH.is_file():
        print(f"Image not found: {IMAGE_PATH}")
        return

    forensic = ImageForensics()

    # Read the selected image.
    image_bytes = IMAGE_PATH.read_bytes()

    # Analyze using the existing forensic service.
    result = forensic.analyze(
        image_bytes,
        filename=IMAGE_PATH.name
    )

    print("\n========== SCAMSCAN FORENSIC TEST ==========")
    print("STATUS:", result.get("status"))

    metadata = result.get("metadata") or {}
    print("FORMAT:", metadata.get("format"))

    # JPEG ELA analysis
    ela = result.get("ela_analysis") or {}
    print("JPEG ELA AVAILABLE:", ela.get("available", False))

    if ela.get("available"):
        print("ELA MEAN DIFFERENCE:", ela.get("mean_difference"))
        print("ELA MAX DIFFERENCE:", ela.get("max_difference"))

    # PNG residual analysis
    png = result.get("png_analysis") or {}
    print("PNG ANALYSIS AVAILABLE:", png.get("available", False))

    if png.get("available"):
        print("PNG METHOD:", png.get("method"))

    print("PNG METADATA:", result.get("png_metadata"))
    print("SUMMARY:", result.get("summary"))
    print("============================================\n")


if __name__ == "__main__":
    main()
