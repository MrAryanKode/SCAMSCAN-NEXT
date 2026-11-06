
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

# -----------------------------------------
# 1. Output configuration
# -----------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

OUTPUT_DIR = (
    PROJECT_ROOT
    / "ai_training"
    / "dataset"
    / "processed"
    / "SCS-INV-0001"
)

OUTPUT_FILE = OUTPUT_DIR / "page_1.png"

# A4-like document dimensions
WIDTH = 1240
HEIGHT = 1754

# -----------------------------------------
# 2. Create document canvas
# -----------------------------------------

image = Image.new(
    "RGB",
    (WIDTH, HEIGHT),
    color="white"
)

draw = ImageDraw.Draw(image)


# -----------------------------------------
# 3. Load Windows fonts
# -----------------------------------------

FONT_DIR = Path("C:/Windows/Fonts")


def load_font(filename, size):
    font_path = FONT_DIR / filename

    if font_path.exists():
        return ImageFont.truetype(str(font_path), size)

    return ImageFont.load_default()


title_font = load_font("arialbd.ttf", 54)
heading_font = load_font("arialbd.ttf", 32)
normal_font = load_font("arial.ttf", 25)
small_font = load_font("arial.ttf", 21)


# -----------------------------------------
# 4. Draw company information
# -----------------------------------------

draw.text(
    (90, 90),
    "ACME TECHNOLOGIES",
    fill="#17365D",
    font=title_font
)

draw.text(
    (90, 165),
    "Digital Solutions and Services",
    fill="#555555",
    font=normal_font
)

draw.text(
    (90, 210),
    "Surat, Gujarat, India",
    fill="#555555",
    font=normal_font
)

draw.line(
    (90, 280, 1150, 280),
    fill="#17365D",
    width=4
)


# -----------------------------------------
# 5. Invoice heading and details
# -----------------------------------------

draw.text(
    (90, 330),
    "TAX INVOICE",
    fill="#17365D",
    font=heading_font
)

draw.text(
    (90, 420),
    "Invoice Number: INV-2026-001",
    fill="black",
    font=normal_font
)

draw.text(
    (90, 475),
    "Date: 06/11/2026",
    fill="black",
    font=normal_font
)

draw.text(
    (90, 530),
    "Customer: Rahul Sharma",
    fill="black",
    font=normal_font
)


# -----------------------------------------
# 6. Product table
# -----------------------------------------

table_top = 640

draw.rectangle(
    (90, table_top, 1150, table_top + 65),
    fill="#17365D"
)

draw.text(
    (115, table_top + 15),
    "Description",
    fill="white",
    font=normal_font
)

draw.text(
    (650, table_top + 15),
    "Quantity",
    fill="white",
    font=normal_font
)

draw.text(
    (900, table_top + 15),
    "Amount",
    fill="white",
    font=normal_font
)

rows = [
    ("Software Development", "1", "10000"),
    ("Technical Support", "1", "1000")
]

row_y = table_top + 65

for description, quantity, amount in rows:
    draw.rectangle(
        (90, row_y, 1150, row_y + 75),
        outline="#CCCCCC",
        width=2
    )

    draw.text(
        (115, row_y + 20),
        description,
        fill="black",
        font=normal_font
    )

    draw.text(
        (690, row_y + 20),
        quantity,
        fill="black",
        font=normal_font
    )

    draw.text(
        (900, row_y + 20),
        amount,
        fill="black",
        font=normal_font
    )

    row_y += 75


# -----------------------------------------
# 7. Financial details
# -----------------------------------------

financial_y = 1050

financial_lines = [
    "Subtotal: INR 11000",
    "GST (18%): INR 1980",
    "Total Amount: INR 12980"
]

for index, line in enumerate(financial_lines):
    font = heading_font if index == 2 else normal_font

    draw.text(
        (650, financial_y),
        line,
        fill="#17365D" if index == 2 else "black",
        font=font
    )

    financial_y += 65


# -----------------------------------------
# 8. Footer and disclaimer
# -----------------------------------------

draw.line(
    (90, 1450, 1150, 1450),
    fill="#CCCCCC",
    width=2
)

draw.text(
    (90, 1490),
    "This is a computer-generated sample invoice.",
    fill="#555555",
    font=small_font
)

draw.text(
    (90, 1535),
    "For ScamScan AI research and testing only.",
    fill="#555555",
    font=small_font
)


# -----------------------------------------
# 9. Save image
# -----------------------------------------

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

image.save(
    OUTPUT_FILE,
    format="PNG"
)

print("=" * 55)
print("SCAMSCAN - SAMPLE INVOICE GENERATOR")
print("=" * 55)

print(f"Image dimensions: {WIDTH} x {HEIGHT}")
print(f"Image format: PNG")
print(f"Output: {OUTPUT_FILE}")

print("\n[SUCCESS] Synthetic invoice generated!")
