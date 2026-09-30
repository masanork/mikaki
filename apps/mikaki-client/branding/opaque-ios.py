"""Remove the icon generator's residual alpha from the iOS app icon catalog."""

from pathlib import Path

from PIL import Image


catalog = Path(__file__).resolve().parents[1] / "src-tauri/gen/apple/Assets.xcassets/AppIcon.appiconset"
for path in catalog.glob("*.png"):
    with Image.open(path) as source:
        background = Image.new("RGBA", source.size, "#081b2d")
        background.alpha_composite(source.convert("RGBA"))
        background.convert("RGB").save(path)

# Legacy browsers can use the same mark through a multi-size ICO.
favicon = Path(__file__).resolve().parents[3] / "branding/favicon"
with Image.open(favicon / "64x64.png") as source:
    source.save(favicon / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])
