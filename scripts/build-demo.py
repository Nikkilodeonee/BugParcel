"""Assemble actual UI screenshots into the README GIF (developer-only Pillow)."""

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frames", type=Path, default=root / ".cache/release-demo")
    parser.add_argument("--font", type=Path, default=Path("C:/Windows/Fonts/segoeui.ttf"))
    parser.add_argument("--output", type=Path, default=root / "docs/demo.gif")
    args = parser.parse_args()
    steps = [
        ("01-start.jpg", "Start with a capture and server logs"),
        ("02-link.jpg", "Connect a failed request to its server logs"),
        ("03-review.jpg", "Review detected values before sharing"),
        ("04-timeline.jpg", "See request timings and chronological evidence"),
        ("05-compare.jpg", "Compare the incident before and after a fix"),
        ("06-export.jpg", "Export standalone HTML anyone can open"),
    ]
    screenshots = [Image.open(args.frames / name).convert("RGB") for name, _ in steps]
    width = max(image.width for image in screenshots)
    height = max(image.height for image in screenshots)
    font = ImageFont.truetype(str(args.font), 24)
    small = ImageFont.truetype(str(args.font), 16)
    frames = []
    for index, (screenshot, (_, caption)) in enumerate(zip(screenshots, steps), 1):
        frame = Image.new("RGB", (width, height + 78), "#f7f6f2")
        frame.paste(screenshot, (0, 78))
        draw = ImageDraw.Draw(frame)
        draw.rectangle((0, 0, width, 77), fill="#133d38")
        draw.text((24, 10), f"{index}/6  {caption}", font=font, fill="white")
        draw.text((24, 44), "BugParcel 1.4  |  Fictional sample data  |  Runs locally", font=small, fill="#c0ded7")
        draw.rectangle((0, 74, width * index // len(steps), 77), fill="#78cfba")
        frames.append(frame.quantize(colors=192, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(args.output, save_all=True, append_images=frames[1:], duration=3000,
                   loop=0, optimize=True, disposal=2)
    with Image.open(args.output) as gif:
        assert gif.n_frames == len(steps)
        assert gif.info["loop"] == 0
        assert sum(gif.seek(i) or gif.info["duration"] for i in range(gif.n_frames)) == 18000
    print(f"Created {args.output}: 6 actual UI states, 18 seconds, {args.output.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
