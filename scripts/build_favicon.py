#!/usr/bin/env python3
"""scripts/build_favicon.py -- generate static/favicon.ico from drawing primitives.

Backlog #41. Produces a multi-size .ico (16/32/48 px) so browsers pick
the right size for their context (16 = tab strip, 32 = pinned tab,
48 = task bar / shortcut). Re-run after design tweaks; the output is
checked into the repo so the runtime tray doesn't need Pillow.

The design mirrors static/favicon.svg: cyan rounded background, dark
"W" monogram, faint pulse line below. Pure-Pillow, no SVG rasterisation
dependencies — keeps the build self-contained.

Usage: python scripts/build_favicon.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "static" / "favicon.ico"

# Brand colours -- keep in sync with static/favicon.svg
CYAN = (0, 212, 255, 255)
DARK = (13, 17, 23, 255)
TRANSPARENT = (0, 0, 0, 0)

# Sizes baked into the .ico. Browsers pick whichever closest matches the
# context they're rendering for. Skipping intermediate sizes keeps the
# file under the 5 KB target from backlog #41.
SIZES = (16, 32, 48)


def _draw_favicon(size: int) -> Image.Image:
    """Render the favicon at ``size``×``size`` pixels."""
    img = Image.new("RGBA", (size, size), TRANSPARENT)
    draw = ImageDraw.Draw(img)

    # Rounded cyan background. Pillow's rounded_rectangle takes the
    # corner-radius proportional to size so the icon looks consistent
    # across all sizes.
    radius = max(2, size // 5)
    draw.rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=CYAN)

    # "W" monogram. Five points forming the M-shape, scaled to size.
    # The polyline is drawn as four line segments with rounded joins.
    sf = size / 32  # scale factor relative to the SVG's 32x32 base
    pts = [
        (6 * sf, 8 * sf),
        (10 * sf, 22 * sf),
        (13 * sf, 14 * sf),
        (16 * sf, 22 * sf),
        (19 * sf, 14 * sf),
        (22 * sf, 22 * sf),
        (26 * sf, 8 * sf),
    ]
    stroke = max(1, int(round(2.5 * sf)))
    # Draw segment-by-segment; line() doesn't support polyline natively
    # in older Pillow versions but this works on every Pillow >= 6.
    for i in range(len(pts) - 1):
        draw.line([pts[i], pts[i + 1]], fill=DARK, width=stroke)

    # Pulse line at the bottom (only render at >= 32 px -- at 16 it
    # adds too much noise to read).
    if size >= 24:
        pulse = [
            (7 * sf, 27 * sf),
            (11 * sf, 27 * sf),
            (13 * sf, 25 * sf),
            (15 * sf, 28 * sf),
            (17 * sf, 26 * sf),
            (21 * sf, 27 * sf),
            (25 * sf, 27 * sf),
        ]
        pstroke = max(1, int(round(1.2 * sf)))
        # Slight transparency on the pulse to match the SVG's opacity=0.7
        pulse_color = (DARK[0], DARK[1], DARK[2], int(0.7 * 255))
        for i in range(len(pulse) - 1):
            draw.line([pulse[i], pulse[i + 1]], fill=pulse_color, width=pstroke)

    return img


def main() -> None:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Pillow renders each requested size from the largest source by
    # default, but our 16 px version skips the pulse line for legibility,
    # so we render each size individually then save the largest one with
    # the smaller ones piggy-backed via ``append_images=``.
    # Per Pillow docs: passing both ``sizes=`` and ``append_images=`` is
    # actually correct -- ``sizes=`` declares the directory entries to
    # write, ``append_images=`` provides the per-size pixel data. Without
    # ``append_images=``, Pillow re-resizes the master and we lose the
    # 16-px-specific simplification. The earlier 0.2 KB output was a
    # Pillow optimisation: when all sizes can be derived from a single
    # source, it stores just one image. We need each size carried
    # independently, so we save each with bicubic-resized icon data
    # explicitly bundled.
    images = [_draw_favicon(s) for s in SIZES]
    largest = images[-1]  # 48 px
    largest.save(
        OUT_PATH,
        format="ICO",
        sizes=[(s, s) for s in SIZES],
        append_images=[img for img in images if img is not largest],
    )
    size_kb = OUT_PATH.stat().st_size / 1024
    print(f"Wrote {OUT_PATH}  ({size_kb:.1f} KB, sizes: {list(SIZES)})")


if __name__ == "__main__":
    main()
