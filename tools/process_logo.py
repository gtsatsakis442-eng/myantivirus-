#!/usr/bin/env python3
"""Derive the Talos app artwork from the source logo `assets/talos-logo.webp`.

Requires Pillow (`pip install pillow`). Crops the circular emblem out of the
wide logo, applies an anti-aliased circular alpha mask (so it sits cleanly on
the dark UI and as a transparent exe icon), and writes:

  * agent/talos-gui/assets/talos_hero.rgba  — 256x256 RGBA (GUI emblem texture)
  * agent/talos-gui/assets/icon-64.rgba     — 64x64 RGBA  (GUI window icon)
  * assets/talos.ico                         — multi-size icon (embedded in .exe)
  * /tmp/talos_logo_preview.png              — preview for review
"""
import os
from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'assets', 'talos-logo.webp')


def circular(side):
    """Centred square crop of the emblem with an anti-aliased circular mask."""
    img = Image.open(SRC).convert('RGBA')
    w, h = img.size
    cx, cy = w // 2, h // 2
    half = side // 2
    crop = img.crop((cx - half, cy - half, cx + half, cy + half))
    # mask drawn at 4x then downsampled for a smooth edge
    m = Image.new('L', (side * 4, side * 4), 0)
    ImageDraw.Draw(m).ellipse((0, 0, side * 4 - 1, side * 4 - 1), fill=255)
    crop.putalpha(m.resize((side, side), Image.LANCZOS))
    return crop


def main():
    emblem = circular(740)                         # generous square around the ring

    hero = emblem.resize((256, 256), Image.LANCZOS)
    win = emblem.resize((64, 64), Image.LANCZOS)

    gdir = os.path.join(ROOT, 'agent', 'talos-gui', 'assets')
    os.makedirs(gdir, exist_ok=True)
    open(os.path.join(gdir, 'talos_hero.rgba'), 'wb').write(hero.tobytes())
    open(os.path.join(gdir, 'icon-64.rgba'), 'wb').write(win.tobytes())

    ico = emblem.resize((256, 256), Image.LANCZOS)
    ico.save(os.path.join(ROOT, 'assets', 'talos.ico'),
             sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])

    hero.convert('RGB').save('/tmp/talos_logo_preview.png')
    print('hero', len(hero.tobytes()), 'win', len(win.tobytes()),
          'ico', os.path.getsize(os.path.join(ROOT, 'assets', 'talos.ico')))


if __name__ == '__main__':
    main()
