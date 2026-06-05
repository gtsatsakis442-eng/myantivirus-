#!/usr/bin/env python3
"""Generate the Talos app icon with no third-party libraries.

Outputs:
  * assets/talos.ico                     — multi-size BMP-in-ICO (Explorer/exe)
  * agent/talos-gui/assets/icon-64.rgba  — raw 64x64 RGBA (egui window icon)

Design: a red security shield with a white check on a dark rounded tile,
matching the GUI's "◆ TALOS" red-on-dark theme. Rendered at 4x supersampling
and area-resampled for clean edges.
"""
import math
import os
import struct

SS = 512  # supersample master resolution


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(len(a)))


def render_master():
    """Return (rgba bytes, SS, SS) for the supersampled master image."""
    w = h = SS
    px = bytearray(w * h * 4)  # transparent

    m = 16                      # tile margin
    rad = 88                    # tile corner radius
    tile_top = (36, 44, 58)
    tile_bot = (20, 25, 33)

    cx = w / 2
    ty, by = 116, 420           # shield top / bottom
    hw = 132                    # shield half-width
    split = 0.58                # upper(straight) vs lower(taper) fraction
    seam = ty + split * (by - ty)
    red_top = (242, 56, 70)
    red_bot = (196, 18, 31)

    # check vertices (absolute), thickness, colour
    ccy = ty + 0.42 * (by - ty)
    ax, ay = cx - 78, ccy + 6
    bx, by2 = cx - 22, ccy + 60
    dx2, dy2 = cx + 88, ccy - 52
    cth = 19.0                  # check half-thickness

    def in_tile(x, y):
        left, top, right, bot = m, m, w - m, h - m
        if not (left <= x <= right and top <= y <= bot):
            return False
        # Clamp to the nearest rounded-corner circle centre, then test radius.
        qx = left + rad if x < left + rad else (right - rad if x > right - rad else x)
        qy = top + rad if y < top + rad else (bot - rad if y > bot - rad else y)
        return (x - qx) ** 2 + (y - qy) ** 2 <= rad * rad

    def in_shield(x, y):
        if y < ty or y > by:
            return False
        if y <= seam:
            left, right = cx - hw, cx + hw
            if not (left <= x <= right):
                return False
            rr = 40
            if y < ty + rr:
                if x < left + rr:
                    return (x - (left + rr)) ** 2 + (y - (ty + rr)) ** 2 <= rr * rr
                if x > right - rr:
                    return (x - (right - rr)) ** 2 + (y - (ty + rr)) ** 2 <= rr * rr
            return True
        tt = (y - seam) / (by - seam)
        half = hw * math.sqrt(max(0.0, 1 - tt * tt))
        return abs(x - cx) <= half

    def seg_dist(x, y, x1, y1, x2, y2):
        vx, vy = x2 - x1, y2 - y1
        wx, wy = x - x1, y - y1
        L2 = vx * vx + vy * vy
        t = 0.0 if L2 == 0 else max(0.0, min(1.0, (wx * vx + wy * vy) / L2))
        px_, py_ = x1 + t * vx, y1 + t * vy
        return math.hypot(x - px_, y - py_)

    for y in range(h):
        for x in range(w):
            if not in_tile(x + 0.5, y + 0.5):
                continue
            i = (y * w + x) * 4
            # tile gradient
            ft = (y - m) / (h - 2 * m)
            r, g, b = lerp(tile_top, tile_bot, max(0.0, min(1.0, ft)))
            a = 255
            xc, yc = x + 0.5, y + 0.5
            if in_shield(xc, yc):
                fs = (yc - ty) / (by - ty)
                r, g, b = lerp(red_top, red_bot, max(0.0, min(1.0, fs)))
                d = min(seg_dist(xc, yc, ax, ay, bx, by2),
                        seg_dist(xc, yc, bx, by2, dx2, dy2))
                if d <= cth:
                    r, g, b = 246, 248, 252
            px[i] = r
            px[i + 1] = g
            px[i + 2] = b
            px[i + 3] = a
    return bytes(px), w, h


def resample(src, sw, sh, dw, dh):
    """Area-average resample RGBA src -> dst of size dw x dh."""
    dst = bytearray(dw * dh * 4)
    for dy in range(dh):
        sy0 = dy * sh / dh
        sy1 = (dy + 1) * sh / dh
        iy0, iy1 = int(sy0), max(int(sy0) + 1, int(math.ceil(sy1)))
        for dx in range(dw):
            sx0 = dx * sw / dw
            sx1 = (dx + 1) * sw / dw
            ix0, ix1 = int(sx0), max(int(sx0) + 1, int(math.ceil(sx1)))
            ar = ag = ab = aa = 0.0
            n = 0
            for sy in range(iy0, min(iy1, sh)):
                for sx in range(ix0, min(ix1, sw)):
                    i = (sy * sw + sx) * 4
                    al = src[i + 3]
                    ar += src[i] * al
                    ag += src[i + 1] * al
                    ab += src[i + 2] * al
                    aa += al
                    n += 1
            j = (dy * dw + dx) * 4
            if aa > 0:
                dst[j] = round(ar / aa)
                dst[j + 1] = round(ag / aa)
                dst[j + 2] = round(ab / aa)
                dst[j + 3] = round(aa / n)
            # else stays transparent
    return bytes(dst)


def bmp_dib(rgba, w, h):
    """32-bit BMP DIB (for ICO): BITMAPINFOHEADER + BGRA bottom-up + AND mask."""
    hdr = struct.pack('<IiiHHIIiiII', 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    rows = bytearray()
    for y in range(h - 1, -1, -1):  # bottom-up
        for x in range(w):
            i = (y * w + x) * 4
            rows += bytes((rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]))
    mask_row = ((w + 31) // 32) * 4
    mask = bytes(mask_row * h)  # all-zero: alpha channel drives transparency
    return hdr + bytes(rows) + mask


def write_ico(path, images):
    """images: list of (size, dib_bytes)."""
    n = len(images)
    out = bytearray(struct.pack('<HHH', 0, 1, n))
    offset = 6 + n * 16
    blobs = []
    for (size, dib) in images:
        b = size if size < 256 else 0
        out += struct.pack('<BBBBHHII', b, b, 0, 0, 1, 32, len(dib), offset)
        offset += len(dib)
        blobs.append(dib)
    for blob in blobs:
        out += blob
    with open(path, 'wb') as f:
        f.write(out)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    master, mw, mh = render_master()

    sizes = [256, 128, 64, 48, 32, 16]
    images = []
    for s in sizes:
        rgba = resample(master, mw, mh, s, s)
        images.append((s, bmp_dib(rgba, s, s)))
    os.makedirs(os.path.join(root, 'assets'), exist_ok=True)
    write_ico(os.path.join(root, 'assets', 'talos.ico'), images)

    # 64x64 raw RGBA for the egui window icon.
    win = resample(master, mw, mh, 64, 64)
    gdir = os.path.join(root, 'agent', 'talos-gui', 'assets')
    os.makedirs(gdir, exist_ok=True)
    with open(os.path.join(gdir, 'icon-64.rgba'), 'wb') as f:
        f.write(win)

    ico = os.path.join(root, 'assets', 'talos.ico')
    print('wrote', ico, os.path.getsize(ico), 'bytes')
    print('wrote', os.path.join(gdir, 'icon-64.rgba'), len(win), 'bytes')


if __name__ == '__main__':
    main()
