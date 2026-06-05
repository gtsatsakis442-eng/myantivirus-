#!/usr/bin/env python3
"""Generate the Talos guardian hero illustration (no third-party libraries).

Talos — the bronze automaton of Greek myth that guarded Crete — rendered as a
Corinthian-helmeted bronze sentinel inside a dark medallion with bronze rings.
Output:
  * agent/talos-gui/assets/talos_hero.rgba  — 256x256 RGBA for the GUI texture
  * /tmp/talos_hero.png                      — preview (for visual review)

Rendered at 2x supersampling and area-resampled for clean edges.
"""
import math
import os
import struct
import zlib

SS = 512
OUT = 256


def clamp(v, a=0.0, b=1.0):
    return a if v < a else (b if v > b else v)


def lerp(a, b, t):
    return tuple(a[i] + (b[i] - a[i]) * t for i in range(len(a)))


BR = [(46, 30, 14), (110, 70, 32), (188, 128, 70), (238, 192, 126), (252, 232, 192)]
STOPS = [0.0, 0.34, 0.60, 0.84, 1.0]


def bronze(light):
    light = clamp(light)
    for i in range(len(STOPS) - 1):
        if light <= STOPS[i + 1]:
            t = (light - STOPS[i]) / (STOPS[i + 1] - STOPS[i])
            return lerp(BR[i], BR[i + 1], t)
    return BR[-1]


CREST_TOP = (236, 58, 72)
CREST_BOT = (140, 18, 30)


def render():
    w = h = SS
    px = bytearray(w * h * 4)
    cx = w / 2
    R = 244
    rim = 22
    face_top = (30, 40, 56)
    face_edge = (11, 14, 20)
    hx, hy, hr, hrv = cx, 196, 82, 108

    def put(i, col, a=255):
        px[i] = int(round(clamp(col[0], 0, 255)))
        px[i + 1] = int(round(clamp(col[1], 0, 255)))
        px[i + 2] = int(round(clamp(col[2], 0, 255)))
        px[i + 3] = a

    def shade(x, y, top_l, bot_l, top, bot):
        g = bot_l + (top_l - bot_l) * clamp((bot - y) / max(1, bot - top))
        s = 0.45 * math.exp(-((x - 206) ** 2 + (y - 150) ** 2) / 12000.0)
        sh = 0.12 * math.exp(-((x - (cx + 78)) ** 2 + (y - 380) ** 2) / 18000.0)
        return g + s - sh

    for y in range(h):
        for x in range(w):
            i = (y * w + x) * 4
            xc, yc = x + 0.5, y + 0.5
            dx, dy = xc - cx, yc - 256
            rr = math.hypot(dx, dy)
            if rr > R:
                continue
            # medallion background / rings
            if rr > R - rim:
                col = bronze(0.6 + 0.36 * math.cos(math.atan2(dy, dx) - 2.2))
            elif rr > R - rim - 7:
                col = (13, 16, 22)
            elif rr > R - rim - 14:
                col = bronze(0.52)
            else:
                col = lerp(face_top, face_edge, clamp(rr / (R - rim - 14)))
                gl = 0.20 * math.exp(-((xc - cx) ** 2 + (yc - 250) ** 2) / 24000.0)
                col = lerp(col, (210, 150, 90), gl)
            ax = abs(xc - cx)

            # --- red crest plume (on top of the dome) ---
            if 44 <= yc <= 156:
                t = (yc - 44) / (156 - 44)
                half = 24 * math.sin(math.pi * clamp(t, 0, 1)) + 5
                if ax <= half:
                    cc = lerp(CREST_TOP, CREST_BOT, clamp((yc - 44) / 130))
                    col = lerp(cc, (255, 206, 212), max(0.0, 0.42 - clamp(ax / 22) * 0.34))
                    put(i, col)
                    continue

            e = math.sqrt(((xc - hx) / hr) ** 2 + ((yc - hy) / hrv) ** 2)
            cheek = (hy - 8 <= yc <= 302) and (24 <= ax <= (70 - (yc - hy) * 0.40))
            helmet = e <= 1.0 or cheek
            face = (ax <= 31) and (182 <= yc <= 298)

            if helmet and not face:
                light = shade(xc, yc, 0.98, 0.32, hy - hrv, 302)
                if 0.9 < e <= 1.0:
                    light -= 0.14            # helmet rim
                put(i, bronze(light))
                continue

            if face:
                if 182 <= yc <= 201:                       # brow ridge
                    put(i, bronze(shade(xc, yc, 0.84, 0.5, 182, 201)))
                    continue
                if ax <= 8 and yc <= 292:                  # nasal guard
                    put(i, bronze(shade(xc, yc, 0.72, 0.42, 201, 292) - 0.05))
                    continue
                eye = min(math.hypot(xc - (cx - 18), yc - 224),
                          math.hypot(xc - (cx + 18), yc - 224))
                if eye <= 11:                              # glowing eyes
                    g = clamp(1 - eye / 11)
                    put(i, lerp((120, 28, 16), (255, 206, 120), g))
                    continue
                put(i, (16, 13, 14))                       # dark face cavity
                continue

            if 238 <= xc <= 274 and 292 <= yc <= 314:      # neck
                put(i, bronze(shade(xc, yc, 0.5, 0.3, 292, 314) - 0.08))
                continue

            chest = False
            if 308 <= yc <= 420:
                tt = (yc - 308) / (420 - 308)
                if ax <= 112 - 38 * tt:
                    chest = True
            if chest:
                light = shade(xc, yc, 0.82, 0.32, 308, 420)
                if abs(yc - 348) < 3 or abs(yc - 382) < 3:
                    light -= 0.26
                col = bronze(light)
                if abs(xc - cx) + abs(yc - 362) <= 24:     # glowing core gem
                    g = clamp(1 - (abs(xc - cx) + abs(yc - 362)) / 24)
                    col = lerp((150, 24, 32), (255, 150, 120), g)
                put(i, col)
                continue

            near = min(math.hypot(xc - (cx - 108), yc - 322),
                       math.hypot(xc - (cx + 108), yc - 322))
            if near <= 60:                                 # pauldrons
                put(i, bronze(shade(xc, yc, 0.88, 0.3, 276, 374) - clamp(near / 60) * 0.22))
                continue

            put(i, col)

    return bytes(px), w, h


def resample(src, sw, sh, dw, dh):
    dst = bytearray(dw * dh * 4)
    for dy in range(dh):
        iy0, iy1 = int(dy * sh / dh), max(int(dy * sh / dh) + 1, int(math.ceil((dy + 1) * sh / dh)))
        for dx in range(dw):
            ix0, ix1 = int(dx * sw / dw), max(int(dx * sw / dw) + 1, int(math.ceil((dx + 1) * sw / dw)))
            ar = ag = ab = aa = 0.0
            n = 0
            for sy in range(iy0, min(iy1, sh)):
                for sx in range(ix0, min(ix1, sw)):
                    j = (sy * sw + sx) * 4
                    al = src[j + 3]
                    ar += src[j] * al
                    ag += src[j + 1] * al
                    ab += src[j + 2] * al
                    aa += al
                    n += 1
            k = (dy * dw + dx) * 4
            if aa > 0:
                dst[k] = round(ar / aa)
                dst[k + 1] = round(ag / aa)
                dst[k + 2] = round(ab / aa)
                dst[k + 3] = round(aa / n)
    return bytes(dst)


def write_png(rgba, w, h, path):
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        raw += rgba[y * w * 4:(y + 1) * w * 4]

    def chunk(t, d):
        c = t + d
        return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
    out = b'\x89PNG\r\n\x1a\n'
    out += chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0))
    out += chunk(b'IDAT', zlib.compress(bytes(raw), 9))
    out += chunk(b'IEND', b'')
    open(path, 'wb').write(out)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    master, w, h = render()
    img = resample(master, w, h, OUT, OUT)
    gdir = os.path.join(root, 'agent', 'talos-gui', 'assets')
    os.makedirs(gdir, exist_ok=True)
    with open(os.path.join(gdir, 'talos_hero.rgba'), 'wb') as f:
        f.write(img)
    write_png(img, OUT, OUT, '/tmp/talos_hero.png')
    print('wrote talos_hero.rgba', len(img), 'bytes; preview /tmp/talos_hero.png')


if __name__ == '__main__':
    main()
