"""Ritar NetAtlas-logotypen (samma som i netatlas.html) som PNG-ikoner, utan externa bibliotek.

    python tools/make_icons.py        # skriver assets/netatlas-icon.png, icon-192.png, icon-512.png, icon-maskable-512.png

"maskable" = hela rutan blå och loggan mindre i mitten, så att Android kan beskära ikonen till cirkel eller rundad ruta.
"""
import math
import os
import struct
import zlib

ASSETS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'assets')
BLUE = (0x00, 0x6f, 0xff)
A, B, C = (16, 9.5), (9.5, 21.5), (22.5, 21.5)   # hörnen i logotypen (viewBox 0 0 32 32)
SS = 4                                          # delpunkter per axel (kantutjämning)


def in_rrect(x, y, r=8):
    cx, cy = min(max(x, r), 32 - r), min(max(y, r), 32 - r)
    return 0 <= x <= 32 and 0 <= y <= 32 and (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def seg_dist(px, py, a, b):
    (ax, ay), (bx, by) = a, b
    dx, dy = bx - ax, by - ay
    t = max(0, min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - ax - t * dx, py - ay - t * dy)


def color_at(x, y, maskable):
    """Färg (rgb) eller None (genomskinligt) i punkten x, y (0–32)."""
    if maskable:
        x, y = 16 + (x - 16) / .62, 16 + (y - 16) / .62   # loggan på 62 % av ytan, bakgrunden fyller allt
    elif not in_rrect(x, y):
        return None
    col = list(BLUE)
    if min(seg_dist(x, y, A, B), seg_dist(x, y, B, C), seg_dist(x, y, C, A)) <= .9:
        col = [c * .25 + 255 * .75 for c in col]
    if any(math.hypot(x - p[0], y - p[1]) <= 2.9 for p in (A, B, C)):
        col = [255, 255, 255]
    return col


def render(n, maskable=False):
    k = 32 / n
    rows = []
    for j in range(n):
        row = bytearray([0])
        for i in range(n):
            cov, acc = 0, [0.0, 0.0, 0.0]
            for sj in range(SS):
                for si in range(SS):
                    c = color_at((i + (si + .5) / SS) * k, (j + (sj + .5) / SS) * k, maskable)
                    if c:
                        cov += 1
                        acc = [acc[q] + c[q] for q in range(3)]
            row += (bytes(round(acc[q] / cov) for q in range(3)) + bytes([round(255 * cov / SS ** 2)])) if cov else b'\0\0\0\0'
        rows.append(bytes(row))

    def chunk(t, d):
        return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', n, n, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(b''.join(rows), 9)) + chunk(b'IEND', b''))


if __name__ == '__main__':
    os.makedirs(ASSETS, exist_ok=True)
    for name, n, m in (('netatlas-icon.png', 256, False), ('icon-192.png', 192, False),
                       ('icon-512.png', 512, False), ('icon-maskable-512.png', 512, True)):
        data = render(n, m)
        with open(os.path.join(ASSETS, name), 'wb') as f:
            f.write(data)
        print(f'assets/{name}: {len(data)} byte')
