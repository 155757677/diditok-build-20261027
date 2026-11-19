# -*- coding: utf-8 -*-
"""
生成桌面图标：东风奕派 eπ 标识。

做法：拿官方 logo（深色字标 + 蓝绿底），把字标抠成"墨迹"蒙版，
再把整张图刷成品牌蓝绿、字标换成纯白，居中留出安全边距。

用法：
    pip install pillow numpy
    python tools/make-icon.py <logo.jpg|logo.png>
产物：
    Assets.xcassets/AppIcon.appiconset/icon-1024.png
"""
import os
import sys

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "Assets.xcassets", "AppIcon.appiconset", "icon-1024.png")

CANVAS = 1024
CONTENT = 0.62          # logo 在图标里的占比，其余是四周留白
FALLBACK_BRAND = (0x01, 0x9F, 0xAB)   # 采样失败时用的奕派蓝绿


def ink_mask(a):
    """越深/越饱和的像素越接近 1，纯白背景接近 0。"""
    return (255 - a.min(axis=2)).astype(np.float32) / 255.0


def sample_brand(a, mask):
    """取 logo 大面积有色区的平均色作为品牌色。"""
    sel = mask > 0.5
    if sel.sum() < 500:
        return FALLBACK_BRAND
    px = a[sel]
    # 丢掉接近黑色的笔划，只留背景色那块
    bright = px[px.max(axis=1) > 90]
    if len(bright) < 500:
        bright = px
    med = np.median(bright, axis=0)
    return tuple(int(round(c)) for c in med)


def build(src):
    im = Image.open(src).convert("RGB")
    a = np.asarray(im).astype(np.int16)
    mask = ink_mask(a)

    # 有字标的区域
    on = mask > 0.18
    ys, xs = np.nonzero(on)
    if len(ys) == 0:
        sys.exit("图里没找到任何内容：%s" % src)
    x0, x1, y0, y1 = xs.min(), xs.max(), ys.min(), ys.max()
    mark = Image.fromarray((mask[y0:y1 + 1, x0:x1 + 1] * 255).astype(np.uint8), "L")
    # 提一下对比，边缘更干净
    lo, hi = 0.25, 0.75
    mark = mark.point(lambda v: 0 if v / 255.0 <= lo else (255 if v / 255.0 >= hi else int((v / 255.0 - lo) / (hi - lo) * 255)))

    brand = sample_brand(a, mask)
    print("品牌色 #%02X%02X%02X，字标区域 %dx%d" % (brand[0], brand[1], brand[2], mark.width, mark.height))

    side = int(CANVAS * CONTENT)
    scale = min(side / mark.width, side / mark.height)
    w, h = max(1, int(mark.width * scale)), max(1, int(mark.height * scale))
    mark = mark.resize((w, h), Image.LANCZOS)

    out = Image.new("RGBA", (CANVAS, CANVAS), brand + (255,))   # 不透明，iOS 要求
    white = Image.new("RGBA", (w, h), (255, 255, 255, 255))
    out.paste(white, ((CANVAS - w) // 2, (CANVAS - h) // 2), mark)

    out.convert("RGB").save(OUT, "PNG")
    print("→ %s  (%d bytes)" % (OUT, os.path.getsize(OUT)))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    build(sys.argv[1])
