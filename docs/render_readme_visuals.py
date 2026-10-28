"""Render the README's original, self-contained looping motion graphics.

Run from the repository root: python docs/render_readme_visuals.py
The artwork is illustrative and does not represent live monitoring telemetry.
"""
from functools import lru_cache
from pathlib import Path
import math

import numpy as np
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "assets"
OUT.mkdir(parents=True, exist_ok=True)
TAU = math.tau
WHITE = (235, 245, 255)
MUTED = (142, 169, 194)
BLUE = (111, 190, 255)


@lru_cache(maxsize=32)
def font(size, weight=500):
    path = ROOT / "landing_page/public/fonts/manrope-variable.ttf"
    face = ImageFont.truetype(str(path), size)
    face.set_variation_by_axes([weight])
    return face


def background(width, height):
    y, x = np.mgrid[:height, :width]
    pool = np.exp(-(((x-width*.78)/(width*.39))**2 + ((y-height*.55)/(height*.8))**2)*2)
    pixels = np.stack([5+pool*5, 13+pool*21, 25+pool*42], axis=-1)
    result = Image.fromarray(pixels.astype('uint8'), 'RGB')
    draw = ImageDraw.Draw(result, 'RGBA')
    for gx in range(0, width, 40):
        draw.line((gx, 0, gx, height), fill=(109, 172, 220, 12))
    for gy in range(0, height, 40):
        draw.line((0, gy, width, gy), fill=(109, 172, 220, 12))
    draw.rounded_rectangle((1, 1, width-2, height-2), radius=22,
                           outline=(141, 190, 229, 56), width=1)
    return result


def label(draw, point, text, size=14, fill=MUTED, weight=500):
    draw.text(point, text, font=font(size, weight), fill=fill)


def panel(draw, box):
    x0, y0, x1, y1 = box
    draw.rounded_rectangle((x0+5, y0+9, x1+5, y1+9), radius=16, fill=(0, 4, 12, 100))
    draw.rounded_rectangle(box, radius=16, fill=(17, 41, 64, 218),
                           outline=(119, 177, 224, 86), width=1)


def project(point, yaw, cx=876, cy=264):
    x, y, z = point
    x, z = x*math.cos(yaw)+z*math.sin(yaw), -x*math.sin(yaw)+z*math.cos(yaw)
    y, z = y*.96-z*.28, y*.28+z*.96
    scale = 650/(650-z)
    return cx+x*scale, cy+y*scale, z


def hero(t):
    base = background(1200, 520).convert('RGBA')
    im = Image.new('RGBA', base.size, (0, 0, 0, 0))

    # Layered translucent halos make the core read as a luminous 3D object.
    halo = Image.new('RGBA', im.size, (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo, 'RGBA')
    for radius in range(230, 29, -20):
        alpha = max(2, 15 - radius // 20)
        hd.ellipse((876-radius, 264-radius, 876+radius, 264+radius),
                   fill=(36, 119, 255, alpha))
    im = Image.alpha_composite(im, halo)
    d = ImageDraw.Draw(im, 'RGBA')

    d.rounded_rectangle((38, 38, 295, 70), radius=16, fill=(29, 74, 112, 120),
                        outline=(103, 181, 244, 130))
    label(d, (53, 48), 'CYBER THREAT INTELLIGENCE', 10, BLUE, 700)
    label(d, (38, 104), 'CyberSentinel', 58, WHITE, 750)
    label(d, (41, 192), 'Spot the lookalike.', 34, WHITE, 650)
    label(d, (41, 239), 'Stop the spoof.', 34, (118, 195, 255), 650)
    label(d, (42, 307), 'Discover threats. Connect the evidence.', 16, MUTED)
    label(d, (42, 335), 'Make every response reviewable.', 16, MUTED)
    for x, text, width in [
        (42, 'LIVE DOMAIN SIGNALS', 170),
        (224, 'CONNECTED EVIDENCE', 174),
        (410, 'ANALYST-READY', 139),
    ]:
        d.rounded_rectangle((x, 402, x+width, 438), radius=11,
                            fill=(22, 45, 68, 210), outline=(112, 160, 202, 100))
        label(d, (x+13, 414), text, 9, (178, 205, 228), 650)
    label(d, (43, 482), 'PYTHON  /  STREAMLIT  /  FASTAPI  /  PLAYWRIGHT',
          10, (100, 137, 168), 600)

    # A rotating wireframe globe encloses an extruded, softly glowing shield.
    yaw = TAU*t
    radius = 158
    paths = []
    for latitude in range(-60, 61, 20):
        a = math.radians(latitude)
        paths.append([(radius*math.cos(a)*math.cos(j*TAU/96),
                       radius*math.sin(a), radius*math.cos(a)*math.sin(j*TAU/96))
                      for j in range(97)])
    for longitude in range(0, 180, 24):
        a = math.radians(longitude)
        paths.append([(radius*math.cos(j*TAU/96)*math.cos(a),
                       radius*math.sin(j*TAU/96), radius*math.cos(j*TAU/96)*math.sin(a))
                      for j in range(97)])
    segments = []
    for path in paths:
        points = [project(point, yaw) for point in path]
        segments.extend((a, b) for a, b in zip(points, points[1:]))

    # Three tilted rings orbit at different speeds to emphasize depth.
    for ring_index, (rx, ry, tilt, color) in enumerate([
        (236, 73, .38, (61, 198, 255, 110)),
        (208, 112, -.58, (119, 112, 255, 92)),
        (188, 54, 1.02, (74, 222, 209, 80)),
    ]):
        angle = np.linspace(0, TAU, 180)
        phase = TAU*t*(1 if ring_index != 1 else -.7)
        orbit = [(876+rx*math.cos(a+phase)*math.cos(tilt),
                  264+ry*math.sin(a+phase),
                  rx*math.cos(a+phase)*math.sin(tilt)) for a in angle]
        d.line([(x, y) for x, y, _ in orbit], fill=color, width=2)
        for marker in range(3):
            a = phase+marker*TAU/3
            x = 876+rx*math.cos(a)*math.cos(tilt)
            y = 264+ry*math.sin(a)
            d.ellipse((x-4, y-4, x+4, y+4), fill=(163, 226, 255, 235))

    for front in (False, True):
        for a, b in segments:
            depth = (a[2]+b[2])/2
            if (depth > 0) == front:
                alpha = 132 if front else 42
                d.line((a[0], a[1], b[0], b[1]),
                       fill=(91, 178, 250, alpha), width=2 if front else 1)

    sway = .30+.13*math.sin(TAU*t)
    shield = [(-65, -91), (65, -91), (59, 15), (35, 66),
              (0, 96), (-35, 66), (-59, 15)]
    for z in range(-25, 1, 2):
        face = [project((x, y, z), sway)[:2] for x, y in shield]
        d.polygon(face, fill=(18, 64+z, 108+z, 255))
    face = [project((x, y, 4), sway)[:2] for x, y in shield]
    d.polygon(face, fill=(27, 86, 145, 255))
    d.line(face+[face[0]], fill=(135, 218, 255, 255), width=4, joint='curve')
    facet = [project((x, y, 6), sway)[:2]
             for x, y in [(0, -88), (61, -88), (56, 13), (0, 90)]]
    d.polygon(facet, fill=(80, 157, 223, 90))
    check = [project((x, y, 10), sway)[:2]
             for x, y in [(-31, -3), (-7, 23), (36, -32)]]
    d.line(check, fill=(233, 250, 255, 255), width=9, joint='curve')

    def signal_card(x, y, heading, detail, icon, accent, bob):
        x += 8*math.sin(bob)
        y += 7*math.cos(bob)
        panel(d, (x, y, x+218, y+66))
        d.rounded_rectangle((x+12, y+14, x+50, y+52), radius=12,
                            fill=(*accent, 48), outline=(*accent, 190), width=1)
        cx, cy = x+31, y+33
        if icon == 'search':
            d.ellipse((cx-8, cy-8, cx+4, cy+4), outline=(*accent, 255), width=2)
            d.line((cx+3, cy+3, cx+10, cy+10), fill=(*accent, 255), width=2)
        elif icon == 'shield':
            points = [(cx-8, cy-9), (cx+8, cy-9), (cx+7, cy+1),
                      (cx, cy+10), (cx-7, cy+1)]
            d.line(points+[points[0]], fill=(*accent, 255), width=2, joint='curve')
            d.line((cx-4, cy, cx-1, cy+4, cx+5, cy-4),
                   fill=(*accent, 255), width=2, joint='curve')
        elif icon == 'pulse':
            d.line((cx-10, cy, cx-5, cy, cx-2, cy-7, cx+2, cy+8,
                    cx+5, cy-2, cx+10, cy-2), fill=(*accent, 255), width=2)
        else:
            d.rounded_rectangle((cx-7, cy-10, cx+7, cy+10), radius=2,
                                outline=(*accent, 255), width=2)
            d.line((cx-4, cy-3, cx+4, cy-3), fill=(*accent, 255), width=1)
            d.line((cx-4, cy+2, cx+4, cy+2), fill=(*accent, 255), width=1)
        label(d, (x+62, y+12), heading, 9, (153, 185, 211), 700)
        label(d, (x+62, y+34), detail, 12, WHITE, 650)
        d.ellipse((x+198, y+12, x+204, y+18), fill=(*accent, 255))

    # Independent animated cards orbit the core like movable evidence nodes.
    signal_card(590, 75, 'LOOKALIKE FOUND', 'brand-login.example',
                'search', (255, 190, 94), TAU*t)
    signal_card(920, 95, 'TLS + DNS EVIDENCE', 'Signals connected',
                'shield', (94, 206, 255), TAU*t+1.6)
    signal_card(972, 354, 'RISK ASSESSMENT', 'Review supporting proof',
                'pulse', (186, 142, 255), TAU*t+3.1)
    signal_card(600, 367, 'RESPONSE READY', 'Evidence report',
                'report', (83, 225, 194), TAU*t+4.7)

    # Small particles travel along the main orbit on each loop.
    for i in range(12):
        angle = TAU*(t+i/12)
        x = 876+242*math.cos(angle)*math.cos(.38)
        y = 264+73*math.sin(angle)
        r = 2+(i % 3)
        d.ellipse((x-r, y-r, x+r, y+r),
                  fill=(128, 215, 255, max(35, 210-i*12)))

    label(d, (967, 486), 'ILLUSTRATIVE MOTION  /  NOT LIVE DATA',
          8, (94, 130, 161), 600)
    return Image.alpha_composite(base, im)


def workflow(t):
    im = background(1200, 244)
    d = ImageDraw.Draw(im, 'RGBA')
    label(d,(34,23),'FROM SIGNAL TO EVIDENCE',12,BLUE,750)
    label(d,(932,23),'ONE CONNECTED WORKFLOW',10,MUTED,600)
    stages = [('01','Discover','CT logs + lookalike domains'),
              ('02','Investigate','DNS, TLS, content + visuals'),
              ('03','Assess','Scoring + supporting reasons'),
              ('04','Respond','Analyst review + PDF evidence')]
    phase = t*4
    for i, (number, title, subtitle) in enumerate(stages):
        x = 34+i*300
        active = max(0, 1-abs(phase-i-.5)*2)
        panel(d,(x,83,x+232,201))
        d.rounded_rectangle((x+15,98,x+48,131),radius=10,
                            fill=(37, 99, 146, int(90+active*120)),outline=(115,182,236,90))
        label(d,(x+22,108),number,10,BLUE,700)
        label(d,(x+61,102),title,20,WHITE,650)
        label(d,(x+16,157),subtitle,11,MUTED,550)
        if i < 3:
            start,end=x+238,x+293
            d.line((start,142,end,142),fill=(66,113,149,180),width=2)
            progress=(t*3-i/3)%1
            px=start+(end-start)*progress
            d.ellipse((px-3,139,px+3,145),fill=(*BLUE,255))
    return im


def export(name, render, frames=48):
    pictures = [render(i/frames).convert('RGB') for i in range(frames)]
    pictures[0].save(OUT/f'{name}-poster.png', optimize=True)
    palette = pictures[0].quantize(colors=192)
    indexed = [picture.quantize(palette=palette, dither=Image.Dither.NONE) for picture in pictures]
    indexed[0].save(OUT/f'{name}.gif', save_all=True, append_images=indexed[1:],
                    duration=80, loop=0, optimize=True, disposal=1)
    print(f'{name}: {(OUT/f"{name}.gif").stat().st_size/1024:.0f} KiB, {frames} frames', flush=True)


if __name__ == '__main__':
    export('cybersentinel-hero', hero)
    export('detection-workflow', workflow)
