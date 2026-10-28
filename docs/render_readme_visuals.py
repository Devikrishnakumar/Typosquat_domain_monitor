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


def project(point, yaw, cx=925, cy=266):
    x, y, z = point
    x, z = x*math.cos(yaw)+z*math.sin(yaw), -x*math.sin(yaw)+z*math.cos(yaw)
    y, z = y*.96-z*.28, y*.28+z*.96
    scale = 650/(650-z)
    return cx+x*scale, cy+y*scale, z


def hero(t):
    im = background(1200, 520)
    d = ImageDraw.Draw(im, 'RGBA')
    d.rounded_rectangle((38, 38, 272, 69), radius=15, fill=(29, 74, 112, 95),
                        outline=(103, 181, 244, 80))
    label(d, (53, 46), 'BRAND DEFENSE / DOMAIN INTELLIGENCE', 10, BLUE, 700)
    label(d, (38, 100), 'CyberSentinel', 61, WHITE, 750)
    label(d, (41, 194), 'See the signal.', 36, WHITE, 600)
    label(d, (41, 244), 'Stop the spoof.', 36, BLUE, 600)
    label(d, (42, 321), 'Discover lookalikes. Inspect the evidence.', 17, MUTED)
    label(d, (42, 351), 'Bring your brand defense into one workspace.', 17, MUTED)
    for x, text, width in [(42, 'CERTIFICATE WATCH', 168), (224, 'VISUAL EVIDENCE', 152), (390, 'RISK + REPORTS', 145)]:
        d.rounded_rectangle((x, 414, x+width, 450), radius=10,
                            fill=(22, 45, 68, 160), outline=(112, 160, 202, 68))
        label(d, (x+13, 426), text, 10, (178, 205, 228), 650)
    label(d, (43, 482), 'PYTHON  /  STREAMLIT  /  FASTAPI  /  PLAYWRIGHT', 10, (100, 137, 168), 600)

    # A rotating three-dimensional wireframe enclosing an extruded shield.
    yaw = TAU*t
    paths = []
    for latitude in range(-60, 61, 20):
        a = math.radians(latitude)
        paths.append([(147*math.cos(a)*math.cos(j*TAU/96),
                       147*math.sin(a), 147*math.cos(a)*math.sin(j*TAU/96)) for j in range(97)])
    for longitude in range(0, 180, 24):
        a = math.radians(longitude)
        paths.append([(147*math.cos(j*TAU/96)*math.cos(a),
                       147*math.sin(j*TAU/96), 147*math.cos(j*TAU/96)*math.sin(a)) for j in range(97)])
    segments = []
    for path in paths:
        points = [project(point, yaw) for point in path]
        segments.extend((a, b) for a, b in zip(points, points[1:]))
    for front in (False, True):
        for a, b in segments:
            depth = (a[2]+b[2])/2
            if (depth > 0) == front:
                alpha = 82 if front else 28
                d.line((a[0], a[1], b[0], b[1]), fill=(91, 163, 223, alpha), width=1)
        if not front:
            sway = .30+.13*math.sin(TAU*t)
            shape = [(-53,-74),(53,-74),(48,12),(28,51),(0,75),(-28,51),(-48,12)]
            for z in range(-20, 1, 2):
                face = [project((x, y, z), sway)[:2] for x, y in shape]
                d.polygon(face, fill=(18, 64+z, 108+z, 255))
            face = [project((x,y,4),sway)[:2] for x,y in shape]
            d.polygon(face, fill=(29, 91, 144, 255))
            d.line(face+[face[0]], fill=(124, 198, 249, 255), width=3)
            facet = [project((x,y,6),sway)[:2] for x,y in [(0,-70),(50,-70),(45,10),(0,70)]]
            d.polygon(facet, fill=(69, 142, 198, 88))
            check = [project((x,y,10),sway)[:2] for x,y in [(-24,-2),(-5,18),(29,-23)]]
            d.line(check, fill=(223, 245, 255, 255), width=7, joint='curve')
    # Orbit lines and floating glass evidence tiles give the composition depth.
    orbit = [project((195*math.cos(a), 44*math.sin(a), 65*math.sin(a)), -.26)[:2]
             for a in np.linspace(0, TAU, 160)]
    d.line(orbit, fill=(90, 164, 220, 66), width=1)
    y = 72+5*math.sin(TAU*t)
    panel(d, (742, y, 1000, y+69))
    d.rounded_rectangle((758,y+18,786,y+46),radius=8,fill=(165,120,51,70),outline=(211,171,103,120))
    label(d,(768,y+23),'!',15,(231,192,127),700)
    label(d,(800,y+13),'LOOKALIKE DISCOVERY',10,(153,185,211),650)
    label(d,(800,y+35),'brand-login.example',14,WHITE,650)
    y = 407-5*math.sin(TAU*t)
    panel(d,(827,y,1158,y+69))
    label(d,(846,y+13),'EVIDENCE, CONNECTED',10,BLUE,700)
    label(d,(846,y+37),'DNS  /  TLS  /  Content  /  pHash',13,WHITE,550)
    label(d,(947,486),'ILLUSTRATIVE 3D MOTION',9,(94,130,161),600)
    return im


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
    pictures = [render(i/frames) for i in range(frames)]
    pictures[0].save(OUT/f'{name}-poster.png', optimize=True)
    palette = pictures[0].quantize(colors=192)
    indexed = [picture.quantize(palette=palette, dither=Image.Dither.NONE) for picture in pictures]
    indexed[0].save(OUT/f'{name}.gif', save_all=True, append_images=indexed[1:],
                    duration=80, loop=0, optimize=True, disposal=1)
    print(f'{name}: {(OUT/f"{name}.gif").stat().st_size/1024:.0f} KiB, {frames} frames', flush=True)


if __name__ == '__main__':
    export('cybersentinel-hero', hero)
    export('detection-workflow', workflow)
