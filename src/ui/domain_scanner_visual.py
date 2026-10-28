"""Local Lucide SVGs composed into a lightweight domain-inspection animation."""
from functools import lru_cache
from pathlib import Path
import base64


@lru_cache(maxsize=4)
def _icon(name):
    svg = (Path(__file__).with_name('icons') / 'lucide' / f'{name}.svg').read_text(encoding='utf-8').replace('currentColor', '#bfdbfe')
    data = base64.b64encode(svg.encode()).decode('ascii')
    return f'<img src="data:image/svg+xml;base64,{data}" width="24" height="24" alt="" aria-hidden="true" />'


def scanner_visual():
    return f'''
    <div class="ps-scan-visual" role="img" aria-label="Illustration of domain inspection, certificate verification, and brand protection">
      <div class="ps-visual-heading"><span class="ps-visual-dot"></span>DOMAIN INTELLIGENCE<span class="ps-visual-label">ILLUSTRATION</span></div>
      <div class="ps-scan-stage">
        <div class="ps-network-lines" aria-hidden="true"><i></i><i></i><i></i></div>
        <div class="ps-network-node ps-node-domain">{_icon('globe')}<span>Domains</span></div>
        <div class="ps-network-node ps-node-certificate">{_icon('file-key')}<span>Certificates</span></div>
        <div class="ps-scan-core"><div class="ps-core-ring"></div><div class="ps-core-icon">{_icon('scan-search')}</div><span>Inspect signals</span></div>
        <div class="ps-network-node ps-node-shield">{_icon('shield-check')}<span>Brand protection</span></div>
      </div>
      <div class="ps-domain-window"><div class="ps-domain-window-top"><i></i><i></i><i></i><span>Domain inspection</span></div>
        <div class="ps-domain-sweep" aria-hidden="true"></div>
        <div class="ps-domain-line"><span>01</span><b>brand.example</b><i></i><i></i><i></i></div>
        <div class="ps-domain-line"><span>02</span><b>certificate signals</b><i></i><i></i><i></i></div>
        <div class="ps-domain-line"><span>03</span><b>visual evidence</b><i></i><i></i><i></i></div>
      </div>
    </div>'''


SCANNER_CSS = '''
.ps-scan-visual { width:100%;box-sizing:border-box;position:relative;border:1px solid #60a5fa40;border-radius:12px;background:linear-gradient(145deg,#142c49c9,#091a2dd9);overflow:hidden;box-shadow:inset 0 1px #b7d8ff18,0 16px 40px #0002; }
.ps-visual-heading { display:flex;align-items:center;gap:8px;padding:16px 18px;border-bottom:1px solid #60a5fa20;color:#aacfff;font:650 10px/1.4 Manrope,sans-serif;letter-spacing:.1em; }
.ps-visual-dot { height:6px;width:6px;border-radius:50%;background:#60a5fa;box-shadow:0 0 10px #60a5fa66; }
.ps-visual-label { margin-left:auto;color:#7f9cba;font-size:8px;letter-spacing:.08em; }
.ps-scan-stage { height:200px;position:relative;background-image:radial-gradient(#60a5fa18 1px,transparent 1px);background-size:18px 18px; }
.ps-network-lines { position:absolute;inset:0; }
.ps-network-lines i { position:absolute;height:1px;background:linear-gradient(90deg,#60a5fa22,#93c5fd,#60a5fa22);background-size:100px 1px;animation:ps-data-flow 4s linear infinite; }
.ps-network-lines i:nth-child(1) { left:17%;top:32%;width:31%;transform:rotate(20deg);transform-origin:left; }
.ps-network-lines i:nth-child(2) { left:17%;top:73%;width:31%;transform:rotate(-20deg);transform-origin:left; }
.ps-network-lines i:nth-child(3) { left:60%;top:48%;width:23%; }
.ps-network-node { position:absolute;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:8px;color:#9ac4f7;font:500 10px/1.4 Manrope,sans-serif; }
.ps-network-node img { width:28px;height:28px;padding:12px;border:1px solid #60a5fa40;border-radius:12px;background:#102942;box-sizing:content-box; }
.ps-node-domain { left:5%;top:16px; }
.ps-node-certificate { left:4%;bottom:12px; }
.ps-node-shield { right:4%;top:62px; }
.ps-node-shield img { background:#17365b; }
.ps-scan-core { position:absolute;top:42px;left:50%;transform:translateX(-50%);width:110px;height:110px;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:10px;color:#e6f1ff;font:600 11px/1.3 Manrope,sans-serif; }
.ps-core-ring { position:absolute;inset:0;border:1px solid #60a5fa30;border-top:2px solid #93c5fd;border-radius:50%;animation:ps-core-orbit 8s linear infinite; }
.ps-core-icon { display:flex;align-items:center;justify-content:center;width:58px;height:58px;border-radius:14px;border:1px solid #93c5fd66;background:linear-gradient(145deg,#2862a7,#153a67);box-shadow:0 0 28px #3b82f628,inset 0 1px #dbeafe30; }
.ps-core-icon img { width:32px;height:32px; }
.ps-domain-window { position:relative;margin:0 18px 18px;border:1px solid #60a5fa30;border-radius:7px;background:#081a2cc9;overflow:hidden; }
.ps-domain-window-top { display:flex;align-items:center;gap:5px;padding:9px 12px;border-bottom:1px solid #60a5fa22;color:#89a4c0;font:500 9px/1.4 Manrope,sans-serif; }
.ps-domain-window-top>i { height:4px;width:4px;border-radius:50%;background:#5884b1; }
.ps-domain-window-top>span { margin-left:7px; }
.ps-domain-line { display:flex;align-items:center;gap:10px;padding:8px 12px;font:400 10px/1.3 Manrope,sans-serif;color:#9db9d7; }
.ps-domain-line>span { color:#536f8e;font-size:9px; }
.ps-domain-line>b { margin-right:auto;font-weight:500; }
.ps-domain-line>i { width:18px;height:3px;background:#254b75;border-radius:2px;animation:ps-signal-light 3.6s ease-in-out infinite; }
.ps-domain-line:nth-child(4)>i { animation-delay:1.2s; }.ps-domain-line:nth-child(5)>i { animation-delay:2.4s; }
.ps-domain-sweep { position:absolute;z-index:1;inset:30px 0 auto;height:22px;pointer-events:none;background:linear-gradient(0deg,#60a5fa00,#60a5fa14);border-top:1px solid #93c5fd88;animation:ps-domain-sweep 3.6s ease-in-out infinite; }
@keyframes ps-domain-sweep { 0%,100% { transform:translateY(0);opacity:.2; } 50% { transform:translateY(64px);opacity:1; } }
@keyframes ps-data-flow { to { background-position:200px 0; } }
@keyframes ps-core-orbit { to { transform:rotate(360deg); } }
@keyframes ps-signal-light { 0%,70%,100% { background:#254b75; } 35% { background:#93c5fd; } }
@media(prefers-reduced-motion:reduce) { .ps-scan-visual * { animation:none!important; } }
'''

HERO_CSS = '''
#ps-security-hero { display:grid;grid-template-columns:1fr 1fr;align-items:center;gap:36px;padding:28px;border:1px solid #60a5fa40;border-top:3px solid #60a5fa;border-radius:10px;background:linear-gradient(120deg,#0d2139db,#102942a8);backdrop-filter:blur(24px);box-shadow:inset 0 1px #dbeafe14,5px 5px 0 #0003; }
#ps-security-hero * { box-sizing:border-box; }
.ps-hero-eyebrow { display:flex;align-items:center;gap:8px;color:#93c5fd;font:650 11px/1.5 Manrope,sans-serif;letter-spacing:.08em;text-transform:uppercase;margin-bottom:16px; }
.ps-hero-eyebrow img { width:18px;height:18px; }
.ps-hero-title { font:600 clamp(30px,3.3vw,44px)/1.12 'Space Grotesk',sans-serif;color:#eff6ff;letter-spacing:-.045em;margin-bottom:20px; }
.ps-hero-title span { color:#93c5fd; }
.ps-hero-description { font:400 15px/1.7 Manrope,sans-serif;color:#becfe0;max-width:500px;margin-bottom:22px; }
.ps-hero-tags { display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px; }
.ps-hero-tags span { padding:6px 9px;border:1px solid #60a5fa30;border-radius:4px;color:#bad3ed;background:#60a5fa08;font:500 11px/1.4 Manrope,sans-serif; }
.ps-stream-status { display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;padding:12px 14px;border:1px solid #60a5fa30;border-radius:6px;background:#60a5fa09;color:#bdcfe2;font:500 11px/1.5 Manrope,sans-serif; }
.ps-stream-status strong { font-weight:650;color:#93c5fd;font-variant-numeric:tabular-nums; }
.ps-status-pip { width:6px;height:6px;border-radius:50%;background:#a5b5c8; }
.ps-stream-connected .ps-status-pip { background:#60a5fa;box-shadow:0 0 10px #60a5fa66; }
@media(max-width:900px) { #ps-security-hero { gap:24px;padding:24px; } .ps-hero-title { font-size:34px; } }
@media(max-width:700px) { #ps-security-hero { grid-template-columns:1fr;padding:20px;gap:24px; } .ps-hero-title { font-size:32px; } .ps-scan-visual { max-width:480px;margin:auto; } }
'''
