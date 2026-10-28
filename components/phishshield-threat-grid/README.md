# PhishShield threat grid

Animated AG Grid Community 36.2.0 table for Domain Explorer. Generated from the official Streamlit CCv2 Pure TypeScript template.

Install from the repository root:

```powershell
.venv/Scripts/python.exe -m pip install -e ./components/phishshield-threat-grid
```

The compiled assets are included, so Node.js is only needed when editing the frontend. From `phishshield_threat_grid/frontend`, run `npm ci` then `npm run build` (Node 24+). The build emits `index.js` and `style.css`; Python loads those exact filenames so stale hashed bundles cannot conflict.

`threat_grid(rows, selected_id=None, key="threat_grid", on_open=None)` accepts finding dictionaries with `id`, `domain`, `brand`, `severity`, `score`, `website`, and `review`. Row clicks and Enter emit an `opened` trigger containing the stable finding ID. The parent validates this ID against the current filtered findings before opening evidence.

Sorting and pagination run locally. Their state is preserved in session storage across reruns. Motion follows the operating system reduced-motion setting. No remote CDN, Google Font fetch, or paid AG Grid modules are required. AG Grid's MIT license is included in `AG-GRID-LICENSE.txt`.


The security illustration is a locally bundled SVG radar. A timestamp-based requestAnimationFrame loop rotates its scan without flashes or glowing dots. Reduced-motion preferences pause the rotation. No remote animation runtime is needed.
