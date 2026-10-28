"""
app.py
CyberSentinel: Next-Gen Brand Protection & Threat Intelligence Platform
Continuous background surveillance defending against lookalike domains,
rogue SSL/TLS certificates, and visual phishing clones.

Design System: White Glassmorphism with Frosted Glass Aesthetics
Strictly enforces:
- Max 3 monitored websites in continuous background surveillance
- Native local execution with embedded SQLite storage (data/phishing_detector.db)
- User-friendly filters (Liveness: Active/Offline, Risk Severity, Target Brand, Status, Search)
- Interactive Tables and Card Gallery views (as referenced from dashboard/app.py)
- Animated radar scanner, aurora background, and luminous glassmorphic metric cards
- Live CT stream telemetry from background worker
- Side-by-side visual pHash comparison, forensic dossier, and case triage
- Vector PDF incident reports and registrar takedown support
"""

import os
import sys
import json
import time
import inspect
from pathlib import Path
from datetime import datetime, timezone
import urllib.parse

import streamlit as st

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
LOGO_PATH = str(Path(ROOT_DIR) / "cybersentinel-mark.png")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# -----------------------------------------------------------------------------
# Streamlit Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="CyberSentinel | Domain Defense",
    page_icon=LOGO_PATH,
    layout="wide",
    initial_sidebar_state="expanded",
)

from src.ui.loading import task_loading

with task_loading('Opening CyberSentinel', 'Loading your workspace and the latest findings.'):
    import pandas as pd
    from dotenv import load_dotenv
    load_dotenv(override=True)
    from src.storage import db
    from src.storage.db import update_candidate_review, get_all_candidates, get_candidate
    from src.storage.models import Candidate, Brand, DiscoveryObservation
    from src.ingest.background_service import (
        start_background_monitor, stop_background_monitor, get_monitor_status,
        MAX_WATCHLIST_LIMIT,
    )
    from src.ui.security_icons import security_icon
    from src.ui.presentation import apply_frontend_theme, render_security_hero, render_sidebar_menu
    from src.ui.dashboard_data import get_all_flagged_with_observations
    from src.ui.navigation import prepare_scan

    @st.cache_resource(show_spinner=False)
    def initialize_database():
        db.init_db()
        return True

    initialize_database()
    start_background_monitor()

# -----------------------------------------------------------------------------
# Premium White Glassmorphism CSS Architecture
# -----------------------------------------------------------------------------
st.markdown("""
<style>
    html, body, [class*="css"] {
        font-family: Inter, "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Full-Screen Looping Video Background */
    .app-video-bg-container {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        z-index: -9999;
        overflow: hidden;
        pointer-events: none;
        background-color: #000000;
    }
    .app-video-bg-container video {
        width: 100%;
        height: 100%;
        object-fit: cover;
        filter: saturate(1.15) brightness(0.72);
    }
    .app-video-vignette {
        position: absolute;
        inset: 0;
        background:
            radial-gradient(circle at center, rgba(0, 0, 0, 0.25) 0%, rgba(0, 0, 0, 0.72) 100%),
            linear-gradient(to top, rgba(0, 0, 0, 0.8) 0%, rgba(0, 0, 0, 0.2) 50%, rgba(0, 0, 0, 0.5) 100%);
        pointer-events: none;
    }

    [data-testid="stAppViewContainer"], .stApp {
        background: transparent !important;
        background-color: transparent !important;
        color: #0f172a !important;
    }

    [data-testid="stHeader"] {
        background: transparent !important;
    }

    /* Frosted Glass Sidebar */
    [data-testid="stSidebar"] {
        background: rgba(10, 14, 22, 0.78) !important;
        backdrop-filter: blur(24px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(24px) saturate(180%) !important;
        border-right: 1px solid rgba(255, 255, 255, 0.12) !important;
        box-shadow: 4px 0 24px rgba(0, 0, 0, 0.4) !important;
    }
    [data-testid="stSidebar"] * {
        color: #f1f5f9 !important;
    }
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] {
        gap: 0.6rem !important;
    }
    [data-testid="stSidebar"] [data-testid="stButton"] > button {
        min-height: 42px !important;
        padding: 0.45rem 0.75rem !important;
        border-radius: 10px !important;
    }
    [data-testid="stSidebar"] [data-testid="stIconMaterial"] {
        font-size: 1.1rem !important;
    }

    /* Dark Transparent Glassmorphic Command Header */
    .command-header {
        background: rgba(13, 17, 23, 0.74) !important;
        backdrop-filter: blur(24px) saturate(190%) !important;
        -webkit-backdrop-filter: blur(24px) saturate(190%) !important;
        border: 1px solid rgba(255, 255, 255, 0.14) !important;
        border-radius: 20px !important;
        padding: 24px 30px !important;
        margin-bottom: 22px !important;
        box-shadow: 0 16px 38px -6px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1) !important;
    }
    .header-title {
        font-size: 2.25rem;
        font-weight: 850;
        letter-spacing: -0.025em;
        background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 50%, #38bdf8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .header-desc {
        color: #94a3b8;
        font-size: 0.96rem;
        margin-top: 6px;
        line-height: 1.55;
    }
    .status-hud-glass {
        background: rgba(255, 255, 255, 0.08);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 14px;
        padding: 12px 20px;
        text-align: right;
        box-shadow: 0 6px 18px rgba(0, 0, 0, 0.25);
    }

    /* Metric Boxes (Luminous Glassmorphic HUD with Dynamic Hover Micro-Interactions) */
    .metric-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
        gap: 12px;
        margin-bottom: 18px;
    }
    .metric-box {
        background: rgba(13, 17, 23, 0.74) !important;
        backdrop-filter: blur(22px) saturate(190%) !important;
        -webkit-backdrop-filter: blur(22px) saturate(190%) !important;
        border: 1px solid rgba(255, 255, 255, 0.13) !important;
        border-radius: 18px !important;
        padding: 16px 18px !important;
        box-shadow: 0 12px 30px rgba(0, 0, 0, 0.38), inset 0 1px 0 rgba(255, 255, 255, 0.12) !important;
        position: relative;
        overflow: hidden;
        translate: 0 0;
        scale: 1;
        transition: translate 0.22s cubic-bezier(0.16, 1, 0.3, 1), scale 0.22s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.22s ease, border-color 0.22s ease !important;
    }
    .metric-box:hover {
        translate: 0 -4px;
        scale: 1.018;
        box-shadow: 0 20px 42px rgba(0, 0, 0, 0.58), 0 0 24px rgba(56, 189, 248, 0.25) !important;
        border-color: rgba(56, 189, 248, 0.55) !important;
    }
    .metric-box::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        box-shadow: 0 0 10px currentColor;
    }
    .m-purple::before { background: linear-gradient(90deg, #8b5cf6, #c084fc); color: #8b5cf6; }
    .m-blue::before { background: linear-gradient(90deg, #0284c7, #38bdf8); color: #38bdf8; }
    .m-red::before { background: linear-gradient(90deg, #ef4444, #f87171); color: #ef4444; }
    .m-amber::before { background: linear-gradient(90deg, #f59e0b, #fbbf24); color: #f59e0b; }
    .m-green::before { background: linear-gradient(90deg, #3b82f6, #60a5fa); color: #3b82f6; }

    .m-header-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 6px;
    }
    .m-label {
        font-size: 0.78rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        color: #94a3b8;
    }
    .m-badge-pill {
        font-size: 0.68rem;
        font-weight: 800;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        padding: 2px 7px;
        border-radius: 9999px;
        display: inline-flex;
        align-items: center;
        gap: 4px;
    }
    .m-pill-purple { background: rgba(139, 92, 246, 0.2); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.45); }
    .m-pill-blue { background: rgba(14, 165, 233, 0.2); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.45); }
    .m-pill-red { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.45); }
    .m-pill-green { background: rgba(16, 185, 129, 0.2); color: #60a5fa; border: 1px solid rgba(16, 185, 129, 0.45); }

    .m-value {
        font-size: 2.35rem;
        font-weight: 900;
        color: #ffffff;
        line-height: 1.1;
        text-shadow: 0 2px 10px rgba(0, 0, 0, 0.5);
    }
    .m-sub {
        font-size: 0.82rem;
        color: #94a3b8;
        margin-top: 6px;
        font-weight: 500;
    }

    /* 3-Website Slot Cards (Interactive Cyber-Bays) */
    .slot-card {
        background: rgba(13, 17, 23, 0.76) !important;
        backdrop-filter: blur(20px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(20px) saturate(180%) !important;
        border: 1.5px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 18px !important;
        padding: 20px 22px !important;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.35) !important;
        position: relative;
        translate: 0 0;
        scale: 1;
        transition: translate 0.2s cubic-bezier(0.16, 1, 0.3, 1), scale 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease, box-shadow 0.2s ease !important;
    }
    .slot-card:hover {
        translate: 0 -3px;
        scale: 1.015;
        border-color: #38bdf8 !important;
        box-shadow: 0 18px 38px rgba(0, 0, 0, 0.55), 0 0 24px rgba(56, 189, 248, 0.3) !important;
    }
    .slot-card-empty {
        background: rgba(13, 17, 23, 0.45) !important;
        backdrop-filter: blur(14px) !important;
        -webkit-backdrop-filter: blur(14px) !important;
        border: 2px dashed rgba(255, 255, 255, 0.2) !important;
        border-radius: 18px !important;
        padding: 24px !important;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        text-align: center;
        translate: 0 0;
        scale: 1;
        transition: translate 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease !important;
    }
    .slot-card-empty:hover {
        translate: 0 -2px;
        border-color: #38bdf8 !important;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.4), 0 0 18px rgba(56, 189, 248, 0.2) !important;
    }
    .slot-badge-active {
        background: rgba(16, 185, 129, 0.2);
        color: #60a5fa;
        border: 1px solid rgba(16, 185, 129, 0.55);
        font-size: 0.72rem;
        font-weight: 800;
        text-transform: uppercase;
        padding: 4px 10px;
        border-radius: 8px;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        margin-bottom: 8px;
        box-shadow: 0 0 12px rgba(16, 185, 129, 0.25);
    }
    .slot-domain {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.28rem;
        font-weight: 850;
        color: #ffffff;
        letter-spacing: -0.01em;
    }

    /* Filter Control Toolbar Card (Transparent Frosted Glass) */
    .filter-panel {
        background: rgba(13, 17, 23, 0.74) !important;
        backdrop-filter: blur(20px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(20px) saturate(180%) !important;
        border: 1.5px solid rgba(255, 255, 255, 0.14) !important;
        border-radius: 18px !important;
        padding: 18px 20px !important;
        margin-bottom: 18px !important;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.08) !important;
    }
    .filter-panel-title {
        font-size: 0.88rem;
        font-weight: 850;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #cbd5e1;
        margin-bottom: 10px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    [data-testid="stSegmentedControl"] {
        max-width: 100%;
        overflow-x: auto;
        overscroll-behavior-x: contain;
        scrollbar-width: none;
        touch-action: pan-x;
    }
    [data-testid="stSegmentedControl"]::-webkit-scrollbar {
        display: none;
    }

    /* Threat Cards (Card Gallery View with Dynamic Neon Edge Illumination) */
    .threat-card {
        background: rgba(13, 17, 23, 0.78) !important;
        backdrop-filter: blur(20px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(20px) saturate(180%) !important;
        border: 1px solid rgba(255, 255, 255, 0.13) !important;
        border-radius: 18px !important;
        padding: 22px !important;
        margin-bottom: 22px !important;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.38) !important;
        translate: 0 0;
        scale: 1;
        transition: translate 0.22s cubic-bezier(0.16, 1, 0.3, 1), scale 0.22s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.22s ease, border-color 0.22s ease !important;
    }
    .threat-card:hover {
        translate: 0 -3px;
        scale: 1.01;
    }
    .threat-card-high {
        border-left: 6px solid #ef4444 !important;
        background: linear-gradient(180deg, rgba(38, 14, 18, 0.85) 0%, rgba(13, 17, 23, 0.78) 100%) !important;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(239, 68, 68, 0.25) !important;
    }
    .threat-card-high:hover {
        border-color: rgba(239, 68, 68, 0.6) !important;
        box-shadow: 0 20px 48px rgba(0, 0, 0, 0.6), 0 0 30px rgba(239, 68, 68, 0.35) !important;
    }
    .threat-card-med {
        border-left: 6px solid #f59e0b !important;
        background: linear-gradient(180deg, rgba(38, 24, 12, 0.85) 0%, rgba(13, 17, 23, 0.78) 100%) !important;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(245, 158, 11, 0.25) !important;
    }
    .threat-card-med:hover {
        border-color: rgba(245, 158, 11, 0.6) !important;
        box-shadow: 0 20px 48px rgba(0, 0, 0, 0.6), 0 0 30px rgba(245, 158, 11, 0.35) !important;
    }
    .threat-card-low {
        border-left: 6px solid #3b82f6 !important;
        background: linear-gradient(180deg, rgba(12, 32, 22, 0.85) 0%, rgba(13, 17, 23, 0.78) 100%) !important;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(16, 185, 129, 0.25) !important;
    }
    .threat-card-low:hover {
        border-color: rgba(16, 185, 129, 0.6) !important;
        box-shadow: 0 20px 48px rgba(0, 0, 0, 0.6), 0 0 30px rgba(16, 185, 129, 0.35) !important;
    }

    .card-domain-title {
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.35rem;
        font-weight: 850;
        color: #ffffff;
        word-break: break-all;
        letter-spacing: -0.015em;
    }
    .pill-high {
        background: rgba(239, 68, 68, 0.24);
        color: #fca5a5;
        border: 1px solid rgba(239, 68, 68, 0.6);
        padding: 6px 14px;
        border-radius: 10px;
        font-weight: 850;
        font-size: 0.84rem;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 0 14px rgba(239, 68, 68, 0.28);
    }
    .pill-med {
        background: rgba(245, 158, 11, 0.24);
        color: #fcd34d;
        border: 1px solid rgba(245, 158, 11, 0.6);
        padding: 6px 14px;
        border-radius: 10px;
        font-weight: 850;
        font-size: 0.84rem;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 0 14px rgba(245, 158, 11, 0.28);
    }
    .pill-low {
        background: rgba(16, 185, 129, 0.24);
        color: #6ee7b7;
        border: 1px solid rgba(16, 185, 129, 0.6);
        padding: 6px 14px;
        border-radius: 10px;
        font-weight: 850;
        font-size: 0.84rem;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 0 14px rgba(16, 185, 129, 0.28);
    }

    .tag-badge {
        font-size: 0.78rem;
        font-weight: 750;
        background: rgba(255, 255, 255, 0.08);
        color: #e2e8f0;
        padding: 5px 12px;
        border-radius: 8px;
        border: 1px solid rgba(255, 255, 255, 0.15);
        display: inline-flex;
        align-items: center;
        gap: 5px;
        margin-right: 6px;
        margin-bottom: 6px;
    }
    .tag-live {
        background: rgba(16, 185, 129, 0.2);
        color: #60a5fa;
        border-color: rgba(16, 185, 129, 0.5);
        font-weight: 850;
        box-shadow: 0 0 10px rgba(16, 185, 129, 0.2);
    }
    .tag-offline {
        background: rgba(239, 68, 68, 0.18);
        color: #f87171;
        border-color: rgba(239, 68, 68, 0.45);
    }
    .tag-alert {
        background: rgba(239, 68, 68, 0.22);
        color: #fca5a5;
        border: 1px solid rgba(239, 68, 68, 0.55);
        font-weight: 850;
        box-shadow: 0 0 10px rgba(239, 68, 68, 0.2);
    }
    .tag-success {
        background: rgba(16, 185, 129, 0.2);
        color: #60a5fa;
        border: 1px solid rgba(16, 185, 129, 0.45);
    }

    /* Radar Beacon Pulses */
    @keyframes beacon-ping {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.8); }
        70% { transform: scale(1.05); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }
    @keyframes red-beacon-ping {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.8); }
        70% { transform: scale(1.05); box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }
    .beacon-live {
        display: inline-block;
        width: 8px;
        height: 8px;
        background: #3b82f6;
        border-radius: 50%;
        margin-right: 5px;
        animation: beacon-ping 1.8s infinite;
    }
    .beacon-alert {
        display: inline-block;
        width: 8px;
        height: 8px;
        background: #ef4444;
        border-radius: 50%;
        margin-right: 5px;
        animation: red-beacon-ping 1.8s infinite;
    }

    /* Live Stream Rows with Hover Illumination */
    .stream-row {
        background: rgba(13, 17, 23, 0.74);
        backdrop-filter: blur(16px);
        border: 1px solid rgba(255, 255, 255, 0.12);
        border-radius: 14px;
        padding: 14px 20px;
        margin-bottom: 10px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 6px 18px rgba(0, 0, 0, 0.25);
        translate: 0 0;
        transition: translate 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .stream-row:hover {
        translate: 0 -2px;
        border-color: rgba(56, 189, 248, 0.4);
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }
    .stream-row-match {
        border-left: 5px solid #ef4444;
        background: linear-gradient(90deg, rgba(60, 15, 20, 0.8) 0%, rgba(13, 17, 23, 0.75) 100%);
    }

    .sim-bar-bg {
        background: rgba(255, 255, 255, 0.12);
        border-radius: 8px;
        height: 9px;
        width: 100%;
        overflow: hidden;
        margin: 6px 0;
        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.4);
    }
    .sim-bar-fill {
        height: 100%;
        border-radius: 8px;
        transition: width 0.6s cubic-bezier(0.16, 1, 0.3, 1);
    }

    /* Laser Scanner Beam */
    @keyframes scan-sweep {
        0% { transform: translateY(-100%); opacity: 0; }
        30% { opacity: 0.9; }
        80% { opacity: 0.9; }
        100% { transform: translateY(320px); opacity: 0; }
    }
    .scanner-laser {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(90deg, transparent 0%, #38bdf8 25%, #ffffff 50%, #38bdf8 75%, transparent 100%);
        box-shadow: 0 0 16px #38bdf8, 0 0 32px rgba(56, 189, 248, 0.8);
        animation: scan-sweep 3.5s cubic-bezier(0.4, 0, 0.2, 1) infinite;
        pointer-events: none;
        z-index: 4;
    }

    /* =====================================================
       ANIMATED 3D WIREFRAME RADAR GLOBE SCANNER
       (Transparent Dark Glassmorphic Viewport)
       ===================================================== */
    .scanner-shell {
        position: relative;
        overflow: hidden;
        min-height: 290px;
        max-height: 330px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 24px;
        border-radius: 22px;
        background: radial-gradient(circle at center, rgba(14, 165, 233, 0.14) 0%, rgba(13, 17, 23, 0.75) 50%, rgba(7, 9, 14, 0.95) 100%) !important;
        backdrop-filter: blur(24px) saturate(180%) !important;
        -webkit-backdrop-filter: blur(24px) saturate(180%) !important;
        border: 1px solid rgba(14, 165, 233, 0.35) !important;
        box-shadow: 0 16px 42px -6px rgba(0, 0, 0, 0.55), inset 0 0 60px rgba(14, 165, 233, 0.08) !important;
    }
    .scanner-grid {
        position: absolute;
        inset: 0;
        background-image:
            linear-gradient(rgba(14, 165, 233, 0.07) 1px, transparent 1px),
            linear-gradient(90deg, rgba(14, 165, 233, 0.07) 1px, transparent 1px);
        background-size: 32px 32px;
        opacity: 0.75;
    }
    .scanner-content {
        position: relative;
        z-index: 5;
        width: 100%;
        display: flex;
        align-items: center;
        flex-direction: column;
    }
    .orb-area {
        position: relative;
        width: 190px;
        height: 190px;
        display: flex;
        align-items: center;
        justify-content: center;
        perspective: 1000px;
    }
    .outer-ring {
        position: absolute;
        width: 185px;
        height: 185px;
        border-radius: 50%;
        border: 1.5px solid rgba(2, 132, 199, 0.55);
        border-top-color: rgba(56, 189, 248, 0.98);
        border-left-color: rgba(14, 165, 233, 0.85);
        animation: ring-spin 5.5s linear infinite;
        box-shadow: 0 0 24px rgba(14, 165, 233, 0.35);
    }
    .outer-ring-two {
        position: absolute;
        width: 220px;
        height: 220px;
        border-radius: 50%;
        border: 1px solid rgba(99, 102, 241, 0.35);
        border-right-color: rgba(129, 140, 248, 0.85);
        animation: ring-spin-reverse 8s linear infinite;
    }
    .sphere {
        position: relative;
        width: 140px;
        height: 140px;
        border-radius: 50%;
        transform-style: preserve-3d;
        filter: drop-shadow(0 0 10px rgba(2, 132, 199, 0.8)) drop-shadow(0 0 26px rgba(14, 165, 233, 0.45));
        animation: sphere-rotate 7s linear infinite;
    }
    .sphere-glow {
        position: absolute;
        inset: -15px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(14, 165, 233, 0.3) 0%, rgba(14, 165, 233, 0.12) 45%, rgba(14, 165, 233, 0) 75%);
        animation: glow-pulse 2.2s ease-in-out infinite;
    }
    .longitude, .latitude {
        position: absolute;
        left: 0; right: 0; top: 0; bottom: 0;
        margin: auto;
        border: 1.3px solid rgba(56, 189, 248, 0.85);
        box-sizing: border-box;
        pointer-events: none;
    }
    .longitude {
        width: 100%;
        height: 100%;
        border-radius: 50%;
    }
    .lon1 { transform: rotateY(15deg) scaleX(0.94); }
    .lon2 { transform: rotateY(30deg) scaleX(0.84); }
    .lon3 { transform: rotateY(45deg) scaleX(0.70); }
    .lon4 { transform: rotateY(60deg) scaleX(0.52); }
    .lon5 { transform: rotateY(78deg) scaleX(0.34); }
    .lon6 { transform: rotateY(102deg) scaleX(0.34); }
    .lon7 { transform: rotateY(120deg) scaleX(0.52); }
    .lon8 { transform: rotateY(135deg) scaleX(0.70); }
    .lon9 { transform: rotateY(150deg) scaleX(0.84); }
    .lon10 { transform: rotateY(165deg) scaleX(0.94); }
    .latitude {
        width: 100%;
        height: 48%;
        border-radius: 50%;
        top: 26%;
    }
    .lat1 { transform: scaleY(0.25); }
    .lat2 { transform: scaleY(0.43); }
    .lat3 { transform: scaleY(0.60); }
    .lat4 { transform: scaleY(0.77); }
    .lat5 { transform: scaleY(0.93); }
    .sphere-center {
        position: absolute;
        width: 9px;
        height: 9px;
        left: calc(50% - 4.5px);
        top: calc(50% - 4.5px);
        border-radius: 50%;
        background: #38bdf8;
        box-shadow: 0 0 8px #ffffff, 0 0 18px #38bdf8, 0 0 35px rgba(2, 132, 199, 0.95);
        animation: center-pulse 1.35s ease-in-out infinite;
    }
    .scanner-status {
        margin-top: 15px;
        color: #ffffff;
        font-size: 1.25rem;
        font-weight: 900;
        letter-spacing: 6px;
        text-shadow: 0 0 16px rgba(14, 165, 233, 0.6);
        animation: status-pulse 1.7s ease-in-out infinite;
    }
    .scanner-substatus {
        margin-top: 5px;
        color: #94a3b8;
        font-size: 0.76rem;
        font-weight: 750;
        letter-spacing: 2.5px;
        text-align: center;
    }

    @keyframes sphere-rotate {
        from { transform: rotateY(0deg) rotateX(9deg); }
        to { transform: rotateY(360deg) rotateX(9deg); }
    }
    @keyframes ring-spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    @keyframes ring-spin-reverse {
        from { transform: rotate(360deg); }
        to { transform: rotate(0deg); }
    }
    @keyframes glow-pulse {
        0%, 100% { opacity: 0.55; transform: scale(0.96); }
        50% { opacity: 1; transform: scale(1.04); }
    }
    @keyframes center-pulse {
        0%, 100% { opacity: 0.6; transform: scale(0.75); }
        50% { opacity: 1; transform: scale(1.4); }
    }
    @keyframes status-pulse {
        0%, 100% { opacity: 0.65; }
        50% { opacity: 1; }
    }

    /* Glassmorphic Streamlit Form Elements with Focus Glow */
    div[data-baseweb="select"] > div, div[data-baseweb="input"] > div {
        background: rgba(15, 23, 42, 0.74) !important;
        backdrop-filter: blur(14px) !important;
        -webkit-backdrop-filter: blur(14px) !important;
        border-radius: 12px !important;
        border: 1.5px solid rgba(255, 255, 255, 0.16) !important;
        color: #ffffff !important;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25) !important;
        transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
    }
    div[data-baseweb="select"] > div:hover, div[data-baseweb="input"] > div:hover {
        border-color: rgba(56, 189, 248, 0.5) !important;
    }
    div[data-baseweb="select"] > div:focus-within, div[data-baseweb="input"] > div:focus-within {
        border-color: #38bdf8 !important;
        box-shadow: 0 0 18px rgba(56, 189, 248, 0.35) !important;
    }
    div[data-baseweb="select"] * {
        color: #f1f5f9 !important;
    }
    .stTextInput input, .stTextArea textarea {
        color: #ffffff !important;
    }
    .stSelectbox label, .stTextInput label, .stTextArea label, .stMultiSelect label, .stRadio label {
        color: #cbd5e1 !important;
        font-weight: 750 !important;
        font-size: 0.88rem !important;
        letter-spacing: 0.02em !important;
    }

    /* Dynamic Interactive Buttons (Cyber-Glass with Glow & Scale) */
    .stButton > button {
        border-radius: 12px !important;
        font-weight: 750 !important;
        letter-spacing: 0.02em !important;
        border: 1px solid rgba(255, 255, 255, 0.16) !important;
        background: rgba(15, 23, 42, 0.68) !important;
        color: #f8fafc !important;
        backdrop-filter: blur(14px) !important;
        -webkit-backdrop-filter: blur(14px) !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.12) !important;
        translate: 0 0 !important;
        scale: 1 !important;
        transition: translate 0.18s cubic-bezier(0.16, 1, 0.3, 1), scale 0.18s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.18s ease, background 0.18s ease, border-color 0.18s ease, color 0.18s ease !important;
        cursor: pointer !important;
    }
    .stButton > button:hover {
        background: rgba(30, 41, 59, 0.88) !important;
        border-color: rgba(56, 189, 248, 0.65) !important;
        color: #38bdf8 !important;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45), 0 0 20px rgba(56, 189, 248, 0.35) !important;
        translate: 0 -2px !important;
        scale: 1.02 !important;
    }
    .stButton > button:active {
        translate: 0 1px !important;
        scale: 0.98 !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3) !important;
    }

    /* Primary Accent Buttons (Luminous Cyber-Gradient) */
    .stButton > button[kind="primary"], button[data-testid="baseButton-primary"] {
        background: linear-gradient(135deg, #0ea5e9 0%, #2563eb 50%, #6366f1 100%) !important;
        color: #ffffff !important;
        border: 1px solid rgba(125, 211, 252, 0.5) !important;
        box-shadow: 0 6px 22px rgba(14, 165, 233, 0.45), 0 0 16px rgba(37, 99, 235, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.35) !important;
        font-weight: 850 !important;
    }
    .stButton > button[kind="primary"]:hover, button[data-testid="baseButton-primary"]:hover {
        background: linear-gradient(135deg, #38bdf8 0%, #3b82f6 50%, #818cf8 100%) !important;
        color: #ffffff !important;
        border-color: rgba(255, 255, 255, 0.8) !important;
        box-shadow: 0 10px 32px rgba(14, 165, 233, 0.65), 0 0 28px rgba(56, 189, 248, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.5) !important;
        translate: 0 -2px !important;
        scale: 1.025 !important;
    }
    .stButton > button[kind="primary"]:active, button[data-testid="baseButton-primary"]:active {
        translate: 0 1px !important;
        scale: 0.98 !important;
    }

    /* Download Buttons (Cyber-Emerald Style) */
    .stDownloadButton > button {
        border-radius: 12px !important;
        font-weight: 800 !important;
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.85) 0%, rgba(5, 150, 105, 0.95) 100%) !important;
        border: 1px solid rgba(52, 211, 153, 0.55) !important;
        color: #ffffff !important;
        box-shadow: 0 4px 18px rgba(16, 185, 129, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.25) !important;
        translate: 0 0 !important;
        scale: 1 !important;
        transition: translate 0.18s cubic-bezier(0.16, 1, 0.3, 1), scale 0.18s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.18s ease !important;
    }
    .stDownloadButton > button:hover {
        background: linear-gradient(135deg, rgba(52, 211, 153, 0.95) 0%, rgba(16, 185, 129, 1) 100%) !important;
        border-color: rgba(255, 255, 255, 0.85) !important;
        box-shadow: 0 8px 30px rgba(16, 185, 129, 0.55), 0 0 25px rgba(52, 211, 153, 0.45) !important;
        translate: 0 -2px !important;
        scale: 1.02 !important;
    }

    /* Form Submit Buttons */
    .stFormSubmitButton > button {
        border-radius: 12px !important;
        font-weight: 850 !important;
        background: linear-gradient(135deg, #0284c7 0%, #2563eb 100%) !important;
        border: 1px solid rgba(56, 189, 248, 0.55) !important;
        color: #ffffff !important;
        box-shadow: 0 6px 22px rgba(2, 132, 199, 0.45) !important;
        translate: 0 0 !important;
        scale: 1 !important;
        transition: translate 0.18s ease, scale 0.18s ease, box-shadow 0.18s ease !important;
    }
    .stFormSubmitButton > button:hover {
        box-shadow: 0 10px 30px rgba(2, 132, 199, 0.65), 0 0 25px rgba(56, 189, 248, 0.5) !important;
        translate: 0 -2px !important;
        scale: 1.02 !important;
    }

    /* Sleek Floating Dock Tabs */
    div[data-baseweb="tab-list"] {
        background: rgba(13, 17, 23, 0.72) !important;
        backdrop-filter: blur(18px) !important;
        -webkit-backdrop-filter: blur(18px) !important;
        border: 1px solid rgba(255, 255, 255, 0.14) !important;
        border-radius: 14px !important;
        padding: 6px 8px !important;
        gap: 8px !important;
        margin-bottom: 20px !important;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3) !important;
    }
    button[role="tab"] {
        border-radius: 10px !important;
        color: #94a3b8 !important;
        font-weight: 750 !important;
        padding: 9px 18px !important;
        border: 1px solid transparent !important;
        transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
        background: transparent !important;
    }
    button[role="tab"]:hover {
        color: #ffffff !important;
        background: rgba(255, 255, 255, 0.08) !important;
        border-color: rgba(255, 255, 255, 0.18) !important;
    }
    button[role="tab"][aria-selected="true"] {
        background: linear-gradient(135deg, rgba(14, 165, 233, 0.3) 0%, rgba(59, 130, 246, 0.4) 100%) !important;
        color: #38bdf8 !important;
        border: 1px solid rgba(56, 189, 248, 0.55) !important;
        box-shadow: 0 4px 16px rgba(14, 165, 233, 0.3) !important;
    }
    div[data-baseweb="tab-highlight"] {
        background-color: #38bdf8 !important;
        height: 3px !important;
        border-radius: 3px !important;
    }

    [data-testid="stDataFrame"], [data-testid="stTable"] {
        background: rgba(13, 17, 23, 0.74) !important;
        backdrop-filter: blur(20px) !important;
        border: 1.5px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 16px !important;
        overflow: hidden !important;
        box-shadow: 0 12px 36px rgba(0, 0, 0, 0.45) !important;
    }
</style>
""", unsafe_allow_html=True)

apply_frontend_theme()

# -----------------------------------------------------------------------------
# Data Access Functions
# -----------------------------------------------------------------------------
def get_monitored_brands():
    """Retrieve monitored brands, strictly bounded to MAX_WATCHLIST_LIMIT (3)."""
    session = db.SessionLocal()
    try:
        return session.query(Brand).limit(MAX_WATCHLIST_LIMIT).all()
    finally:
        session.close()


def add_monitored_website(domain, name=None):
    """Add a new target website to the 3-website watchlist."""
    session = db.SessionLocal()
    try:
        count = session.query(Brand).count()
        if count >= MAX_WATCHLIST_LIMIT:
            return False, f"Maximum watchlist capacity reached ({MAX_WATCHLIST_LIMIT} websites). Remove one first."
        clean_d = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].rstrip(".")
        if not clean_d or "." not in clean_d:
            return False, "Please enter a valid domain name (e.g. paypal.com or netflix.com)."
        existing = session.query(Brand).filter_by(official_domain=clean_d).first()
        if existing:
            return False, f"'{clean_d}' is already in your monitored watchlist."
        brand_name = name.strip() if name and name.strip() else clean_d.split(".")[0].capitalize()
        b = Brand(
            organization_id=1,
            name=brand_name,
            official_domain=clean_d,
            official_website_url=f"https://{clean_d}",
            keywords=json.dumps([brand_name.lower(), clean_d.split(".")[0]]),
            alert_threshold=70,
        )
        session.add(b)
        session.commit()
        return True, f"Now monitoring: {brand_name} ({clean_d})"
    finally:
        session.close()


def remove_monitored_website(brand_id):
    """Remove a website from the 3-website watchlist."""
    session = db.SessionLocal()
    try:
        b = session.query(Brand).filter_by(id=brand_id).first()
        if b:
            name = b.name
            session.delete(b)
            session.commit()
            return True, f"Removed {name} from monitoring."
        return False, "Target website not found."
    finally:
        session.close()


# -----------------------------------------------------------------------------
# Sidebar Navigation & System Telemetry
# -----------------------------------------------------------------------------
with task_loading('Loading findings', 'Reading the latest evidence from your local database.'):
    all_flagged = get_all_flagged_with_observations()
    watched_brands = get_monitored_brands()
status_data = get_monitor_status()
events_seen = status_data.get("events_seen", 0)
matches_found = status_data.get("matches_found", 0)
active_brand_count = len(watched_brands)
monitor_state = str(status_data.get("state") or "unknown").replace("_", " ").upper()
try:
    heartbeat_age = time.time() - float(status_data.get("updated_at", 0))
except (TypeError, ValueError):
    heartbeat_age = float("inf")
monitor_active = status_data.get("state") == "connected" and 0 <= heartbeat_age <= 120
monitor_label = "MONITORING LIVE" if monitor_active else f"MONITOR {monitor_state}"
monitor_color = "#60a5fa" if monitor_active else "#fbbf24"

with st.sidebar:
    page = render_sidebar_menu(
        [
            ":material/travel_explore: Domain Explorer",
            ":material/space_dashboard: Executive Dashboard",
            ":material/verified_user: Brand Watchlist (Max 3)",
            ":material/radar: Live CT Stream",
            ":material/troubleshoot: On-Demand Scanner",
            ":material/science: Attack Simulations",
            ":material/description: Legal Reports & Dossiers",
        ],
        state_key="phishshield_current_page",
    )

    from src.ui.live_stream import render_monitor_badge
    render_monitor_badge()

    st.button("Refresh findings", icon=":material/refresh:", help="Refresh findings", key="sidebar_refresh", width="stretch")




# -----------------------------------------------------------------------------
# Global White Glassmorphic Command Header
# -----------------------------------------------------------------------------
if page != ":material/travel_explore: Domain Explorer":
    st.markdown(f"""
    <div class="command-header">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:16px;">
            <div>
                <div class="header-title">CyberSentinel security command</div>
                <div class="header-desc">
                    Continuous surveillance defending against lookalike domains,
                    unauthorized SSL/TLS certificates, and credential-harvesting phishing clones.
                </div>
            </div>
            <div class="status-hud-glass">
                <div style="display:flex; align-items:center; justify-content:flex-end; gap:8px; font-weight:800; color:{monitor_color}; font-size:0.88rem;">
                    <span style="display:inline-block; width:9px; height:9px; background:{monitor_color}; border-radius:50%; box-shadow:0 0 10px {monitor_color};"></span>
                    {security_icon("radar", live=monitor_active)} {monitor_label}
                </div>
                <div style="font-family:ui-monospace, Consolas, monospace; font-size:0.82rem; color:#c6d9e8; margin-top:4px; font-weight:600;">
                    Guarding <b>{active_brand_count}/3</b> Websites &nbsp;|&nbsp; CT Log: <b>{events_seen}</b> events
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# =============================================================================
# PAGE 1: DOMAIN EXPLORER (The Primary Threat Analysis & Filtering Hub)
# =============================================================================
if page == ":material/travel_explore: Domain Explorer":
    render_security_hero()

    # 2. Key Threat Metrics in Dynamic Luminous HUD Cards
    total_cand = len(all_flagged)
    live_cand = sum(1 for c, _ in all_flagged if c.is_live)
    login_cand = sum(1 for c, _ in all_flagged if c.has_login_form)
    high_cand = sum(1 for c, _ in all_flagged if (c.risk_level or "").upper() == "HIGH")

    st.markdown(f"""
    <div class="metric-grid">
        <div class="metric-box m-purple">
            <div class="m-header-row">
                <span class="m-label">{security_icon("domain")}Database Candidates</span>
                <span class="m-badge-pill m-pill-purple">RECORDS</span>
            </div>
            <div class="m-value">{total_cand}</div>
            <div class="m-sub">Stored threat records</div>
        </div>
        <div class="metric-box m-blue">
            <div class="m-header-row">
                <span class="m-label">{security_icon("language", live=monitor_active)}Live / Active Domains</span>
                <span class="m-badge-pill m-pill-blue"><span class="beacon-live"></span>ONLINE</span>
            </div>
            <div class="m-value">{live_cand}</div>
            <div class="m-sub">Reachable HTTP/HTTPS hosts</div>
        </div>
        <div class="metric-box m-amber">
            <div class="m-header-row">
                <span class="m-label">{security_icon("policy")}Login Trap Forms</span>
                <span class="m-badge-pill m-pill-red">LOGIN FORMS</span>
            </div>
            <div class="m-value">{login_cand}</div>
            <div class="m-sub">Credential phishers detected</div>
        </div>
        <div class="metric-box m-red">
            <div class="m-header-row">
                <span class="m-label">{security_icon("security")}High Risk Impersonators</span>
                <span class="m-badge-pill m-pill-red"><span class="beacon-alert"></span>CRITICAL</span>
            </div>
            <div class="m-value">{high_cand}</div>
            <div class="m-sub">Immediate action required</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 3. User-Friendly Filters Control Center ("filters like active or not" with White Glass Styling)
    with st.container(border=True, key='threat_filters'):

        # Quick 1-Touch Filter Triage Presets
        if "quick_filter" not in st.session_state:
            st.session_state["quick_filter"] = "ALL"
        cur_qf = st.session_state.get("quick_filter", "ALL")

        st.markdown(":material/filter_alt: **Filter findings**")
        qf_c1, qf_c2, qf_c3, qf_c4, qf_c5 = st.columns(5)
        mx_total = sum(1 for _, obs in all_flagged if (obs.get("dns", {}).get("records", {}).get("MX") or obs.get("dns", {}).get("MX")))

        with qf_c1:
            if st.button(f"All ({total_cand})", key="qf_btn_all", icon=":material/view_list:", width="stretch", type="primary" if cur_qf == "ALL" else "secondary"):
                st.session_state["quick_filter"] = "ALL"
                st.rerun()
        with qf_c2:
            if st.button(f"Active ({live_cand})", key="qf_btn_active", icon=":material/check_circle:", width="stretch", type="primary" if cur_qf == "ACTIVE" else "secondary"):
                st.session_state["quick_filter"] = "ACTIVE"
                st.rerun()
        with qf_c3:
            if st.button(f"High Risk ({high_cand})", key="qf_btn_high", icon=":material/gpp_bad:", width="stretch", type="primary" if cur_qf == "HIGH" else "secondary"):
                st.session_state["quick_filter"] = "HIGH"
                st.rerun()
        with qf_c4:
            if st.button(f"Login Traps ({login_cand})", key="qf_btn_login", icon=":material/warning:", width="stretch", type="primary" if cur_qf == "LOGIN" else "secondary"):
                st.session_state["quick_filter"] = "LOGIN"
                st.rerun()
        with qf_c5:
            if st.button(f"MX Active ({mx_total})", key="qf_btn_mx", icon=":material/mail:", width="stretch", type="primary" if cur_qf == "MX" else "secondary"):
                st.session_state["quick_filter"] = "MX"
                st.rerun()

        
        

        fc_row2_c1, fc_row2_c2, fc_row2_c3 = st.columns([2, 1.4, 1.4])

        with fc_row2_c1:
            search_query = st.text_input("Search domains or brands", placeholder="e.g. paypal, paypa1, verify...")

        with fc_row2_c2:
            sort_by = st.selectbox(
                "Sort findings",
                options=["Highest risk first", "Most recent first", "Highest visual match", "Domain A-Z"],
                index=0,
            )

        with fc_row2_c3:
            view_mode = st.session_state.get('candidate_view_mode', 'Table') or 'Table'
            st.markdown('View style')
            view_table, view_cards = st.columns(2, gap='small')
            with view_table:
                if st.button('Table', icon=':material/table_rows:', key='view_layout_table', type='primary' if view_mode == 'Table' else 'secondary', width='stretch'):
                    st.session_state['candidate_view_mode'] = 'Table'
                    st.rerun()
            with view_cards:
                if st.button('Cards', icon=':material/grid_view:', key='view_layout_cards', type='primary' if view_mode == 'Cards' else 'secondary', width='stretch'):
                    st.session_state['candidate_view_mode'] = 'Cards'
                    st.rerun()

        with st.expander('More filters', icon=':material/tune:'):
            fc_row1_c1, fc_row1_c2, fc_row1_c3, fc_row1_c4 = st.columns(4)

            with fc_row1_c1:
                # Website Liveness Filter (Active or Inactive)
                default_live_idx = 1 if cur_qf == "ACTIVE" else 0
                filter_liveness = st.selectbox(
                    "Website status",
                    options=["All Statuses", "Reachable only", "Offline only"],
                    index=default_live_idx,
                    help="Filter domains by whether the suspect website is actively resolving and responding over HTTP/HTTPS.",
                )

            with fc_row1_c2:
                # Threat Severity Filter (Risk Level)
                default_risk = ["HIGH"] if cur_qf == "HIGH" else ["HIGH", "MEDIUM", "LOW"]
                filter_risk = st.multiselect(
                    "Risk severity",
                    options=["HIGH", "MEDIUM", "LOW"],
                    default=default_risk,
                    help="Filter candidate domains by calculated threat score and severity.",
                )

            with fc_row1_c3:
                # Target Monitored Brand Filter
                brand_opts = ["All Brands"] + sorted(list({c.matched_brand for c, _ in all_flagged if c.matched_brand}))
                filter_brand = st.selectbox("Target brand", brand_opts, index=0)

            with fc_row1_c4:
                # Investigation / Review Status Filter
                filter_status = st.selectbox(
                    "Review status",
                    options=["All Statuses", "new", "under_investigation", "takedown_requested", "resolved", "false_positive"],
                    index=0,
                )


    # 4. Filtering Engine Logic
    filtered_list = []
    for c, obs in all_flagged:
        # Quick Preset Filter Check
        if cur_qf == "ACTIVE" and not c.is_live:
            continue
        if cur_qf == "HIGH" and (c.risk_level or "").upper() != "HIGH":
            continue
        if cur_qf == "LOGIN" and not c.has_login_form:
            continue
        if cur_qf == "MX":
            mx_recs = obs.get("dns", {}).get("records", {}).get("MX", []) or obs.get("dns", {}).get("MX", [])
            if not mx_recs:
                continue

        # Liveness Filter
        if filter_liveness == "Reachable only" and not c.is_live:
            continue
        if filter_liveness == "Offline only" and c.is_live:
            continue

        # Severity Filter
        r_level = (c.risk_level or "LOW").upper()
        if r_level not in filter_risk:
            continue

        # Brand Filter
        if filter_brand != "All Brands" and c.matched_brand != filter_brand:
            continue

        # Triage Status Filter
        if filter_status != "All Statuses" and (c.status or "new") != filter_status:
            continue

        # Search Query Filter
        if search_query:
            q = search_query.lower().strip()
            if q not in c.domain.lower() and q not in (c.matched_brand or "").lower():
                continue

        filtered_list.append((c, obs))

    # Apply Sorting
    if sort_by == "Highest risk first":
        filtered_list.sort(key=lambda x: float(x[0].risk_score or 0.0), reverse=True)
    elif sort_by == "Most recent first":
        filtered_list.sort(key=lambda x: str(x[0].detected_at or ""), reverse=True)
    elif sort_by == "Highest visual match":
        filtered_list.sort(key=lambda x: float(x[0].visual_similarity or 0.0), reverse=True)
    elif sort_by == "Domain A-Z":
        filtered_list.sort(key=lambda x: x[0].domain.lower())

    # Results Header & Quick Actions Bar
    res_bar1, res_bar2 = st.columns([4, 1])
    with res_bar1:
        st.markdown(f"**Displaying {len(filtered_list)} candidate domains matching current filters:**")
    with res_bar2:
        # Export CSV Button
        if filtered_list:
            export_rows = []
            for c, obs in filtered_list:
                whois = obs.get("whois", {})
                export_rows.append({
                    "ID": c.id,
                    "Domain": c.domain,
                    "Target Brand": c.matched_brand,
                    "Liveness": "Active" if c.is_live else "Offline",
                    "Risk Score": c.risk_score,
                    "Risk Level": c.risk_level,
                    "Visual Match": f"{int((c.visual_similarity or 0.0) * 100)}%",
                    "Login Form": bool(c.has_login_form),
                    "Registrar": whois.get("registrar") or c.registered_domain or "Unknown",
                    "Status": c.status,
                    "Detected At": c.detected_at,
                })
            df_exp = pd.DataFrame(export_rows)
            st.download_button(
                ":material/download: Export CSV",
                data=df_exp.to_csv(index=False),
                file_name="phishshield_filtered_domains.csv",
                mime="text/csv",
                width="stretch",
            )

    if not filtered_list:
        st.info("No candidates match your current filter criteria. Adjust the filters above or click 'Load Realistic Demo Scenarios' in Tab .")
    else:
        # -----------------------------------------------------------------
        # VIEW 1: INTERACTIVE DATA TABLE VIEW (Glassmorphic Container)
        # -----------------------------------------------------------------
        if view_mode in (None, "Table"):
            from phishshield_threat_grid import threat_grid
            rows = [{
                'id': c.id, 'domain': c.domain,
                'brand': c.matched_brand or 'Unknown',
                'severity': c.risk_level or 'LOW', 'score': float(c.risk_score or 0),
                'website': 'Reachable' if c.is_live else 'Offline',
                'review': (c.status or 'new').replace('_', ' ').capitalize(),
            } for c, _ in filtered_list]
            grid_key = 'animated_findings'
            def open_grid_finding():
                opened = st.session_state[grid_key].get('opened')
                if opened in {c.id for c, _ in filtered_list}:
                    st.session_state['selected_candidate_id'] = opened
            threat_grid(rows, selected_id=st.session_state.get('selected_candidate_id'), key=grid_key, on_open=open_grid_finding)

        # -----------------------------------------------------------------
        # VIEW 2: VISUAL CARD GALLERY VIEW (White Frosted Glass Cards)
        # -----------------------------------------------------------------
        else:
            for c, obs in filtered_list:
                r_lvl = (c.risk_level or "LOW").upper()
                card_cls = "threat-card threat-card-high" if r_lvl == "HIGH" else ("threat-card threat-card-med" if r_lvl == "MEDIUM" else "threat-card threat-card-low")
                pill_cls = "pill-high" if r_lvl == "HIGH" else ("pill-med" if r_lvl == "MEDIUM" else "pill-low")

                whois = obs.get("whois", {})
                dns = obs.get("dns", {})
                ips = dns.get("records", {}).get("A", []) or dns.get("A", [])
                ip_str = ips[0] if ips else "NXDOMAIN"
                mx = dns.get("records", {}).get("MX", []) or dns.get("MX", [])
                reg = whois.get("registrar") or c.registered_domain or "Unknown / Privacy Protected"
                sim_pct = int((c.visual_similarity or 0.0) * 100) if c.visual_similarity is not None else 0

                st.markdown(f"""
                <div class="{card_cls}">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
                        <div>
                            <div class="card-domain-title">{c.domain}</div>
                            <div style="color:#94a3b8; font-size:0.86rem; margin-top:2px;">
                                Target: <b style="color:#38bdf8;">{c.matched_brand}</b> &nbsp;|&nbsp; First Seen: <b style="color:#f1f5f9;">{c.detected_at[:19].replace('T', ' ')} UTC</b>
                            </div>
                        </div>
                        <div style="text-align:right;">
                            <span class="{pill_cls}">RISK: {r_lvl} ({c.risk_score}/100)</span>
                        </div>
                    </div>
                """, unsafe_allow_html=True)

                cg_c1, cg_c2 = st.columns([1.2, 1.8])

                with cg_c1:
                    shot_path = c.screenshot_path
                    if shot_path and os.path.exists(shot_path):
                        st.image(shot_path, caption=f"Capture: {c.domain}", width="stretch")
                    else:
                        st.caption("No screenshot available (host was offline/unreachable).")

                    if c.visual_similarity is not None:
                        bar_color = "#ef4444" if sim_pct >= 75 else ("#f59e0b" if sim_pct >= 40 else "#3b82f6")
                        st.markdown(f"""
                        <div style="margin-top:6px;">
                            <div style="display:flex; justify-content:space-between; font-size:0.8rem; font-weight:750; color:#e2e8f0;">
                                <span>Visual pHash Match</span>
                                <span>{sim_pct}%</span>
                            </div>
                            <div class="sim-bar-bg">
                                <div class="sim-bar-fill" style="width:{sim_pct}%; background:{bar_color};"></div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                with cg_c2:
                    st.markdown(f"""
                    <div style="margin-bottom:12px;">
                        <span class="tag-badge {'tag-live' if c.is_live else 'tag-offline'}">{' Active (HTTP 200)' if c.is_live else ' Inactive / Offline'}</span>
                        <span class="tag-badge {'tag-alert' if c.has_login_form else 'tag-badge'}">{' Password Harvester' if c.has_login_form else 'No Login Form'}</span>
                        <span class="tag-badge {'tag-alert' if mx else 'tag-badge'}">{' MX Weaponized' if mx else 'No Mail Server'}</span>
                    </div>
                    <div style="font-size:0.88rem; color:#cbd5e1; line-height:1.65; margin-bottom:14px;">
                        - <b>Resolved IP:</b> <code>{ip_str}</code><br/>
                        - <b>Registrar:</b> <code>{reg}</code><br/>
                        - <b>Triage Status:</b> <code>{c.status or 'new'}</code><br/>
                        - <b>Recommendation:</b> {c.recommended_action or 'Investigate host.'}
                    </div>
                    """, unsafe_allow_html=True)

                    if st.button(":material/biotech: Open investigation", key=f"inv_btn_card_{c.id}", width="stretch"):
                        st.session_state["selected_candidate_id"] = c.id
                        st.rerun()

                st.markdown("</div>", unsafe_allow_html=True)

        selected_id = st.session_state.get('selected_candidate_id')
        if selected_id not in [c.id for c, _ in filtered_list]:
            selected_id = None
        if selected_id is not None:
            st.markdown("### :material/policy: Finding details")
            if st.button("Close details", icon=":material/close:", key="close_finding"):
                st.session_state['selected_candidate_id'] = None
                st.session_state['finding_table_version'] = st.session_state.get('finding_table_version', 0) + 1
                st.rerun()

        cand_target = next((c for c, _ in filtered_list if c.id == selected_id), None)
        obs_target = next((obs for c, obs in filtered_list if c.id == selected_id), {})

        if cand_target:
            whois_info = obs_target.get("whois", {})
            dns_info = obs_target.get("dns", {})

            r_lvl = (cand_target.risk_level or "LOW").upper()
            st.markdown(f"""
            <div style="background:rgba(13, 17, 23, 0.76); backdrop-filter:blur(18px); border:1px solid rgba(255,255,255,0.14); border-radius:14px; padding:18px 22px; margin-bottom:18px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; box-shadow:0 10px 28px rgba(0,0,0,0.35);">
                <div>
                    <span style="font-size:1.35rem; font-weight:850; color:#ffffff; font-family:'JetBrains Mono', monospace;">{cand_target.domain}</span>
                    <div style="color:#94a3b8; font-size:0.88rem; margin-top:4px;">
                        Target: <b style="color:#38bdf8;">{cand_target.matched_brand}</b> &nbsp;|&nbsp; Liveness: <b>{' Live' if cand_target.is_live else ' Offline'}</b> &nbsp;|&nbsp; Status: <code>{cand_target.status}</code>
                    </div>
                </div>
                <div>
                    <span class="{'pill-high' if r_lvl == 'HIGH' else ('pill-med' if r_lvl == 'MEDIUM' else 'pill-low')}">
                        SEVERITY: {r_lvl} ({cand_target.risk_score}/100)
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            dossier_tab1, dossier_tab2, dossier_tab3, dossier_tab4 = st.tabs([
                ":material/compare: Visual evidence",
                ":material/dns: Infrastructure",
                ":material/edit_note: Case notes",
                ":material/policy: Response & reports",
            ])

            # Sub-Tab 1: Visual Comparison
            with dossier_tab1:
                col_ref, col_sus = st.columns(2)
                brand_safe = ''.join(ch if ch.isalnum() or ch in '-_' else '_' for ch in (cand_target.matched_brand or 'unknown'))
                ref_shot = f"reference_assets/brands/{brand_safe}_reference.png"

                with col_ref:
                    st.markdown(f"**Official Brand Portal ({cand_target.matched_brand})**")
                    if os.path.exists(ref_shot):
                        st.image(ref_shot, width="stretch")
                    else:
                        st.info("Official brand screenshot not yet cached.")

                with col_sus:
                    st.markdown(f"**Flagged Suspect Website ({cand_target.domain})**")
                    sus_shot = cand_target.screenshot_path
                    if sus_shot and os.path.exists(sus_shot):
                        st.image(sus_shot, width="stretch")
                    else:
                        st.info("No screenshot captured (host was offline or timed out).")

                if cand_target.visual_similarity is not None:
                    p_match = int(cand_target.visual_similarity * 100)
                    st.metric("Perceptual Hash Similarity (pHash)", f"{p_match}%")
                    if p_match >= 75:
                        st.error(f" Direct Visual Clone Detected ({p_match}%): Page replicates brand layout, typography, and styling to deceive victims.")
                    elif p_match >= 40:
                        st.warning(f" Moderate Similarity Detected ({p_match}%): Partial visual resemblance detected.")
                    else:
                        st.success(f" Low Visual Similarity ({p_match}%): Distinct appearance.")

            # Sub-Tab 2: Infrastructure
            with dossier_tab2:
                w_col1, w_col2 = st.columns(2)
                with w_col1:
                    st.markdown("#### :material/badge: Domain Registration (WHOIS / RDAP)")
                    st.markdown(f"""
                    - **Registrar:** `{whois_info.get('registrar') or cand_target.registered_domain or 'Privacy Protected'}`
                    - **Registration Date:** `{whois_info.get('creation_date') or cand_target.registered_at or 'Unknown'}`
                    - **Abuse Email:** `{', '.join(whois_info.get('emails', [])) if whois_info.get('emails') else 'None published'}`
                    - **Nameservers:** `{', '.join(whois_info.get('name_servers', [])) if whois_info.get('name_servers') else 'None'}`
                    """)

                with w_col2:
                    st.markdown("#### :material/dns: DNS Infrastructure")
                    ips = dns_info.get("records", {}).get("A", []) or dns_info.get("A", [])
                    mx_recs = dns_info.get("records", {}).get("MX", []) or dns_info.get("MX", [])
                    st.markdown(f"""
                    - **Resolved IP(s):** `{', '.join(ips) if ips else 'NXDOMAIN'}`
                    - **Mail Servers (MX):** `{', '.join(mx_recs) if mx_recs else 'None'}`
                    """)
                    if mx_recs:
                        st.warning(" **Active Mail Exchanger (MX):** This domain is configured to send and receive emails, posing a direct spear-phishing risk.")

            # Sub-Tab 3: Analyst Review & Status Update
            with dossier_tab3:
                st.markdown("#### :material/edit_note: Threat Triage & Investigation Review")
                status_choices = ["new", "under_investigation", "takedown_requested", "false_positive", "resolved"]
                cur_stat = cand_target.status or "new"
                idx = status_choices.index(cur_stat) if cur_stat in status_choices else 0

                with st.form(f"review_form_{cand_target.id}"):
                    new_status = st.selectbox("Update Case Status", status_choices, index=idx)
                    analyst_notes = st.text_area("Analyst Notes / Takedown Reference", value=cand_target.analyst_notes or "", placeholder="Enter investigation findings, registrar ticket numbers...")
                    if st.form_submit_button("Save Review Update", icon=":material/save:", type="primary"):
                        try:
                            update_candidate_review(cand_target.id, new_status, analyst_notes)
                            st.success("Candidate review successfully updated in SQLite!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error updating review: {e}")

            # Sub-Tab 4: Incident Response & Legal Notice
            with dossier_tab4:
                st.markdown("#### :material/policy: Incident Response & Takedown Actions")
                with st.container():
                    st.markdown("**:material/description: PDF evidence dossier**")
                    st.write("Generate a formal, publication-ready cybersecurity incident dossier.")
                    if st.button("Generate Security PDF Report", icon=":material/description:", key=f"btn_pdf_{cand_target.id}", type="primary"):
                        cand_payload = {
                            "domain": cand_target.domain,
                            "matched_brand": cand_target.matched_brand,
                            "risk_score": cand_target.risk_score,
                            "risk_level": cand_target.risk_level,
                            "is_live": cand_target.is_live,
                            "visual_similarity": cand_target.visual_similarity,
                            "has_login_form": cand_target.has_login_form,
                            "screenshot_path": cand_target.screenshot_path,
                            "reference_screenshot_path": ref_shot,
                            "recommended_action": cand_target.recommended_action,
                            "registered_domain": cand_target.registered_domain,
                            "registered_at": cand_target.registered_at,
                        }
                        from src.reporting.reportlab_generator import generate_security_report
                        pdf_path = generate_security_report(
                            candidate=cand_payload,
                            whois_info=whois_info,
                            dns_info=dns_info,
                        )
                        if pdf_path and os.path.exists(pdf_path):
                            with open(pdf_path, "rb") as f:
                                pdf_data = f.read()
                            st.download_button(
                                label="Download incident report",
                                icon=":material/download:",
                                data=pdf_data,
                                file_name=os.path.basename(pdf_path),
                                mime="application/pdf",
                                key=f"dl_pdf_{cand_target.id}",
                            )
                            st.success(f"Report ready: `{os.path.basename(pdf_path)}`")

                st.markdown("---")
                st.markdown("#### :material/mail: Automated Registrar Takedown Email Notice")
                abuse_addr = ", ".join(whois_info.get("emails", [])) or "abuse@registrar.com"
                em_subject = f"URGENT: Phishing & Brand Impersonation Takedown Request - {cand_target.domain}"
                em_body = f"""To: {abuse_addr}
Subject: {em_subject}

Dear Abuse & Legal Team,

We have detected a fraudulent website operating on your network:
- Fraudulent Domain: {cand_target.domain}
- Target Impersonated Brand: {cand_target.matched_brand}
- Threat Level: {cand_target.risk_level} ({cand_target.risk_score}/100)
- Liveness: {'Active HTTP host' if cand_target.is_live else 'Offline / Resolving'}

FORENSIC EVIDENCE:
1. Brand Impersonation: Domain unauthorizedly targets {cand_target.matched_brand}.
2. Visual Clone: Perceptual hash similarity of {int((cand_target.visual_similarity or 0.0)*100)}% to official brand assets.
3. Credential Harvesting: Active credential input forms detected.

Pursuant to your Acceptable Use Policy and ICANN RAA obligations, please suspend DNS resolution for this domain immediately.

CyberSentinel Incident Response Team
"""
                st.text_area("Notice Body", value=em_body, height=160)
                st.markdown(f'<a href="mailto:{abuse_addr}?subject={urllib.parse.quote(em_subject)}&body={urllib.parse.quote(em_body)}" target="_blank" style="display:inline-block; padding:8px 16px; background:#0284c7; color:white; border-radius:8px; font-weight:700; text-decoration:none;"> Open in Mail Client ({abuse_addr})</a>', unsafe_allow_html=True)


# =============================================================================
# PAGE 2: EXECUTIVE DASHBOARD (Overview & High-Level Telemetry)
# =============================================================================
elif page == ":material/space_dashboard: Executive Dashboard":
    st.markdown("### :material/space_dashboard: Executive Threat Overview")
    st.caption("Strategic posture summary across all guarded brands, detected lookalikes, and live certificate feeds.")

    # KPI Grid
    col_kpi1, col_kpi2, col_kpi3, col_kpi4 = st.columns(4)
    total_cand = len(all_flagged)
    live_cand = sum(1 for c, _ in all_flagged if c.is_live)
    high_cand = sum(1 for c, _ in all_flagged if (c.risk_level or "").upper() == "HIGH")
    med_cand = sum(1 for c, _ in all_flagged if (c.risk_level or "").upper() == "MEDIUM")
    low_cand = sum(1 for c, _ in all_flagged if (c.risk_level or "").upper() == "LOW")

    col_kpi1.metric("Guarded brands", f"{active_brand_count}/3")
    col_kpi2.metric("Recorded findings", total_cand)
    col_kpi3.metric("High-risk findings", high_cand)
    col_kpi4.metric("Certificates evaluated", events_seen)

    from src.ui.threat_charts import render_threat_charts
    render_threat_charts(all_flagged, watched_brands)


# =============================================================================
# PAGE 3: BRAND WATCHLIST (Strict Max 3 Websites)
# =============================================================================
elif page == ":material/verified_user: Brand Watchlist (Max 3)":
    st.markdown("### :material/verified_user: Monitored Target Websites (Strict Max 3)")
    st.caption("The background monitoring service continuously inspects all new certificate transparency logs and domain permutations against these 3 websites.")

    slots_used = len(watched_brands)
    slot_c1, slot_c2, slot_c3 = st.columns(3)
    slots = [slot_c1, slot_c2, slot_c3]

    for i in range(MAX_WATCHLIST_LIMIT):
        with slots[i]:
            if i < slots_used:
                b = watched_brands[i]
                cand_count = sum(1 for c, _ in all_flagged if c.matched_brand == b.official_domain or c.matched_brand == b.name)
                st.markdown(f"""
                <div class="slot-card">
                    <span class="slot-badge-active"><span class="beacon-live"></span>Slot {i+1} Guard Active</span>
                    <div class="slot-domain">{b.official_domain}</div>
                    <div style="font-size:0.88rem; color:#94a3b8; margin-top:6px; line-height:1.55;">
                        Brand Name: <b style="color:#ffffff;">{b.name}</b><br/>
                        Flagged Impersonators: <b style="color:#38bdf8;">{cand_count} targets</b>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                st.write("")
                slot_btn_c1, slot_btn_c2 = st.columns(2)
                with slot_btn_c1:
                    st.button('Scan', icon=':material/search:', key=f'scan_slot_{b.id}',
                              width='stretch', on_click=prepare_scan, args=(b.official_domain,))
                with slot_btn_c2:
                    if st.button(f"Remove", icon=":material/delete:", key=f"rm_brand_slot_{b.id}", use_container_width=True):
                        ok, msg = remove_monitored_website(b.id)
                        if ok:
                            st.success(msg)
                            st.rerun()
            else:
                st.markdown(f"""
                <div class="slot-card-empty">
                    <div style="color:#38bdf8; margin-bottom:4px;">{security_icon("add")}</div>
                    <div style="font-weight:850; color:#cbd5e1; font-size:1rem;">Slot {i+1} Available</div>
                    <div style="font-size:0.82rem; color:#94a3b8; margin-top:3px;">Add a target website below to protect</div>
                </div>
                """, unsafe_allow_html=True)

    st.markdown("---")

    if slots_used < MAX_WATCHLIST_LIMIT:
        st.markdown(f"#### :material/add_circle: Add Target Website ({slots_used}/{MAX_WATCHLIST_LIMIT} Slots Occupied)")
        add_c1, add_c2, add_c3 = st.columns([2.5, 1.5, 1])
        with add_c1:
            in_d = st.text_input("Website Domain to Protect", placeholder="e.g. paypal.com, netflix.com", key="add_dom_in")
        with add_c2:
            in_n = st.text_input("Brand Display Name (Optional)", placeholder="e.g. PayPal", key="add_name_in")
        with add_c3:
            st.write("&nbsp;")
            if st.button("Protect Website", icon=":material/verified_user:", type="primary", use_container_width=True):
                ok, msg = add_monitored_website(in_d, in_n)
                if ok:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)
    else:
        st.info(" Watchlist is at full capacity (3 websites). To monitor a different website, remove one above.")


# =============================================================================
# PAGE 4: LIVE CT STREAM TELEMETRY
# =============================================================================
elif page == ":material/radar: Live CT Stream":
    st.markdown('### :material/radar: Live certificate monitor')
    st.caption('Follow new TLS certificates and watch for domains that mention your protected brands.')
    from src.ui.live_stream import render_live_stream
    render_live_stream()


# =============================================================================
# PAGE 5: ON-DEMAND SCANNER
# =============================================================================
elif page == ":material/troubleshoot: On-Demand Scanner":
    st.markdown("### :material/travel_explore: On-Demand Brand Impersonation Scan")
    st.caption("Instantly scan one of your monitored websites for lookalikes using dnstwist and Certificate Transparency logs.")

    if not watched_brands:
        st.warning("Please add at least one website to your monitored watchlist in the Watchlist tab.")
    else:
        target_options = [b.official_domain for b in watched_brands]
        preset_dom = st.session_state.get("sel_scan_domain")
        sel_idx = target_options.index(preset_dom) if preset_dom in target_options else 0
        if st.session_state.get('scan_target_domain') not in target_options:
            st.session_state['scan_target_domain'] = target_options[sel_idx]
        sel_domain = st.selectbox("Select Target Website from Watchlist", target_options, key='scan_target_domain')
        b_target = next((b for b in watched_brands if b.official_domain == sel_domain), None)
        b_name = b_target.name if b_target else sel_domain.split(".")[0].capitalize()

        scan_c1, scan_c2 = st.columns(2)
        with scan_c1:
            perm_limit = st.slider("Permutation Limit", 10, 50, 25, 5)
        with scan_c2:
            query_ct = st.checkbox("Query crt.sh Certificate Logs", value=True)

        if st.button("Start Impersonation Scan", icon=":material/radar:", type="primary", use_container_width=True):
            pbar = st.progress(0.0)
            status_box = st.empty()

            def cb(msg, pct):
                status_box.markdown(f"**:material/progress_activity: Progress:** `{msg}`")
                pbar.progress(pct)

            try:
                with task_loading('Investigating domain lookalikes', 'Resolving domains, checking certificates, and collecting evidence.'):
                    from src.discovery.domain_scanner import DomainScanner
                    scanner = DomainScanner()
                    found = scanner.scan_brand(
                        brand_domain=sel_domain,
                        brand_name=b_name,
                        max_permutations=perm_limit,
                        include_crtsh=query_ct,
                        take_screenshots=True,
                        progress_callback=cb,
                    )
                pbar.progress(1.0)
                status_box.success(f" Scan completed! Discovered {len(found)} candidate lookalikes.")
                st.session_state["ondemand_findings"] = found
            except Exception as e:
                status_box.error(f"Scan error: {e}")

        if "ondemand_findings" in st.session_state:
            findings = st.session_state["ondemand_findings"]
            st.markdown(f"#### Discovered Candidates ({len(findings)})")
            for item in findings:
                r_lvl = item.get("risk_level", "LOW")
                r_cls = "threat-card-high" if r_lvl == "HIGH" else ("threat-card-med" if r_lvl == "MEDIUM" else "threat-card-low")
                st.markdown(f"""
                <div class="threat-card {r_cls}" style="padding:16px; margin-bottom:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <span style="font-family:'JetBrains Mono', monospace; font-size:1.12rem; font-weight:800;">{item.get('domain')}</span>
                            <div style="font-size:0.82rem; color:#64748b; margin-top:2px;">
                                Permutation: <b>{item.get('permutation_type')}</b> &nbsp;|&nbsp; Resolved IP: <b>{item.get('ip') or 'None'}</b>
                            </div>
                        </div>
                        <div>
                            <span class="{'pill-high' if r_lvl == 'HIGH' else ('pill-med' if r_lvl == 'MEDIUM' else 'pill-low')}">
                                {r_lvl} ({item.get('risk_score')}/100)
                            </span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)


# =============================================================================
# PAGE 6: ATTACK SIMULATIONS (Demo Scenarios & Dynamic Cycle)
# =============================================================================
elif page == ":material/science: Attack Simulations":
    from src.simulation.demo_data import seed_simulation_data, clear_simulation_data, ensure_demo_assets
    with task_loading('Loading demo scenarios', 'Preparing local example screenshots.'):
        ensure_demo_assets()
    st.markdown("### :material/science: Pre-Packaged Attack Scenarios (Demo Mode)")
    st.caption("Demonstrate the complete detection, visual clone comparison, and incident response pipeline without waiting for live network scans.")

    btn_s1, btn_s2 = st.columns(2)
    with btn_s1:
        if st.button("Load Realistic Demo Scenarios", icon=":material/science:", type="primary", use_container_width=True):
            with task_loading('Loading demo findings', 'Preparing evidence for the example domains.'):
                seeded = seed_simulation_data()
            st.success(f"Loaded {len(seeded)} threat scenarios into SQLite: {', '.join(seeded)}")
            st.rerun()
    with btn_s2:
        if st.button("Clear Demo Data", icon=":material/delete:", use_container_width=True):
            cleared = clear_simulation_data()
            st.info(f"Cleared {cleared} demo records.")
            st.rerun()

    st.markdown("---")

    # High-Risk Demo Scenario Showcase
    st.markdown("""
    <div class="threat-card threat-card-high">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="card-domain-title">paypal-security-verification-login.com</span>
            <span class="pill-high"> HIGH RISK (94/100)</span>
        </div>
        <div style="margin-top:8px; font-size:0.9rem; color:#cbd5e1;">
            <b>Vector:</b> Cloned PayPal login with urgent suspension notification and active password harvester.<br/>
            <b>Forensics:</b> 90.6% visual pHash match, active MX mail exchanger, registered 3 days ago via Namecheap.
        </div>
    </div>
    """, unsafe_allow_html=True)
    c_demo1, c_demo2 = st.columns(2)
    with c_demo1:
        st.image("reference_assets/brands/paypal_com_reference.png", caption="Official Brand Reference", use_container_width=True)
    with c_demo2:
        st.image("data/screenshots/demo_paypal_high_risk.png", caption="Suspect Phishing Clone (90.6% Visual Match)", use_container_width=True)

    # Medium-Risk Demo Scenario Showcase
    st.markdown("""
    <div class="threat-card threat-card-med" style="margin-top:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="card-domain-title">paypa1-support-billing.net</span>
            <span class="pill-med"> MEDIUM RISK (56/100)</span>
        </div>
        <div style="margin-top:8px; font-size:0.9rem; color:#cbd5e1;">
            <b>Vector:</b> Homoglyph character substitution (l -> 1) parked on Hostinger network awaiting weaponization.
        </div>
    </div>
    """, unsafe_allow_html=True)
    c_demo3, c_demo4 = st.columns(2)
    with c_demo3:
        st.image("reference_assets/brands/paypal_com_reference.png", caption="Official Brand Reference", use_container_width=True)
    with c_demo4:
        st.image("data/screenshots/demo_paypal_medium_risk.png", caption="Parked Lookalike Portal", use_container_width=True)


# =============================================================================
# PAGE 7: LEGAL REPORTS & DOSSIERS
# =============================================================================
elif page == ":material/description: Legal Reports & Dossiers":
    from src.ui.report_workspace import render_report_workspace
    render_report_workspace(all_flagged)
