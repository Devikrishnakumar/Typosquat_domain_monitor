"""Shared visual design for the local and Compose Streamlit dashboards."""

import base64
from pathlib import Path

import streamlit as st


@st.cache_data
def typography_css() -> str:
    """Embed local fonts so both the dashboard and isolated hero load reliably."""
    font_dir = Path(__file__).resolve().parents[2] / 'landing_page' / 'public' / 'fonts'
    rules = []
    for family, filename, weights in [('Manrope', 'manrope-variable.ttf', '200 800'), ('Space Grotesk', 'spacegrotesk-variable.ttf', '300 700')]:
        data = base64.b64encode((font_dir / filename).read_bytes()).decode('ascii')
        rules.append(f"@font-face {{font-family:'{family}';src:url(data:font/ttf;base64,{data}) format('truetype');font-weight:{weights};font-display:swap;}}")
    return '\n'.join(rules)


def apply_frontend_theme() -> None:
    """Apply the shared glass theme and deferred background video."""
    st.html('<link rel="stylesheet" href="https://api.fontshare.com/v2/css?f[]=general-sans@400,500,600,700&amp;display=swap">')
    st.markdown(
        """
        <style>
        :root {
            color-scheme: dark;
            --ps-ink: #f7fbff;
            --ps-muted: #d3deeb;
            --ps-border: rgba(215, 233, 255, .22);
            --ps-surface: rgba(13, 27, 46, .42);
        }
        html, body, .stApp, [data-testid="stAppViewContainer"],
        [data-testid="stMain"] {
            background: transparent !important;
            color: var(--ps-ink) !important;
            font-family: Inter, "Segoe UI", sans-serif !important;
        }
        body {
            overflow-x: hidden;
            background: #123858 !important;
        }
        body::before {
            position: fixed;
            z-index: 0;
            inset: -18%;
            background:
                radial-gradient(ellipse at 18% 24%, rgba(12, 118, 167, .22), transparent 34%),
                radial-gradient(ellipse at 79% 19%, rgba(66, 75, 181, .2), transparent 32%),
                radial-gradient(ellipse at 66% 82%, rgba(14, 131, 117, .15), transparent 36%);
            content: "";
            pointer-events: none;
            animation: ps-aurora-drift 28s ease-in-out infinite alternate;
        }
        #ps-video-background {
            position: fixed;
            z-index: 0;
            inset: 0;
            overflow: hidden;
            background: #123858;
            pointer-events: none;
        }
        #ps-video-background video {
            position: absolute;
            inset: 0;
            width: 100%;
            height: 100%;
            object-fit: cover;
            filter: grayscale(1) sepia(1) hue-rotate(170deg) saturate(3.6) brightness(1.15);
        }
        #ps-video-background > div {
            position: absolute;
            inset: 0;
            background:
                linear-gradient(180deg, rgba(5, 15, 28, .18), rgba(5, 15, 28, .35)),
                radial-gradient(ellipse at 50% 35%, transparent 30%, rgba(5, 15, 28, .18) 100%);
        }
        @keyframes ps-aurora-drift {
            from { transform: translate3d(-1.5%, -1%, 0) scale(1); }
            to { transform: translate3d(1.5%, 1%, 0) scale(1.04); }
        }
        .stApp, [data-testid="stAppViewContainer"] {
            position: relative;
            z-index: 1;
        }
        [data-testid="stHeader"], [data-testid="stToolbar"] {
            background: transparent !important;
        }
        [data-testid="stMainBlockContainer"] {
            max-width: 1540px;
            padding-top: 1.5rem;
            padding-bottom: 3rem;
        }
        [data-testid="stSidebar"] {
            background: transparent !important;
            border: 0 !important;
        }
        [data-testid="stSidebar"] * { color: #f2f7ff !important; }
        .command-header, .section-card, .filter-panel,
        .metric-box, .metric-card, .risk-box, .stream-row,
        .status-hud-glass, .simulation-note,
        [data-testid="stVerticalBlockBorderWrapper"],
        [data-testid="stVerticalBlock"] > div > [data-testid="stContainer"] {
            background: var(--ps-surface) !important;
            color: var(--ps-ink) !important;
            border: 1px solid var(--ps-border) !important;
            border-radius: 16px !important;
            box-shadow: 0 12px 32px rgba(0, 0, 0, .18),
                        inset 0 1px rgba(255, 255, 255, .09) !important;
            backdrop-filter: blur(18px) saturate(140%) !important;
            -webkit-backdrop-filter: blur(18px) saturate(140%) !important;
        }
        .command-header, .section-card, .filter-panel,
        .metric-box, .metric-card, .risk-box, .stream-row,
        .status-hud-glass, .simulation-note {
            position: relative;
            isolation: isolate;
            overflow: hidden;
        }
        .command-header { padding: 22px 26px !important; margin-bottom: 20px !important; }
        .header-title {
            color: var(--ps-ink) !important;
            background: none !important;
            -webkit-text-fill-color: currentColor !important;
            font-size: clamp(1.35rem, 2.4vw, 1.9rem) !important;
            font-weight: 750 !important;
            letter-spacing: -.035em !important;
            text-shadow: 0 2px 14px rgba(0, 0, 0, .28) !important;
        }
        .dashboard-title, .brand-title, .dashboard-subtitle,
        .header-desc, .m-label, .metric-label, .risk-box-title,
        .m-sub, .metric-small, .filter-panel-title,
        .metric-value, .metric-box .m-value, .risk-number,
        .section-card, .simulation-note, .stream-row,
        .stApp h1, .stApp h2, .stApp h3, .stApp h4,
        .stApp [data-testid="stMarkdownContainer"] p {
            color: var(--ps-ink) !important;
            opacity: 1 !important;
            text-shadow: 0 1px 10px rgba(0, 0, 0, .2);
        }
        .m-label, .metric-label, .risk-box-title,
        .m-sub, .metric-small, .header-desc, .dashboard-subtitle,
        .stApp [data-testid="stCaptionContainer"],
        .stApp [data-testid="stMarkdownContainer"] small {
            color: var(--ps-muted) !important;
        }
        .filter-panel { padding: 18px 20px !important; }
        .metric-box:hover {
            translate: 0 -2px !important;
            scale: 1 !important;
            border-color: rgba(165, 221, 255, .48) !important;
            box-shadow: 0 14px 36px rgba(0, 0, 0, .25) !important;
        }
        .stApp [data-testid="stMetric"],
        .stApp [data-testid="stDataFrame"],
        .stApp [data-testid="stTable"],
        .stApp [data-testid="stExpander"] {
            background: rgba(13, 27, 46, .5) !important;
            color: var(--ps-ink) !important;
            border: 1px solid var(--ps-border) !important;
            border-radius: 12px !important;
            box-shadow: 0 8px 24px rgba(0, 0, 0, .16) !important;
        }
        .stApp [data-testid="stMetricLabel"],
        .stApp [data-testid="stMetricValue"],
        .stApp [data-testid="stMarkdownContainer"],
        .stApp [data-testid="stMarkdownContainer"] label {
            color: var(--ps-ink);
        }
        .stApp input, .stApp textarea,
        .stApp [data-baseweb="select"] > div {
            background: rgba(11, 24, 41, .68) !important;
            color: #f7fbff !important;
            border-color: rgba(215, 233, 255, .3) !important;
            border-radius: 10px !important;
        }
        .stApp input::placeholder, .stApp textarea::placeholder {
            color: #c3d0df !important;
        }
        .stApp [data-testid="stButton"] > button,
        .stApp [data-testid="stDownloadButton"] > button,
        .stApp [data-testid="stFormSubmitButton"] > button {
            min-height: 44px;
            border-radius: 12px !important;
            font-weight: 700 !important;
            letter-spacing: .01em;
            transition: transform .18s ease, box-shadow .18s ease,
                        background .18s ease, border-color .18s ease !important;
        }
        .stApp [data-testid="stButton"] > button:hover,
        .stApp [data-testid="stDownloadButton"] > button:hover,
        .stApp [data-testid="stFormSubmitButton"] > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 24px rgba(8, 16, 31, .3),
                        0 0 18px rgba(20, 174, 218, .2) !important;
        }
        .stApp [data-testid="stButton"] > button:focus-visible,
        .stApp [data-testid="stDownloadButton"] > button:focus-visible,
        .stApp [data-testid="stFormSubmitButton"] > button:focus-visible {
            outline: 3px solid rgba(112, 221, 255, .72) !important;
            outline-offset: 2px;
        }
        .stApp [data-testid="stButton"] > button[kind="primary"],
        .stApp [data-testid="baseButton-primary"],
        .stApp [data-testid="stBaseButton-primary"],
        .stApp [data-testid="stFormSubmitButton"] > button {
            background: linear-gradient(120deg, #0d9488, #087db8 52%, #4f58c9) !important;
            border: 1px solid rgba(161, 239, 255, .56) !important;
            color: #fff !important;
            box-shadow: 0 7px 20px rgba(7, 112, 159, .25),
                        inset 0 1px rgba(255, 255, 255, .24) !important;
        }
        .stApp [data-testid="stButton"] > button[kind="secondary"],
        .stApp [data-testid="baseButton-secondary"],
        .stApp [data-testid="stBaseButton-secondary"],
        .stApp [data-testid="stDownloadButton"] > button,
        .stApp [data-testid="stButton"] > button {
            background: rgba(219, 239, 255, .12) !important;
            border: 1px solid rgba(180, 218, 247, .27) !important;
            color: #f7fbff !important;
        }
        .stApp [data-testid="stButton"] > button:hover,
        .stApp [data-testid="stDownloadButton"] > button:hover {
            background: rgba(103, 189, 229, .2) !important;
            border-color: rgba(144, 224, 255, .62) !important;
            color: #fff !important;
        }
        .stApp [data-testid="stButton"] > button[kind="primary"]:hover,
        .stApp [data-testid="stFormSubmitButton"] > button:hover {
            background: linear-gradient(120deg, #2563eb, #3b82f6 52%, #666ee0) !important;
        }
        .stApp [data-testid="stButton"] > button[kind="primary"],
        .stApp [data-testid="baseButton-primary"],
        .stApp [data-testid="stBaseButton-primary"] {
            background: linear-gradient(120deg, rgba(19, 170, 156, .72), rgba(17, 152, 212, .78) 52%, rgba(102, 110, 224, .72)) !important;
            border: 1px solid rgba(161, 239, 255, .46) !important;
            box-shadow: 0 7px 20px rgba(7, 112, 159, .2),
                        inset 0 1px rgba(255, 255, 255, .18) !important;
            backdrop-filter: blur(14px) saturate(145%);
        }
        .stApp [data-testid="stAlert"] { border-radius: 12px !important; }
        .brand-title { color: #f7fbff !important; }
        .brand-subtitle { color: #d3deeb !important; opacity: 1 !important; }
        @media (max-width: 760px) {
            [data-testid="stMainBlockContainer"] { padding: 1rem 1rem 2rem; }
            .command-header { padding: 18px !important; }
            .filter-panel { padding: 14px !important; }
        }
        @media (prefers-reduced-motion: reduce) {
            body::before { animation: none !important; }
            #ps-video-background video { display: none; }
            *, *::before, *::after {
                scroll-behavior: auto !important;
                animation-duration: .01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: .01ms !important;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.markdown('<style>' + typography_css() + Path(__file__).with_name('professional.css').read_text(encoding='utf-8') + '</style>', unsafe_allow_html=True)
    st.html('<style>' + Path(__file__).with_name('navigation.css').read_text(encoding='utf-8') + '</style>')
    st.html('<style>' + Path(__file__).with_name('neumorphic.css').read_text(encoding='utf-8') + '</style>')
    st.html('<style>' + Path(__file__).with_name('glass.css').read_text(encoding='utf-8') + '</style>')
    video_script = Path(__file__).with_name('background_video.js').read_text(encoding='utf-8')
    st.html('<script>' + video_script + '</script>', unsafe_allow_javascript=True)



def render_sidebar_menu(options: list[str], state_key: str) -> str:
    """Render one set of destinations with callbacks that run before page setup."""
    from src.ui.navigation import DESTINATIONS, navigate_to

    selected = st.session_state.get(state_key, options[0])
    linked_page = DESTINATIONS.get(st.query_params.get('view'))
    if linked_page in options:
        selected = linked_page
    if selected not in options:
        selected = options[0]
    st.session_state[state_key] = selected
    expanded_key = f'{state_key}_menu_expanded'
    expanded = st.session_state.setdefault(expanded_key, True)

    def toggle_navigation():
        st.session_state[expanded_key] = not st.session_state[expanded_key]

    labels = {
        'Executive Dashboard': 'Overview', 'Brand Watchlist (Max 3)': 'Brand watchlist',
        'On-Demand Scanner': 'Domain scanner', 'Attack Simulations': 'Simulations',
        'Legal Reports & Dossiers': 'Report workspace',
    }
    fallback_icons = [
        ':material/space_dashboard:', ':material/travel_explore:', ':material/history:',
        ':material/business:', ':material/science:', ':material/description:',
        ':material/monitor_heart:',
    ]

    def option_parts(option, index):
        if option.startswith(':material/'):
            stop = option.find(':', 1)
            label = option[stop+1:].strip()
            return labels.get(label, label), option[:stop+1]
        return labels.get(option, option), fallback_icons[index % len(fallback_icons)]

    with st.container(key='navigation_shell'):
        with st.container(key='navigation_full' if expanded else 'navigation_compact'), st.container(key='navigation_panel'):
            logo_data = base64.b64encode((Path(__file__).resolve().parents[2] / 'cybersentinel-mark.png').read_bytes()).decode('ascii')
            st.html(f'''<div class="ps-nav-brand">
              <span class="ps-nav-mark" aria-hidden="true"><img src="data:image/png;base64,{logo_data}" alt="" /></span>
              <div><strong>CyberSentinel</strong><span>BRAND PROTECTION</span></div>
            </div>''')
            st.button('Collapse menu' if expanded else 'Expand menu',
                      icon=':material/menu_open:' if expanded else ':material/menu:',
                      help='Collapse menu' if expanded else 'Expand menu',
                      key=f'menu_toggle_{state_key}', width='stretch', on_click=toggle_navigation)
            for index, option in enumerate(options):
                if expanded and index in (0, 3):
                    st.caption('Workspace' if index == 0 else 'Operations')
                label, icon = option_parts(option, index)
                st.button(label, icon=icon, help=label, key=f'menu_item_{state_key}_{index}',
                          width='stretch', type='primary' if option == selected else 'secondary',
                          on_click=navigate_to, args=(option, state_key))
    return selected


@st.fragment(run_every="10s")
def render_security_hero() -> None:
    """Blue domain-inspection illustration with separately reported live telemetry."""
    from html import escape
    from src.ingest.background_service import get_monitor_status
    from src.ui.domain_scanner_visual import scanner_visual, SCANNER_CSS, HERO_CSS, _icon
    status = get_monitor_status()
    state = status.get('state', 'unknown')
    label = {
        'connected':'Receiving live certificates', 'waiting':'Waiting for certificates',
        'connecting':'Connecting to the feed', 'reconnecting':'Reconnecting to the feed',
        'stalled':'Feed idle', 'stale':'Monitor needs attention', 'stopped':'Monitor stopped',
    }.get(state, 'Checking monitor status')
    count = max(0,int(status.get('events_seen',0) or 0))
    matches = max(0,int(status.get('matches_found',0) or 0))
    targets = status.get('active_targets', [])
    target_count = len(targets) if isinstance(targets,list) else 0
    status_class = 'ps-stream-connected' if state == 'connected' else 'ps-stream-disconnected'
    from phishshield_threat_grid import security_visual
    st.html(f'<style>{HERO_CSS}</style>')
    with st.container(key='explorer_hero'):
        copy, visual = st.columns([1.05, 1], gap='large')
        with copy:
            st.html(f"""
            <div class="ps-hero-copy">
              <div class="ps-hero-eyebrow">{_icon('shield-check')} Brand protection / Domain intelligence</div>
              <div class="ps-hero-title">See the signal.<br><span>Stop the spoof.</span></div>
              <div class="ps-hero-description">Inspect lookalike domains, follow certificate signals, and bring the evidence together for a confident response.</div>
              <div class="ps-hero-tags"><span>Certificate watch</span><span>Domain intelligence</span><span>Evidence collection</span></div>
              <div class="ps-stream-status {status_class}"><span class="ps-status-pip"></span><span>{escape(label)}</span><strong>{count:,} certificates</strong><span>{matches:,} matches</span><span>{target_count}/3 brands watched</span></div>
            </div>
            """)
        with visual:
            security_visual()
