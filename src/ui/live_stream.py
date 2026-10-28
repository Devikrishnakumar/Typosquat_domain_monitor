"""Automatically refreshed, honest live-feed status and certificate activity."""
import json
import time
from pathlib import Path
import pandas as pd
import streamlit as st
from src.ingest.background_service import get_monitor_status, start_background_monitor, stop_background_monitor, EVENTS_FILE


def render_monitor_badge():
    status = get_monitor_status()
    state = status.get('state', 'unknown')
    label = {'connected':'Receiving certificates', 'waiting':'Waiting for certificates', 'connecting':'Connecting', 'reconnecting':'Reconnecting', 'stalled':'Feed idle', 'stale':'Monitor needs attention', 'stopped':'Monitor stopped'}.get(state, 'Checking monitor')
    with st.container(border=True, key="sidebar_monitor_status"):
        st.markdown(f":material/{'sensors' if state == 'connected' else 'sync'}: **{label}**")
        st.caption(f"Watching {len(status.get('active_targets', []))}/3 websites · {int(status.get('events_seen', 0)):,} certificates")


def read_recent_events(path=EVENTS_FILE):
    try:
        lines = Path(path).read_text(encoding='utf-8').splitlines()[-80:]
    except OSError:
        return []
    events = []
    for line in reversed(lines):
        try:
            item = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(item, dict) and item.get('source') == 'LIVE_CERTSTREAM' and item.get('stream_mode') == 'live' and item.get('event_type') in {'certificate_update', 'certificate_match'}:
            events.append(item)
    return events


@st.fragment(run_every='3s')
def render_live_stream():
    status = get_monitor_status()
    state = status.get('state', 'unknown')
    labels = {'connected': 'Receiving live certificates', 'waiting': 'Connected · waiting for certificates', 'connecting': 'Connecting to the feed', 'reconnecting': 'Reconnecting to the feed', 'stalled': 'Connected, but no recent data', 'stale': 'Monitor needs attention', 'stopped': 'Monitor stopped'}
    title = labels.get(state, 'Checking monitor status')
    with st.container(border=True):
        if state == 'connected':
            st.success(title, icon=':material/sensors:')
        elif state in {'waiting', 'connecting', 'reconnecting'}:
            st.info(title, icon=':material/sync:')
        else:
            st.warning(title, icon=':material/wifi_off:')
        st.caption('Refreshes automatically every 3 seconds. A certificate match is a lead for investigation, not a confirmed phishing site.')
        c1,c2,c3 = st.columns(3)
        c1.metric('Certificates received', int(status.get('events_seen', 0)))
        c2.metric('Matched domains', int(status.get('matches_found', 0)))
        age = time.time() - float(status.get('last_event_at', 0)) if status.get('last_event_at') else None
        c3.metric('Last certificate', f'{max(0,int(age))}s ago' if age is not None else 'Waiting')
        targets = status.get('active_targets', [])
        st.write('**Watching:** ' + (', '.join(targets) if targets else 'No websites added yet'))
        if st.button('Reconnect feed', icon=':material/sync:', key='reconnect_live_feed'):
            stop_background_monitor()
            start_background_monitor()
            st.rerun(scope='fragment')
        with st.expander('Connection details', icon=':material/settings_ethernet:'):
            st.write(status.get('message') or title)
            st.code(status.get('certstream_url', 'Not configured'), language=None)
            st.caption('If no certificates arrive, check your network or reconnect. Counters reset when the monitor restarts.')

    events = read_recent_events()
    show_matches = st.toggle('Show brand matches only', key='stream_matches_only')
    if show_matches:
        events = [e for e in events if e.get('matched_brand') or e.get('brand_match')]
    st.markdown('#### :material/receipt_long: Recent certificate activity')
    if not events:
        st.info('No brand matches in the recent feed.' if show_matches else 'No certificates received yet. The connection status above shows what is happening.', icon=':material/info:')
        return
    rows=[]
    for event in events[:30]:
        rows.append({'Domain': event.get('matched_domain') or event.get('domain') or 'Not provided', 'Result': 'Brand match' if event.get('brand_match') or event.get('matched_brand') else 'No brand keyword match', 'Brand': event.get('matched_brand') or ', '.join(event.get('matched_brands', [])) or '—', 'Issuer': event.get('issuer') or 'Not provided', 'Received (UTC)': str(event.get('observed_at', ''))[:19].replace('T', ' ')})
    st.dataframe(pd.DataFrame(rows), hide_index=True, width='stretch', height=min(460, 40+35*len(rows)))
    st.caption('Recent activity is sampled for display; the certificate counter includes every processed update. Brand matches are always logged.')
