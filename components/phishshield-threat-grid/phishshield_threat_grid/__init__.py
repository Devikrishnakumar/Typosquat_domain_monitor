"""Locally bundled AG Grid Community table, built on Streamlit CCv2."""
import streamlit as st

_grid = st.components.v2.component(
    'phishshield-threat-grid.phishshield_threat_grid',
    js='index.js', css='style.css',
    html='''
    <section class="ps-threat-grid" aria-label="Domain investigation findings">
      <div class="ps-grid-top"><span class="ps-grid-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Z"/><path d="m8 12 3 3 5-6"/></svg>
        Threat findings</span><span class="ps-count" aria-live="polite"></span></div>
      <div class="ps-grid"></div>
      <div class="ps-grid-footer">Click a row or press Enter to investigate. Click column headings to sort.</div>
    </section>
    ''',
)


def threat_grid(rows, *, selected_id=None, key='threat_grid', on_open=None):
    """Send the stable finding ID when a row is opened."""
    return _grid(key=key, data={'rows': rows, 'selected_id': selected_id, 'storage_key': key}, on_opened_change=on_open or (lambda: None))


def security_visual(key='domain_security_visual'):
    """Imported useAnimations Lottie artwork with local assets and reduced motion."""
    return _grid(key=key, data={'mode':'scanner','rows':[],'selected_id':None,'storage_key':key}, on_opened_change=lambda: None)
