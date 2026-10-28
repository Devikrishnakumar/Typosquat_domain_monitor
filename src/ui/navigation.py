"""Shared destinations for sidebar buttons, shortcuts, and deep links."""
import streamlit as st

PAGE_KEY = 'phishshield_current_page'
DESTINATIONS = {
    'explorer': ':material/travel_explore: Domain Explorer',
    'overview': ':material/space_dashboard: Executive Dashboard',
    'watchlist': ':material/verified_user: Brand Watchlist (Max 3)',
    'live': ':material/radar: Live CT Stream',
    'scanner': ':material/troubleshoot: On-Demand Scanner',
    'simulations': ':material/science: Attack Simulations',
    'reports': ':material/description: Legal Reports & Dossiers',
}


def navigate_to(page, state_key=PAGE_KEY):
    """Update navigation before the next render, without an extra script run."""
    st.session_state[state_key] = page
    slug = next((slug for slug, label in DESTINATIONS.items() if label == page), None)
    if slug:
        st.query_params['view'] = slug


def prepare_scan(domain):
    st.session_state['sel_scan_domain'] = domain
    # A stable widget key also lets a shortcut change an already visited scanner.
    st.session_state['scan_target_domain'] = domain
    navigate_to(DESTINATIONS['scanner'])
