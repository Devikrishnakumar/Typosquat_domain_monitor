import streamlit as st
from phishshield_threat_grid import threat_grid
st.set_page_config(layout="wide")
result = threat_grid([{"id": 1, "domain": "lookalike.example", "brand": "example.com", "severity": "HIGH", "score": 85, "website": "Reachable", "review": "New"}])
if result.opened:
    st.write("Selected finding:", result.opened)
