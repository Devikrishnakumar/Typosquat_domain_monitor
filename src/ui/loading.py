"""Task-scoped security loading animation; cleared as soon as work finishes."""
from contextlib import contextmanager
from html import escape
import streamlit as st

# Local CSS ring inspired by https://css-loaders.com/spinner/.
# No animation download or external runtime is needed while the app is starting.
LOADING_CSS = '''<style>
.ps-task-loading {display:flex;align-items:center;gap:18px;padding:20px;
 border:1px solid #93c5fd45;border-radius:12px;background:#102131;color:#edf7ff}
.ps-task-loading strong {font:600 16px/1.4 system-ui,sans-serif}
.ps-task-loading p {margin:6px 0 0;font:400 13px/1.5 system-ui,sans-serif;color:#b7cbdc}
.ps-loading-ring {width:42px;height:42px;box-sizing:border-box;flex:0 0 42px;
 border:3px solid #93c5fd30;border-top-color:#93c5fd;border-right-color:#38bdf8;
 border-radius:50%;animation:ps-ring-turn .85s linear infinite}
@keyframes ps-ring-turn {to {transform:rotate(360deg)}}
@media(prefers-reduced-motion:reduce) {.ps-loading-ring {animation:none}}
</style>'''


@contextmanager
def task_loading(title, detail='Working with the available evidence…'):
    placeholder = st.empty()
    placeholder.html(f'''
    {LOADING_CSS}
    <div class="ps-task-loading" role="status" aria-live="polite" aria-busy="true">
      <div class="ps-loading-ring" aria-hidden="true"></div>
      <div><strong>{escape(title)}</strong><p>{escape(detail)}</p></div>
    </div>''')
    try:
        yield
    finally:
        placeholder.empty()
