"""Locally hosted Google Material Symbols for security dashboard cards."""
import base64
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=16)
def security_icon(name: str, live: bool = False) -> str:
    if name not in {'domain', 'language', 'security', 'policy', 'radar', 'warning', 'search', 'add'}:
        raise ValueError('Unknown security icon')
    svg = (Path(__file__).with_name('icons') / f'{name}.svg').read_text(encoding='utf-8')
    svg = svg.replace('<svg ', '<svg fill="#93c5fd" ', 1)
    data = base64.b64encode(svg.encode()).decode('ascii')
    classes = 'ps-security-icon ps-icon-live' if live else 'ps-security-icon'
    return f'<img class="{classes}" src="data:image/svg+xml;base64,{data}" width="22" height="22" alt="" aria-hidden="true" />'
