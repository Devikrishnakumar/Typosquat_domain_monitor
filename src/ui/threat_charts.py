"""Consistent, evidence-driven charts for the glass security dashboard."""
import altair as alt
import pandas as pd
import streamlit as st

SEVERITY = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
COLORS = ['#e76b87', '#ff929b', '#f1c681', '#93c5fd']


def severity_counts(candidates):
    """Keep critical and unassessed findings distinct in the chart."""
    return pd.DataFrame([
        {'Severity': level, 'Findings': sum((c.risk_level or '').upper() == level for c in candidates)}
        for level in SEVERITY
    ])


def glass_chart(chart, height=260):
    return (chart.properties(height=height, background='transparent')
            .configure(font='Manrope')
            .configure_view(stroke=None)
            .configure_axis(labelColor='#b7cbdc', titleColor='#b7cbdc', gridColor='#b5d5ea16', domain=False, ticks=False, labelFontSize=12, titleFontSize=12, labelPadding=10)
            .configure_legend(labelColor='#cbdce9', title=None, labelFontSize=12, orient='bottom', symbolType='circle'))


def render_threat_charts(findings, brands):
    candidates = [c for c, _ in findings]
    left, right = st.columns(2)
    with left, st.container(border=True):
        st.markdown('#### :material/shield: Severity distribution')
        st.caption('Recorded findings by assessed severity. Hover for counts and share.')
        if not candidates:
            st.info('Investigate a domain to see the severity distribution.')
        else:
            counts = severity_counts(candidates)
            unknown = len(candidates) - int(counts.Findings.sum())
            levels, palette = SEVERITY.copy(), COLORS.copy()
            if unknown:
                counts = pd.concat([counts, pd.DataFrame([{'Severity': 'UNASSESSED', 'Findings': unknown}])], ignore_index=True)
                levels.append('UNASSESSED'); palette.append('#8cabc2')
            counts['Share'] = counts.Findings / len(candidates)
            hover = alt.selection_point(fields=['Severity'], on='pointerover', clear='pointerout')
            ring = alt.Chart(counts).mark_arc(innerRadius=78, outerRadius=108, cornerRadius=4, padAngle=.035).encode(
                theta=alt.Theta('Findings:Q'), color=alt.Color('Severity:N', scale=alt.Scale(domain=levels, range=palette), sort=levels),
                opacity=alt.condition(hover, alt.value(1), alt.value(.45)),
                tooltip=['Severity:N', alt.Tooltip('Findings:Q', format=',.0f'), alt.Tooltip('Share:Q', format='.1%')],
            ).add_params(hover)
            total = alt.Chart(pd.DataFrame([{'label': str(len(candidates))}])).mark_text(font='Space Grotesk', fontSize=36, fontWeight=600, color='#edf7ff', dy=-7).encode(text='label:N')
            subtitle = alt.Chart(pd.DataFrame([{'label': 'total findings'}])).mark_text(fontSize=12, color='#abc2d4', dy=24).encode(text='label:N')
            st.altair_chart(glass_chart(ring + total + subtitle, 270), theme=None, width='stretch')
    with right, st.container(border=True):
        st.markdown('#### :material/verified_user: Brand exposure')
        st.caption('Findings matching each monitored brand. Counts include all review states.')
        if not brands:
            st.info('Add a monitored brand to see exposure across your watchlist.')
        else:
            data = pd.DataFrame([{'Brand': b.name, 'Domain': b.official_domain, 'Findings': sum(c.matched_brand in (b.official_domain, b.name) for c in candidates)} for b in brands])
            base = alt.Chart(data).encode(y=alt.Y('Domain:N', title=None, sort='-x', axis=alt.Axis(labelLimit=180)))
            hover = alt.selection_point(fields=['Domain'], on='pointerover', clear='pointerout')
            bars = base.mark_bar(cornerRadiusEnd=5, size=28, color='#60a5fa').encode(
                x=alt.X('Findings:Q', title='Recorded findings', axis=alt.Axis(tickMinStep=1, tickCount=5), scale=alt.Scale(domainMin=0)),
                opacity=alt.condition(hover, alt.value(1), alt.value(.6)),
                tooltip=['Brand:N', 'Domain:N', alt.Tooltip('Findings:Q', format=',.0f')],
            ).add_params(hover)
            labels = base.mark_text(align='left', dx=9, color='#eaf5ff', fontSize=13).encode(x='Findings:Q', text=alt.Text('Findings:Q', format=',.0f'))
            st.altair_chart(glass_chart(bars + labels, 270).properties(padding={'left': 0, 'right': 24, 'top': 16, 'bottom': 0}), theme=None, width='stretch')

    with st.container(border=True):
        st.markdown('#### :material/timeline: Discovery activity')
        st.caption('Newly recorded findings over the last 14 days (UTC). This shows discovery volume, not live traffic.')
        dates = pd.to_datetime(pd.Series([c.detected_at for c in candidates], dtype='object'), errors='coerce', utc=True).dropna()
        if dates.empty:
            st.info('No timestamped findings are available yet.')
        else:
            end = pd.Timestamp.now(tz='UTC').normalize()
            days = pd.date_range(end=end, periods=14, freq='D')
            counts = dates.dt.normalize().value_counts().reindex(days, fill_value=0).sort_index()
            data = pd.DataFrame({'Date': days, 'Findings': counts.values})
            base = alt.Chart(data).encode(x=alt.X('Date:T', title=None, axis=alt.Axis(format='%d %b', tickCount=7)), y=alt.Y('Findings:Q', title='New findings', axis=alt.Axis(tickMinStep=1)), tooltip=[alt.Tooltip('Date:T', format='%d %b %Y'), alt.Tooltip('Findings:Q', format=',.0f')])
            area = base.mark_area(interpolate='linear', color=alt.Gradient(gradient='linear', stops=[alt.GradientStop(color='#60a5fa4d', offset=0), alt.GradientStop(color='#60a5fa00', offset=1)], x1=0, x2=0, y1=0, y2=1))
            line = base.mark_line(color='#60a5fa', strokeWidth=2.5, point=alt.OverlayMarkDef(color='#93c5fd', filled=True, size=42))
            st.altair_chart(glass_chart(area + line, 220), theme=None, width='stretch')
