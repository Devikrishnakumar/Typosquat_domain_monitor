"""Guided report workspace with evidence readiness and persistent downloads."""
from pathlib import Path
from datetime import datetime, timezone
import logging
import streamlit as st
from src.reporting.reportlab_generator import generate_security_report
from src.ui.loading import task_loading


def _has_values(data, fields):
    return isinstance(data, dict) and any(data.get(field) for field in fields)


def render_report_workspace(all_flagged):
    st.markdown('### :material/description: Create an incident report')
    st.caption('Choose a finding, check the evidence, and download a PDF your team can review.')
    st.html('''<div class="ps-report-steps" aria-label="Report workflow"><div class="ps-report-step"><span>01</span>Choose a finding</div><div class="ps-report-step"><span>02</span>Review the evidence</div><div class="ps-report-step"><span>03</span>Generate & download</div></div>''')
    if not all_flagged:
        st.info('No findings yet. Investigate a domain or load a demo scenario to create your first report.', icon=':material/info:')
        from src.ui.navigation import DESTINATIONS, navigate_to
        st.button('Open domain explorer', icon=':material/travel_explore:',
                  on_click=navigate_to, args=(DESTINATIONS['explorer'],))
        return

    editor, preview = st.columns([1.45, 1], gap='large')
    with editor:
        with st.container(border=True):
            st.markdown('#### 1. Choose a finding')
            search = st.text_input('Search findings', placeholder='Type a domain or brand name', key='report_search')
            matches = [(c,o) for c,o in all_flagged if search.lower().strip() in f'{c.domain} {c.matched_brand}'.lower()]
            if not matches:
                st.info('No findings match your search. Try a shorter name or clear the search.', icon=':material/search:')
                return
            choices = {c.id:c for c,_ in matches}
            chosen_id = st.selectbox('Domain to report', list(choices), format_func=lambda cid: f'{choices[cid].domain} | {choices[cid].risk_level or "Unknown"}', key='report_finding_id')
            selected = choices[chosen_id]
            observation = next((o for c,o in matches if c.id == chosen_id), {}) or {}
            whois = observation.get('whois', {}) or {}
            dns = observation.get('dns', {}) or {}
            st.caption(f'{len(matches)} matching findings. Reports use the evidence already collected for the selected domain.')
        with st.container(border=True):
            st.markdown('#### 2. Review the evidence')
            shot = selected.screenshot_path
            checks = {
                'Page screenshot': bool(shot and Path(shot).is_file()),
                'Registration details': _has_values(whois, ['registrar','creation_date','created','emails','abuse_email','name_servers']),
                'DNS records': _has_values(dns.get('records', dns) if isinstance(dns, dict) else {}, ['A','AAAA','MX','NS','CNAME']),
            }
            for label, available in checks.items():
                icon = 'check_circle' if available else 'info'
                status = ':green[Available]' if available else ':gray[Not collected]'
                st.markdown(f':material/{icon}: **{label}** | {status}')
            collected = sum(checks.values())
            st.caption(f'{collected} of 3 evidence types available. Missing evidence will remain marked as unavailable in the report.')
            if collected < 3:
                st.info('You can export now, or run another investigation to collect more evidence.', icon=':material/info:')
            with st.expander('Inspect collected evidence', icon=':material/fact_check:'):
                if checks['Page screenshot']:
                    st.image(shot, caption='Collected page screenshot', width='stretch')
                st.write('Registration details'); st.json(whois or {'status':'Not collected'}, expanded=False)
                st.write('DNS records'); st.json(dns or {'status':'Not collected'}, expanded=False)

    with preview, st.container(border=True):
        st.markdown('#### 3. Generate & download')
        st.markdown(':material/article: **Incident report | PDF**')
        st.write(selected.domain)
        st.caption(f'Target brand: {selected.matched_brand or "Unknown"}')
        a,b = st.columns(2)
        a.metric('Risk score', f'{selected.risk_score or 0}/100')
        b.metric('Severity', selected.risk_level or 'Unknown')
        st.markdown('**Included in your report**')
        st.markdown('- Finding and risk summary\n- Available screenshots and infrastructure\n- Registration details and response guidance')
        payload = {key:getattr(selected,key,None) for key in ('domain','matched_brand','risk_score','risk_level','is_live','visual_similarity','has_login_form','screenshot_path','recommended_action','registered_domain','registered_at')}
        payload['source'] = getattr(selected, 'event_category', None) or 'Recorded investigation'
        brand_safe = ''.join(ch if ch.isalnum() or ch in '-_' else '_' for ch in (selected.matched_brand or ''))
        reference = Path('reference_assets/brands') / f'{brand_safe}_reference.png'
        payload['reference_screenshot_path'] = str(reference) if brand_safe and reference.is_file() else None
        report_key = f'prepared_report_{selected.id}'
        if st.button('Generate PDF report', icon=':material/description:', type='primary', width='stretch'):
            try:
                with task_loading('Building your incident report', 'Assembling the collected evidence into a downloadable PDF.'):
                    output = generate_security_report(candidate=payload, whois_info=whois, dns_info=dns)
                    if not output or not Path(output).is_file():
                        raise RuntimeError('The PDF file was not created.')
                    report = {'data':Path(output).read_bytes(), 'name':Path(output).name, 'domain':selected.domain, 'created':datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')}
                    st.session_state[report_key] = report
                    history = st.session_state.get('report_history', [])
                    st.session_state['report_history'] = [report] + [r for r in history if r['name'] != report['name']][:4]
            except Exception:
                logging.getLogger(__name__).exception('Incident report generation failed')
                st.error('The PDF could not be created. Your finding is unchanged. Try generating it again.', icon=':material/error:')
        if report_key in st.session_state:
            report = st.session_state[report_key]
            st.success('Your report is ready.', icon=':material/check_circle:')
            st.download_button('Download PDF report', data=report['data'], file_name=report['name'], mime='application/pdf', icon=':material/download:', key=f'download_prepared_{selected.id}', width='stretch')
            st.caption(f'Prepared {report["created"]}. Generate again after collecting new evidence.')
        else:
            st.caption('Generate the report to enable its download. No report is sent automatically.')
    history = st.session_state.get('report_history', [])
    if history:
        with st.expander('Recent reports in this session', icon=':material/history:'):
            for index, report in enumerate(history):
                st.download_button(f'{report["domain"]} | {report["created"]}', data=report['data'], file_name=report['name'], mime='application/pdf', icon=':material/download:', key=f'recent_report_{index}')
