import type { FrontendRenderer, FrontendRendererArgs } from '@streamlit/component-v2-lib';
import { AllCommunityModule, ModuleRegistry, createGrid, themeQuartz, colorSchemeDark, type ColDef, type ICellRendererParams, type GridApi } from 'ag-grid-community';
import './style.css';
import { renderScanner } from './scanner';
ModuleRegistry.registerModules([AllCommunityModule]);
type Finding = { id: number; domain: string; brand: string; severity: string; score: number; website: string; review: string };
type Data = { rows: Finding[]; selected_id: number | null; storage_key: string; mode?: 'scanner' };
type State = { opened: number };
type Instance = { api: GridApi<Finding>; grid: HTMLElement; signature: string; open: (id: number) => void; cleanup: () => void };
const instances = new WeakMap<FrontendRendererArgs['parentElement'], Instance>();
// Finding content is untrusted. Use textContent, never interpolate HTML.
function badge(p: ICellRendererParams<Finding>, severity = false) {
  const el = document.createElement('span');
  const value = String(p.value ?? 'Unknown');
  const tone = severity ? value.toLowerCase() : value === 'Reachable' ? 'live' : 'offline';
  el.className = `ps-badge ps-${['high','medium','low','live','offline'].includes(tone) ? tone : 'offline'}`;
  el.textContent = value; return el;
}
const columns: ColDef<Finding>[] = [
  { field: 'domain', headerName: 'Domain', flex: 2.4, minWidth: 230, cellClass: 'ps-domain', tooltipField: 'domain' },
  { field: 'brand', headerName: 'Target brand', flex: 1.3, minWidth: 140 },
  { field: 'severity', headerName: 'Severity', width: 115, cellRenderer: (p: ICellRendererParams<Finding>) => badge(p, true) },
  { field: 'score', headerName: 'Risk / 100', width: 140, cellRenderer: (p: ICellRendererParams<Finding>) => {
    const score = Math.max(0, Math.min(100, Number(p.value) || 0));
    const wrap = document.createElement('div'); wrap.className = 'ps-risk';
    const track = document.createElement('span'); track.className = 'ps-risk-track';
    const fill = document.createElement('span'); fill.className = 'ps-risk-fill'; fill.style.width = `${score}%`;
    fill.style.background = score >= 70 ? '#ff858b' : score >= 40 ? '#f3c477' : '#93c5fd';
    track.append(fill); const label = document.createElement('span'); label.textContent = score.toFixed(0);
    wrap.append(track, label); return wrap;
  } },
  { field: 'website', headerName: 'Website', width: 130, cellRenderer: (p: ICellRendererParams<Finding>) => badge(p) },
  { field: 'review', headerName: 'Review status', flex: 1, minWidth: 140 },
  { colId: 'open', headerName: '', width: 56, minWidth: 56, sortable: false, resizable: false, cellRenderer: (p: ICellRendererParams<Finding>) => {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'ps-open'; button.textContent = '↗'; button.setAttribute('aria-label', `Open investigation for ${p.data?.domain}`); return button;
  } },
];
const render: FrontendRenderer<State, Data> = ({parentElement, data, setTriggerValue}) => {
  if (data.mode === 'scanner') return renderScanner(parentElement);
  const root = parentElement.querySelector<HTMLElement>('.ps-threat-grid')!;
  root.style.backdropFilter = 'blur(22px) saturate(125%)';
  const grid = root.querySelector<HTMLElement>('.ps-grid')!;
  root.querySelector<HTMLElement>('.ps-count')!.textContent = `${data.rows.length} findings`;
  const signature = JSON.stringify(data.rows);
  const existing = instances.get(parentElement);
  if (existing && existing.grid === grid) {
    existing.open = id => setTriggerValue('opened', id);
    if (signature !== existing.signature) {
      existing.api.setGridOption('rowData', data.rows);
      existing.signature = signature;
    }
    existing.api.setGridOption('getRowClass', p => p.data?.id === data.selected_id ? 'ps-selected-row' : '');
    existing.api.redrawRows();
    return existing.cleanup;
  }
  existing?.cleanup();
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  root.classList.toggle('ps-motion-off', reduced.matches);
  grid.style.height = `${Math.min(548, 88 + Math.min(data.rows.length, 10) * 46)}px`;
  const storageKey = `phishshield-grid:${data.storage_key}`;
  let saved: { sort?: any; page?: number } = {};
  try { saved = JSON.parse(sessionStorage.getItem(storageKey) || '{}'); } catch { /* optional storage */ }
  const restoredPage = saved.page ?? 0;
  let hydrated = false;
  const theme = themeQuartz.withPart(colorSchemeDark).withParams({
    browserColorScheme: 'dark', fontFamily: 'Manrope, sans-serif', fontSize: 13,
    backgroundColor: 'transparent', foregroundColor: '#eaf3fb', headerBackgroundColor: 'rgba(26, 57, 85, .38)', headerTextColor: '#b8ccdc',
    oddRowBackgroundColor: 'rgba(159, 200, 242, .035)',
    chromeBackgroundColor: 'rgba(19, 43, 68, .24)',
    accentColor: '#93c5fd', borderColor: 'rgba(181,213,234,.22)', rowHoverColor: 'rgba(147,197,253,.07)',
    selectedRowBackgroundColor: 'rgba(147,197,253,.12)', spacing: 6, wrapperBorderRadius: 8, headerFontSize: 11,
  });
  const open = (row?: Finding) => { if (row) instances.get(parentElement)?.open(row.id); };
  const api = createGrid<Finding>(grid, {
    theme, themeStyleContainer: parentElement as HTMLElement,
    rowData: data.rows, columnDefs: columns,
    defaultColDef: { sortable: true, resizable: true, suppressMovable: true },
    getRowId: p => String(p.data.id), rowHeight: 46, headerHeight: 42,
    animateRows: !reduced.matches,
    pagination: true, paginationPageSize: 10, paginationPageSizeSelector: false,
    getRowClass: p => p.data?.id === data.selected_id ? 'ps-selected-row' : '',
    onRowClicked: e => open(e.data),
    onCellKeyDown: e => { if ((e.event as KeyboardEvent)?.key === 'Enter') open(e.data); },
    onGridReady: e => { if (saved.sort) e.api.applyColumnState({ state: saved.sort }); },
    onFirstDataRendered: e => { if (restoredPage) e.api.paginationGoToPage(restoredPage); hydrated = true; },
    onSortChanged: e => { saved.sort = e.api.getColumnState().map(c => ({colId:c.colId,sort:c.sort,sortIndex:c.sortIndex})); try { sessionStorage.setItem(storageKey, JSON.stringify(saved)); } catch { /* optional */ } },
    onPaginationChanged: e => { if (!hydrated) return; saved.page = e.api.paginationGetCurrentPage(); try { sessionStorage.setItem(storageKey, JSON.stringify(saved)); } catch { /* optional */ } },
  });
  const motion = () => { root.classList.toggle('ps-motion-off', reduced.matches); api.setGridOption('animateRows', !reduced.matches); };
  reduced.addEventListener('change', motion);
  const cleanup = () => { reduced.removeEventListener('change', motion); api.destroy(); instances.delete(parentElement); };
  instances.set(parentElement, {api, grid, signature, open: id => setTriggerValue('opened', id), cleanup});
  return cleanup;
};
export default render;
