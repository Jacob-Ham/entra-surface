"""Static report assets: CSS, filter module and main browser script.

Kept as Python strings so the report remains a single-directory deployment.
The CSS contains two insertion tokens replaced at render time with the
Collect and Analysis backend styles.
"""
from __future__ import annotations

REPORT_CSS = """<style>
  :root {
    color-scheme: light;
    --surface-1:      #fcfcfb;
    --page-plane:     #f9f9f7;
    --text-primary:   #0b0b0b;
    --text-secondary: #46453f;
    --text-muted:     #6b6961;
    --gridline:       #e1e0d9;
    --border:         rgba(11,11,11,0.10);
    --status-critical:#a23731;
    --status-serious: #b95c26;
    --status-medium:  #8a7a1f;
    --status-low:     #4a659e;
    --status-good:    #22703f;
    --row-hover:      #e8e6df;
    --accent:         #2f63a8;
  }
  @media (prefers-color-scheme: dark) {
    :root:where(:not([data-theme="light"])) {
      color-scheme: dark;
      --surface-1:      #232321;
      --page-plane:     #181816;
      --text-primary:   #ffffff;
      --text-secondary: #d2d1c6;
      --text-muted:     #9d9b91;
      --gridline:       #3a3a36;
      --border:         rgba(255,255,255,0.13);
      --status-critical:#b3443f;
      --status-serious: #cf7a54;
      --status-medium:  #ab9536;
      --status-low:     #617fbb;
      --status-good:    #2e8b57;
      --row-hover:      #2d2d2a;
      --accent:         #7fa7e0;
    }
  }
  :root[data-theme="dark"] {
    color-scheme: dark;
    --surface-1:      #232321;
    --page-plane:     #181816;
    --text-primary:   #ffffff;
    --text-secondary: #d2d1c6;
    --text-muted:     #9d9b91;
    --gridline:       #3a3a36;
    --border:         rgba(255,255,255,0.13);
    --status-critical:#b3443f;
    --status-serious: #cf7a54;
    --status-medium:  #ab9536;
    --status-low:     #617fbb;
    --status-good:    #2e8b57;
    --row-hover:      #2d2d2a;
    --accent:         #7fa7e0;
  }
  * { box-sizing: border-box; }
  html { background: var(--page-plane); }
  body {
    margin: 0;
    background: var(--page-plane);
    color: var(--text-primary);
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  .app-main {
    min-height: 100vh;
    transition: margin-left 0.18s ease;
  }
  body.sidebar-open .app-main { margin-left: 260px; }
  .sidebar {
    position: fixed; inset: 0 auto 0 0; width: 260px; z-index: 90;
    display: flex; flex-direction: column;
    padding: 24px 18px 20px; overflow-y: auto;
    background: var(--surface-1); border-right: 1px solid var(--border);
    box-shadow: 10px 0 30px rgba(0,0,0,0.10);
    transform: translateX(-100%); visibility: hidden;
    transition: transform 0.18s ease, visibility 0.18s;
  }
  body.sidebar-open .sidebar { transform: translateX(0); visibility: visible; }
  .sidebar-title {
    margin: 0; color: var(--text-muted); font-size: 10px; font-weight: 600;
    letter-spacing: 0.08em; text-transform: uppercase;
  }
  .sidebar-brand {
    color: var(--text-primary); font-size: 16px; font-weight: 700;
    letter-spacing: 0; text-transform: none;
  }
  .sidebar-head {
    display: flex; align-items: center; justify-content: space-between;
    gap: 8px; position: relative;
  }
  .sidebar-settings-btn {
    width: 24px; height: 24px; padding: 0; flex: none;
    display: inline-flex; align-items: center; justify-content: center;
    background: transparent; color: var(--text-muted);
    border: 1px solid transparent; border-radius: 6px;
    font-family: inherit; cursor: pointer;
  }
  .sidebar-settings-btn:hover,
  .sidebar-settings-btn[aria-expanded="true"] {
    background: var(--row-hover); color: var(--text-primary);
    border-color: var(--border);
  }
  .sidebar-theme {
    margin-top: 14px; padding-top: 14px;
    border-top: 1px solid var(--gridline);
  }
  .sidebar-theme .theme-toggle { width: 100%; }
  .sidebar-theme .theme-toggle button {
    flex: 1; padding: 6px 8px; font-size: 12px;
  }
  .settings-overlay {
    position: fixed; inset: 0; z-index: 200;
    background: rgba(0,0,0,0.45);
    display: flex; align-items: center; justify-content: center;
    padding: 24px;
  }
  .settings-overlay.hidden { display: none; }
  body.settings-open { overflow: hidden; }
  .settings-box {
    width: min(620px, 94vw); max-height: min(82vh, 720px);
    display: flex; flex-direction: column; overflow: hidden;
    background: var(--surface-1); border: 1px solid var(--border);
    border-radius: 12px; box-shadow: 0 24px 70px rgba(0,0,0,0.38);
  }
  .settings-head {
    display: flex; align-items: flex-start; justify-content: space-between;
    gap: 12px; padding: 14px 18px;
    border-bottom: 1px solid var(--gridline);
  }
  .settings-head h3 { margin: 0; font-size: 16px; }
  .settings-head .sub {
    margin: 2px 0 0; color: var(--text-secondary); font-size: 12px;
  }
  .settings-tabs {
    display: flex; flex-wrap: wrap; gap: 4px; padding: 10px 14px 0;
    border-bottom: 1px solid var(--gridline);
  }
  .settings-tab {
    background: transparent; border: 1px solid transparent; border-bottom: 0;
    border-radius: 7px 7px 0 0; color: var(--text-secondary);
    padding: 7px 14px; font: inherit; font-size: 12.5px; cursor: pointer;
  }
  .settings-tab:hover { color: var(--text-primary); background: var(--row-hover); }
  .settings-tab.active {
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 10%, transparent);
    border-color: color-mix(in srgb, var(--accent) 28%, transparent);
    font-weight: 600;
  }
  .settings-body { padding: 16px 18px; overflow: auto; }
  .settings-panel.hidden { display: none; }
  .settings-section + .settings-section {
    margin-top: 16px; padding-top: 16px;
    border-top: 1px solid var(--gridline);
  }
  .settings-section h4 {
    margin: 0 0 6px; color: var(--text-muted); font-size: 10.5px;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;
  }
  .settings-value {
    color: var(--text-secondary); font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11.5px; line-height: 1.45; overflow-wrap: anywhere;
  }
  .settings-note {
    margin: 0; color: var(--text-secondary); font-size: 12.5px; line-height: 1.5;
  }
  .settings-field {
    display: flex; flex-direction: column; gap: 4px;
    color: var(--text-secondary); font-size: 12px;
  }
  .settings-field input {
    background: var(--page-plane); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 7px 9px; font-size: 12.5px; font-family: inherit;
  }
  .settings-field input:focus {
    outline: none;
    border-color: color-mix(in srgb, var(--accent) 55%, var(--border));
  }
  .settings-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 10px 12px;
    margin-top: 12px;
  }
  .settings-grid .wide { grid-column: 1 / -1; }
  .settings-actions { margin-top: 12px; }
  .settings-check {
    display: flex; align-items: center; gap: 8px; margin-top: 10px;
    color: var(--text-secondary); font-size: 12.5px; cursor: pointer;
  }
  .settings-check input { margin: 0; }
  .settings-status {
    margin-top: 10px; font-size: 12px; color: var(--text-secondary);
  }
  .settings-status.error { color: var(--status-critical); }
  .settings-status.hidden { display: none; }
  @media (max-width: 520px) {
    .settings-grid { grid-template-columns: 1fr; }
  }
  .settings-foot {
    display: flex; align-items: center; justify-content: flex-end; gap: 8px;
    flex-wrap: wrap; padding: 12px 18px;
    border-top: 1px solid var(--gridline);
  }
  .settings-foot .settings-status { margin: 0; flex: 1; }
  .sidebar-nav { display: flex; flex-direction: column; gap: 4px; margin-top: 14px; }
  .sidebar-nav-item {
    display: flex; align-items: center; width: 100%;
    background: transparent; border: 1px solid transparent; border-radius: 7px;
    padding: 8px 10px; color: var(--text-secondary); text-align: left;
    font-size: 13px; line-height: 1.35; font-family: inherit; cursor: pointer;
  }
  .sidebar-nav-item:hover { background: var(--row-hover); color: var(--text-primary); }
  .sidebar-nav-item.active {
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    border-color: color-mix(in srgb, var(--accent) 30%, transparent);
    color: var(--accent); font-weight: 600;
  }
  .sidebar-principal {
    margin-top: auto; padding-top: 14px;
    border-top: 1px solid var(--gridline);
  }
  .sidebar-principal-body {
    display: flex; align-items: center; gap: 10px; margin-top: 10px;
    min-width: 0;
  }
  .sidebar-principal-info { min-width: 0; }
  .sidebar-principal-name {
    font-size: 12.5px; font-weight: 600; overflow-wrap: anywhere;
  }
  .sidebar-principal-sub {
    color: var(--text-muted); font-size: 10.5px;
    margin-top: 2px; overflow-wrap: anywhere;
  }
  .sidebar-principal-empty { color: var(--text-muted); font-size: 11.5px; }
  .sidebar-toggle {
    position: fixed; top: 50%; left: 0; transform: translateY(-50%);
    z-index: 95; width: 26px; height: 52px; padding: 0;
    display: flex; align-items: center; justify-content: center;
    background: var(--surface-1); color: var(--text-muted);
    border: 1px solid var(--border); border-left: 0;
    border-radius: 0 8px 8px 0;
    box-shadow: 4px 4px 16px rgba(0,0,0,0.12);
    font-size: 18px; line-height: 1; font-family: inherit; cursor: pointer;
    transition: left 0.18s ease, color 0.15s ease, background 0.15s ease;
  }
  .sidebar-toggle:hover { color: var(--text-primary); background: var(--row-hover); }
  body.sidebar-open .sidebar-toggle { left: 260px; }
  .wrap { max-width: 1400px; margin: 0 auto; padding: 36px 28px 72px; }
  header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
  header h1 { font-size: 22px; margin: 0 0 4px; }
  header p { margin: 0; color: var(--text-secondary); font-size: 13px; }
  .theme-toggle {
    display: flex; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; flex: none;
  }
  .theme-toggle button {
    background: var(--surface-1); color: var(--text-secondary); border: none;
    padding: 7px 14px; font-size: 13px; font-family: inherit; cursor: pointer;
  }
  .theme-toggle button + button { border-left: 1px solid var(--border); }
  .theme-toggle button:hover { color: var(--text-primary); }
  .theme-toggle button[aria-pressed="true"] { background: var(--row-hover); color: var(--text-primary); font-weight: 600; }
  .summary-bar {
    display: flex; flex-wrap: wrap; gap: 6px 20px; align-items: baseline;
    margin: 14px 0 6px; font-size: 12px; color: var(--text-secondary);
  }
  .summary-bar .sum-item { white-space: nowrap; }
  .summary-bar .sum-label {
    color: var(--text-muted); font-size: 10px; text-transform: uppercase;
    letter-spacing: 0.02em; margin-right: 5px;
  }
  .summary-bar .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; color: var(--text-primary); }
  .tabs { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin: 20px 0 6px; }
  .tab-btn {
    background: var(--surface-1); color: var(--text-secondary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 7px 14px; font-size: 13px; font-family: inherit; cursor: pointer;
  }
  .tab-btn.active { background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent); font-weight: 600; border-color: color-mix(in srgb, var(--accent) 35%, transparent); }
  .tab-btn .tab-count { color: var(--text-muted); font-size: 11px; margin-left: 5px; }
  .reanalyze-btn { margin-left: auto; }
  .controls {
    display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
    margin: 10px 0 12px;
  }
  .controls .filter-row {
    display: flex; flex: 1; gap: 8px; align-items: center; position: relative; min-width: 260px;
  }
  .controls input, .controls select {
    background: var(--surface-1);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 13px;
  }
  .controls input[type="search"] { flex: 1; min-width: 220px; }
  .mode-btn {
    background: var(--surface-1); color: var(--text-secondary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 7px 12px; font-size: 13px; cursor: pointer; white-space: nowrap;
  }
  .mode-btn:hover { color: var(--text-primary); }
  .mode-btn[aria-pressed="true"] {
    background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent);
    border-color: color-mix(in srgb, var(--accent) 35%, transparent); font-weight: 600;
  }
  .suggest-wrap {
    position: absolute; top: calc(100% + 4px); left: 0; width: 100%; z-index: 40;
    background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px;
    box-shadow: 0 10px 28px rgba(0,0,0,0.16); overflow: hidden;
  }
  .suggest-wrap ul { list-style: none; margin: 0; padding: 4px 0; max-height: 240px; overflow-y: auto; }
  .suggest-wrap li {
    padding: 6px 12px; font-size: 13px; cursor: pointer;
  }
  .suggest-wrap li.active { background: var(--row-hover); color: var(--accent); }
  .suggest-wrap li .sugg-hint { color: var(--text-muted); font-size: 11px; margin-left: 8px; }
  .filter-error {
    width: 100%; color: var(--status-critical); font-size: 12px; margin-top: 4px;
  }
  .filter-spinner {
    flex: 0 0 auto; width: 16px; height: 16px;
    border: 2px solid var(--border); border-top-color: var(--accent);
    border-radius: 50%; animation: filter-spin 0.7s linear infinite;
  }
  @keyframes filter-spin { to { transform: rotate(360deg); } }
  .ca-analysis { margin: 4px 0; }
  .ca-controls { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 4px 0 10px; }
  .ca-sep { font-size: 12.5px; }
  .ca-user-input {
    flex: 1; min-width: 240px; max-width: 420px;
    background: var(--surface-1); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px; padding: 7px 10px; font-size: 13px;
  }
  .ca-whatif select, .ca-small-input {
    background: var(--surface-1); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px; padding: 5px 8px; font-size: 12px;
  }
  .ca-small-input { min-width: 170px; }
  .ca-whatif {
    display: flex; flex-direction: column; gap: 6px; margin: 8px 0 4px; max-width: 460px;
  }
  .ca-whatif label {
    display: grid; grid-template-columns: 130px 1fr; align-items: center; gap: 8px;
    font-size: 12.5px; color: var(--text-secondary);
  }
  .ca-whatif label.ca-check {
    display: flex; align-items: center; gap: 6px;
  }
  .ca-whatif select, .ca-whatif .ca-small-input { width: 100%; }
  .ca-status { margin: 6px 0 12px; font-size: 13px; color: var(--text-muted); }
  .ca-status .ca-step-label { color: var(--text-primary); font-weight: 500; }
  .ca-status .step-detail { color: var(--text-muted); margin-left: 8px; font-size: 12px; }
  .ca-status.error { color: var(--status-critical); }
  th.col-drag-source { opacity: 0.45; }
  body.col-dragging { cursor: grabbing; user-select: none; }
  body.col-dragging th { cursor: grabbing; }
  th.col-drop-target { outline: 2px dashed var(--accent); outline-offset: -3px; }
  section { margin-top: 32px; }
  section[data-category] { margin-top: 26px; }
  section.hidden { display: none; }
  .hidden { display: none; }
  /* higher-specificity layout rules must not resurrect hidden controls */
  .drawer-tabs.hidden { display: none; }
  .ca-whatif label.hidden { display: none; }
  section h2 { font-size: 15px; font-weight: 600; margin: 0 0 4px; }
  section .sub { color: var(--text-secondary); font-size: 12px; margin: 0 0 10px; }
  .section-toggle {
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 30px; min-height: 30px; padding: 6px 8px;
    margin: -6px -8px -6px 0; border: 0; border-radius: 6px;
    background: none; color: var(--text-muted); cursor: pointer;
    font: inherit; font-size: 14px; line-height: 1; vertical-align: middle;
  }
  .section-toggle:hover { color: var(--text-primary); background: var(--row-hover); }
  .section-title-toggle { cursor: pointer; }
  .section-title-toggle:hover { color: var(--text-primary); }
  section.section-collapsed > .table-scroll,
  section.section-collapsed > .table-pager,
  section.section-collapsed > .sub,
  section.section-collapsed > .empty { display: none; }
  .table-scroll {
    overflow-x: auto;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .table-pager {
    display: flex; align-items: center; justify-content: flex-start;
    flex-wrap: wrap; gap: 4px 16px;
    min-height: 36px; padding: 5px 14px;
    background: var(--surface-1);
    border: 1px solid var(--border);
    border-top: 1px solid var(--gridline);
    border-radius: 0 0 8px 8px;
    color: var(--text-muted); font-size: 11.5px; line-height: 1.3;
  }
  .table-pager.hidden { display: none; }
  .table-scroll:has(+ .table-pager:not(.hidden)) {
    border-bottom: 0;
    border-bottom-left-radius: 0;
    border-bottom-right-radius: 0;
  }
  .tp-range {
    color: var(--text-secondary); font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .tp-range.error { color: var(--status-critical); }
  .tp-rows {
    display: inline-flex; align-items: center; gap: 4px;
    margin-left: auto;
    color: var(--text-muted); white-space: nowrap; cursor: pointer;
  }
  .tp-rows:hover .tp-rows-label { color: var(--text-secondary); }
  .tp-select-wrap { position: relative; display: inline-flex; align-items: center; }
  .tp-select-wrap::after {
    content: ""; position: absolute; right: 5px; top: 50%;
    width: 4px; height: 4px; pointer-events: none;
    border-right: 1.5px solid var(--text-muted);
    border-bottom: 1.5px solid var(--text-muted);
    transform: translateY(-70%) rotate(45deg);
  }
  .tp-size {
    appearance: none; -webkit-appearance: none;
    height: 24px; min-width: 38px; padding: 0 17px 0 6px;
    border: 0; border-radius: 5px; background: transparent;
    color: var(--text-secondary);
    font: inherit; font-variant-numeric: tabular-nums;
    cursor: pointer;
  }
  .tp-size:hover { background: var(--row-hover); color: var(--text-primary); }
  .tp-size:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
  .tp-nav { display: inline-flex; align-items: center; }
  .tp-btn {
    display: inline-flex; align-items: center; justify-content: center;
    width: 24px; height: 24px; padding: 0;
    border: 0; border-radius: 5px; background: transparent;
    color: var(--text-secondary); cursor: pointer;
    transition: background-color .12s ease, color .12s ease;
  }
  .tp-btn:hover:not(:disabled) { background: var(--row-hover); color: var(--text-primary); }
  .tp-btn:active:not(:disabled) { background: var(--border); }
  .tp-btn:disabled { opacity: .35; color: var(--text-muted); cursor: default; }
  .tp-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
  .tp-info {
    padding: 0 8px; color: var(--text-muted);
    font-variant-numeric: tabular-nums; white-space: nowrap;
  }
  @media (max-width: 560px) {
    .table-pager { gap: 3px 12px; }
    .tp-rows-label { display: none; }
    .tp-info { padding: 0 6px; }
  }
  table { border-collapse: collapse; font-size: 13px; table-layout: fixed; }
  table.findings { width: 100%; }
  thead th {
    position: relative;
    text-align: left; padding: 11px 16px 11px 14px; color: var(--text-muted);
    font-weight: 500; font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.02em;
    border-bottom: 1px solid var(--gridline); cursor: pointer; user-select: none;
    overflow-wrap: anywhere;
  }
  thead th:hover { color: var(--text-primary); }
  thead th.sorted::after { content: " \\2195"; }
  .col-resizer {
    position: absolute; top: 0; right: 0; width: 8px; height: 100%; cursor: col-resize; z-index: 1;
  }
  .col-resizer:hover, .col-resizer.resizing { background: var(--border); }
  .colman { position: relative; display: flex; justify-content: flex-end; margin: 6px 0 8px; }
  .table-head-row {
    display: flex; align-items: flex-start; justify-content: space-between;
    gap: 12px; flex-wrap: wrap;
  }
  .table-head-row h2 { margin: 0 0 4px; }
  .table-head-row .colman { margin: 0; }
  .colman-btn {
    display: inline-flex; align-items: center; gap: 6px; height: 28px;
    padding: 0 7px; border: 1px solid transparent; border-radius: 6px;
    background: transparent; color: var(--text-muted);
    font: inherit; font-size: 12px; font-weight: 500; cursor: pointer;
    transition: background-color .12s ease, color .12s ease;
  }
  .colman-btn:hover { background: var(--row-hover); color: var(--text-primary); }
  .colman-btn[aria-expanded="true"] {
    color: var(--accent); background: color-mix(in srgb, var(--accent) 10%, transparent);
  }
  .colman-btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .colman-chevron { flex: none; opacity: .55; transition: transform .15s ease; }
  .colman-btn[aria-expanded="true"] .colman-chevron { transform: rotate(180deg); }
  .colman-badge {
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 16px; height: 16px; padding: 0 4px; border-radius: 999px;
    background: color-mix(in srgb, var(--accent) 13%, transparent); color: var(--accent);
    font-size: 10px; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums;
  }
  .colman-badge.hidden { display: none; }
  .colman-pop {
    position: absolute; right: 0; top: calc(100% + 6px); z-index: 30;
    display: flex; flex-direction: column;
    width: min(288px, calc(100vw - 16px));
    max-height: min(360px, 70vh); max-height: min(360px, 70dvh);
    overflow: hidden; text-align: left;
    background: var(--surface-1); border: 1px solid var(--border); border-radius: 12px;
    box-shadow: 0 12px 32px rgba(0,0,0,.18), 0 2px 6px rgba(0,0,0,.08);
    transform-origin: top right; animation: colman-in .13s ease-out;
  }
  .colman-pop.hidden { display: none; }
  @keyframes colman-in {
    from { opacity: 0; transform: translateY(-3px) scale(.985); }
    to { opacity: 1; transform: none; }
  }
  .colman-list {
    flex: 1 1 auto; min-height: 0; overflow-y: auto;
    padding: 0 0 4px; overscroll-behavior: contain;
  }
  .colman-group { padding: 4px 0 3px; }
  .colman-group-title {
    position: sticky; top: 0; z-index: 1;
    padding: 7px 12px 3px; background: var(--surface-1);
    font-size: 10px; font-weight: 600; text-transform: uppercase;
    letter-spacing: .04em; color: var(--text-muted);
  }
  .colman-item {
    display: flex; align-items: center; gap: 8px; min-height: 30px; padding: 5px 12px;
    font-size: 12.5px; color: var(--text-secondary); cursor: pointer;
    transition: background-color .1s ease, color .1s ease;
  }
  .colman-item:hover { background: var(--row-hover); color: var(--text-primary); }
  .colman-item input {
    flex: none; width: 14px; height: 14px; margin: 0;
    accent-color: var(--accent); cursor: pointer;
  }
  .colman-item input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .colman-item span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .colman-foot {
    flex: none; padding: 6px 12px 7px; border-top: 1px solid var(--gridline);
  }
  .colman-reset {
    padding: 2px 0; border: 0; border-radius: 4px; background: none; cursor: pointer;
    color: var(--text-muted); font: inherit; font-size: 11.5px;
  }
  .colman-reset:hover { color: var(--text-primary); text-decoration: underline; }
  .colman-reset:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  @media (prefers-reduced-motion: reduce) {
    .colman-pop { animation: none; }
    .colman-chevron { transition: none; }
  }
  tbody td { padding: 11px 14px; border-bottom: 1px solid var(--gridline); vertical-align: top; overflow-wrap: anywhere; }
  tbody tr:hover { background: var(--row-hover); }
  tbody tr.hidden { display: none; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; color: var(--text-secondary); overflow-wrap: anywhere; }
  .muted { color: var(--text-muted); font-size: 12px; }
  .badge {
    display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600;
    border: 1px solid transparent;
  }
  .sev-critical { color: var(--status-critical); background: color-mix(in srgb, var(--status-critical) 16%, transparent); }
  .sev-high { color: var(--status-serious); background: color-mix(in srgb, var(--status-serious) 16%, transparent); }
  .sev-medium { color: var(--status-medium); background: color-mix(in srgb, var(--status-medium) 16%, transparent); }
  .sev-low { color: var(--status-low); background: color-mix(in srgb, var(--status-low) 14%, transparent); }
  .sev-info { color: var(--text-muted); border-color: var(--border); background: transparent; }
  .role-badge { cursor: pointer; }
  .filter-tag { cursor: pointer; }
  .filter-tag:hover { background: var(--row-hover); color: var(--text-primary); }
  .role-badge:hover { background: var(--row-hover); color: var(--text-primary); }
  .badge-enabled { color: var(--status-good); border-color: color-mix(in srgb, var(--status-good) 45%, transparent); }
  .badge-disabled { color: var(--text-muted); border-color: var(--border); }
  .badge-guest { color: var(--status-serious); border-color: color-mix(in srgb, var(--status-serious) 45%, transparent); }
  .badge-hybrid { color: var(--text-muted); border-color: var(--border); }
  .tag-chip {
    display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
    border: 1px solid var(--border); color: var(--text-secondary);
  }
  .tag-privileged { color: var(--status-serious); border-color: color-mix(in srgb, var(--status-serious) 45%, transparent); }
  .tag-spray { color: var(--status-medium); border-color: color-mix(in srgb, var(--status-medium) 45%, transparent); }
  .tag-divergence { color: var(--status-low); border-color: color-mix(in srgb, var(--status-low) 45%, transparent); }
  .realm { margin: 8px 0 10px; color: var(--text-secondary); font-size: 12px; }
  .realm b { color: var(--text-primary); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; }
  details.inline-more { display: inline; }
  details.inline-more summary { display: inline; cursor: pointer; color: var(--accent); }
  details.inline-more > span { display: inline; }
  .engine-card {
    border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px;
    background: var(--surface-1); margin: 4px 0 6px;
  }
  .engine-card .kv-table { width: 100%; }
  .perm { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; border-bottom: 1px dotted var(--text-muted); cursor: default; overflow-wrap: anywhere; }
  .az-count { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; border: 1px solid var(--border); color: var(--text-primary); background: var(--surface-1); margin-right: 4px; vertical-align: 1px; }
  td.clickable { cursor: pointer; }
  td.clickable:hover { text-decoration: none; color: var(--text-primary); background: var(--row-hover); }
  thead th.no-sort { cursor: default; }
  thead th.no-sort:hover { color: var(--text-secondary); }
  td.expand-cell { text-align: center; }
  .expand-btn {
    width: 24px; height: 24px; padding: 0; font-size: 14px; font-weight: 600;
    display: inline-flex; align-items: center; justify-content: center;
  }
  .empty { padding: 24px; text-align: center; color: var(--text-muted); }
  .overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.45);
    display: flex; align-items: center; justify-content: center; padding: 24px; z-index: 100;
  }
  .overlay.hidden { display: none; }
  .modal {
    background: var(--surface-1); border: 1px solid var(--border); border-radius: 12px;
    width: 1100px; max-width: 95vw; height: 82vh; max-height: 95vh; min-width: 420px; min-height: 280px;
    display: flex; flex-direction: column;
    box-shadow: 0 20px 60px rgba(0,0,0,0.25);
    resize: both; overflow: auto;
  }
  .modal-header {
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    padding: 14px 18px; border-bottom: 1px solid var(--gridline); flex: none;
  }
  .modal-header h3 { margin: 0; font-size: 15px; }
  .modal-header .sub { color: var(--text-secondary); font-size: 12px; margin: 2px 0 0; }
  .modal-body { padding: 14px 18px 18px; overflow: auto; }
  .icon-btn {
    background: none; border: 1px solid var(--border); color: var(--text-secondary);
    font-size: 16px; line-height: 1; cursor: pointer; padding: 5px 10px; border-radius: 6px; flex: none;
  }
  .icon-btn:hover { background: var(--row-hover); color: var(--text-primary); }
  #drilldown-table { table-layout: auto; width: 100%; }
  #drilldown-table, #drilldown-apps-table { table-layout: auto; width: 100%; }
  #drilldown-table th, #drilldown-table td { padding: 8px 12px; border-bottom: 1px solid var(--gridline); text-align: left; font-size: 13px; }
  #drilldown-apps-table th, #drilldown-apps-table td { padding: 8px 12px; border-bottom: 1px solid var(--gridline); text-align: left; font-size: 13px; }
  #drilldown-table th { color: var(--text-muted); font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.02em; white-space: nowrap; }
  .detail-section { margin-bottom: 22px; }
  .detail-section:last-child { margin-bottom: 0; }
  .detail-section h4 { margin: 0 0 8px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em; color: var(--text-muted); }
  .kv-table { width: 100%; border-collapse: collapse; }
  .kv-table tr { border-bottom: 1px solid var(--gridline); }
  .kv-table tr:last-child { border-bottom: none; }
  .kv-table th {
    text-align: left; vertical-align: top; width: 240px; padding: 6px 12px 6px 0;
    font-size: 12px; font-weight: 600; color: var(--text-secondary); white-space: nowrap;
  }
  .kv-table td { padding: 6px 0; font-size: 12.5px; overflow-wrap: anywhere; vertical-align: top; }
  .kv-table pre {
    margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px;
    white-space: pre-wrap; overflow-wrap: anywhere; background: var(--page-plane);
    border: 1px solid var(--border); border-radius: 6px; padding: 8px; max-height: 240px; overflow: auto;
  }
  .profile-list { margin: 0 0 10px; padding: 0 0 0 18px; font-size: 12.5px; }
  .profile-list li { margin: 3px 0; overflow-wrap: anywhere; }
  .profile-list ul { list-style: circle; padding-left: 14px; }
  .drawer-tabs-wrap { margin: 0; }
  .drawer-tabs { display: flex; flex-wrap: wrap; gap: 4px; margin: 0 0 12px; }
  .drawer-tab {
    background: none; border: 1px solid var(--border); border-radius: 6px;
    padding: 6px 12px; font-size: 12px; color: var(--text-secondary);
    font-family: inherit; cursor: pointer;
  }
  .drawer-tab.active { background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent); font-weight: 600; border-color: color-mix(in srgb, var(--accent) 35%, transparent); }
  .dtab-pane { display: none; }
  .dtab-pane.active { display: block; }
  .minor-table { width: 100%; border-collapse: collapse; font-size: 12px; margin: 4px 0 10px; table-layout: fixed; }
  .minor-table th {
    text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--gridline);
    color: var(--text-muted); font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.02em;
  }
  .minor-table td { padding: 6px 10px; border-bottom: 1px solid var(--gridline); overflow-wrap: anywhere; vertical-align: top; }
  .user-owned-table th:first-child, .user-owned-table td:first-child { width: 140px; white-space: nowrap; }
  .user-owned-table th:nth-child(2), .user-owned-table td:nth-child(2) { min-width: 220px; }
  .user-owned-table th { padding: 8px 10px; }
  .user-owned-table td { padding: 8px 10px; line-height: 1.45; }
  .user-owned-table .owned-grant { display: block; }
  .user-owned-table .owned-grant + .owned-grant { margin-top: 2px; }
  .dtab-sp-link, .app-link {
    background: none; border: none; padding: 0; margin: 0;
    color: var(--accent); text-decoration: underline; cursor: pointer;
    font-family: inherit; font-size: 12px; text-align: left;
  }
  .drawer-back-row { margin: 0 0 6px; }
  .list-more-btn {
    font-size: 11.5px; font-family: inherit; background: none; border: none;
    color: var(--accent); cursor: pointer; padding: 2px 0;
  }
  .list-more-btn:hover { text-decoration: underline; }
  tr.drawer { display: none; }
  tr.drawer.open { display: table-row; }
  tr.drawer td { padding: 8px 12px 12px; background: var(--page-plane); }
  .drawer-body {
    border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px;
    background: var(--surface-1);
    max-width: min(100%, 1320px, calc(100vw - 80px));
  }
  body.sidebar-open .drawer-body {
    max-width: min(100%, 1320px, calc(100vw - 340px));
  }
  __COLLECT_CSS__
  __ANALYSIS_CSS__
  @media (max-width: 900px) {
    body.sidebar-open .app-main { margin-left: 0; }
    .sidebar { width: min(84vw, 320px); }
    body.sidebar-open .sidebar-toggle { left: min(84vw, 320px); }
    body.sidebar-open .drawer-body {
      max-width: min(100%, calc(100vw - 80px));
    }
  }
</style>"""


JS_FILTER_MODULE = """<script id="filter-module">
// Advanced filter query language — mirrors the Python grammar in
// entra_surface/filters.py (parse_advanced_query); keep both in sync when extending
// the grammar or alias tables.
(function() {
  var LIST_FIELDS = {roles:1, eligible:1, grproles:1, grptype:1, dynmods:1, dynattrs:1,
    azroles:1, azusrroles:1, azsproles:1, adtags:1, appdirroles:1,
    polapps:1, polcontrols:1, arcazroles:1,
    owner:1, ownerupn:1, ownerstatus:1};

  // column-name aliases -> DOM field names (any-match), mirrored from Python
  var COLUMN_ALIASES = {
    privileges: ['severity'], severity: ['severity'], sev: ['severity'],
    roles: ['roles', 'grproles', 'appdirroles'],
    grproles: ['grproles'], appdirroles: ['appdirroles'],
    eligible: ['eligible'],
    user: ['user'], upn: ['userupn', 'upn'], userupn: ['userupn'],
    privapps: ['privapps'], capablegrp: ['capgroups'], capgroups: ['capgroups'],
    groupsowned: ['grpowned'], grpowned: ['grpowned'], caexcl: ['caexcl'],
    accountsource: ['hybrid'], hybrid: ['hybrid'],
    status: ['userstatus', 'status', 'spstatus', 'ownerstatus', 'adstatus'],
    userstatus: ['userstatus'], spstatus: ['spstatus'],
    ownerstatus: ['ownerstatus'], adstatus: ['adstatus'],
    ownersource: ['ownersource'], owneraddn: ['owneraddn'],
    ownersid: ['owneradsid'], owneradsid: ['owneradsid'],
    ownerimmutableid: ['ownerimmutableid'],
    target: ['target'], targettype: ['targettype'],
    objectid: ['id'], id: ['id'],
    passwords: ['pw'], pw: ['pw'], keys: ['keys'],
    roleassignment: ['rolecount'], rolecount: ['rolecount'],
    group: ['group'], type: ['grptype'], grptype: ['grptype'],
    groupsource: ['groupsource'],
    members: ['grpmembers'], grpmembers: ['grpmembers'],
    privmembers: ['grppriv'], grppriv: ['grppriv'],
    owners: ['grpowners'], grpowners: ['grpowners'],
    policy: ['polname'], polname: ['polname'],
    state: ['polstate'], polstate: ['polstate'],
    scope: ['polscope'], polscope: ['polscope'],
    apps: ['polapps'], polapps: ['polapps'],
    controls: ['polcontrols'], polcontrols: ['polcontrols'],
    included: ['polinc'], polinc: ['polinc'],
    excluded: ['polexc'], polexc: ['polexc'],
    application: ['app'], app: ['app'],
    owner: ['owner'], ownerupn: ['ownerupn'],
    resource: ['resource'], permission: ['permission'],
    membershiprule: ['dynrule'], dynrule: ['dynrule'],
    referencedattributes: ['dynattrs'], dynattrs: ['dynattrs'],
    modifiableby: ['dynmods'], dynmods: ['dynmods'],
    aduser: ['aduser'], adupn: ['adupn'],
    adcn: ['adcn'], addn: ['addn'],
    sid: ['adsid'], adsid: ['adsid'],
    onprempwchange: ['adpw'], adpw: ['adpw'],
    targetingtags: ['adtags'], adtags: ['adtags'],
    azapp: ['azapp'], azgroup: ['azgroup'], azuser: ['azuser'],
    azroles: ['azroles'], azsproles: ['azsproles'], azusrroles: ['azusrroles'],
    azscopetype: ['azscopetype'], azsub: ['azsub'], azrg: ['azrg'],
    azprovider: ['azprovider'], azresource: ['azresource'],
    arcmachine: ['arcmachine'], arcsub: ['arcsub'], arcrg: ['arcrg'],
    arcresourceid: ['arcresourceid'], arcstatus: ['arcstatus'],
    arcprincipal: ['arcprincipal'], arcprincipaltype: ['arcprincipaltype'],
    arctag: ['arctag'], arcazroles: ['arcazroles'], arcprovider: ['arcprovider'],
    pwlastset: ['pwlastset'],
    appid: ['appid'], spty: ['sptype'], servicetype: ['sptype'],
    poltype: ['poltype'], polcreated: ['polcreated'], created: ['polcreated'],
    polmodified: ['polmodified'], lastmodified: ['polmodified'],
    immutableid: ['immutableid'],
    check: ['check'], category: ['category']
  };

  var DISPLAY_NAMES = {
    privileges: 'Privileges', roles: 'Directory roles', eligible: 'Eligible',
    user: 'User', upn: 'UPN', privapps: 'Priv apps', capablegrp: 'Capable grp',
    groupsowned: 'Groups owned', caexcl: 'CA excl.', accountsource: 'Account Source',
    status: 'Status', target: 'Target', targettype: 'Target Type',
    objectid: 'Object ID', passwords: 'Passwords', keys: 'Keys',
    roleassignment: 'Role assignment', group: 'Group', type: 'Type',
    groupsource: 'Group source',
    members: 'Members', privmembers: 'Priv. members', owners: 'Owners',
    policy: 'Policy', state: 'State', scope: 'Scope', apps: 'Apps',
    controls: 'Controls', included: 'Included', excluded: 'Excluded',
    application: 'Application', owner: 'Owner', ownerupn: 'Owner UPN',
    ownerstatus: 'Owner Status', resource: 'Resource', permission: 'Permission',
    ownersource: 'Owner Source', owneraddn: 'Owner AD DN', ownersid: 'Owner SID',
    ownerimmutableid: 'Owner Immutable ID',
    spstatus: 'SP Status', membershiprule: 'Membership rule',
    referencedattributes: 'Referenced attributes', modifiableby: 'Modifiable by',
    aduser: 'User', adupn: 'UPN', adcn: 'AD CN', addn: 'AD DN', sid: 'SID',
    onprempwchange: 'On-prem pw change', targetingtags: 'Targeting tags',
    appid: 'App ID', spty: 'SP type', poltype: 'Policy type',
    polcreated: 'Created', polmodified: 'Last modified', immutableid: 'Immutable ID',
    check: 'Check', category: 'Category'
  };

  var PHRASES = [
    ['Directory roles', 'roles'], ['Priv. members', 'privmembers'],
    ['Priv apps', 'privapps'], ['Capable grp', 'capablegrp'],
    ['Groups owned', 'groupsowned'], ['CA excl.', 'caexcl'],
    ['Account Source', 'accountsource'], ['Group source', 'groupsource'],
    ['Target Type', 'targettype'],
    ['Target Status', 'status'], ['Object ID', 'objectid'],
    ['Role assignment', 'roleassignment'], ['SP Status', 'spstatus'],
    ['Owner UPN', 'ownerupn'], ['Owner Status', 'ownerstatus'],
    ['Owner Source', 'ownersource'], ['Owner AD DN', 'owneraddn'],
    ['Owner SID', 'ownersid'], ['Owner Immutable ID', 'ownerimmutableid'],
    ['Membership rule', 'membershiprule'],
    ['Referenced attributes', 'referencedattributes'],
    ['Modifiable by', 'modifiableby'],
    ['attribute modifiable by', 'modifiableby'],
    ['Modifiable by', 'modifiableby'],
    ['AD CN', 'adcn'], ['AD DN', 'addn'],
    ['On-prem pw change', 'onprempwchange'], ['Targeting tags', 'targetingtags'],
    ['App ID', 'appid'], ['SP type', 'spty'], ['Policy type', 'poltype'],
    ['Created', 'polcreated'], ['Last modified', 'polmodified'],
    ['Immutable ID', 'immutableid'],
  ];

  var BS = String.fromCharCode(92);  // backslash, avoids escape-layering with Python strings
  var REGEX_SPECIALS = '.*+?^$(){}[]|' + BS;

  function escapeRegExp(s) {
    var out = '';
    for (var i = 0; i < s.length; i++) {
      var c = s.charAt(i);
      out += REGEX_SPECIALS.indexOf(c) !== -1 ? BS + c : c;
    }
    return out;
  }

  var PHRASE_RES = PHRASES.map(function(p) {
    return [new RegExp(BS + 'b' + escapeRegExp(p[0]) + '(?=' + BS + 's*:)', 'i'), p[1]];
  });
  var DISPLAY_CANON = {};
  PHRASES.forEach(function(p) { DISPLAY_CANON[normalizeField(p[0])] = p[1]; });

  function rewritePhrases(text) {
    for (var i = 0; i < PHRASE_RES.length; i++) {
      text = text.replace(PHRASE_RES[i][0], PHRASE_RES[i][1]);
    }
    return text;
  }

  function normalizeField(name) {
    return (name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  // Every column label/id in the rendered catalog is filterable, including
  // table-specific labels and columns added after the static alias list.
  var AUTO_ALIASES = {};
  var AUTO_DISPLAY = {};
  var AUTO_PHRASES = {};
  var AUTO_PHRASE_ORDER = [];
  function addAutoAlias(name, field, display) {
    var canon = normalizeField(name);
    var norm = normalizeField(field);
    if (!canon || !norm) return;
    var bucket = AUTO_ALIASES[canon] || (AUTO_ALIASES[canon] = []);
    if (bucket.indexOf(norm) === -1) bucket.push(norm);
    if (display) {
      if (!AUTO_DISPLAY[canon]) AUTO_DISPLAY[canon] = display;
      if (/[^A-Za-z0-9]/.test(display) && !AUTO_PHRASES[canon]) {
        AUTO_PHRASES[canon] = display;
        AUTO_PHRASE_ORDER.push(canon);
      }
    }
  }
  (function() {
    try {
      var el = document.getElementById('table-catalog-data');
      var catalog = el ? JSON.parse(el.textContent) : {};
      Object.keys(catalog || {}).forEach(function(tid) {
        ((catalog[tid] || {}).fields || []).forEach(function(f) {
          addAutoAlias(f.id, f.id, '');
          addAutoAlias(f.label || f.id, f.id, f.label || f.id);
        });
      });
      var extra = AUTO_PHRASE_ORDER.map(function(canon) {
        return [AUTO_PHRASES[canon], canon];
      });
      extra.sort(function(a, b) { return b[0].length - a[0].length; });
      PHRASE_RES = extra.map(function(p) {
        return [new RegExp(BS + 'b' + escapeRegExp(p[0])
                           + '(?=' + BS + 's*:)', 'i'), p[1]];
      }).concat(PHRASE_RES);
    } catch (e) {}
  })();

  function pushFields(out, values) {
    (values || []).forEach(function(v) {
      if (out.indexOf(v) === -1) out.push(v);
    });
  }

  function fieldsFor(name) {
    var canon = normalizeField(name);
    var fields = [];
    pushFields(fields, COLUMN_ALIASES[canon]);
    var mapped = DISPLAY_CANON[canon];
    if (mapped) pushFields(fields, COLUMN_ALIASES[mapped]);
    pushFields(fields, AUTO_ALIASES[canon]);
    return fields.length ? fields : null;
  }

  function columns() {
    var out = [], byDisplay = {};
    function addColumn(canon, display) {
      var key = normalizeField(display);
      var item = byDisplay[key];
      if (!item) {
        item = {canonical: canon, display: display, fields: []};
        byDisplay[key] = item;
        out.push(item);
      }
      pushFields(item.fields, COLUMN_ALIASES[canon]);
      pushFields(item.fields, AUTO_ALIASES[canon]);
    }
    Object.keys(DISPLAY_NAMES).forEach(function(canon) {
      addColumn(canon, DISPLAY_NAMES[canon]);
    });
    Object.keys(AUTO_DISPLAY).forEach(function(canon) {
      addColumn(canon, AUTO_DISPLAY[canon]);
    });
    out.sort(function(a, b) { return a.display < b.display ? -1 : 1; });
    return out;
  }

  function tokenize(text) {
    var tokens = [], i = 0, n = text.length;
    while (i < n) {
      var ch = text[i];
      if (/\\s/.test(ch)) { i++; continue; }
      if (ch === '(' || ch === ')') { tokens.push({t: ch === '(' ? 'lparen' : 'rparen', v: ch}); i++; continue; }
      if (ch === '"') {
        var j = i + 1, buf = '';
        while (j < n && text[j] !== '"') { buf += text[j]; j++; }
        if (j >= n) throw new Error('unterminated quote at position ' + i);
        tokens.push({t: 'quoted', v: buf});
        i = j + 1;
        continue;
      }
      var k = i;
      while (k < n && !/\\s/.test(text[k]) && text[k] !== '(' && text[k] !== ')' && text[k] !== '"') k++;
      tokens.push({t: 'word', v: text.slice(i, k)});
      i = k;
    }
    return tokens;
  }

  function isOp(tok, op) {
    return !!tok && tok.t === 'word' && tok.v.toUpperCase() === op;
  }

  function parse(text) {
    try {
      var rewritten = rewritePhrases(text || '');
      var tokens = tokenize(rewritten), pos = 0;
      if (!tokens.length) return {ast: {op: 'text', value: ''}};
      function isAnyOperator(tok) {
        return !!tok && tok.t === 'word' &&
          (tok.v.toUpperCase() === 'AND' || tok.v.toUpperCase() === 'OR' || tok.v.toUpperCase() === 'NOT');
      }
      function isValueTerminator(tok) {
        return isAnyOperator(tok) ||
          (!!tok && tok.t === 'word' && tok.v.toUpperCase().indexOf('UNIQ:') === 0);
      }
      function consumeValueWords(value) {
        // append following plain words so unquoted values with spaces work
        while (true) {
          var tok = pos < tokens.length ? tokens[pos] : null;
          if (!tok || tok.t !== 'word' || isValueTerminator(tok)) return value;
          pos++;
          value += ' ' + tok.v;
        }
      }
      function resolveField(name) {
        if (name.toUpperCase() === 'CONTAINS') return null;
        var fields = fieldsFor(name);
        if (!fields) throw new Error("unknown field '" + name + "' (try privileges, roles, target, check, category)");
        return fields;
      }
      function peek() { return pos < tokens.length ? tokens[pos] : null; }
      function advance() { return tokens[pos++]; }
      function expect(kind) {
        var tok = peek();
        if (!tok || tok.t !== kind) {
          throw new Error('expected ' + kind + " near '" + (tok ? tok.v : '<end>') + "'");
        }
        return advance();
      }
      function parseOr() {
        var children = [parseAnd()];
        while (isOp(peek(), 'OR')) { advance(); children.push(parseAnd()); }
        return children.length === 1 ? children[0] : {op: 'or', children: children};
      }
      function parseAnd() {
        var children = [parseTerm()];
        while (isOp(peek(), 'AND')) { advance(); children.push(parseTerm()); }
        return children.length === 1 ? children[0] : {op: 'and', children: children};
      }
      function parseTerm() {
        var tok = peek();
        if (!tok) throw new Error('unexpected end of query');
        if (tok.t === 'rparen') throw new Error("unexpected ')' near '" + tok.v + "'");
        if (tok.t === 'lparen') { advance(); var node = parseOr(); expect('rparen'); return node; }
        if (isOp(tok, 'NOT')) { advance(); return {op: 'not', child: parseTerm()}; }
        if (tok.t === 'quoted') { advance(); return {op: 'text', value: tok.v}; }
        var word = advance().v;
        if (isOp({t: 'word', v: word}, 'AND') || isOp({t: 'word', v: word}, 'OR')) {
          throw new Error("unexpected operator '" + word + "'");
        }
        if (word.toUpperCase() === 'NOT') return {op: 'not', child: parseTerm()};
        if (word.indexOf(':') === -1) return {op: 'text', value: word};
        var idx = word.indexOf(':');
        var field = word.slice(0, idx), rest = word.slice(idx + 1);
        if (!field) return {op: 'text', value: word};
        if (field.toUpperCase() === 'CONTAINS') {
          // bare contains: / contains: value is a text predicate (B-033)
          if (!rest) {
            var vt0 = peek();
            if (!vt0 || (vt0.t !== 'word' && vt0.t !== 'quoted')) {
              throw new Error("expected value after 'contains:'");
            }
            advance();
            return {op: 'text', value: consumeValueWords(vt0.v)};
          }
          return {op: 'text', value: consumeValueWords(rest)};
        }
        if (!rest) {
          var vt = peek();
          if (!vt || (vt.t !== 'word' && vt.t !== 'quoted')) {
            throw new Error("expected value after '" + field + ":'");
          }
          advance();
          return {op: 'eq', fields: resolveField(field), value: consumeValueWords(vt.v)};
        }
        if (rest.toUpperCase() === 'CONTAINS') {
          var vt2 = peek();
          if (!vt2 || (vt2.t !== 'word' && vt2.t !== 'quoted')) {
            throw new Error("expected value after '" + field + ":contains:'");
          }
          advance();
          return {op: 'contains', fields: resolveField(field), value: consumeValueWords(vt2.v)};
        }
        if (rest.toUpperCase().indexOf('CONTAINS:') === 0) {
          return {op: 'contains', fields: resolveField(field),
                  value: consumeValueWords(rest.slice('contains:'.length))};
        }
        if (field.toUpperCase() === 'UNIQ') {
          var names = rest.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
          if (!names.length) {
            var vt3 = peek();
            if (!vt3 || (vt3.t !== 'word' && vt3.t !== 'quoted')) {
              throw new Error("expected field after 'uniq:'");
            }
            advance();
            names = [vt3.v];
          }
          var ufields = [];
          names.forEach(function(n) {
            var resolved = resolveField(n);
            if (resolved) ufields = ufields.concat(resolved);
          });
          return {op: 'uniq', fields: ufields};
        }
        return {op: 'eq', fields: resolveField(field), value: consumeValueWords(rest)};
      }
      var node = parseOr();
      var extra = peek();
      if (extra) throw new Error("unexpected '" + extra.v + "'");
      return {ast: node};
    } catch (e) {
      return {error: String(e.message || e)};
    }
  }

  function globRegex(pattern) {
    var parts = pattern.split('*');
    var out = '';
    for (var i = 0; i < parts.length; i++) {
      out += escapeRegExp(parts[i]);
      if (i < parts.length - 1) out += '.*';
    }
    return new RegExp(out, 'i');
  }

  function globMatches(pattern, value, search) {
    // '*' alone means "any non-empty value"; otherwise '*' wildcards match
    // any sequence. search=true matches anywhere in the value.
    if (pattern === '*') return !!value;
    var re = globRegex(pattern);
    if (search) return re.test(value);
    var m = re.exec(value);
    return !!(m && m[0] === value);
  }

  function evaluate(ast, fields, fullText) {
    // normalize the field map to lowercase keys (DOM maps are already
    // lowercase; serve-side maps use CamelCase — handle both)
    var fl = {};
    Object.keys(fields || {}).forEach(function(k) { fl[k.toLowerCase()] = fields[k]; });
    var op = ast.op;
    if (op === 'text') {
      return (fullText || '').toLowerCase().indexOf(ast.value.toLowerCase()) !== -1;
    }
    if (op === 'not') return !evaluate(ast.child, fl, fullText);
    if (op === 'and' || op === 'or') {
      for (var i = 0; i < ast.children.length; i++) {
        var r = evaluate(ast.children[i], fl, fullText);
        if (op === 'and' && !r) return false;
        if (op === 'or' && r) return true;
      }
      return op === 'and';
    }
    if (op === 'eq' || op === 'contains') {
      var needle = ast.value.toLowerCase();
      var hasGlob = needle.indexOf('*') !== -1;
      var fieldList = ast.fields || [];
      for (var f = 0; f < fieldList.length; f++) {
        var field = fieldList[f];
        var fieldL = String(field).toLowerCase();
        var value = (fl[fieldL] || '').toLowerCase();
        if (op === 'contains') {
          if (hasGlob) {
            if (globMatches(needle, value, true)) return true;
          } else if (value.indexOf(needle) !== -1) {
            return true;
          }
        } else if (LIST_FIELDS[fieldL]) {
          if (hasGlob) {
            var items = value.split(',');
            for (var j = 0; j < items.length; j++) {
              if (globMatches(needle, items[j].trim().toLowerCase())) return true;
            }
          } else {
            for (var j2 = 0; j2 < value.split(',').length; j2++) {
              if (value.split(',')[j2].trim().toLowerCase() === needle) return true;
            }
          }
        } else {
          if (hasGlob) {
            if (globMatches(needle, value)) return true;
          } else if (value === needle) {
            return true;
          }
        }
      }
      return false;
    }
    if (op === 'uniq') return true;
    return false;
  }

  function uniqFields(ast) {
    var out = [];
    function walk(node) {
      if (!node) return;
      if (node.op === 'uniq') {
        (node.fields || []).forEach(function(f) {
          if (out.indexOf(f) === -1) out.push(f);
        });
        return;
      }
      (node.children || []).forEach(walk);
      if (node.child) walk(node.child);
    }
    walk(ast);
    return out;
  }

  window.ADV_FILTER = {parse: parse, evaluate: evaluate, listFields: LIST_FIELDS,
                       fieldsFor: fieldsFor, columns: columns,
                       normalizeField: normalizeField, uniqFields: uniqFields};
})();
</script>
"""


REPORT_JS = """<script>
(function() {
  var root = document.documentElement;
  var lightBtn = document.getElementById('theme-light-btn');
  var darkBtn = document.getElementById('theme-dark-btn');

  function currentTheme() {
    var attr = root.getAttribute('data-theme');
    if (attr === 'light' || attr === 'dark') return attr;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  function updateThemeButtons() {
    var active = currentTheme();
    lightBtn.setAttribute('aria-pressed', String(active === 'light'));
    darkBtn.setAttribute('aria-pressed', String(active === 'dark'));
  }
  function setTheme(theme) {
    root.setAttribute('data-theme', theme);
    try { localStorage.setItem('entra-audit-theme', theme); } catch (e) {}
    updateThemeButtons();
  }
  try {
    var stored = localStorage.getItem('entra-audit-theme');
    if (stored === 'light' || stored === 'dark') root.setAttribute('data-theme', stored);
  } catch (e) {}
  lightBtn.addEventListener('click', function() { setTheme('light'); });
  darkBtn.addEventListener('click', function() { setTheme('dark'); });
  updateThemeButtons();
})();

(function() {
  var gear = document.getElementById('sidebar-settings-btn');
  var overlay = document.getElementById('settings-overlay');
  var closeBtn = document.getElementById('settings-close');
  var doneBtn = document.getElementById('settings-done');
  var saveBtn = document.getElementById('settings-save');
  var testBtn = document.getElementById('settings-test');
  var proxyEnabled = document.getElementById('settings-proxy-enabled');
  var proxyUrl = document.getElementById('settings-proxy-url');
  var proxyUser = document.getElementById('settings-proxy-user');
  var proxyPass = document.getElementById('settings-proxy-pass');
  var proxyNoProxy = document.getElementById('settings-proxy-no-proxy');
  var proxyInsecure = document.getElementById('settings-proxy-insecure');
  var proxyStatus = document.getElementById('settings-proxy-status');
  var settingsStatus = document.getElementById('settings-status');
  var uaGlobal = document.getElementById('settings-ua-global');
  var uaCollect = document.getElementById('settings-ua-collect');
  var uaTokens = document.getElementById('settings-ua-tokens');
  var tabs = Array.prototype.slice.call(
    document.querySelectorAll('#settings-overlay button[data-settings-tab]'));
  if (!gear || !overlay) return;

  function setProxyStatus(text, failed) {
    if (!proxyStatus) return;
    proxyStatus.textContent = text || '';
    proxyStatus.classList.toggle('hidden', !text);
    proxyStatus.classList.toggle('error', !!failed);
  }

  function setStatus(text, failed) {
    if (!settingsStatus) return;
    settingsStatus.textContent = text || '';
    settingsStatus.classList.toggle('hidden', !text);
    settingsStatus.classList.toggle('error', !!failed);
  }

  function fillProxy(proxy) {
    proxy = proxy || {};
    if (proxyEnabled) proxyEnabled.checked = !!proxy.enabled;
    if (proxyUrl) proxyUrl.value = proxy.url || '';
    if (proxyUser) proxyUser.value = proxy.username || '';
    if (proxyPass) proxyPass.value = proxy.password || '';
    if (proxyNoProxy) proxyNoProxy.value = proxy.no_proxy || '';
    if (proxyInsecure) proxyInsecure.checked = !!proxy.insecure_tls;
  }

  function fillUserAgents(userAgents) {
    userAgents = userAgents || {};
    if (uaGlobal) uaGlobal.value = userAgents.global || '';
    if (uaCollect) uaCollect.value = userAgents.collect || '';
    if (uaTokens) uaTokens.value = userAgents.tokens || '';
  }

  function userAgentPayload() {
    return {
      global: uaGlobal ? uaGlobal.value.trim() : '',
      collect: uaCollect ? uaCollect.value.trim() : '',
      tokens: uaTokens ? uaTokens.value.trim() : ''
    };
  }

  function proxyPayload() {
    return {
      enabled: !!(proxyEnabled && proxyEnabled.checked),
      url: proxyUrl ? proxyUrl.value.trim() : '',
      username: proxyUser ? proxyUser.value.trim() : '',
      password: proxyPass ? proxyPass.value : '',
      no_proxy: proxyNoProxy ? proxyNoProxy.value.trim() : '',
      insecure_tls: !!(proxyInsecure && proxyInsecure.checked)
    };
  }

  function loadSettings() {
    return fetch('/api/settings')
      .then(function(r) {
        return r.json().then(function(data) {
          if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
          return data;
        });
      })
      .then(function(data) {
        fillProxy(data.proxy);
        fillUserAgents(data.user_agents);
        setProxyStatus('', false);
        setStatus('', false);
      })
      .catch(function(err) {
        setStatus(err.message || 'Could not load settings.', true);
      });
  }

  function saveSettings() {
    var proxy = proxyPayload();
    var userAgents = userAgentPayload();
    if (proxy.enabled && !proxy.url) {
      setStatus('Enter a proxy URL.', true);
      selectTab('proxy');
      if (proxyUrl) proxyUrl.focus();
      return;
    }
    if (saveBtn) saveBtn.disabled = true;
    setStatus('Saving...', false);
    fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxy: proxy, user_agents: userAgents })
    }).then(function(r) {
      return r.json().then(function(data) {
        if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
        return data;
      });
    }).then(function(data) {
      fillProxy(data.proxy);
      fillUserAgents(data.user_agents);
      setStatus('Settings saved.', false);
    }).catch(function(err) {
      setStatus(err.message || 'Could not save settings.', true);
    }).then(function() {
      if (saveBtn) saveBtn.disabled = false;
    });
  }

  function testProxy() {
    var proxy = proxyPayload();
    if (!proxy.enabled) {
      setProxyStatus('Enable the proxy before testing it.', true);
      selectTab('proxy');
      return;
    }
    if (!proxy.url) {
      setProxyStatus('Enter a proxy URL.', true);
      selectTab('proxy');
      if (proxyUrl) proxyUrl.focus();
      return;
    }
    if (testBtn) testBtn.disabled = true;
    setProxyStatus('Testing proxy...', false);
    fetch('/api/settings/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proxy: proxy })
    }).then(function(r) {
      return r.json().then(function(data) {
        if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
        return data;
      });
    }).then(function(data) {
      var bits = ['Proxy connection OK'];
      if (data.status) bits.push('HTTP ' + data.status);
      if (typeof data.elapsed_ms === 'number') bits.push(data.elapsed_ms + ' ms');
      if (data.tls_verify === false) bits.push('TLS verification off');
      setProxyStatus(bits.join(' \u00b7 ') + '.', false);
    }).catch(function(err) {
      setProxyStatus(err.message || 'Could not reach the proxy.', true);
    }).then(function() {
      if (testBtn) testBtn.disabled = false;
    });
  }

  function selectTab(name) {
    tabs.forEach(function(tab) {
      var active = tab.getAttribute('data-settings-tab') === name;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', String(active));
      var panel = document.getElementById(
        'settings-panel-' + tab.getAttribute('data-settings-tab'));
      if (panel) panel.classList.toggle('hidden', !active);
    });
  }

  function setOpen(open) {
    if (open) {
      selectTab('general');
      overlay.classList.remove('hidden');
      document.body.classList.add('settings-open');
      gear.setAttribute('aria-expanded', 'true');
      if (closeBtn) closeBtn.focus();
      loadSettings();
    } else {
      overlay.classList.add('hidden');
      document.body.classList.remove('settings-open');
      gear.setAttribute('aria-expanded', 'false');
      gear.focus();
    }
  }

  gear.addEventListener('click', function(event) {
    event.stopPropagation();
    setOpen(true);
  });
  if (closeBtn) closeBtn.addEventListener('click', function() { setOpen(false); });
  if (doneBtn) doneBtn.addEventListener('click', function() { setOpen(false); });
  if (saveBtn) saveBtn.addEventListener('click', saveSettings);
  if (testBtn) testBtn.addEventListener('click', testProxy);
  overlay.addEventListener('click', function(event) {
    if (event.target === overlay) setOpen(false);
  });
  tabs.forEach(function(tab) {
    tab.addEventListener('click', function() {
      selectTab(tab.getAttribute('data-settings-tab'));
    });
    tab.addEventListener('keydown', function(event) {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      event.preventDefault();
      var index = tabs.indexOf(tab);
      var step = event.key === 'ArrowRight' ? 1 : -1;
      var next = tabs[(index + step + tabs.length) % tabs.length];
      selectTab(next.getAttribute('data-settings-tab'));
      next.focus();
    });
  });
  document.addEventListener('keydown', function(event) {
    if (event.key !== 'Escape' || overlay.classList.contains('hidden')) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    setOpen(false);
  });
})();

(function() {
  var body = document.body;
  var sidebar = document.getElementById('sidebar');
  var toggle = document.getElementById('sidebar-toggle');
  var arrow = toggle && toggle.querySelector('.sidebar-toggle-arrow');
  if (!sidebar || !toggle) return;

  function setOpen(open) {
    body.classList.toggle('sidebar-open', open);
    toggle.setAttribute('aria-expanded', String(open));
    toggle.setAttribute('aria-label', open ? 'Close sidebar' : 'Open sidebar');
    toggle.title = open ? 'Close sidebar' : 'Open sidebar';
    if (arrow) arrow.textContent = open ? '\u2039' : '\u203a';
    sidebar.setAttribute('aria-hidden', String(!open));
    sidebar.toggleAttribute('inert', !open);
    try { localStorage.setItem('entra-audit-sidebar', open ? 'open' : 'closed'); } catch (e) {}
  }
  var stored = null;
  try { stored = localStorage.getItem('entra-audit-sidebar'); } catch (e) {}
  setOpen(stored !== 'closed');
  toggle.addEventListener('click', function() {
    setOpen(!body.classList.contains('sidebar-open'));
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && body.classList.contains('sidebar-open')) {
      setOpen(false);
      toggle.focus();
    }
  });
})();

(function() {
  var target = document.getElementById('sidebar-principal-body');
  if (!target) return;

  function showEmpty(text) {
    target.innerHTML = '';
    var span = document.createElement('span');
    span.className = 'sidebar-principal-empty';
    span.textContent = text;
    target.appendChild(span);
  }

  function render(data) {
    var tokens = data.tokens || [];
    var active = null;
    for (var i = 0; i < tokens.length; i++) {
      if (tokens[i].active) { active = tokens[i]; break; }
    }
    target.innerHTML = '';
    if (!active) {
      showEmpty('No active token');
      return;
    }
    var p = active.principal || {};
    var name = p.name || p.upn || 'Unredeemed refresh token';
    var activeClient = active.client_name || active.client_id || '';
    var sub = p.upn || (activeClient ? 'Client: ' + activeClient : '');
    var avatar = document.createElement('span');
    avatar.className = 'token-avatar';
    avatar.textContent = (name || '?').trim().charAt(0).toUpperCase() || '?';
    var info = document.createElement('div');
    info.className = 'sidebar-principal-info';
    var nameEl = document.createElement('div');
    nameEl.className = 'sidebar-principal-name';
    nameEl.textContent = name;
    info.appendChild(nameEl);
    if (sub) {
      var subEl = document.createElement('div');
      subEl.className = 'sidebar-principal-sub';
      subEl.textContent = sub;
      info.appendChild(subEl);
    }
    if (p.audience) {
      var audEl = document.createElement('div');
      audEl.className = 'sidebar-principal-sub';
      var aud = String(active.audience_name || p.audience || '');
      if (aud.indexOf('https://') === 0) aud = aud.slice(8);
      else if (aud.indexOf('http://') === 0) aud = aud.slice(7);
      audEl.textContent = aud;
      if (active.audience_name && p.audience) audEl.title = p.audience;
      info.appendChild(audEl);
    }
    target.appendChild(avatar);
    target.appendChild(info);
  }

  function refresh() {
    fetch('/api/tokens?enrich=0')
      .then(function(r) { return r.json(); })
      .then(render)
      .catch(function() { showEmpty('Could not load active token'); });
  }

  document.addEventListener('tokens:changed', refresh);
  document.addEventListener('visibilitychange', function() {
    if (!document.hidden) refresh();
  });
  refresh();
})();

(function() {
  var nav = document.getElementById('sidebar-nav');
  if (!nav) return;
  var items = Array.prototype.slice.call(nav.querySelectorAll('button[data-view]'));
  var views = Array.prototype.slice.call(document.querySelectorAll('.app-view[data-view]'));
  function apply(view) {
    views.forEach(function(v) {
      v.classList.toggle('hidden', v.getAttribute('data-view') !== view);
    });
    items.forEach(function(b) {
      var active = b.getAttribute('data-view') === view;
      b.classList.toggle('active', active);
      if (active) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
    document.dispatchEvent(new CustomEvent('app:view', { detail: view }));
    window.scrollTo(0, 0);
  }
  items.forEach(function(b) {
    b.addEventListener('click', function() { apply(b.getAttribute('data-view')); });
  });
})();

(function() {
  var tabsEl = document.getElementById('category-tabs');
  if (tabsEl) {
    var btns = Array.prototype.slice.call(tabsEl.querySelectorAll('button[data-category]'));
    var sections = Array.prototype.slice.call(document.querySelectorAll('section[data-category]'));
    function apply(category) {
      var caView = window.__caView || 'main';
      sections.forEach(function(s) {
        var hidden = category !== 'all' && s.getAttribute('data-category') !== category;
        if (!hidden && s.hasAttribute('data-caview')) {
          hidden = s.getAttribute('data-caview') !== caView;
        }
        s.classList.toggle('hidden', hidden);
      });
      btns.forEach(function(b) {
        b.classList.toggle('active', b.getAttribute('data-category') === category);
      });
    }
    btns.forEach(function(b) { b.addEventListener('click', function() { apply(b.getAttribute('data-category')); }); });
  }
})();

(function() {
  function allTables() {
    return Array.prototype.slice.call(document.querySelectorAll('table.findings'));
  }
  var FIELD_LABELS = {
    severity: 'Privileges', owner: 'Owner', ownerUpn: 'Owner UPN',
    ownerStatus: 'Owner Status', ownerSource: 'Owner Source',
    ownerAdDn: 'Owner AD DN', ownerAdSid: 'Owner SID',
    ownerImmutableId: 'Owner Immutable ID', app: 'Application',
    resource: 'Resource', permission: 'Permission', spStatus: 'SP Status',
    target: 'Target', targetType: 'Target Type', id: 'Object ID', status: 'Target Status',
    pw: 'Passwords', keys: 'Keys', roleCount: 'Role assignment',
    userUpn: 'UPN', roles: 'Directory roles', eligible: 'Eligible roles',
    privApps: 'Privileged apps owned',
    capGroups: 'Role-capable group memberships', grpOwned: 'Groups owned',
    group: 'Group', grpType: 'Type', grpRoles: 'Directory roles',
    grpMembers: 'Members', grpPriv: 'Privileged members', grpOwners: 'Owners',
    polName: 'Policy', polState: 'State', polScope: 'Scope', polApps: 'Apps',
    polControls: 'Controls', polInc: 'Included users', polExc: 'Excluded users',
    dynGroup: 'Group', dynRule: 'Membership rule', dynAttrs: 'Referenced attributes',
    dynMods: 'attribute modifiable by',
    azRoles: 'Azure roles',
    azUsrRoles: 'Azure roles',
    azSpRoles: 'Azure roles',
    azApp: 'Application / SP', azUser: 'User', azGroup: 'Group',
    azScopeType: 'Scope Type', azSub: 'Subscription', azRg: 'Resource Group',
    azProvider: 'Provider', azResource: 'Resource',
    appId: 'App ID', spType: 'SP type', appDirRoles: 'Directory roles',
    pwLastSet: 'Password last set', pwExpiry: 'Expiration date',
    polType: 'Policy type', polCreated: 'Created', polModified: 'Last modified',
    immutableId: 'Immutable ID',
    ssoProtocol: 'SSO protocol', ssoPublisher: 'Publisher',
    ssoAudience: 'Audience', ssoAssignment: 'Assignment required',
    ssoAssigned: 'Assigned', ssoCertExpiry: 'Signing certificate',
    ssoHomeTenant: 'Home tenant', ssoVerified: 'Publisher status',
    ssoReplyUrls: 'Reply URLs', ssoNotify: 'Notification emails',
    ssoCertThumb: 'Certificate thumbprint'
  };
  var DRILLDOWN_COLUMNS = {
    owner:      ['app', 'resource', 'permission', 'severity', 'spStatus'],
    ownerUpn:   ['app', 'resource', 'permission', 'severity', 'spStatus'],
    app:        ['ownerUpn', 'resource', 'permission', 'severity', 'spStatus'],
    resource:   ['app', 'ownerUpn', 'permission', 'severity', 'spStatus'],
    permission: ['app', 'ownerUpn', 'resource', 'severity', 'spStatus'],
    target:     ['targetType', 'id', 'roleCount', 'pw', 'keys', 'severity', 'status'],
    roles:      ['userUpn', 'privApps', 'capGroups', 'grpOwned', 'severity'],
    eligible:   ['userUpn', 'group', 'severity'],
    group:      ['group', 'grpType', 'grpRoles', 'grpMembers', 'grpPriv', 'grpOwners', 'severity'],
    grpRoles:   ['group', 'grpMembers', 'grpPriv', 'severity'],
    polName:    ['polState', 'polScope', 'polApps', 'polControls', 'polInc', 'polExc', 'severity'],
    dynGroup:   ['dynRule', 'dynAttrs', 'dynMods'],
    dynAttrs:   ['dynGroup', 'dynRule', 'dynMods'],
    dynRule:    ['dynGroup', 'dynAttrs', 'dynMods'],
    dynMods:    ['dynGroup', 'dynRule', 'dynAttrs'],
    ssoProtocol: ['app', 'ssoPublisher', 'ssoAudience', 'ssoAssignment', 'ssoAssigned', 'ssoCertExpiry', 'owner', 'status'],
    ssoPublisher: ['app', 'ssoProtocol', 'ssoAudience', 'ssoAssignment', 'owner', 'status'],
    azRoles:    ['azGroup', 'azRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource'],
    azUsrRoles: ['azUser', 'azUsrRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource'],
    azSpRoles:  ['azApp', 'azSpRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource'],
    azGroup:    ['azGroup', 'azRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource'],
    azUser:     ['azUser', 'azUsrRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource'],
    azApp:      ['azApp', 'azSpRoles', 'severity', 'azScopeType', 'azSub', 'azRg', 'azProvider', 'azResource']
  };

  function collectRecords() {
    var records = [];
    allTables().forEach(function(table) {
      Array.prototype.forEach.call(table.tBodies[0].rows, function(row) {
        var rec = {};
        Array.prototype.forEach.call(row.cells, function(td) {
          var field = td.getAttribute('data-field');
          if (field) rec[field] = td.getAttribute('data-value') || '';
        });
        rec.__ids = {
          sp: row.getAttribute('data-sp-id') || '',
          app: row.getAttribute('data-app-id') || '',
          owner: row.getAttribute('data-owner-id') || '',
          profile: row.getAttribute('data-profile-id') || ''
        };
        rec.__gid = row.getAttribute('data-group-id') || '';
        rec.__pid = row.getAttribute('data-policy-id') || '';
        rec.__check = row.getAttribute('data-check-id') || '';
        records.push(rec);
      });
    });
    return records;
  }
  var allRecords = collectRecords();

  var overlay = document.getElementById('drilldown-overlay');
  var titleEl = document.getElementById('drilldown-title');
  var subtitleEl = document.getElementById('drilldown-subtitle');
  var theadRow = document.getElementById('drilldown-thead-row');
  var tbody = document.getElementById('drilldown-tbody');
  var tabsWrap = document.getElementById('drilldown-tabs');
  var usersScroll = document.getElementById('drilldown-users-scroll');
  var appsScroll = document.getElementById('drilldown-apps-scroll');
  var appsThead = document.getElementById('drilldown-apps-thead');
  var appsTbody = document.getElementById('drilldown-apps-tbody');

  var ROLE_APPS = {};
  try { ROLE_APPS = JSON.parse(document.getElementById('role-apps-data').textContent); } catch (e) {}
  var PERMISSION_APPS = {};
  try { PERMISSION_APPS = JSON.parse(document.getElementById('permission-apps-data').textContent); } catch (e) {}

  var drilldownSeq = 0;
  var drilldownAbort = null;

  function beginDrilldownRequest() {
    drilldownSeq += 1;
    if (drilldownAbort) {
      try { drilldownAbort.abort(); } catch (e) {}
    }
    drilldownAbort = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    return { seq: drilldownSeq, signal: drilldownAbort ? drilldownAbort.signal : null };
  }

  function isCurrentDrilldown(token) {
    return !!token && token.seq === drilldownSeq;
  }

  function isAbortError(err) {
    return !!err && err.name === 'AbortError';
  }

  function clearDrilldownTable(message) {
    theadRow.innerHTML = '';
    tbody.innerHTML = '';
    if (message) {
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      td.className = 'muted';
      td.textContent = message;
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  }

  function closeDrilldown() {
    drilldownSeq += 1;  // ignore any in-flight response
    if (drilldownAbort) {
      try { drilldownAbort.abort(); } catch (e) {}
      drilldownAbort = null;
    }
    overlay.classList.add('hidden');
    tabsWrap.classList.add('hidden');
    tabsWrap.innerHTML = '';
    usersScroll.classList.remove('hidden');
    appsScroll.classList.add('hidden');
    clearDrilldownTable('');
    subtitleEl.textContent = '';
  }

  var CONTAINS_FIELDS = { roles: true, eligible: true, grpRoles: true, dynMods: true, dynAttrs: true, azRoles: true, azUsrRoles: true, azSpRoles: true };
  var SERVE_DRILLDOWN_FIELDS = {
    owner: 1, ownerUpn: 1, ownerStatus: 1, app: 1, resource: 1, permission: 1,
    spStatus: 1, target: 1, targetType: 1, id: 1, roleCount: 1, pw: 1, keys: 1,
    status: 1, user: 1, userUpn: 1, roles: 1, eligible: 1, privApps: 1, capGroups: 1,
    grpOwned: 1, hybrid: 1, userStatus: 1, caExcl: 1, group: 1, grpType: 1,
    grpRoles: 1, grpMembers: 1, grpPriv: 1, grpOwners: 1, severity: 1,
    polName: 1, polState: 1, polScope: 1, polApps: 1, polControls: 1,
    polInc: 1, polExc: 1, dynGroup: 1, dynRule: 1, dynAttrs: 1, dynMods: 1,
    adUser: 1, adUpn: 1, adCn: 1, adDn: 1, adSid: 1, adPw: 1, adTags: 1, adStatus: 1,
    ssoProtocol: 1, ssoPublisher: 1
  };

  function isRoleDrilldown(field) {
    return field === 'roles' || field === 'permission';
  }

  function openDrilldown(field, value) {
    if (value === '' || value == null) return;  // never query for an empty value
    if (isRoleDrilldown(field)) { openRoleDrilldown(field, value); return; }
    var token = beginDrilldownRequest();
    tabsWrap.classList.add('hidden');
    tabsWrap.innerHTML = '';
    usersScroll.classList.remove('hidden');
    appsScroll.classList.add('hidden');
    // set the title immediately and replace the previous entity's rows with a
    // loading state so a slow response can never expose stale content
    titleEl.textContent = (FIELD_LABELS[field] || field) + ': ' + value;
    subtitleEl.textContent = 'Loading\u2026';
    clearDrilldownTable('Loading\u2026');
    overlay.classList.remove('hidden');
    if (SERVE_DRILLDOWN_FIELDS[field]) {
      var opts = token.signal ? { signal: token.signal } : undefined;
      fetch('/api/drilldown?field=' + encodeURIComponent(field) + '&value=' + encodeURIComponent(value), opts)
        .then(function(r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function(d) {
          if (!isCurrentDrilldown(token)) return;
          if (!d || d.rows_html == null) { fillUsersLocal(field, value); return; }
          titleEl.textContent = d.title;
          subtitleEl.textContent = d.subtitle;
          theadRow.innerHTML = d.thead_html;
          tbody.innerHTML = d.rows_html;
        })
        .catch(function(err) {
          if (isAbortError(err) || !isCurrentDrilldown(token)) return;
          fillUsersLocal(field, value);
        });
      return;
    }
    fillUsersLocal(field, value);
  }

  function fillUsersLocal(field, value) {
    var wanted = String(value).split(',').map(function(x) { return x.trim(); })
        .filter(function(x) { return x; });
    var matches = allRecords.filter(function(r) {
      var v = r[field] || '';
      if (CONTAINS_FIELDS[field]) {
        var have = String(v).split(',').map(function(x) { return x.trim(); });
        return wanted.length && wanted.every(function(x) { return have.indexOf(x) >= 0; });
      }
      return v === value;
    });
    var columns = DRILLDOWN_COLUMNS[field] || Object.keys(FIELD_LABELS).filter(function(f) { return f !== field; });

    subtitleEl.textContent = matches.length + (matches.length === 1 ? ' matching finding in the collected set' : ' matching findings in the collected set');

    theadRow.innerHTML = '';
    theadRow.appendChild(document.createElement('th'));
    columns.forEach(function(f) {
      var th = document.createElement('th');
      th.textContent = FIELD_LABELS[f] || f;
      theadRow.appendChild(th);
    });

    tbody.innerHTML = '';
    matches.forEach(function(r, rIdx) {
      var tr = document.createElement('tr');
      tr.setAttribute('data-sp-id', r.__ids.sp);
      tr.setAttribute('data-app-id', r.__ids.app);
      tr.setAttribute('data-owner-id', r.__ids.owner);
      tr.setAttribute('data-profile-id', r.__ids.profile || r.__ids.owner || '');
      tr.setAttribute('data-group-id', r.__gid || '');
      tr.setAttribute('data-policy-id', r.__pid || '');
      tr.setAttribute('data-detail-key', 'dd-' + matches.length + '-' + rIdx);

      var expandTd = document.createElement('td');
      expandTd.className = 'expand-cell';
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'icon-btn expand-btn';
      btn.setAttribute('aria-label', 'View full details');
      btn.textContent = '+';
      expandTd.appendChild(btn);
      tr.appendChild(expandTd);

      columns.forEach(function(f) {
        var td = document.createElement('td');
        var val = r[f];
        if (!val) val = (f === 'owner') ? '(no owner)' : '\\u2014';
        td.textContent = val;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
      var tdr = document.createElement('tr');
      tdr.className = 'drawer';
      tdr.setAttribute('data-detail-for', tr.getAttribute('data-detail-key'));
      var tdc = document.createElement('td');
      tdc.colSpan = columns.length + 1;
      var tdb = document.createElement('div');
      tdb.className = 'drawer-body';
      tdc.appendChild(tdb);
      tdr.appendChild(tdc);
      tbody.appendChild(tdr);
    });
    if (!matches.length) {
      var emptyTr = document.createElement('tr');
      var emptyTd = document.createElement('td');
      emptyTd.colSpan = columns.length + 1;
      emptyTd.className = 'muted';
      emptyTd.textContent = 'No matching findings.';
      emptyTr.appendChild(emptyTd);
      tbody.appendChild(emptyTr);
    }
  }

  function fillAppsPane(value, isPermission) {
    var entries = (isPermission ? PERMISSION_APPS[value] : ROLE_APPS[value]) || [];
    appsTbody.innerHTML = '';
    appsThead.innerHTML = '';
    appsThead.appendChild(document.createElement('th'));
    ['Application', 'ObjectId', isPermission ? 'Resource' : 'Assignment'].forEach(function(label) {
      var th = document.createElement('th');
      th.textContent = label;
      appsThead.appendChild(th);
    });
    if (!entries.length) {
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      td.colSpan = 4;
      td.className = 'muted';
      td.textContent = isPermission
          ? 'No service principals hold this permission.'
          : 'No service principals hold this directory role.';
      tr.appendChild(td);
      appsTbody.appendChild(tr);
      return;
    }
    entries.forEach(function(a, i) {
      var rowKey = 'ra-' + i;
      var tr = document.createElement('tr');
      tr.setAttribute('data-sp-id', a.id);
      if (a.app_object_id) tr.setAttribute('data-app-id', a.app_object_id);
      tr.setAttribute('data-detail-key', rowKey);
      var expandTd = document.createElement('td');
      expandTd.className = 'expand-cell';
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'icon-btn expand-btn';
      btn.setAttribute('aria-label', 'View full details');
      btn.textContent = '+';
      expandTd.appendChild(btn);
      tr.appendChild(expandTd);
      var nameTd = document.createElement('td');
      nameTd.textContent = a.name;
      tr.appendChild(nameTd);
      var idTd = document.createElement('td');
      idTd.className = 'mono';
      idTd.textContent = a.id;
      tr.appendChild(idTd);
      var assignTd = document.createElement('td');
      if (isPermission) {
        assignTd.textContent = a.resource || '\u2014';
      } else {
        assignTd.textContent = (a.eligible ? '(eligible) ' : '') + (a.path ? ('via ' + a.path.join(' \u2192 ')) : 'Direct');
      }
      tr.appendChild(assignTd);
      appsTbody.appendChild(tr);
      var tdr = document.createElement('tr');
      tdr.className = 'drawer';
      tdr.setAttribute('data-detail-for', rowKey);
      var tdc = document.createElement('td');
      tdc.colSpan = 4;
      var tdb = document.createElement('div');
      tdb.className = 'drawer-body';
      tdc.appendChild(tdb);
      tdr.appendChild(tdc);
      appsTbody.appendChild(tdr);
    });
  }

  function fillPermissionUsersPane(permission) {
    var entries = PERMISSION_APPS[permission] || [];
    var seen = {};
    var rows = [];
    entries.forEach(function(a) {
      (a.owners || []).forEach(function(o) {
        var ownerKey = (o.object_id || o.upn || o.display_name || '') + '|' + (a.id || '');
        if (seen[ownerKey]) return;
        seen[ownerKey] = 1;
        rows.push({owner: o, app: a});
      });
    });
    theadRow.innerHTML = '';
    theadRow.appendChild(document.createElement('th'));
    ['Owner', 'Owner UPN', 'Status', 'Application', 'Permission'].forEach(function(label) {
      var th = document.createElement('th');
      th.textContent = label;
      theadRow.appendChild(th);
    });
    tbody.innerHTML = '';
    if (!rows.length) {
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'muted';
      td.textContent = 'No recorded owners for principals holding this permission.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    rows.forEach(function(r, i) {
      var o = r.owner;
      var tr = document.createElement('tr');
      if (o.object_id) {
        tr.setAttribute('data-owner-id', o.object_id);
        tr.setAttribute('data-profile-id', o.object_id);
      }
      tr.setAttribute('data-detail-key', 'pd-' + i);
      var expandTd = document.createElement('td');
      expandTd.className = 'expand-cell';
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'icon-btn expand-btn';
      btn.setAttribute('aria-label', 'View full details');
      btn.textContent = '+';
      expandTd.appendChild(btn);
      tr.appendChild(expandTd);
      var nameTd = document.createElement('td');
      nameTd.textContent = o.display_name || o.upn || o.object_id || '';
      tr.appendChild(nameTd);
      var upnTd = document.createElement('td');
      upnTd.className = 'mono';
      upnTd.textContent = o.upn || '\u2014';
      tr.appendChild(upnTd);
      var statusTd = document.createElement('td');
      statusTd.textContent = o.enabled ? 'Enabled' : 'Disabled';
      tr.appendChild(statusTd);
      var appTd = document.createElement('td');
      appTd.textContent = r.app.name || '';
      tr.appendChild(appTd);
      var permTd = document.createElement('td');
      permTd.textContent = permission;
      tr.appendChild(permTd);
      tbody.appendChild(tr);
      var tdr = document.createElement('tr');
      tdr.className = 'drawer';
      tdr.setAttribute('data-detail-for', tr.getAttribute('data-detail-key'));
      var tdc = document.createElement('td');
      tdc.colSpan = 6;
      var tdb = document.createElement('div');
      tdb.className = 'drawer-body';
      tdc.appendChild(tdb);
      tdr.appendChild(tdc);
      tbody.appendChild(tdr);
    });
  }

  function openRoleDrilldown(field, value) {
    if (value === '' || value == null) return;
    var token = beginDrilldownRequest();
    var isPermission = field === 'permission';
    var entries = (isPermission ? PERMISSION_APPS[value] : ROLE_APPS[value]) || [];
    var ownerSeen = {};
    entries.forEach(function(a) {
      (a.owners || []).forEach(function(o) {
        ownerSeen[(o.object_id || o.upn || o.display_name || '') + '|' + (a.id || '')] = 1;
      });
    });
    var ownerCount = Object.keys(ownerSeen).length;
    titleEl.textContent = (FIELD_LABELS[field] || field) + ': ' + value;
    tabsWrap.innerHTML = '';
    var mkTab = function(id, label, active) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'drawer-tab' + (active ? ' active' : '');
      b.setAttribute('data-dtab', id);
      b.textContent = label;
      return b;
    };
    tabsWrap.appendChild(mkTab('users', 'Users' + (isPermission ? ' (' + ownerCount + ')' : ''), !isPermission));
    tabsWrap.appendChild(mkTab('apps', 'Applications (' + entries.length + ')', isPermission));
    tabsWrap.classList.remove('hidden');
    usersScroll.classList.toggle('hidden', isPermission);
    appsScroll.classList.toggle('hidden', !isPermission);
    fillAppsPane(value, isPermission);
    if (isPermission) {
      fillPermissionUsersPane(value);
      subtitleEl.textContent = entries.length
          + (entries.length === 1 ? ' principal holds this permission' : ' principals hold this permission')
          + (ownerCount ? ' \u00b7 ' + ownerCount + ' recorded owner(s)' : ' \u00b7 no recorded owners');
    } else if (SERVE_DRILLDOWN_FIELDS[field]) {
      // drop the previous role's users immediately; only this request's
      // response may repopulate the shared table
      clearDrilldownTable('Loading\u2026');
      subtitleEl.textContent = 'Loading\u2026';
      var opts = token.signal ? { signal: token.signal } : undefined;
      fetch('/api/drilldown?field=' + encodeURIComponent(field) + '&value=' + encodeURIComponent(value), opts)
        .then(function(r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function(d) {
          if (!isCurrentDrilldown(token)) return;
          if (!d || d.rows_html == null) { fillUsersLocal(field, value); return; }
          subtitleEl.textContent = d.subtitle;
          theadRow.innerHTML = d.thead_html;
          tbody.innerHTML = d.rows_html;
        })
        .catch(function(err) {
          if (isAbortError(err) || !isCurrentDrilldown(token)) return;
          fillUsersLocal(field, value);
        });
    } else {
      fillUsersLocal(field, value);
    }
    overlay.classList.remove('hidden');
  }

  tabsWrap.addEventListener('click', function(e) {
    var b = e.target.closest('.drawer-tab');
    if (!b) return;
    var id = b.getAttribute('data-dtab');
    Array.prototype.forEach.call(tabsWrap.querySelectorAll('.drawer-tab'), function(x) {
      x.classList.toggle('active', x === b);
    });
    usersScroll.classList.toggle('hidden', id !== 'users');
    appsScroll.classList.toggle('hidden', id !== 'apps');
  });

  document.addEventListener('click', function(e) {
    var badge = e.target.closest('.role-badge');
    if (!badge) return;
    var value = badge.getAttribute('data-role') || '';
    if (!value) return;  // decorative/unmapped chip: never open an empty drilldown
    e.stopPropagation();
    openDrilldown(badge.getAttribute('data-role-field') || 'roles', value);
  });
  document.addEventListener('click', function(e) {
    var tag = e.target.closest('.filter-tag');
    if (!tag) return;
    var value = tag.getAttribute('data-filter-value') || '';
    if (!value) return;
    e.stopPropagation();
    openDrilldown(tag.getAttribute('data-filter-field') || '', value);
  });

  document.getElementById('drilldown-close').addEventListener('click', closeDrilldown);
  overlay.addEventListener('click', function(e) { if (e.target === overlay) closeDrilldown(); });
  document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeDrilldown(); });

  // One delegated handler covers tables present at load time and CA-result
  // tables created later by caRenderResults. The identity/app capture
  // handlers above run first and stop propagation for object-cell clicks.
  document.addEventListener('click', function(e) {
    var cell = e.target.closest('td.clickable');
    if (!cell) return;
    var table = cell.closest('table.findings');
    if (!table || !table.tBodies.length) return;
    var row = cell.closest('tr');
    var field = cell.getAttribute('data-field');
    var value = cell.getAttribute('data-value');
    if (!field || !value) return;
    if (table.getAttribute('data-ca-result') === '1') {
      // CA result rows are not registered as server drilldown records; open
      // the object drawer for policy cells, and let the capture handlers deal
      // with user/app cells. Other CA text cells are informational.
      if (field === 'polName' && row && row.getAttribute('data-policy-id')) {
        var drawerRow = row.nextElementSibling;
        var alreadyOpen = !!(drawerRow && drawerRow.classList.contains('drawer')
                             && drawerRow.classList.contains('open'));
        if (!alreadyOpen) {
          var expand = row.querySelector('.expand-btn');
          if (expand) expand.click();
        }
      }
      return;
    }
    openDrilldown(field, value);
  });
})();

(function() {
  var MEMBER_CAP = 500;
  // runtime caches; populated on demand from the API endpoints
  var DETAILS = { sp: {}, app: {}, user: {}, device: {} };
  var PROFILES = {};
  var PROFILES2 = { sp: {}, app: {} };
  var GROUPS = {};
  var POLICIES = {};

  function pEsc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function activeDrawerTab(container) {
    var active = container ? container.querySelector('.drawer-tabs-wrap .drawer-tab.active') : null;
    return active ? (active.getAttribute('data-dtab') || '') : '';
  }
  function pSev(sev) {
    var cls = { Critical: 'sev-critical', High: 'sev-high', Medium: 'sev-medium', Low: 'sev-low' }[sev] || 'sev-info';
    return '<span class="badge ' + cls + '">' + pEsc(sev) + '</span>';
  }
  function pRoleName(r) {
    var label = r.name || '';
    if (r.disabled) label += ' (disabled role)';
    else if (r.scope && r.scope !== 'Tenant-wide') label += ' [' + r.scope + ']';
    return pEsc(label);
  }
  function pSection(label, html) {
    return '<div class="detail-section"><h4>' + pEsc(label) + '</h4>' + html + '</div>';
  }
  function pList(items, render) {
    if (!items || !items.length) return '<p class="muted">None.</p>';
    return '<ul class="profile-list">' + items.map(render).join('') + '</ul>';
  }

  function minorTable(cols, rows) {
    // cols: [[header, rowField], ...]
    if (!rows || !rows.length) return '';
    var head = '<tr>' + cols.map(function(c) { return '<th>' + pEsc(c[0]) + '</th>'; }).join('') + '</tr>';
    var body = rows.map(function(r) {
      return '<tr>' + cols.map(function(c) {
        return '<td>' + pEsc(r[c[1]] || '') + '</td>';
      }).join('') + '</tr>';
    }).join('');
    return '<table class="minor-table"><thead>' + head + '</thead><tbody>' + body + '</tbody></table>';
  }

  function azTableHtml(list, withSp) {
    if (!list || !list.length) return '<p class="muted">No Azure (ARM) role assignments captured for this principal.</p>';
    var rows = list.map(function(a) {
      var sub = (a.scope_sub_name || '') + (a.scope_sub ? ((a.scope_sub_name ? ' (' : '') + a.scope_sub + (a.scope_sub_name ? ')' : '')) : '');
      if (!sub) sub = a.scope_type === 'Management group' ? (a.scope_mgmt || '—') : '—';
      var rg = a.scope_type === 'Management group' ? (a.scope_mgmt || '—') : (a.scope_rg || '—');
      return {
        role: pSev(a.severity || 'Info') + ' ' + pEsc(a.role + (a.eligible ? ' (eligible)' : '')),
        sp: pEsc(a.sp_name || '—'),
        stype: pEsc(a.scope_type || '—'),
        sub: pEsc(sub),
        rg: pEsc(rg),
        prov: pEsc(a.scope_provider || '—'),
        res: pEsc(a.scope_resource || '—')
      };
    });
    var cols = [['Role', 'role']];
    if (withSp) cols.push(['Service Principal', 'sp']);
    cols.push(['Scope Type', 'stype'], ['Subscription', 'sub'], ['Resource Group', 'rg'],
              ['Provider', 'prov'], ['Resource', 'res']);
    var head = '<tr>' + cols.map(function(c) { return '<th>' + pEsc(c[0]) + '</th>'; }).join('') + '</tr>';
    var body = rows.map(function(r) {
      return '<tr>' + cols.map(function(c) { return '<td>' + (r[c[1]] || '') + '</td>'; }).join('') + '</tr>';
    }).join('');
    return '<table class="minor-table"><thead>' + head + '</thead><tbody>' + body + '</tbody></table>';
  }

  function rawValueHtml(v) {
    if (v !== null && typeof v === 'object') return '<pre>' + pEsc(JSON.stringify(v, null, 2)) + '</pre>';
    return pEsc(String(v == null ? '' : v));
  }

  function renderKVHtml(record) {
    if (!record) return '';
    var rows = Object.keys(record).sort().map(function(k) {
      return '<tr><th>' + pEsc(k) + '</th><td>' + rawValueHtml(record[k]) + '</td></tr>';
    }).join('');
    return '<table class="kv-table">' + rows + '</table>';
  }

  function ssoProtocolLabel(rec) {
    if (!rec) return '';
    var mode = String(rec.preferredSingleSignOnMode || '').toLowerCase();
    var labels = {saml: 'SAML', wsfed: 'WS-Fed', 'ws-federation': 'WS-Fed',
                  password: 'Password', linked: 'Linked', oidc: 'OIDC',
                  openidconnect: 'OIDC'};
    if (labels[mode]) return labels[mode];
    if (rec.samlMetadataUrl || rec.samlSingleSignOnSettings) return 'SAML';
    var replies = (rec.replyUrls && rec.replyUrls.length)
        ? rec.replyUrls
        : ((rec.application && rec.application.replyUrls) || []);
    if (!Array.isArray(replies)) replies = [replies];
    if (replies.length) return 'OIDC';
    return '';
  }

  function ssoPublisherInfo(rec) {
    var vp = rec && rec.verifiedPublisher;
    if (typeof vp === 'string') {
      try { vp = JSON.parse(vp); } catch (e) { vp = {}; }
    }
    if (!vp || typeof vp !== 'object') vp = {};
    return {name: vp.displayName || (rec && rec.publisherName) || '',
            verified: !!vp.displayName};
  }

  function ssoCertLabel(rec) {
    if (!rec) return '';
    var end = rec.preferredTokenSigningKeyEndDateTime || '';
    var thumb = rec.preferredTokenSigningKeyThumbprint || '';
    var keys = rec.keyCredentials || [];
    if (typeof keys === 'string') {
      try { keys = JSON.parse(keys); } catch (e) { keys = []; }
    }
    if (!Array.isArray(keys)) keys = [];
    if (!end) {
      var candidates = keys.filter(function(k) {
        if (!k || !k.endDateTime) return false;
        return !k.usage || /sign/i.test(String(k.usage));
      });
      if (candidates.length) {
        candidates.sort(function(a, b) {
          return String(b.endDateTime).localeCompare(String(a.endDateTime));
        });
        end = candidates[0].endDateTime;
        thumb = thumb || candidates[0].thumbprint || '';
      }
    }
    if (!end) return '';
    var d = new Date(end);
    if (isNaN(d.getTime())) return String(end).slice(0, 10);
    var date = d.toISOString().slice(0, 10);
    var days = Math.round((d.getTime() - Date.now()) / 86400000);
    var label = date;
    if (days < 0) label = 'Expired ' + date;
    else if (days <= 30) label = date + ' (' + days + 'd)';
    return label + (thumb ? ' \u00b7 ' + thumb : '');
  }

  function renderSpAppTabs(prof, rec, container, activeTab) {
    var isSp = (prof.kind || 'sp') === 'sp';
    var kvRows = [];
    if (rec) {
      kvRows.push(['Display name', rec.displayName || '']);
      if (rec.objectId) kvRows.push(['ObjectId', rec.objectId]);
      if (rec.appId) kvRows.push(['AppId', rec.appId]);
      var pub = isSp ? (rec.publisherName || '') : (rec.publisherDomain || '');
      if (pub && pub.toLowerCase() !== 'default directory') {
        kvRows.push(['Publisher', pub]);
      }
      if (isSp) {
        var spEnabled = rec.accountEnabled;
        var spStatus = (spEnabled === undefined || spEnabled === null || spEnabled === '')
            ? 'Unknown'
            : ((spEnabled === true || spEnabled === 1 || spEnabled === '1' || spEnabled === 'true')
                ? 'Enabled' : 'Disabled');
        kvRows.push(['Status', spStatus]);
        if (prof.application) {
          var appVal = prof.app_oid
              ? '<button type="button" class="app-link" data-app-oid="' + pEsc(prof.app_oid) + '">' + pEsc(prof.application) + '</button>'
              : pEsc(prof.application);
          kvRows.push(['Application', prof.application, appVal]);
        }
        kvRows.push(['Assignment required', rec.appRoleAssignmentRequired ? 'Yes' : 'No']);
      } else {
        kvRows.push(['Public client', rec.publicClient === 1 ? 'Yes' : 'No']);
        if (rec.signInAudience) kvRows.push(['Sign-in audience', rec.signInAudience]);
      }
      var urls = rec.replyUrls;
      if (urls) {
        if (!Array.isArray(urls)) urls = [urls];
        kvRows.push(['Reply URLs', urls.join(', ')]);
      }
    } else {
      kvRows.push(['Display name', prof.application || '']);
    }
    var kv = '<table class="kv-table">' + kvRows.map(function(r) {
      var val = r.length > 2 ? r[2] : pEsc(r[1]);
      return '<tr><th>' + pEsc(r[0]) + '</th><td>' + val + '</td></tr>';
    }).join('') + '</table>';

    var ownersHtml = (prof.owners && prof.owners.length)
        ? '<ul class="profile-list">' + prof.owners.map(function(o) {
            return '<li><span class="mono">' + pEsc(o.upn || o.name) + '</span>'
                + ' <span class="muted">(' + pEsc(o.type) + ')</span></li>';
          }).join('') + '</ul>'
        : '<p class="muted">No owners recorded.</p>';
    var dirRolesHtml = (prof.dir_roles && prof.dir_roles.length)
        ? '<ul class="profile-list">' + prof.dir_roles.map(function(r) {
            var tag = pSev(r.severity) + ' ' + pEsc(r.name);
            if (r.eligible) tag += ' <span class="muted">(eligible)</span>';
            if (r.path) tag += ' <span class="muted">via ' + pEsc(r.path.join(' \u2192 ')) + '</span>';
            return '<li>' + tag + '</li>';
          }).join('') + '</ul>'
        : '<p class="muted">No directory roles assigned.</p>';
    var groupsHtml = (prof.groups && prof.groups.length)
        ? '<p>' + prof.groups.map(function(g) { return pEsc(g.name); }).join(', ') + '</p>'
        : '<p class="muted">Not a member of any captured group.</p>';

    var ssoRows = [];
    if (isSp && rec) {
      var ssoProtocol = ssoProtocolLabel(rec);
      var pubInfo = ssoPublisherInfo(rec);
      var showPublisher = pubInfo.name
          && pubInfo.name.toLowerCase() !== 'default directory';
      var ssoCert = ssoCertLabel(rec);
      var notify = rec.notificationEmailAddresses || [];
      if (!Array.isArray(notify)) notify = notify ? [notify] : [];
      var linkedApp = rec.application || {};
      var assignedUsers = prof.sso_assigned_user_count || 0;
      var assignedGroups = prof.sso_assigned_groups || 0;
      var assignedParts = [];
      if (assignedUsers) assignedParts.push(assignedUsers + ' user(s)');
      if (assignedGroups) assignedParts.push(assignedGroups + ' group(s)');
      var assignedLabel = assignedParts.join(' \u00b7 ');
      var hasAssignments = !!(assignedUsers || assignedGroups);
      var hasSsoInfo = !!(ssoProtocol || showPublisher || ssoCert
          || notify.length || rec.samlMetadataUrl || linkedApp.signInAudience
          || hasAssignments);
      if (hasSsoInfo) {
        if (ssoProtocol) ssoRows.push(['Protocol', pEsc(ssoProtocol)]);
        if (showPublisher) {
          ssoRows.push(['Publisher status', pubInfo.verified ? 'Verified' : 'Unverified']);
        }
        if (rec.appOwnerTenantId) {
          ssoRows.push(['Home tenant', '<span class="mono">' + pEsc(rec.appOwnerTenantId) + '</span>']);
        }
        if (assignedLabel) ssoRows.push(['Assigned', pEsc(assignedLabel)]);
        if (ssoCert) ssoRows.push(['Signing certificate', pEsc(ssoCert)]);
        if (notify.length) ssoRows.push(['Cert notifications', pEsc(notify.join(', '))]);
        if (rec.samlMetadataUrl) ssoRows.push(['SAML metadata', pEsc(rec.samlMetadataUrl)]);
        if (linkedApp.signInAudience) ssoRows.push(['Sign-in audience', pEsc(linkedApp.signInAudience)]);
      }
    }
    var ssoHtml = '';
    if (ssoRows.length) {
      ssoHtml = pSection('SSO', '<table class="kv-table">' + ssoRows.map(function(r) {
        return '<tr><th>' + pEsc(r[0]) + '</th><td>' + r[1] + '</td></tr>';
      }).join('') + '</table>');
    }
    var azHtml = '';
    var overview = kv + ssoHtml
        + pSection('Owners (' + (prof.owners ? prof.owners.length : 0) + ')', ownersHtml)
        + pSection('Assigned roles (' + (prof.dir_roles ? prof.dir_roles.length : 0) + ')', dirRolesHtml)
        + pSection('Assigned groups (' + (prof.groups ? prof.groups.length : 0) + ')', groupsHtml);

    var rawPane = rec ? renderKVHtml(rec) : '<p class="muted">Not available in the collected data.</p>';

    var isAppMode = (prof.kind || 'sp') !== 'sp';
    var panes;
    if (isAppMode) {
      var spList = prof.sp_list || [];
      var spListHtml;
      if (!spList.length) {
        spListHtml = '<p class="muted">No service principal captured for this application.</p>';
      } else {
        spListHtml = '<table class="minor-table"><thead><tr><th>Service Principal</th><th>ObjectId</th><th>AppId</th></tr></thead><tbody>'
          + spList.map(function(spr) {
              return '<tr><td><button type="button" class="dtab-sp-link" data-sp-id="' + pEsc(spr.object_id) + '">' + pEsc(spr.display_name || spr.object_id) + '</button></td>'
                + '<td class="mono">' + pEsc(spr.object_id) + '</td>'
                + '<td class="mono">' + pEsc(spr.app_id || '') + '</td></tr>';
            }).join('') + '</tbody></table>'
          + '<p class="muted">Click a service principal to open its full detail view.</p>';
      }
      panes = [
        ['overview', 'Overview', overview],
        ['azure', 'Azure roles (' + (prof.az_roles ? prof.az_roles.length : 0) + ')', azTableHtml(prof.az_roles || [], true)],
        ['sps', 'Service Principal' + (spList.length ? ' (' + spList.length + ')' : ''), spListHtml],
        ['raw', 'Raw', rawPane]
      ];
    } else {
      var gTitle = 'Roles granted to others (' + prof.granted_roles.length + ')';
      var aTitle = 'App roles assigned to this principal (' + prof.assigned_roles.length + ')';
      var gPane = minorTable([['Principal Name', 'principal_name'], ['Principal Type', 'principal_type'], ['Role', 'role'], ['Description', 'description']], prof.granted_roles)
          || '<p class="muted">No roles granted by this principal.</p>';
      var aPane = minorTable([['Principal Name', 'principal_name'], ['Principal Type', 'principal_type'], ['Role', 'role'], ['Application', 'application'], ['Description', 'description']], prof.assigned_roles)
          || '<p class="muted">No app-role assignments to this principal. Directory roles (incl. those inherited via group membership) are listed under Overview &rarr; Assigned roles.</p>';
      panes = [
        ['overview', 'Overview', overview],
        ['azure', 'Azure roles (' + (prof.az_roles ? prof.az_roles.length : 0) + ')', azTableHtml(prof.az_roles || [], false)],
        ['granted', gTitle, gPane],
        ['assigned', aTitle, aPane],
        ['raw', 'Raw', rawPane]
      ];
    }
    var initialTab = activeTab || 'overview';
    var tabsHtml = '<div class="drawer-tabs">' + panes.map(function(pt) {
      return '<button type="button" class="drawer-tab' + (pt[0] === initialTab ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pEsc(pt[1]) + '</button>';
    }).join('') + '</div>';
    var panesHtml = panes.map(function(pt) {
      return '<div class="dtab-pane' + (pt[0] === initialTab ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pt[2] + '</div>';
    }).join('');

    var wrap = document.createElement('div');
    wrap.className = 'drawer-tabs-wrap';
    wrap.innerHTML = tabsHtml + panesHtml;
    container.appendChild(wrap);
    Array.prototype.forEach.call(wrap.querySelectorAll('.drawer-tab'), function(b) {
      b.addEventListener('click', function() {
        var tab = b.getAttribute('data-dtab');
        Array.prototype.forEach.call(wrap.querySelectorAll('.drawer-tab'), function(x) {
          x.classList.toggle('active', x.getAttribute('data-dtab') === tab);
        });
        Array.prototype.forEach.call(wrap.querySelectorAll('.dtab-pane'), function(x) {
          x.classList.toggle('active', x.getAttribute('data-dtab') === tab);
        });
      });
    });
    Array.prototype.forEach.call(wrap.querySelectorAll('.dtab-sp-link'), function(b) {
      b.addEventListener('click', function() {
        var spOid = b.getAttribute('data-sp-id');
        var spProf = PROFILES2.sp[spOid];
        // Keep outer back rows (for example, the user drawer's "Back to user")
        // so nested navigation does not lose its way home.
        var outerBacks = Array.prototype.filter.call(
          container.children, function(el) {
            return el.classList && el.classList.contains('drawer-back-row');
          });
        container.innerHTML = '';
        outerBacks.forEach(function(row) { container.appendChild(row); });
        var backRow = document.createElement('div');
        backRow.className = 'drawer-back-row';
        backRow.innerHTML = '<button type="button" class="drawer-tab drawer-back">&larr; Back to ' + pEsc(prof.application || 'application') + '</button>';
        container.appendChild(backRow);
        Array.prototype.forEach.call(backRow.querySelectorAll('.drawer-back'), function(x) {
          x.addEventListener('click', function() {
            backRow.remove();
            Array.prototype.forEach.call(
              Array.prototype.slice.call(container.children),
              function(el) {
                if (outerBacks.indexOf(el) < 0) el.remove();
              });
            renderSpAppTabs(prof, rec, container, 'sps');
          });
        });
        if (spProf) {
          renderSpAppTabs(spProf, DETAILS.sp[spOid] || null, container);
        } else {
          fetchSpApp(spOid, 'sp', container);
        }
      });
    });
  }

  function attachDrawerTabs(wrap) {
    Array.prototype.forEach.call(wrap.querySelectorAll('.drawer-tab'), function(b) {
      b.addEventListener('click', function() {
        var tab = b.getAttribute('data-dtab');
        Array.prototype.forEach.call(wrap.querySelectorAll('.drawer-tab'), function(x) {
          x.classList.toggle('active', x.getAttribute('data-dtab') === tab);
        });
        Array.prototype.forEach.call(wrap.querySelectorAll('.dtab-pane'), function(x) {
          x.classList.toggle('active', x.getAttribute('data-dtab') === tab);
        });
      });
    });
  }

  function renderPolicyTabs(pol, container, activeTab) {
    var kv = [['Name', pol.policy_name || ''],
              ['ObjectId', pol.policy_id || ''],
              ['State', pol.state || '?'],
              ['Scope', pol.scope || '?'],
              ['Controls', (pol.conditions_html.controls || []).join(', ') || '—'],
              ['Applications', (pol.conditions_html.apps || []).join(', ') || '—'],
              ['Template', pol.template_id || '—'],
              ['Created', pol.created || '—'],
              ['Modified', pol.modified || '—']];
    var kvHtml = '<table class="kv-table">' + kv.map(function(r) {
      return '<tr><th>' + pEsc(r[0]) + '</th><td>' + pEsc(r[1]) + '</td></tr>';
    }).join('') + '</table>';
    var rolesHtml = (pol.conditions_html.inc_roles && pol.conditions_html.inc_roles.length)
        ? '<p>' + pol.conditions_html.inc_roles.map(function(r) { return pSev(r.severity) + ' ' + pEsc(r.name); }).join(' &nbsp;&middot;&nbsp; ') + '</p>'
        : '<p class="muted">None captured.</p>';
    var groupsHtml = 'Included groups: ' + ((pol.conditions_html.inc_groups || []).map(function(g) { return pEsc(g.name); }).join(', ') || 'none')
        + '<br>Excluded groups: ' + ((pol.conditions_html.exc_groups || []).map(function(g) { return pEsc(g.name); }).join(', ') || 'none');
    var conditionsHtml = '<pre>' + pEsc(pol.conditions_raw || '{}') + '</pre>';
    var overview = kvHtml
        + pSection('Included roles (' + ((pol.conditions_html.inc_roles || []).length) + ')', rolesHtml)
        + pSection('Groups', '<p class="muted">' + groupsHtml + '</p>')
        + pSection('Conditions (raw)', conditionsHtml);
    var incHtml = (pol.included && pol.included.length)
        ? '<ul class="profile-list">' + pol.included.map(function(u) { return '<li>' + pEsc(u) + '</li>'; }).join('') + '</ul>'
        : '<p class="muted">No included users captured.</p>';
    var excHtml = (pol.excluded && pol.excluded.length)
        ? '<ul class="profile-list">' + pol.excluded.map(function(u) { return '<li>' + pEsc(u) + '</li>'; }).join('') + '</ul>'
        : '<p class="muted">No excluded users captured.</p>';
    var panes = [
      ['overview', 'Overview', overview],
      ['included', 'Included users (' + (pol.included ? pol.included.length : 0) + ')', incHtml],
      ['excluded', 'Excluded users (' + (pol.excluded ? pol.excluded.length : 0) + ')', excHtml]
    ];
    var initialTab = activeTab || 'overview';
    var tabsHtml = '<div class="drawer-tabs">' + panes.map(function(pt) {
      return '<button type="button" class="drawer-tab' + (pt[0] === initialTab ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pEsc(pt[1]) + '</button>';
    }).join('') + '</div>';
    var panesHtml = panes.map(function(pt) {
      return '<div class="dtab-pane' + (pt[0] === initialTab ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pt[2] + '</div>';
    }).join('');
    var wrap = document.createElement('div');
    wrap.className = 'drawer-tabs-wrap';
    wrap.innerHTML = tabsHtml + panesHtml;
    container.appendChild(wrap);
    attachDrawerTabs(wrap);
  }

  function renderGroupTabs(g, container, activeTab) {
    var kvRows = [
      ['Name', g.group_name || ''],
      ['ObjectId', g.group_id || ''],
      ['Types', (g.types || []).join(', ')],
      ['Visibility', g.visibility || '—'],
      ['Public', g.is_public ? 'Yes' : 'No'],
      ['Mail-enabled', g.mail ? 'Yes' : 'No'],
      ['Auto-membership rule', g.dynamic ? (g.rule || 'yes') : 'No'],
      ['Assignable to role', g.assignable ? 'Yes' : 'No']
    ];
    var kv = '<table class="kv-table">' + kvRows.map(function(r) {
      return '<tr><th>' + pEsc(r[0]) + '</th><td>' + pEsc(r[1]) + '</td></tr>';
    }).join('') + '</table>';
    var dirRolesHtml = (g.dir_roles && g.dir_roles.length)
        ? '<p>' + g.dir_roles.map(function(r) { return pSev(r.severity) + ' ' + pRoleName(r); }).join(' &nbsp;&middot;&nbsp; ') + '</p>'
        : '<p class="muted">No directory roles assigned to this group.</p>';
    var eligRolesHtml = (g.eligible_roles && g.eligible_roles.length)
        ? '<p>' + g.eligible_roles.map(function(r) { return '<button type="button" class="elig-link dtab-sp-link" data-elig-role="' + pEsc(r.name) + '">' + pSev(r.severity) + ' ' + pRoleName(r) + '</button> <span class="muted">(PIM eligible)</span>'; }).join(' &nbsp;&middot;&nbsp; ') + '</p>'
        : '';
    var ownersHtml = (g.owners && g.owners.length)
        ? '<p>' + g.owners.map(function(o) { return pEsc(o); }).join(', ') + '</p>'
        : '<p class="muted">No owners recorded.</p>';
    var membershipHtml = '<p class="muted">' + (g.user_member_count || 0) + ' user member(s)';
    if (g.device_member_count) membershipHtml += ' · ' + g.device_member_count + ' device member(s)';
    if (g.nested_group_count) membershipHtml += ' · ' + g.nested_group_count + ' nested group(s)';
    if (g.sp_members && g.sp_members.length) membershipHtml += ' · ' + g.sp_members.length + ' app member(s): ' + pEsc(g.sp_members.map(function(m) { return m.name; }).join(', '));
    if (g.parents && g.parents.length) membershipHtml += ' · member of: ' + pEsc(g.parents.join(', '));
    if (g.children && g.children.length) membershipHtml += ' · contains groups: ' + pEsc(g.children.join(', '));
    membershipHtml += '</p>';
    var dynHtml = '';
    if (g.dyn_rule) {
      var dynAttrs = (g.dyn_attrs || []).map(function(a) { return '<span class="tag-chip">' + pEsc(a) + '</span>'; }).join(' ');
      var dynMods = (g.dyn_mods || []).map(function(m) {
        var cls = m === 'User modifiable' ? 'tag-spray'
                : m === 'User Administrator' ? 'tag-divergence'
                : m === 'Directory Writer' ? 'tag-privileged' : '';
        return '<span class="tag-chip ' + cls + '">' + pEsc(m) + '</span>';
      }).join(' ');
      dynHtml = pSection('Dynamic membership',
          '<p class="mono">' + pEsc(g.dyn_rule) + '</p>'
          + '<p>Referenced attributes: ' + (dynAttrs || '<span class="muted">none</span>') + '</p>'
          + '<p>Membership modifiable by: ' + (dynMods || '<span class="muted">none</span>') + '</p>');
    }
    var azHtml = '';
    var overview = kv
        + dynHtml
        + pSection('Directory roles (' + ((g.dir_roles || []).length) + ')', dirRolesHtml)
        + (eligRolesHtml ? pSection('Eligible (PIM) roles (' + g.eligible_roles.length + ')', eligRolesHtml) : '')
        + pSection('Owners (' + ((g.owners || []).length) + ')', ownersHtml)
        + pSection('Membership', membershipHtml);
    var allMembers = g.members || [];
    var capped = allMembers.length > MEMBER_CAP;
    var shownMembers = capped ? allMembers.slice(0, MEMBER_CAP) : allMembers;
    var memberRows = shownMembers.map(function(m) {
      var roleHtml = (m.roles || []).filter(function(r) { return r.severity !== 'Info'; })
          .map(function(r) {
            var tag = pSev(r.severity) + ' ' + pRoleName(r);
            if (r.path && r.path.length > 1) {
              tag += ' <span class="muted">via ' + pEsc(r.path.join(' \u2192 ')) + '</span>';
            }
            return tag;
          }).join(' ');
      return {
        member: m.upn || m.name,
        name: (m.upn && m.name) ? m.name : '—',
        roles: roleHtml || '—',
        priv: m.privileged ? 'Yes' : '—'
      };
    });
    var membersHtml = memberRows.length
        ? '<table class="minor-table"><thead><tr><th>Member</th><th>Name</th><th>Directory roles</th><th>Privileged</th></tr></thead><tbody>'
          + memberRows.map(function(r) {
              return '<tr><td>' + pEsc(r.member) + '</td><td>' + pEsc(r.name) + '</td><td>' + r.roles + '</td><td>' + pEsc(r.priv) + '</td></tr>';
            }).join('') + '</tbody></table>'
        : '<p class="muted">No user members recorded.</p>';
    if (capped) membersHtml += '<p class="muted">Showing first ' + MEMBER_CAP + ' of ' + allMembers.length + ' members.</p>';
    var allSpMembers = g.sp_members || [];
    var cappedSp = allSpMembers.length > MEMBER_CAP;
    var shownSpMembers = cappedSp ? allSpMembers.slice(0, MEMBER_CAP) : allSpMembers;
    var spMemberRows = shownSpMembers.map(function(m) {
      var roleHtml = (m.roles || []).filter(function(r) { return r.severity !== 'Info'; })
          .map(function(r) {
            var tag = pSev(r.severity) + ' ' + pRoleName(r);
            if (r.kind === 'app') {
              tag += ' <span class="muted">@ ' + pEsc(r.resource || 'app role') + '</span>';
            } else if (r.path && r.path.length > 1) {
              tag += ' <span class="muted">via ' + pEsc(r.path.join(' \u2192 ')) + '</span>';
            }
            return tag;
          }).join(' ');
      return {
        name: '<button type="button" class="dtab-sp-link obj-link" data-obj-id="' + pEsc(m.id) + '" data-obj-kind="sp">' + pEsc(m.name) + '</button>',
        object_id: m.id,
        roles: roleHtml || '—',
        status: m.enabled ? 'Enabled' : 'Disabled'
      };
    });
    var spMembersHtml = spMemberRows.length
        ? '<table class="minor-table"><thead><tr><th>Service principal</th><th>ObjectId</th><th>Roles</th><th>Status</th></tr></thead><tbody>'
          + spMemberRows.map(function(r) {
              return '<tr><td>' + r.name + '</td><td class="mono">' + pEsc(r.object_id) + '</td><td>' + r.roles + '</td><td>' + pEsc(r.status) + '</td></tr>';
            }).join('') + '</tbody></table>'
        : '<p class="muted">No app (service principal) members recorded.</p>';
    if (cappedSp) spMembersHtml += '<p class="muted">Showing first ' + MEMBER_CAP + ' of ' + allSpMembers.length + ' SP members.</p>';
    var panes = [
      ['overview', 'Overview', overview],
      ['azure', 'Azure roles (' + (g.az_roles ? g.az_roles.length : 0) + ')', azTableHtml(g.az_roles || [], false)],
      ['user-members', 'User Members (' + (g.user_member_count || 0) + ')', membersHtml],
      ['sp-members', 'App Members (' + (g.sp_members ? g.sp_members.length : 0) + ')', spMembersHtml]
    ];
    var initialTab = activeTab || 'overview';
    var tabsHtml = '<div class="drawer-tabs">' + panes.map(function(pt) {
      return '<button type="button" class="drawer-tab' + (pt[0] === initialTab ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pEsc(pt[1]) + '</button>';
    }).join('') + '</div>';
    var panesHtml = panes.map(function(pt) {
      return '<div class="dtab-pane' + (pt[0] === initialTab ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pt[2] + '</div>';
    }).join('');
    var wrap = document.createElement('div');
    wrap.className = 'drawer-tabs-wrap';
    wrap.innerHTML = tabsHtml + panesHtml;
    container.appendChild(wrap);
    attachDrawerTabs(wrap);
    Array.prototype.forEach.call(wrap.querySelectorAll('.obj-link'), function(b) {
      b.addEventListener('click', function() {
        var oid = b.getAttribute('data-obj-id');
        var kind = b.getAttribute('data-obj-kind');
        var returnTab = activeDrawerTab(container) || 'overview';
        container.innerHTML = '';
        var backRow = document.createElement('div');
        backRow.className = 'drawer-back-row';
        backRow.innerHTML = '<button type="button" class="drawer-tab drawer-back">&larr; Back to ' + pEsc(g.group_name || 'group') + '</button>';
        container.appendChild(backRow);
        Array.prototype.forEach.call(backRow.querySelectorAll('.drawer-back'), function(x) {
          x.addEventListener('click', function() {
            container.innerHTML = '';
            renderGroupTabs(g, container, returnTab);
          });
        });
        var prof2 = PROFILES2.sp[oid];
        if (prof2) {
          renderSpAppTabs(prof2, DETAILS.sp[oid] || null, container);
          return;
        }
        if (kind === 'sp') {
          fetchSpApp(oid, 'sp', container);
          return;
        }
        container.appendChild(section('Application', DETAILS.app[oid] || null));
      });
    });
    attachEligLinks(wrap, g, container, g.group_name || 'group', function() {
      renderGroupTabs(g, container);
    });
  }

  function fillUserDetails(wrap, uid) {
    var rec = DETAILS.user[uid] || null;
    var descEl = wrap.querySelector('.user-desc');
    if (descEl) {
      var pairs = [
        ['Object ID', uid],
        ['Job title', rec ? rec.jobTitle : null],
        ['Department', rec ? rec.department : null],
        ['Company', rec ? rec.companyName : null],
        ['Office', rec ? rec.officeLocation : null],
        ['City', rec ? rec.city : null],
        ['Country', rec ? rec.country : null],
        ['Mail', rec ? rec.mail : null],
        ['Employee ID', rec ? rec.employeeId : null],
        ['Usage location', rec ? rec.usageLocation : null],
        ['Account type', rec ? rec.userType : null],
        ['Created', rec ? rec.createdDateTime : null]
      ];
      var items = pairs.filter(function(pair) { return pair[1]; })
          .map(function(pair) {
            return '<li><span class="muted">' + pEsc(pair[0]) + ':</span> '
                + pEsc(String(pair[1])) + '</li>';
          });
      descEl.innerHTML = '<div class="detail-section"><h4>User details</h4>'
          + (items.length ? '<ul class="profile-list">' + items.join('') + '</ul>'
                          : '<p class="muted">No additional details captured for this user.</p>')
          + '</div>';
    }
    var rawEl = wrap.querySelector('.user-raw');
    if (rawEl) {
      rawEl.innerHTML = rec ? renderKVHtml(rec)
                            : '<p class="muted">Not available in the collected data.</p>';
    }
  }

  function renderProfileTabs(p, container, activeTab) {
    var overview = privilegeAnalysisHtml(p) + '<div class="user-desc"></div>' + openProfileHtml(p);
    var ownedLinks = (p.owned_objects || []).map(function(o) {
      var grantsHtml = (o.grants && o.grants.length)
          ? o.grants.map(function(g) {
              return '<span class="owned-grant">' + pEsc(g.permission)
                  + ' @ ' + pEsc(g.resource) + '</span>';
            }).join('')
          : '—';
      var credParts = [];
      if (o.pw) credParts.push(o.pw + (o.pw === 1 ? ' password' : ' passwords'));
      if (o.key) credParts.push(o.key + (o.key === 1 ? ' key' : ' keys'));
      var creds = credParts.length ? credParts.join(', ') : '—';
      var status = (typeof o.status === 'boolean') ? (o.status ? 'Enabled' : 'Disabled') : '—';
      var kind = o.type === 'Application' ? 'app' : 'sp';
      var nameCell = '<button type="button" class="dtab-sp-link obj-link" data-obj-id="' + o.object_id + '" data-obj-kind="' + (o.type === 'Group' ? 'group' : kind) + '">' + pEsc(o.name) + '</button>';
      return {
        type: o.type,
        name: nameCell,
        object_id: o.object_id,
        grants_html: grantsHtml, creds: creds, status: status
      };
    });
    var showAppColumns = ownedLinks.some(function(o) { return o.type !== 'Group'; });
    var ownedHeaders = [['Type', 'type'], ['Name', 'name']];
    if (showAppColumns) {
      ownedHeaders.push(['Privileged grants', 'grants'],
                        ['Credentials', 'creds'], ['Status', 'status']);
    }
    var ownedHtml = ownedLinks.length
        ? cappedTableHtml(
            ownedHeaders,
            ownedLinks.map(function(r) {
              var cells = ['<td>' + pEsc(r.type) + '</td>',
                           '<td>' + r.name + '</td>'];
              if (showAppColumns) {
                if (r.type === 'Group') {
                  cells.push('<td colspan="3" class="muted">—</td>');
                } else {
                  cells.push('<td class="owned-grants">' + r.grants_html + '</td>',
                             '<td>' + pEsc(r.creds) + '</td>',
                             '<td>' + pEsc(r.status) + '</td>');
                }
              }
              return cells;
            }), 'user-owned-table')
        : '<p class="muted">No owned objects recorded.</p>';
    var deviceLinks = (p.devices || []).map(function(d) {
      return {
        name: '<button type="button" class="dtab-sp-link obj-link" data-obj-id="' + d.object_id + '" data-obj-kind="device">' + pEsc(d.name) + '</button>',
        object_id: d.object_id,
        os: d.os || '—',
        ad: d.ad_bound ? 'Yes' : '—',
        last_logon: d.last_logon || '—',
        status: d.enabled ? 'Enabled' : 'Disabled'
      };
    });
    var devicesHtml = deviceLinks.length
        ? cappedTableHtml(
            [['Device', 'name'], ['ObjectId', 'object_id'], ['OS', 'os'],
             ['AD-bound', 'ad'], ['Last logon', 'last_logon'], ['Status', 'status']],
            deviceLinks.map(function(r) {
              return ['<td>' + r.name + '</td>',
                      '<td class="mono">' + pEsc(r.object_id) + '</td>',
                      '<td>' + pEsc(r.os) + '</td>', '<td>' + pEsc(r.ad) + '</td>',
                      '<td>' + pEsc(r.last_logon) + '</td>',
                      '<td>' + pEsc(r.status) + '</td>'];
            }))
        : '<p class="muted">No devices recorded for this user.</p>';
    var uid = p.user_id || '';
    var rawPane = '<div class="user-raw" data-user-raw="' + pEsc(uid) + '"><p class="muted">Loading\u2026</p></div>';
    var panes = [
      ['overview', 'Overview', overview],
      ['azure', 'Azure roles (' + (p.az_roles ? p.az_roles.length : 0) + ')', azTableHtml(p.az_roles || [], false)],
      ['owned', 'Owned objects (' + (p.owned_objects ? p.owned_objects.length : 0) + ')', ownedHtml],
      ['devices', 'Devices (' + (p.devices ? p.devices.length : 0) + ')', devicesHtml],
      ['raw', 'Raw', rawPane]
    ];
    var initialTab = activeTab || 'overview';
    var tabsHtml = '<div class="drawer-tabs">' + panes.map(function(pt) {
      return '<button type="button" class="drawer-tab' + (pt[0] === initialTab ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pEsc(pt[1]) + '</button>';
    }).join('') + '</div>';
    var panesHtml = panes.map(function(pt) {
      return '<div class="dtab-pane' + (pt[0] === initialTab ? ' active' : '') + '" data-dtab="' + pt[0] + '">' + pt[2] + '</div>';
    }).join('');
    var wrap = document.createElement('div');
    wrap.className = 'drawer-tabs-wrap';
    wrap.innerHTML = tabsHtml + panesHtml;
    container.appendChild(wrap);
    attachDrawerTabs(wrap);
    // user descriptions (overview) and the Raw pane are backed by the raw
    // user record, fetched on demand
    if (uid) {
      if (DETAILS.user[uid]) {
        fillUserDetails(wrap, uid);
      } else {
        fetch('/api/details/user/' + encodeURIComponent(uid))
          .then(function(r) { return r.json(); })
          .then(function(rec) {
            DETAILS.user[uid] = (rec && !rec.error) ? rec : null;
            fillUserDetails(wrap, uid);
          })
          .catch(function() {
            DETAILS.user[uid] = null;
            fillUserDetails(wrap, uid);
          });
      }
    }
    Array.prototype.forEach.call(wrap.querySelectorAll('.ca-link'), function(b) {
      b.addEventListener('click', function() {
        var name = b.getAttribute('data-ca-name');
        var entry = (p.ca_exclusions || []).find(function(x) { return x.name === name; });
        if (!entry) return;
        container.innerHTML = '';
        var kv = '<table class="kv-table">'
          + '<tr><th>Policy</th><td>' + pEsc(entry.name || name) + '</td></tr>'
          + '<tr><th>State</th><td>' + pEsc(entry.state || '?') + '</td></tr>'
          + '<tr><th>Scope</th><td>' + pEsc(entry.scope || '?') + '</td></tr>'
          + '</table>';
        var exHtml = (entry.excluded && entry.excluded.length)
            ? '<ul class="profile-list">' + entry.excluded.map(function(u) {
                return '<li>' + pEsc(u) + '</li>';
              }).join('') + '</ul>'
            : '<p class="muted">None.</p>';
        var inHtml = (entry.included && entry.included.length)
            ? '<ul class="profile-list">' + entry.included.map(function(u) {
                return '<li>' + pEsc(u) + '</li>';
              }).join('') + '</ul>'
            : '<p class="muted">None recorded.</p>';
        container.innerHTML = kv
            + pSection('Excluded users (' + (entry.excluded ? entry.excluded.length : 0) + ')', exHtml)
            + pSection('Included users (' + (entry.included ? entry.included.length : 0) + ')', inHtml)
            + '<div class="drawer-back-row"><button type="button" class="drawer-tab drawer-back">&larr; Back to ' + pEsc(p.user_display || 'user') + '</button></div>';
        Array.prototype.forEach.call(container.querySelectorAll('.drawer-back'), function(x) {
          x.addEventListener('click', function() {
            container.innerHTML = '';
            renderProfileTabs(p, container);
          });
        });
      });
    });
    Array.prototype.forEach.call(wrap.querySelectorAll('.obj-link'), function(b) {
      b.addEventListener('click', function() {
        var oid = b.getAttribute('data-obj-id');
        var kind = b.getAttribute('data-obj-kind');
        var activeTab = container.querySelector(
          '.drawer-tabs-wrap .drawer-tab.active');
        var returnTab = activeTab ? activeTab.getAttribute('data-dtab') : 'overview';
        container.innerHTML = '';
        var backRow = document.createElement('div');
        backRow.className = 'drawer-back-row';
        backRow.innerHTML = '<button type="button" class="drawer-tab drawer-back">&larr; Back to ' + pEsc(p.user_display || 'user') + '</button>';
        container.appendChild(backRow);
        Array.prototype.forEach.call(backRow.querySelectorAll('.drawer-back'), function(x) {
          x.addEventListener('click', function() {
            container.innerHTML = '';
            renderProfileTabs(p, container, returnTab);
          });
        });
        var prof2 = null;
        if (kind === 'app') { prof2 = PROFILES2.app[oid]; }
        else if (kind === 'sp') { prof2 = PROFILES2.sp[oid]; }
        if (kind === 'group') {
          var grp = GROUPS[oid];
          if (grp) { renderGroupTabs(grp, container); return; }
          fetchProfile('group', oid, function(g) { renderGroupTabs(g, container); }, container);
          return;
        }
        if (prof2) {
          renderSpAppTabs(prof2, kind === 'app' ? (DETAILS.app[oid] || null) : (DETAILS.sp[oid] || null), container);
          return;
        }
        if (kind === 'app' || kind === 'sp') {
          fetchSpApp(oid, kind, container);
          return;
        }
        if (kind === 'device') {
          fetchDetailsAll([['device', oid]], container);
          return;
        }
      });
    });
    attachEligLinks(wrap, p, container, p.user_display || 'user', function() {
      renderProfileTabs(p, container);
    });
  }

  function capAnnotate(items) {
    return items.map(function(c) {
      var line = c.name;
      if (c.roles && c.roles.length) {
        line += ' \u2014 ' + c.roles.map(function(r) { return r.name + ' (' + r.severity + ')'; }).join(', ');
      }
      return line;
    });
  }

  var LIST_CAP = 10;

  function cappedListHtml(items, renderFn) {
    if (!items || !items.length) return '<p class="muted">None.</p>';
    var lis = items.map(renderFn);
    if (lis.length <= LIST_CAP) {
      return '<ul class="profile-list">' + lis.join('') + '</ul>';
    }
    return '<ul class="profile-list">' + lis.slice(0, LIST_CAP).join('') + '</ul>'
        + '<ul class="profile-list hidden" data-list-more="1">'
        + lis.slice(LIST_CAP).join('') + '</ul>'
        + '<button type="button" class="list-more-btn" data-list-more-btn="1">'
        + 'Show all (' + lis.length + ')</button>';
  }

  function cappedTableHtml(headers, rows, tableClass) {
    var tableClassAttr = 'minor-table' + (tableClass ? ' ' + tableClass : '');
    function tableHtml(r) {
      return '<table class="' + tableClassAttr + '"><thead><tr>'
          + headers.map(function(c) { return '<th>' + pEsc(c[0]) + '</th>'; }).join('')
          + '</tr></thead><tbody>'
          + r.map(function(row) {
              return '<tr>' + row.join('') + '</tr>';
            }).join('')
          + '</tbody></table>';
    }
    if (rows.length <= LIST_CAP) return tableHtml(rows);
    return '<div>' + tableHtml(rows.slice(0, LIST_CAP))
        + '<div class="hidden" data-table-more="1">' + tableHtml(rows.slice(LIST_CAP)) + '</div>'
        + '<button type="button" class="list-more-btn" data-table-more-btn="1">'
        + 'Show all (' + rows.length + ')</button></div>';
  }

  // "Show all" buttons expand the hidden remainder of a capped list/table
  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.list-more-btn');
    if (!btn) return;
    var sec = btn.parentElement;
    var more = sec && sec.querySelector('ul[data-list-more="1"], div[data-table-more="1"]');
    if (more) {
      more.classList.remove('hidden');
      btn.remove();
    }
  });

  function eligDetailHtml(entry) {
    var rows = [
      ['Role', entry.name || '\u2014'],
      ['Severity', entry.severity || 'Info'],
      ['Source', entry.source || '\u2014'],
      ['Scope', entry.scope || 'Tenant-wide']
    ];
    if (entry.path && entry.path.length) {
      rows.push(['Group path', entry.path.join(' \u2192 ')]);
    }
    var s = entry.schedule;
    if (s) {
      rows.push(['Assignment state', s.assignment_state || '\u2014']);
      rows.push(['Member type', s.member_type || '\u2014']);
      rows.push(['Permanent', s.permanent ? 'Yes' : 'No']);
      rows.push(['Starts', s.start || '\u2014']);
      rows.push(['Ends', s.end || (s.permanent ? 'Never' : '\u2014')]);
      rows.push(['Status', s.status || '\u2014']);
    }
    return '<table class="kv-table">' + rows.map(function(r) {
      return '<tr><th>' + pEsc(r[0]) + '</th><td>' + pEsc(String(r[1])) + '</td></tr>';
    }).join('') + '</table>';
  }

  function openEligDetail(p, name, container, backLabel, backFn) {
    var entry = (p.eligible_roles || []).find(function(r) { return r.name === name; });
    if (!entry) return;
    container.innerHTML = '';
    container.innerHTML = '<div class="detail-section"><h4>PIM eligibility \u2014 '
        + pEsc(entry.name) + ' ' + pSev(entry.severity) + '</h4>'
        + eligDetailHtml(entry) + '</div>'
        + '<div class="drawer-back-row"><button type="button" class="drawer-tab drawer-back">&larr; Back to '
        + pEsc(backLabel) + '</button></div>';
    Array.prototype.forEach.call(container.querySelectorAll('.drawer-back'), function(x) {
      x.addEventListener('click', function() {
        container.innerHTML = '';
        backFn();
      });
    });
  }

  function attachEligLinks(scope, p, container, backLabel, backFn) {
    Array.prototype.forEach.call(scope.querySelectorAll('.elig-link'), function(b) {
      b.addEventListener('click', function() {
        openEligDetail(p, b.getAttribute('data-elig-role'), container, backLabel, backFn);
      });
    });
  }

  function privilegeAnalysisHtml(p) {
    // every factor that contributed to the user's severity rating, with the
    // reason it was attributed ("via" path, naming the object type)
    function viaSource(s) {
      s = s || 'assigned';
      if (s.indexOf('PIM eligible via ') === 0) {
        return 'PIM eligibility in ' + s.slice('PIM eligible via '.length);
      }
      if (s === 'PIM eligible') return 'PIM eligibility';
      if (s.indexOf('via ') === 0) return 'membership in ' + s.slice(4);
      return s;
    }
    var factors = [];
    (p.roles || []).forEach(function(r) {
      factors.push(pSev(r.severity) + ' ' + pRoleName(r)
          + ' <span class="muted">\u2014 via ' + pEsc(viaSource(r.source)) + '</span>');
    });
    (p.eligible_roles || []).forEach(function(r) {
      factors.push('<button type="button" class="elig-link dtab-sp-link" data-elig-role="' + pEsc(r.name) + '">'
          + pSev(r.severity) + ' ' + pRoleName(r) + '</button>'
          + ' <span class="muted">\u2014 via ' + pEsc(viaSource(r.source)) + '</span>');
    });
    (p.priv_apps || []).forEach(function(a) {
      var kind = a.kind === 'service principal' ? ' service principal' : ' application';
      (a.grants || []).forEach(function(g) {
        factors.push(pSev(g.severity) + ' ' + pEsc(g.permission)
            + ' <span class="muted">on ' + pEsc(g.resource)
            + ' \u2014 via ownership of ' + pEsc(a.app_name) + kind + '</span>');
      });
    });
    (p.dir_sp_roles || []).forEach(function(s) {
      factors.push(pSev(s.severity) + ' ' + pEsc(s.role)
          + ' <span class="muted">\u2014 via ownership of ' + pEsc(s.sp_name)
          + ' service principal</span>');
    });
    if (p.cap_member && p.cap_member.length) {
      factors.push(pSev('Medium') + ' member of role-capable group(s)'
          + ' <span class="muted">\u2014 via membership in '
          + pEsc(p.cap_member.map(function(g) { return g.name; }).join(', ')) + ' group(s)</span>');
    }
    (p.owned_cap || []).forEach(function(g) {
      var roles = g.roles || [];
      if (roles.length) {
        roles.forEach(function(r) {
          factors.push(pSev(r.severity) + ' ' + pEsc(r.name)
              + ' <span class="muted">\u2014 via ownership of ' + pEsc(g.name) + ' group</span>');
        });
      } else {
        factors.push(pSev('High') + ' ' + pEsc(g.name)
            + ' <span class="muted">\u2014 via ownership of role-capable group</span>');
      }
    });
    var head = 'Privilege Analysis';
    if (!factors.length) {
      return '<div class="detail-section"><h4>' + head
          + '</h4><p class="muted">No privilege signals captured.</p></div>';
    }
    return '<div class="detail-section"><h4>' + head + '</h4>'
        + cappedListHtml(factors, function(f) { return '<li>' + f + '</li>'; })
        + '</div>';
  }

  function openProfileHtml(p) {
    function groupRank(g) {
      return (g.roles && g.roles.length) ? 2 : (g.capable ? 1 : 0);
    }
    var html = '';
    html += pSection('Directory roles', cappedListHtml(p.roles, function(r) {
      return '<li>' + pSev(r.severity) + ' ' + pRoleName(r) + ' <span class="muted">(' + pEsc(r.source) + ')</span></li>';
    }));
    html += pSection('Eligible (PIM) roles', cappedListHtml(p.eligible_roles, function(r) {
      var extra = '';
      if (r.schedule && r.schedule.permanent) extra = ' <span class="tag-chip tag-privileged">permanent</span>';
      if (r.path && r.path.length) extra += ' <span class="muted">via ' + pEsc(r.path.join(' \u2192 ')) + '</span>';
      return '<li><button type="button" class="elig-link dtab-sp-link" data-elig-role="' + pEsc(r.name) + '">'
          + pSev(r.severity) + ' ' + pRoleName(r) + '</button>' + extra + '</li>';
    }));
    html += pSection('Privileged objects owned', cappedListHtml(p.priv_apps, function(a) {
      var grants = a.grants.map(function(g) {
        return '<li>' + pEsc(g.permission) + ' <span class="muted">→ ' + pEsc(g.resource) + '</span> ' + pSev(g.severity) + '</li>';
      }).join('');
      return '<li><b>' + pEsc(a.app_name) + '</b><ul>' + grants + '</ul></li>';
    }));
    html += pSection('Service principals with directory roles (owned)', cappedListHtml(p.dir_sp_roles, function(s) {
      return '<li>' + pEsc(s.sp_name) + ' — ' + pEsc(s.role) + ' ' + pSev(s.severity) + '</li>';
    }));
    var ownedCap = (p.owned_cap || []).slice().sort(function(a, b) {
      var ra = groupRank(a), rb = groupRank(b);
      if (ra !== rb) return rb - ra;
      return (a.name || '').toLowerCase() < (b.name || '').toLowerCase() ? -1 : 1;
    });
    html += pSection('Owned role-capable groups (' + ownedCap.length + ')',
        cappedListHtml(ownedCap, function(g) {
          var roles = (g.roles || []).map(function(r) {
            return pSev(r.severity) + ' ' + pRoleName(r);
          }).join(' &nbsp;&middot;&nbsp; ');
          return '<li><b>' + pEsc(g.name) + '</b>'
              + (roles ? ' &mdash; ' + roles : '') + '</li>';
        }));
    // role-bearing groups first, then role-capable, then alphabetical
    var gl = (p.groups || []).slice().sort(function(a, b) {
      var ra = groupRank(a), rb = groupRank(b);
      if (ra !== rb) return rb - ra;
      return (a.name || '').toLowerCase() < (b.name || '').toLowerCase() ? -1 : 1;
    });
    var groupsHtml = cappedListHtml(gl, function(g) {
      var extra = '';
      if (g.capable) extra += ' <span class="tag-chip tag-privileged" title="Role-capable group (assignable to directory roles / role-bearing)">role-capable</span>';
      if (g.roles && g.roles.length) extra += ' <span class="muted">— ' + g.roles.map(function(r) { return r.name; }).join(', ') + '</span>';
      return '<li><button type="button" class="dtab-sp-link obj-link" data-obj-id="' + pEsc(g.group_id) + '" data-obj-kind="group">' + pEsc(g.name) + '</button>' + extra + '</li>';
    });
    if (!gl.length) {
      groupsHtml = '<p class="muted">Not a member of any captured group.</p>';
    }
    if (p.owned_count) {
      groupsHtml += '<p class="muted">Owns ' + p.owned_count + ' group(s)';
      if (p.owned_cap.length) groupsHtml += ', incl. role-capable: ' + pEsc(capAnnotate(p.owned_cap).join('; '));
      groupsHtml += '</p>';
    }
    html += pSection('Groups (' + gl.length + ')', groupsHtml);
    html += pSection('CA exclusions (' + (p.ca_exclusions ? p.ca_exclusions.length : 0) + ')',
        cappedListHtml(p.ca_exclusions, function(x) {
          return '<li><button type="button" class="dtab-sp-link ca-link" data-ca-name="' + pEsc(x.name) + '">' + pEsc(x.name) + '</button> <span class="muted">(' + pEsc(x.state || '?') + ')</span></li>';
        }));
    var bits = [];
    if (p.hybrid) bits.push('On-prem synced');
    if (p.user_type === 'Guest') bits.push('Guest user');
    if (p.ca_exclusions && p.ca_exclusions.length) bits.push('Excluded from ' + p.ca_exclusions.length + ' CA polic' + (p.ca_exclusions.length === 1 ? 'y' : 'ies'));
    bits.push(p.user_enabled ? 'Account enabled' : 'Account disabled');
    html += pSection('Context', '<ul class="profile-list"><li>' + pEsc(bits.join(' · ')) + '</li></ul>');
    return html;
  }

  function renderKV(record) {
    var table = document.createElement('table');
    table.className = 'kv-table';
    Object.keys(record).sort().forEach(function(key) {
      var val = record[key];
      var tr = document.createElement('tr');
      var th = document.createElement('th');
      th.textContent = key;
      var td = document.createElement('td');
      if (val !== null && typeof val === 'object') {
        var pre = document.createElement('pre');
        pre.textContent = JSON.stringify(val, null, 2);
        td.appendChild(pre);
      } else {
        td.textContent = String(val);
      }
      tr.appendChild(th);
      tr.appendChild(td);
      table.appendChild(tr);
    });
    return table;
  }

  function section(label, record) {
    var wrap = document.createElement('div');
    wrap.className = 'detail-section';
    var h4 = document.createElement('h4');
    h4.textContent = label;
    wrap.appendChild(h4);
    if (!record || Object.keys(record).length === 0) {
      var p = document.createElement('p');
      p.className = 'muted';
      p.textContent = 'Not available in the collected data.';
      wrap.appendChild(p);
    } else {
      wrap.appendChild(renderKV(record));
    }
    return wrap;
  }

  function deviceSection(record) {
    var owners = (record && record.owners) || [];
    var data = {};
    if (record) {
      Object.keys(record).forEach(function(k) {
        if (k !== 'owners') data[k] = record[k];
      });
    }
    var wrap = section('Device', data);
    var ownerWrap = document.createElement('div');
    ownerWrap.className = 'detail-section';
    var h4 = document.createElement('h4');
    h4.textContent = 'Owners';
    ownerWrap.appendChild(h4);
    if (owners.length) {
      var ul = document.createElement('ul');
      ul.className = 'profile-list';
      owners.forEach(function(o) {
        var upn = o.upn || '';
        var label = upn || o.name || o.objectId || '';
        var bits = [];
        if (o.name && o.name !== label) bits.push(o.name);
        if (o.enabled === false) bits.push('disabled');
        var li = document.createElement('li');
        li.innerHTML = '<span class="mono">' + pEsc(label) + '</span>'
            + (bits.length ? ' <span class="muted">(' + pEsc(bits.join(', ')) + ')</span>' : '');
        ul.appendChild(li);
      });
      ownerWrap.appendChild(ul);
    } else {
      var p = document.createElement('p');
      p.className = 'muted';
      p.textContent = 'No owners recorded.';
      ownerWrap.appendChild(p);
    }
    wrap.appendChild(ownerWrap);
    return wrap;
  }

  function drawerFor(row) {
    var key = row.getAttribute('data-detail-key');
    if (!key) return null;
    var sib = row.nextElementSibling;
    if (sib && sib.getAttribute('data-detail-for') === key && sib.classList.contains('drawer')) return sib;
    return null;
  }

  function setDrawerButton(row, open) {
    var btn = row ? row.querySelector('.expand-btn') : null;
    if (!btn) return;
    btn.textContent = open ? '\u2212' : '+';
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    btn.setAttribute('aria-label', open ? 'Hide full details' : 'View full details');
    btn.title = open ? 'Hide full details' : 'View full details';
  }

  function activateDrawerTab(container, tab) {
    if (!container || !tab) return;
    var found = false;
    Array.prototype.forEach.call(container.querySelectorAll('.drawer-tabs-wrap .drawer-tab'), function(x) {
      var match = x.getAttribute('data-dtab') === tab;
      x.classList.toggle('active', match);
      if (match) found = true;
    });
    if (!found) return;
    Array.prototype.forEach.call(container.querySelectorAll('.drawer-tabs-wrap .dtab-pane'), function(x) {
      x.classList.toggle('active', x.getAttribute('data-dtab') === tab);
    });
  }

  function markDrawerFilled(drawer) {
    if (!drawer) return;
    delete drawer.dataset.loading;
    drawer.dataset.filled = '1';
  }

  function markDrawerFailed(drawer) {
    if (!drawer) return;
    delete drawer.dataset.loading;
    delete drawer.dataset.filled;  // let a later click retry a failed fetch
  }

  function populateDrawer(row) {
    var drawer = drawerFor(row);
    if (!drawer || drawer.dataset.filled || drawer.dataset.loading) return;
    var body = drawer.querySelector('.drawer-body');
    if (!body) return;
    // Some rows (for example the CA what-if evaluation) ship a drawer that is
    // already rendered server-side. Keep it instead of clearing it and
    // fetching a generic profile.
    if (drawer.dataset.prefilled) {
      markDrawerFilled(drawer);
      return;
    }
    drawer.dataset.loading = '1';
    body.innerHTML = '';
    var returnTab = drawer.__returnTab || '';
    delete drawer.__returnTab;
    var finished = false;
    function done(ok) {
      if (finished) return;
      finished = true;
      if (ok) {
        activateDrawerTab(body, returnTab);
        markDrawerFilled(drawer);
      } else {
        markDrawerFailed(drawer);
      }
    }
    var spId2 = row.getAttribute('data-sp-id') || '';
    var appId2 = row.getAttribute('data-app-id') || '';
    if (spId2 && !PROFILES2.sp[spId2]) {
      // the SP profile may not be cached yet even when the app profile is
      // (e.g. after navigating app -> back); prefer the SP drawer
      fetchSpApp(spId2, 'sp', body, done);
      return;
    }
    var prof2 = (spId2 && PROFILES2.sp[spId2]) ? PROFILES2.sp[spId2]
              : (appId2 && PROFILES2.app[appId2]) ? PROFILES2.app[appId2] : null;
    if (prof2) {
      var rec2 = (spId2 && PROFILES2.sp[spId2]) ? (DETAILS.sp[spId2] || null) : (DETAILS.app[appId2] || null);
      if (!rec2) {
        // The profile is cached but the raw/details fetch failed earlier;
        // retry both rather than leaving the Raw tab permanently empty.
        fetchSpApp(spId2 || appId2, spId2 ? 'sp' : 'app', body, done);
        return;
      }
      renderSpAppTabs(prof2, rec2, body, returnTab);
      done(true);
      return;
    }
    if (spId2 || appId2) {
      fetchSpApp(spId2 || appId2, spId2 ? 'sp' : 'app', body, done);
      return;
    }
    var profileId = row.getAttribute('data-profile-id') || '';
    var p = PROFILES[profileId];
    if (profileId && p) {
      renderProfileTabs(p, body, returnTab);
      done(true);
      return;
    }
    if (profileId) {
      fetch('/api/user/' + encodeURIComponent(profileId))
        .then(function(r) { return r.ok ? r.json() : null; })
        .catch(function() { return null; })
        .then(function(prof) {
          if (prof && prof.user_id && !prof.error) {
            PROFILES[profileId] = prof;
            renderProfileTabs(prof, body, returnTab);
            done(true);
            return;
          }
          // Not every row with data-profile-id is a privileged-user finding;
          // fall back to the raw user record so '+/identity' still works.
          body.innerHTML = '';
          fetchDetailsAll([['user', profileId]], body, done);
        });
      return;
    }
    var gid2 = row.getAttribute('data-group-id') || '';
    if (gid2 && GROUPS[gid2]) {
      renderGroupTabs(GROUPS[gid2], body, returnTab);
      done(true);
      return;
    }
    if (gid2) {
      fetchProfile('group', gid2, function(g) { renderGroupTabs(g, body, returnTab); }, body, done);
      return;
    }
    var pid2 = row.getAttribute('data-policy-id') || '';
    if (pid2 && POLICIES[pid2]) {
      renderPolicyTabs(POLICIES[pid2], body, returnTab);
      done(true);
      return;
    }
    if (pid2) {
      fetchProfile('policy', pid2, function(pol) { renderPolicyTabs(pol, body, returnTab); }, body, done);
      return;
    }
    var wants = [];
    if (row.getAttribute('data-device-id')) wants.push(['device', row.getAttribute('data-device-id')]);
    if (row.getAttribute('data-app-id')) wants.push(['app', row.getAttribute('data-app-id')]);
    if (row.getAttribute('data-sp-id')) wants.push(['sp', row.getAttribute('data-sp-id')]);
    if (wants.length) {
      fetchDetailsAll(wants, body, done);
      return;
    }
    body.appendChild(mutedP('No additional details captured for this object.'));
    done(true);
  }

  function mutedP(msg) {
    var mp = document.createElement('p');
    mp.className = 'muted';
    mp.textContent = msg;
    return mp;
  }

  function fetchProfile(kind, oid, cb, body, doneCb) {
    fetch('/api/profile/' + kind + '/' + encodeURIComponent(oid))
      .then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function(data) {
        if (!data || data.error) {
          body.appendChild(mutedP('No data for this object.'));
          if (doneCb) doneCb(false);
          return;
        }
        if (kind === 'group') GROUPS[oid] = data;
        else if (kind === 'policy') POLICIES[oid] = data;
        cb(data);
        if (doneCb) doneCb(true);
      })
      .catch(function() {
        body.appendChild(mutedP('Failed to load.'));
        if (doneCb) doneCb(false);
      });
  }

  function fetchSpApp(oid, kind, body, doneCb) {
    var p1 = fetch('/api/profile/' + kind + '/' + encodeURIComponent(oid)).then(function(r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
    var p2 = fetch('/api/details/' + kind + '/' + encodeURIComponent(oid))
      .then(function(r) {
        if (!r.ok) return { ok: false, data: null };
        return r.json().then(function(data) { return { ok: true, data: data }; });
      })
      .catch(function() { return { ok: false, data: null }; });
    Promise.all([p1, p2]).then(function(res) {
      var prof = res[0], recInfo = res[1] || { ok: false, data: null };
      var rec = recInfo.data;
      if (!prof || prof.error) {
        body.appendChild(mutedP('No data for this principal.'));
        if (doneCb) doneCb(false);
        return;
      }
      if (rec && rec.error) rec = null;  // details missing: render from the profile alone
      if (kind === 'sp') {
        PROFILES2.sp[oid] = prof;
        if (rec) DETAILS.sp[oid] = rec;
        else delete DETAILS.sp[oid];
      } else {
        PROFILES2.app[oid] = prof;
        if (rec) DETAILS.app[oid] = rec;
        else delete DETAILS.app[oid];
      }
      renderSpAppTabs(prof, rec, body);
      // A transient detail failure must not mark the drawer permanently
      // filled: re-opening it retries the raw/details fetch.
      if (doneCb) doneCb(!!rec || recInfo.ok);
    }).catch(function() {
      body.appendChild(mutedP('Failed to load.'));
      if (doneCb) doneCb(false);
    });
  }

  function fetchDetailsAll(wants, body, doneCb) {
    var pending = wants.length;
    var loaded = [];
    var failed = 0;
    function finish() {
      loaded.forEach(function(pair) {
        if (pair[0] === 'device') {
          body.appendChild(deviceSection(pair[2]));
          return;
        }
        var label = pair[0] === 'app' ? 'Application'
                  : pair[0] === 'user' ? 'User' : 'Service Principal';
        body.appendChild(section(label, pair[2]));
      });
      if (!loaded.length) {
        body.appendChild(mutedP(failed ? 'Failed to load details.'
                                      : 'No additional details captured for this object.'));
        if (doneCb) doneCb(!failed);
        return;
      }
      if (doneCb) doneCb(true);
    }
    wants.forEach(function(pair) {
      var kind = pair[0], oid = pair[1];
      var cached = DETAILS[kind] && DETAILS[kind][oid];
      if (cached) { loaded.push([kind, oid, cached]); if (--pending === 0) finish(); return; }
      fetch('/api/details/' + kind + '/' + encodeURIComponent(oid))
        .then(function(r) { return r.ok ? r.json() : null; })
        .then(function(d) {
          if (d && !d.error) {
            if (!DETAILS[kind]) DETAILS[kind] = {};
            DETAILS[kind][oid] = d;
            loaded.push([kind, oid, d]);
          } else if (d && d.error) {
            failed += 1;
          }
          if (--pending === 0) finish();
        })
        .catch(function() {
          failed += 1;
          if (--pending === 0) finish();
        });
    });
  }

  function toggleDrawer(row) {
    var drawer = drawerFor(row);
    if (!drawer) return;
    if (drawer.classList.contains('open')) {
      drawer.classList.remove('open');
      setDrawerButton(row, false);
      return;
    }
    populateDrawer(row);
    drawer.classList.add('open');
    setDrawerButton(row, true);
  }

  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.expand-btn');
    if (!btn) return;
    var row = btn.closest('tr');
    if (!row) return;
    toggleDrawer(row);
  });

  // User identity cells (User / UPN) open the same profile drawer as '+'
  // instead of the aggregate drilldown popup.
  document.addEventListener('click', function(e) {
    var cell = e.target.closest('td.clickable');
    if (!cell) return;
    var field = cell.getAttribute('data-field') || '';
    if (field !== 'user' && field !== 'userUpn' && field !== 'adUser' && field !== 'adUpn') return;
    var row = cell.closest('tr');
    if (!row) return;
    var pid = row.getAttribute('data-profile-id') || '';
    if (!pid) return;
    // Always own the click: the drawer fetches the profile on demand, so a
    // cold PROFILES cache must not fall through to the aggregate drilldown.
    e.stopImmediatePropagation();
    toggleDrawer(row);
  }, true);

  // Application cell in the ownership tables opens the app drawer; rows
  // without a local app registration (foreign SPs) open the SP drawer.
  document.addEventListener('click', function(e) {
    var cell = e.target.closest('td.clickable');
    if (!cell) return;
    var field = cell.getAttribute('data-field') || '';
    if (field !== 'app') return;
    var row = cell.closest('tr');
    if (!row) return;
    if (!row.getAttribute('data-app-id')) {
      e.stopImmediatePropagation();
      toggleDrawer(row);
      return;
    }
    e.stopImmediatePropagation();
    openAppDrawer(row.getAttribute('data-app-id'), row);
  }, true);

  // App-link buttons (SP drawer's Application row) navigate to the app drawer.
  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.app-link');
    if (!btn) return;
    var drawerTr = btn.closest('tr.drawer');
    var key = drawerTr ? drawerTr.getAttribute('data-detail-for') : '';
    // scope the row lookup to the drawer's own table - data-detail-key values
    // collide across tables (every table numbers rows from 0)
    var table = drawerTr ? drawerTr.closest('table') : null;
    var row = (table && key) ? table.querySelector('tr[data-detail-key="' + key + '"]') : null;
    // Prefer the row's app id (the same id the column-cell path uses and is
    // known to resolve); fall back to the profile-derived id for rows that
    // carry no app id (e.g. Azure Roles table rows).
    var oid = (row && row.getAttribute('data-app-id')) || btn.getAttribute('data-app-oid');
    if (!oid) return;
    if (row) {
      openAppDrawer(oid, row);
    } else {
      openAppDrawerInPlace(oid, btn.closest('.drawer-body'));
    }
  });

  function openAppDrawer(oid, row) {
    var drawer = drawerFor(row);
    if (!drawer) return;
    delete drawer.dataset.filled;  // back must re-populate even if the drawer was filled once
    delete drawer.dataset.loading;
    if (!drawer.classList.contains('open')) drawer.classList.add('open');
    setDrawerButton(row, true);
    var body = drawer.querySelector('.drawer-body');
    var returnTab = activeDrawerTab(body);
    if (returnTab) drawer.__returnTab = returnTab;
    var hasSp = !!row.getAttribute('data-sp-id');
    drawer.dataset.loading = '1';
    body.innerHTML = '';
    if (hasSp) {
      // only offer "back" when there is a real parent service principal;
      // app-only rows would otherwise loop back into the same app profile
      var backRow = document.createElement('div');
      backRow.className = 'drawer-back-row';
      backRow.innerHTML = '<button type="button" class="drawer-tab drawer-back">&#8592; Back to service principal</button>';
      body.appendChild(backRow);
      backRow.querySelector('.drawer-back').addEventListener('click', function() {
        // the app view itself was marked filled; clear it so the parent
        // service-principal view is allowed to repopulate
        delete drawer.dataset.filled;
        delete drawer.dataset.loading;
        body.innerHTML = '';
        populateDrawer(row);
      });
    }
    renderApp(oid, body, function(ok) {
      if (ok) markDrawerFilled(drawer);
      else markDrawerFailed(drawer);
    });
  }

  function openAppDrawerInPlace(oid, body) {
    body.innerHTML = '';
    renderApp(oid, body);
  }

  function renderApp(oid, body, doneCb) {
    fetchSpApp(oid, 'app', body, doneCb);
  }

  window.__renderProfileTabs = renderProfileTabs;

})();

(function() {
  function allTables() {
    return Array.prototype.slice.call(document.querySelectorAll('table.findings'));
  }
  var input = document.getElementById('filter-input');
  var advToggle = document.getElementById('advanced-toggle');
  var suggestWrap = document.getElementById('suggest-wrap');
  var suggestList = document.getElementById('suggest-list');
  var errorEl = document.getElementById('filter-error');
  var advOn = false;
  window.__filterState = { advanced: false,
                           q: input ? input.value : '', seq: 0 };
  var suggestionRange = null;
  var activeSuggestion = -1;
  var SUGGEST = {};
  try { SUGGEST = JSON.parse(document.getElementById('suggest-data').textContent); } catch (e) {}
  Object.keys(SUGGEST).forEach(function(k) { SUGGEST[k.toLowerCase()] = SUGGEST[k]; });

  function rowFieldMap(row) {
    var map = { check: (row.getAttribute('data-check-id') || '').toLowerCase(), category: '' };
    var sec = row.closest('section');
    if (sec) map.category = (sec.getAttribute('data-category') || '').toLowerCase();
    Array.prototype.forEach.call(row.cells, function(td) {
      var f = td.getAttribute('data-field');
      if (f) map[f.toLowerCase()] = td.getAttribute('data-value') || '';
    });
    // merge extras-blob values so uniq/filters cover non-rendered columns too
    var tbl = row.closest('table');
    if (tbl && window.__columns && window.__columns.extras) {
      var blob = window.__columns.extras(tbl.id);
      var key = row.getAttribute('data-detail-key');
      if (blob && key && blob[key]) {
        Object.keys(blob[key]).forEach(function(f) {
          if (!Object.prototype.hasOwnProperty.call(map, f.toLowerCase())) {
            map[f.toLowerCase()] = (blob[key][f] && blob[key][f][1]) || '';
          }
        });
      }
    }
    return map;
  }

  function setRowVisibility(test, uniqFields, tables) {
    var seenByTable = {};
    (tables || allTables()).forEach(function(table) {
      var seen = (uniqFields && uniqFields.length) ? (seenByTable[table.id] = {}) : null;
      Array.prototype.forEach.call(table.tBodies[0].rows, function(row) {
        if (row.classList.contains('drawer')) return;
        var show = test(row);
        if (show && seen) {
          var map = rowFieldMap(row);
          var key = uniqFields.map(function(f) {
            return (map[f] || '').toLowerCase();
          }).join('\\u0001');
          if (Object.prototype.hasOwnProperty.call(seen, key)) show = false;
          else seen[key] = true;
        }
        row.classList.toggle('hidden', !show);
        var next = row.nextElementSibling;
        if (next && next.getAttribute('data-detail-for') === row.getAttribute('data-detail-key')) {
          next.classList.toggle('hidden', !show);
        }
      });
    });
  }

  function hideSuggest() {
    suggestWrap.classList.add('hidden');
    suggestList.innerHTML = '';
    suggestionRange = null;
    activeSuggestion = -1;
  }

  function knownFields() {
    var out = [];
    (ADV_FILTER.columns() || []).forEach(function(c) {
      out.push(c.display);
    });
    return out;
  }

  function fieldValueSuggest(fieldName, prefix) {
    var internal = ADV_FILTER.fieldsFor(fieldName) || [];
    var seen = {}, out = [];
    internal.forEach(function(f) {
      (SUGGEST[f] || []).forEach(function(v) {
        if (String(v).toLowerCase().indexOf(prefix.toLowerCase()) === 0 && !seen[v]) {
          seen[v] = true;
          out.push(v);
        }
      });
    });
    return out;
  }

  function tokenRange() {
    var value = input.value;
    var caret = input.selectionStart == null ? value.length : input.selectionStart;
    var start = caret;
    while (start > 0 && !/[\\s()]/.test(value[start - 1])) start--;
    var end = caret;
    while (end < value.length && !/[\\s()]/.test(value[end])) end++;
    var token = value.slice(start, end);
    // Multi-word column names contain spaces, so expand the token back over the
    // longest known display label when the caret is in its value (e.g.
    // completing `Home tenant:...`).
    var ci = token.indexOf(':');
    if (ci !== -1) {
      var colon = start + ci;
      var before = value.slice(0, colon).toLowerCase();
      var bestStart = start;
      knownFields().forEach(function(display) {
        var d = display.toLowerCase();
        if (!d || before.slice(-d.length) !== d) return;
        var at = colon - d.length;
        if (at > 0 && !/[\\s()]/.test(value[at - 1])) return;
        if (at < bestStart) bestStart = at;
      });
      if (bestStart < start) {
        start = bestStart;
        token = value.slice(start, end);
      }
    }
    return { start: start, end: end, token: token };
  }

  function buildSuggestions() {
    if (!advOn || document.activeElement !== input) { hideSuggest(); return; }
    var r = tokenRange();
    var token = r.token;
    var items = [];
    var ci = token.indexOf(':');
    if (ci !== -1) {
      var field = token.slice(0, ci);
      var prefix = token.slice(ci + 1).toLowerCase();
      if (field.toLowerCase() === 'uniq') {
        knownFields().forEach(function(display) {
          if (ADV_FILTER.normalizeField(display).indexOf(prefix) === 0) {
            items.push({ text: 'uniq:' + display, display: 'uniq:' + display, hint: 'column' });
          }
        });
      } else {
        fieldValueSuggest(field, prefix).slice(0, 8).forEach(function(v) {
          items.push({ text: field + ':' + v, display: field + ':' + v, hint: 'value' });
        });
      }
    } else if (token) {
      var pre = ADV_FILTER.normalizeField(token);
      knownFields().forEach(function(display) {
        if (ADV_FILTER.normalizeField(display).indexOf(pre) === 0) {
          items.push({ text: display + ':', display: display + ':', hint: 'column' });
        }
      });
    } else {
      ['AND', 'OR', 'NOT', 'contains:', 'uniq:'].forEach(function(op) {
        items.push({ text: op, display: op, hint: 'operator' });
      });
    }
    if (!items.length) { hideSuggest(); return; }
    suggestionRange = r;
    activeSuggestion = -1;
    suggestList.innerHTML = '';
    items.slice(0, 8).forEach(function(it) {
      var li = document.createElement('li');
      li.textContent = it.display;
      li.dataset.sugg = it.text;
      var hint = document.createElement('span');
      hint.className = 'sugg-hint';
      hint.textContent = it.hint;
      li.appendChild(hint);
      suggestList.appendChild(li);
    });
    suggestWrap.classList.remove('hidden');
  }

  function acceptSuggestion(item) {
    if (!suggestionRange) return;
    var r = suggestionRange;
    var value = input.value;
    // A field/operator suggestion already ends with the colon; keep the caret
    // there so the value can be typed immediately instead of after a space.
    var trailing = item.charAt(item.length - 1) === ':' ? '' : ' ';
    input.value = value.slice(0, r.start) + item + trailing + value.slice(r.end);
    var pos = r.start + item.length + trailing.length;
    input.setSelectionRange(pos, pos);
    hideSuggest();
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }

  function applyRowFilter() {
    var q = input.value;
    if (!advOn) {
      window.__advancedQueryInvalid = false;
      var needle = q.toLowerCase();
      setRowVisibility(function(row) {
        return q.length === 0 || row.textContent.toLowerCase().indexOf(needle) !== -1;
      });
      errorEl.classList.add('hidden');
      hideSuggest();
      return;
    }
    var parsed = ADV_FILTER.parse(q);
    if (parsed.error) {
      window.__advancedQueryInvalid = true;
      errorEl.textContent = 'Filter error: ' + parsed.error;
      errorEl.classList.remove('hidden');
      hideSuggest();
      return;
    }
    window.__advancedQueryInvalid = false;
    errorEl.classList.add('hidden');
    if (q.trim() === '') {
      setRowVisibility(function() { return true; });
      buildSuggestions();
      return;
    }
    // Served tables are filtered by the server. Static tables have every row
    // in the DOM, so apply the parsed query locally there (e.g. Azure roles).
    setRowVisibility(function(row) {
      return ADV_FILTER.evaluate(parsed.ast, rowFieldMap(row),
                                 row.textContent.toLowerCase());
    }, ADV_FILTER.uniqFields(parsed.ast),
       allTables().filter(function(t) {
         return t.getAttribute('data-serve') !== '1';
       }));
    buildSuggestions();
  }

  input.addEventListener('input', function() {
    if (window.__filterState) {
      window.__filterState.advanced = advOn;
      window.__filterState.q = input.value;
      window.__filterState.seq += 1;
    }
    applyRowFilter();
    if (advOn) buildSuggestions();
  });

  input.addEventListener('keydown', function(e) {
    if (!advOn || suggestWrap.classList.contains('hidden')) return;
    var items = suggestList.querySelectorAll('li');
    if (!items.length) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      activeSuggestion += e.key === 'ArrowDown' ? 1 : -1;
      if (activeSuggestion >= items.length) activeSuggestion = 0;
      if (activeSuggestion < 0) activeSuggestion = items.length - 1;
      Array.prototype.forEach.call(items, function(li, i) {
        li.classList.toggle('active', i === activeSuggestion);
      });
    } else if (e.key === 'Enter' || e.key === 'Tab') {
      var idx = activeSuggestion >= 0 ? activeSuggestion : 0;
      if (items[idx]) {
        e.preventDefault();
        acceptSuggestion(items[idx].dataset.sugg);
      }
    } else if (e.key === 'Escape') {
      hideSuggest();
    }
  });

  suggestList.addEventListener('mousedown', function(e) {
    var li = e.target.closest('li');
    if (!li) return;
    e.preventDefault();
    acceptSuggestion(li.dataset.sugg);
  });

  input.addEventListener('blur', function() {
    setTimeout(hideSuggest, 150);
  });

  advToggle.addEventListener('click', function() {
    advOn = !advOn;
    advToggle.setAttribute('aria-pressed', String(advOn));
    if (window.__filterState) {
      window.__filterState.advanced = advOn;
      window.__filterState.q = input.value;
      window.__filterState.seq += 1;
    }
    if (advOn) setRowVisibility(function() { return true; });
    if (!advOn && window.__filterBusyReset) window.__filterBusyReset();
    input.placeholder = advOn
        ? 'Advanced: severity:High AND target:contains:admin, uniq:owner\u2026'
        : 'Filter all tables by target, owner, evidence\u2026';
    hideSuggest();
    errorEl.classList.add('hidden');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });

  // ---- column reordering (drag headers; session only) --------------------
  var suppressSortClick = 0;

  function stampColumnIds() {
    // Legacy column-identity stamping: only for tables without a column
    // catalog (the dynamic CA-analysis tables), which keep index-based sort.
    allTables().forEach(function(table) {
      if (window.__columns && window.__columns.isManaged(table)) return;
      Array.prototype.forEach.call(table.tHead.rows[0].cells, function(th, i) {
        if (!th.classList.contains('no-sort')) {
          if (th.dataset.colidx === undefined) th.dataset.colidx = String(i);
          th.title = 'Click to sort · drag to reorder';
        }
      });
    });
  }

  function moveColumn(table, sourceTh, targetTh) {
    var headerRow = table.tHead.rows[0];
    var colCount = headerRow.cells.length;
    var srcIdx = Array.prototype.indexOf.call(headerRow.cells, sourceTh);
    var tgtIdx = Array.prototype.indexOf.call(headerRow.cells, targetTh);
    if (srcIdx < 0 || tgtIdx < 0 || srcIdx === tgtIdx) return;
    headerRow.insertBefore(sourceTh, targetTh);
    // Legacy (catalog-less) tables sort by the visual index, so restamp it
    // after every move; otherwise sorting targets the pre-drag column.
    Array.prototype.forEach.call(headerRow.cells, function(th, i) {
      if (!th.classList.contains('no-sort')) th.dataset.colidx = String(i);
    });
    // keep colgroup widths aligned with the header order
    var cols = table.querySelectorAll('colgroup col');
    if (cols.length) {
      var srcCol = cols[srcIdx];
      var tgtCol = cols[tgtIdx];
      if (srcCol && tgtCol) srcCol.parentNode.insertBefore(srcCol, tgtCol);
    }
    // Mirror the exact same single-cell move on every data row. A relative
    // move composes across drags; rebuilding cells from original column
    // identities would assume they are still in original order and misfile
    // them after the first drag.
    Array.prototype.forEach.call(table.tBodies[0].rows, function(row) {
      if (row.classList.contains('drawer')) return;
      if (row.cells.length !== colCount) return;  // malformed row: leave it alone
      row.insertBefore(row.cells[srcIdx], row.cells[tgtIdx]);
    });
    if (window.__columns && window.__columns.isManaged(table)) {
      window.__columns.onReorder(table);
    }
  }

  var dragState = null;
  document.addEventListener('mousedown', function(e) {
    if (e.button !== 0) return;
    var th = e.target.closest('th');
    if (!th || th.classList.contains('no-sort') || e.target.closest('.col-resizer')) return;
    var table = th.closest('table.findings');
    if (!table) return;
    // Catalog-less serve tables (CA analysis results) cannot send a column
    // order to the server, so paging/sorting would realign rows under the
    // dragged headers. Keep their server-defined column order stable.
    if (table.getAttribute('data-serve') === '1'
        && window.__columns && !window.__columns.isManaged(table)) return;
    e.preventDefault();  // avoid text selection while starting a drag
    dragState = { table: table, th: th, startX: e.clientX, moved: false, dropTarget: null };
  });

  document.addEventListener('mousemove', function(e) {
    if (!dragState) return;
    if (!dragState.moved && Math.abs(e.clientX - dragState.startX) < 8) return;
    if (!dragState.moved) {
      dragState.moved = true;
      document.body.classList.add('col-dragging');
      dragState.th.classList.add('col-drag-source');
    }
    var over = document.elementFromPoint(e.clientX, e.clientY);
    var target = over ? over.closest('th') : null;
    if (target && (target.closest('table') !== dragState.table
                   || target.classList.contains('no-sort')
                   || target === dragState.th)) {
      target = null;
    }
    var prev = dragState.dropTarget;
    if (prev && prev !== target) prev.classList.remove('col-drop-target');
    if (target && target !== prev) target.classList.add('col-drop-target');
    dragState.dropTarget = target;
  });

  document.addEventListener('mouseup', function() {
    if (!dragState) return;
    var st = dragState;
    dragState = null;
    document.body.classList.remove('col-dragging');
    st.th.classList.remove('col-drag-source');
    if (st.dropTarget) st.dropTarget.classList.remove('col-drop-target');
    if (!st.moved || !st.dropTarget) return;
    suppressSortClick = Date.now();  // the following click is a drag, not a sort
    window.__suppressSortClickUntil = suppressSortClick;
    moveColumn(st.table, st.th, st.dropTarget);
  });

  stampColumnIds();
  window.__stampColumnIds = stampColumnIds;

  function wireTableSort(table) {
    if (!table || !table.tHead || table.__sortWired) return;
    table.__sortWired = true;
    table.tHead.addEventListener('click', function(e) {
      if (table.__loaderMade) return;  // serve-mode loader owns sorting
      var th = e.target.closest('th');
      if (!th || !table.tHead.contains(th) || th.classList.contains('no-sort')) return;
      if (suppressSortClick && Date.now() - suppressSortClick < 300) return;
      var headers = table.tHead.rows[0].cells;
      var idx = Array.prototype.indexOf.call(headers, th);
      if (idx < 0) return;
      var asc = th.__asc === undefined ? true : !!th.__asc;
      var mantissa = Array.prototype.filter.call(table.tBodies[0].rows, function(r) {
        return !r.classList.contains('drawer');
      });
      var drawers = Array.prototype.filter.call(table.tBodies[0].rows, function(r) {
        return r.classList.contains('drawer');
      });
      drawers.forEach(function(d) { d.remove(); });
      mantissa.sort(function(a, b) {
        var ac = a.cells[idx], bc = b.cells[idx];
        var av = ac ? ac.textContent.trim().toLowerCase() : '';
        var bv = bc ? bc.textContent.trim().toLowerCase() : '';
        if (av < bv) return asc ? -1 : 1;
        if (av > bv) return asc ? 1 : -1;
        return 0;
      });
      var order = [];
      mantissa.forEach(function(r) {
        order.push(r);
        var key = r.getAttribute('data-detail-key');
        var d = drawers.find(function(x) { return x.getAttribute('data-detail-for') === key; });
        if (d) order.push(d);
      });
      order.forEach(function(r) { table.tBodies[0].appendChild(r); });
      Array.prototype.forEach.call(headers, function(h) { h.classList.remove('sorted'); });
      th.classList.add('sorted');
      th.__asc = !asc;
    });
  }
  allTables().forEach(wireTableSort);
  window.__wireTableSort = wireTableSort;

  function colForTh(table, th) {
    var cg = table.querySelector('colgroup');
    if (!cg || !table.tHead) return null;
    var idx = Array.prototype.indexOf.call(table.tHead.rows[0].cells, th);
    return cg.children[idx] || null;
  }

  function makeColumnsResizable(table) {
    if (!table || !table.tHead) return;
    var headers = table.tHead.rows[0].cells;
    Array.prototype.forEach.call(headers, function(th, index) {
      if (index === headers.length - 1 || th.classList.contains('no-sort')) return;
      if (th.querySelector(':scope > .col-resizer')) return;
      var handle = document.createElement('span');
      handle.className = 'col-resizer';
      handle.addEventListener('click', function(e) { e.stopPropagation(); });
      handle.addEventListener('mousedown', function(e) {
        e.preventDefault();
        e.stopPropagation();
        var col = colForTh(table, th);
        if (!col) return;
        var startX = e.clientX;
        var startWidth = col.getBoundingClientRect().width;
        var moved = false;
        handle.classList.add('resizing');
        document.body.style.userSelect = 'none';
        function onMouseMove(e2) {
          if (!moved && Math.abs(e2.clientX - startX) > 3) moved = true;
          var newWidth = Math.max(50, startWidth + (e2.clientX - startX));
          col.style.width = newWidth + 'px';
        }
        function onMouseUp() {
          document.removeEventListener('mousemove', onMouseMove);
          document.removeEventListener('mouseup', onMouseUp);
          handle.classList.remove('resizing');
          document.body.style.userSelect = '';
          // The browser fires a click after the drag on the mousedown/mouseup
          // common ancestor; if it lands on the header it would toggle the
          // sort. Suppress sort clicks for a beat, exactly like column drags.
          if (moved) {
            suppressSortClick = Date.now();
            window.__suppressSortClickUntil = suppressSortClick;
          }
        }
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
      });
      th.appendChild(handle);
    });
  }
  allTables().forEach(makeColumnsResizable);
  window.__makeColumnsResizable = makeColumnsResizable;

  window.__applyCurrentFilter = applyRowFilter;

  // ---- column manager (add/remove columns per table) ---------------------
  var COLUMN_CATALOG = {};
  try { COLUMN_CATALOG = JSON.parse(document.getElementById('table-catalog-data').textContent) || {}; } catch (e) {}
  var COLUMN_EXTRAS = {};
  var COLUMN_STORE = 'entra-surface:cols:v1:';
  var FAMILY_LABELS = {
    sp: 'Application / service principal', user: 'User', group: 'Group',
    policy: 'Conditional Access', auth: 'Authentication', arc: 'Azure Arc'
  };

  function columnMeta(tid) {
    var meta = {};
    var entry = COLUMN_CATALOG[tid];
    ((entry && entry.fields) || []).forEach(function(f) { meta[f.id] = f; });
    return meta;
  }

  function columnExtras(tid) {
    if (Object.prototype.hasOwnProperty.call(COLUMN_EXTRAS, tid)) return COLUMN_EXTRAS[tid];
    var el = document.getElementById('extras-' + tid);
    var blob = null;
    if (el) { try { blob = JSON.parse(el.textContent) || {}; } catch (e) { blob = null; } }
    COLUMN_EXTRAS[tid] = blob;
    return blob;
  }

  function isManagedColumnTable(table) {
    return !!(table && table.id && COLUMN_CATALOG[table.id] && table.tHead);
  }

  function columnFields(table) {
    var out = [];
    Array.prototype.forEach.call(table.tHead.rows[0].cells, function(th) {
      var f = th.getAttribute('data-field');
      if (f) out.push(f);
    });
    return out;
  }

  function defaultColumnFields(tid) {
    var entry = COLUMN_CATALOG[tid] || {};
    return (entry.fields || []).filter(function(f) { return f['default']; })
        .map(function(f) { return f.id; });
  }

  function readColumnState(tid) {
    try {
      var raw = localStorage.getItem(COLUMN_STORE + tid);
      if (!raw) return null;
      var arr = JSON.parse(raw);
      if (!Array.isArray(arr)) return null;
      var meta = columnMeta(tid), seen = {}, out = [];
      arr.forEach(function(id) {
        if (meta[id] && !seen[id]) { seen[id] = 1; out.push(id); }
      });
      return out.length ? out : null;
    } catch (e) { return null; }
  }

  function writeColumnState(tid, fields) {
    try {
      if (fields.join(',') === defaultColumnFields(tid).join(',')) {
        localStorage.removeItem(COLUMN_STORE + tid);
      } else {
        localStorage.setItem(COLUMN_STORE + tid, JSON.stringify(fields));
      }
    } catch (e) {}
  }

  function syncCols(table, preservedWidths) {
    var cg = table.querySelector('colgroup');
    if (!cg || !table.tHead) return;
    var headers = table.tHead.rows[0].cells;
    var widths = preservedWidths || {};
    var meta = columnMeta(table.id);
    var html = '';
    Array.prototype.forEach.call(headers, function(th) {
      var f = th.getAttribute('data-field');
      if (!f) { html += '<col style="width:44px">'; return; }
      var m = meta[f] || {};
      html += '<col style="width:' + (widths[f] || ((m.width || 120) + 'px')) + '">';
    });
    cg.innerHTML = html;
  }

  function extraCell(tid, detailKey, field, meta) {
    var blob = columnExtras(tid);
    var pair = blob && blob[detailKey] ? blob[detailKey][field] : null;
    // Always emit a cell so enabling a column cannot shift later cells when a
    // particular row has no recorded extra value (B-023).
    if (!pair) pair = ['', ''];
    var td = document.createElement('td');
    if (meta && meta.cls) td.className = meta.cls;
    td.setAttribute('data-field', field);
    td.setAttribute('data-value', pair[1] || '');
    td.innerHTML = pair[0];
    return td;
  }

  function rebuildTable(table, fields) {
    var tid = table.id;
    var meta = columnMeta(tid);
    var theadRow = table.tHead.rows[0];
    // Capture widths keyed by field before headers/colgroup are reordered, so
    // syncCols pairs old <col> indices with the *same* fields, not the new
    // header order (B-098).
    var preservedWidths = {};
    var oldCg = table.querySelector('colgroup');
    if (oldCg) {
      Array.prototype.forEach.call(oldCg.children, function(col, i) {
        var th = theadRow.cells[i];
        var f = th && th.getAttribute('data-field');
        if (f && col.style && col.style.width) preservedWidths[f] = col.style.width;
      });
    }
    var thByField = {};
    Array.prototype.forEach.call(theadRow.cells, function(th) {
      var f = th.getAttribute('data-field');
      if (f) thByField[f] = th;
    });
    var ordered = [];
    Array.prototype.slice.call(theadRow.cells).forEach(function(th) {
      if (th.getAttribute('data-field')) {
        if (fields.indexOf(th.getAttribute('data-field')) < 0) th.remove();
      } else {
        ordered.push(th);
      }
    });
    fields.forEach(function(f) {
      var th = thByField[f];
      if (!th) {
        th = document.createElement('th');
        th.setAttribute('data-type', 'text');
        th.setAttribute('data-field', f);
        th.title = 'Click to sort \u00b7 drag to reorder';
        th.textContent = (meta[f] && meta[f].label) || f;
      }
      ordered.push(th);
    });
    ordered.forEach(function(th) { theadRow.appendChild(th); });
    Array.prototype.forEach.call(table.tBodies[0].rows, function(row) {
      if (row.classList.contains('drawer')) {
        var dtd = row.querySelector('td');
        if (dtd) dtd.colSpan = fields.length + 1;
        return;
      }
      var tdByField = {};
      var expander = null;
      Array.prototype.slice.call(row.cells).forEach(function(td) {
        var f = td.getAttribute('data-field');
        if (f) {
          if (fields.indexOf(f) >= 0) tdByField[f] = td;
          else td.remove();
        } else if (expander === null) {
          expander = td;
        }
      });
      if (!expander) return;
      var detailKey = row.getAttribute('data-detail-key') || '';
      var frag = document.createDocumentFragment();
      frag.appendChild(expander);
      fields.forEach(function(f) {
        var td = tdByField[f];
        if (!td) td = extraCell(tid, detailKey, f, meta[f]);
        if (td) frag.appendChild(td);
      });
      row.appendChild(frag);
    });
    syncCols(table, preservedWidths);
    if (window.__makeColumnsResizable) window.__makeColumnsResizable(table);
    if (window.__wireTableSort) window.__wireTableSort(table);
    if (window.__applyCurrentFilter) window.__applyCurrentFilter();
  }

  function applyColumnList(table, fields) {
    table.__columnFields = fields.slice();
    table.__pendingCols = null;
    writeColumnState(table.id, fields);
    if (table.__loaderMade && table.__reload) {
      table.__reload();
    } else {
      rebuildTable(table, fields);
    }
    updateColumnUI(table);
  }

  function updateColumnUI(table) {
    var ui = table.__colman;
    if (!ui) return;
    var visible = {};
    window.__columns.getFields(table).forEach(function(f) { visible[f] = 1; });
    var hidden = 0;
    defaultColumnFields(table.id).forEach(function(f) { if (!visible[f]) hidden++; });
    ui.badge.textContent = hidden ? String(hidden) : '';
    ui.badge.classList.toggle('hidden', !hidden);
    ui.badge.title = hidden
        ? hidden + (hidden === 1 ? ' hidden default column' : ' hidden default columns') : '';
  }

  function escHtml(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function closeColumnPops() {
    Array.prototype.forEach.call(document.querySelectorAll('.colman-pop'), function(p) {
      p.classList.add('hidden');
    });
    Array.prototype.forEach.call(document.querySelectorAll('.colman-btn'), function(b) {
      b.setAttribute('aria-expanded', 'false');
    });
  }
  document.addEventListener('click', closeColumnPops);

  function renderColumnPop(table) {
    var ui = table.__colman;
    var entry = COLUMN_CATALOG[table.id];
    if (!ui || !entry) return;
    var visible = {};
    window.__columns.getFields(table).forEach(function(f) { visible[f] = 1; });
    var byFamily = {}, order = [];
    (entry.fields || []).forEach(function(f) {
      var fam = f.family || 'sp';
      if (!byFamily[fam]) { byFamily[fam] = []; order.push(fam); }
      byFamily[fam].push(f);
    });
    var famOrder = order.filter(function(f) { return f === entry.family; })
        .concat(order.filter(function(f) { return f !== entry.family; }));
    var multiFamily = famOrder.length > 1;
    var oldList = ui.pop.querySelector('.colman-list');
    var scrollTop = oldList ? oldList.scrollTop : 0;
    var html = '<div class="colman-list">';
    famOrder.forEach(function(fam) {
      html += '<div class="colman-group">';
      if (multiFamily) {
        html += '<div class="colman-group-title">'
            + escHtml(FAMILY_LABELS[fam] || fam) + '</div>';
      }
      byFamily[fam].forEach(function(f) {
        html += '<label class="colman-item"><input type="checkbox" data-field="'
            + escHtml(f.id) + '"' + (visible[f.id] ? ' checked' : '') + '> <span>'
            + escHtml(f.label || f.id) + '</span></label>';
      });
      html += '</div>';
    });
    html += '</div>';
    html += '<div class="colman-foot"><button type="button" class="colman-reset">'
        + 'Reset to defaults</button></div>';
    ui.pop.innerHTML = html;
    var list = ui.pop.querySelector('.colman-list');
    if (list) list.scrollTop = scrollTop;
    var reset = ui.pop.querySelector('.colman-reset');
    if (reset) reset.addEventListener('click', function(e) {
      e.stopPropagation();
      applyColumnList(table, defaultColumnFields(table.id));
      renderColumnPop(table);
    });
  }

  function buildColumnUI(table) {
    if (table.__colman || !COLUMN_CATALOG[table.id]) return;
    var scroll = table.closest('.table-scroll');
    if (!scroll) return;
    var wrap = document.createElement('div');
    wrap.className = 'colman';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'colman-btn';
    btn.setAttribute('aria-expanded', 'false');
    btn.innerHTML = '<span class="colman-btn-label">Columns</span>';
    var badge = document.createElement('span');
    badge.className = 'colman-badge hidden';
    btn.appendChild(badge);
    btn.insertAdjacentHTML('beforeend',
        '<svg class="colman-chevron" width="10" height="10" viewBox="0 0 16 16" '
        + 'aria-hidden="true"><path d="M4 6.5 8 10.5l4-4" fill="none" '
        + 'stroke="currentColor" stroke-width="1.5" stroke-linecap="round" '
        + 'stroke-linejoin="round"/></svg>');
    var pop = document.createElement('div');
    pop.className = 'colman-pop hidden';
    wrap.appendChild(btn);
    wrap.appendChild(pop);
    // lift the picker onto the section's title line (h2 + button share a row)
    var section = table.closest('section');
    var h2 = section ? section.querySelector(':scope > h2') : null;
    if (section && h2) {
      var headRow = document.createElement('div');
      headRow.className = 'table-head-row';
      section.insertBefore(headRow, h2);
      headRow.appendChild(h2);
      headRow.appendChild(wrap);
    } else {
      scroll.parentNode.insertBefore(wrap, scroll);
    }
    table.__colman = { wrap: wrap, btn: btn, badge: badge, pop: pop };
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      var open = !pop.classList.contains('hidden');
      closeColumnPops();
      if (!open) {
        renderColumnPop(table);
        pop.classList.remove('hidden');
        btn.setAttribute('aria-expanded', 'true');
      }
    });
    // keep the popover open while the user toggles columns inside it
    pop.addEventListener('click', function(e) { e.stopPropagation(); });
    pop.addEventListener('change', function(e) {
      var cb = e.target;
      if (!cb || cb.tagName !== 'INPUT') return;
      var field = cb.getAttribute('data-field');
      var current = window.__columns.getFields(table);
      if (cb.checked) {
        if (current.indexOf(field) < 0) current.push(field);
      } else {
        if (current.length <= 1) { cb.checked = true; return; }
        current = current.filter(function(x) { return x !== field; });
      }
      applyColumnList(table, current);
      renderColumnPop(table);
    });
    updateColumnUI(table);
  }

  window.__columns = {
    catalog: COLUMN_CATALOG,
    isManaged: isManagedColumnTable,
    extras: columnExtras,
    getFields: function(table) {
      if (table.__pendingCols) return table.__pendingCols.slice();
      return table.__columnFields ? table.__columnFields.slice() : columnFields(table);
    },
    setFields: function(table, fields) {
      table.__columnFields = fields.slice();
      updateColumnUI(table);
    },
    colForTh: colForTh,
    syncCols: syncCols,
    apply: applyColumnList,
    reset: function(table) { applyColumnList(table, defaultColumnFields(table.id)); },
    onReorder: function(table) {
      table.__columnFields = columnFields(table);
      table.__pendingCols = null;
      writeColumnState(table.id, table.__columnFields);
      updateColumnUI(table);
    }
  };

  allTables().forEach(function(table) {
    if (!isManagedColumnTable(table)) return;
    var saved = readColumnState(table.id);
    if (saved) {
      table.__columnFields = saved.slice();
      if (table.getAttribute('data-serve') === '1') {
        table.__pendingCols = saved.slice();
      } else {
        rebuildTable(table, saved);
      }
    }
    buildColumnUI(table);
  });
})();

(function() {
  var spinner = document.getElementById('filter-spinner');
  if (!spinner) return;
  var timer = null;
  var pending = 0;
  function advancedMode() {
    var adv = document.getElementById('advanced-toggle');
    return !!(adv && adv.getAttribute('aria-pressed') === 'true');
  }
  function start() {
    if (!advancedMode()) return false;
    pending += 1;
    if (!timer) {
      timer = setTimeout(function() {
        timer = null;
        if (pending > 0) spinner.classList.remove('hidden');
      }, 2000);
    }
    return true;
  }
  function end() {
    pending = Math.max(0, pending - 1);
    if (!pending) {
      if (timer) { clearTimeout(timer); timer = null; }
      spinner.classList.add('hidden');
    }
  }
  function reset() {
    pending = 0;
    if (timer) { clearTimeout(timer); timer = null; }
    spinner.classList.add('hidden');
  }
  window.__filterBusyStart = start;
  window.__filterBusyEnd = end;
  window.__filterBusyReset = reset;
})();

(function() {
  var filterInput = document.getElementById('filter-input');

  function tableVisible(table) {
    return !!(table && table.getClientRects && table.getClientRects().length);
  }

  function makeLoader(table) {
    if (table.__loaderMade) return;
    var pager = table.closest('.table-scroll') ? table.closest('.table-scroll').nextElementSibling : null;
    if (!pager || !pager.classList.contains('table-pager')) return;
    table.__loaderMade = true;
    var state = { page: 1, size: 25, sort: '', dir: 'asc' };
    var tbody = table.tBodies[0];
    var range = pager.querySelector('.tp-range');
    var info = pager.querySelector('.tp-info');
    var prev = pager.querySelector('.tp-prev');
    var next = pager.querySelector('.tp-next');
    var sizeSel = pager.querySelector('.tp-size');
    var reqSeq = 0;
    var pendingAbort = null;

    function setRange(page, size, total) {
      if (!range) return;
      range.classList.remove('error');
      if (!total) {
        range.textContent = '0 rows';
        return;
      }
      var start = (page - 1) * size + 1;
      var end = Math.min(page * size, total);
      range.textContent = start + '\u2013' + end + ' of ' + total
          + (total === 1 ? ' row' : ' rows');
    }

    function domFieldKey() {
      var out = [];
      if (!table.tHead) return '';
      Array.prototype.forEach.call(table.tHead.rows[0].cells, function(th) {
        var f = th.getAttribute('data-field');
        if (f) out.push(f);
      });
      return out.join(',');
    }

    function load(force) {
      var fs = window.__filterState;
      if (!fs) {
        var advEl = document.getElementById('advanced-toggle');
        fs = { advanced: !!(advEl && advEl.getAttribute('aria-pressed') === 'true'),
               q: filterInput ? filterInput.value : '', seq: 0 };
      }
      var advanced = !!fs.advanced;
      var q = fs.q || '';
      // Never replace a table with results for a query the client already
      // rejected as invalid advanced syntax.
      if (advanced && window.__advancedQueryInvalid) return;
      if (!force && !tableVisible(table)) {
        table.__dirty = true;
        return;
      }
      table.__dirty = false;
      var querySeq = fs.seq;
      var seq = ++reqSeq;
      if (pendingAbort) {
        try { pendingAbort.abort(); } catch (e) {}
      }
      pendingAbort = (typeof AbortController !== 'undefined') ? new AbortController() : null;

      var params = 'page=' + state.page + '&size=' + state.size;
      if (q) params += '&q=' + encodeURIComponent(q);
      if (advanced) params += '&mode=advanced';
      if (state.sort) params += '&sort=' + encodeURIComponent(state.sort) + '&dir=' + state.dir;
      var managed = window.__columns && window.__columns.isManaged(table);
      if (managed) params += '&cols=' + encodeURIComponent(window.__columns.getFields(table).join(','));
      var opts = pendingAbort ? { signal: pendingAbort.signal } : undefined;
      var busy = !!(advanced && q && window.__filterBusyStart
                    && window.__filterBusyStart());
      fetch('/api/table/' + encodeURIComponent(table.id) + '?' + params, opts)
        .then(function(r) {
          if (r.status === 400) return null;  // parse error: keep the current table
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(function(d) {
          if (seq !== reqSeq) return;  // an older response lost the race
          if (window.__filterState && window.__filterState.seq !== querySeq) return;
          var advNow = document.getElementById('advanced-toggle');
          if (window.__advancedQueryInvalid && advNow
              && advNow.getAttribute('aria-pressed') === 'true') return;
          if (!d || d.error || d.rows_html == null) return;
          if (managed && d.fields && window.__columns) {
            var newKey = d.fields.join(',');
            // compare against the DOM, not a captured key: a "Reset to
            // defaults" must rebuild headers that are still in dragged order
            if (newKey !== domFieldKey()) {
              if (d.thead_html != null && table.tHead) table.tHead.rows[0].innerHTML = d.thead_html;
              var cg = table.querySelector('colgroup');
              if (cg && d.colgroup_html != null) cg.innerHTML = d.colgroup_html;
              if (window.__makeColumnsResizable) window.__makeColumnsResizable(table);
              if (window.__wireTableSort) window.__wireTableSort(table);
            }
            window.__columns.setFields(table, d.fields);
            table.__pendingCols = null;
          }
          tbody.innerHTML = d.rows_html;
          setRange(d.page, d.size, d.total);
          info.textContent = 'Page ' + d.page + ' of ' + d.pages;
          pager.classList.remove('hidden');
          prev.disabled = d.page <= 1;
          next.disabled = d.page >= d.pages;
        })
        .catch(function(err) {
          if (err && err.name === 'AbortError') return;
          if (seq !== reqSeq) return;
          if (range) {
            range.textContent = 'Failed to load rows';
            range.classList.add('error');
          }
          pager.classList.remove('hidden');
        })
        .finally(function() {
          if (busy && window.__filterBusyEnd) window.__filterBusyEnd();
        });
    }
    table.__reload = function() { state.page = 1; load(); };
    table.__reloadFiltered = function() { state.page = 1; load(); };
    prev.addEventListener('click', function() { state.page = Math.max(1, state.page - 1); load(); });
    next.addEventListener('click', function() { state.page += 1; load(); });
    sizeSel.addEventListener('change', function() { state.size = parseInt(sizeSel.value, 10) || 25; state.page = 1; load(); });
    table.tHead.addEventListener('click', function(e) {
      var th = e.target.closest('th');
      if (!th || th.classList.contains('no-sort')) return;
      e.stopPropagation();
      if (window.__suppressSortClickUntil && Date.now() - window.__suppressSortClickUntil < 300) return;
      var managed = window.__columns && window.__columns.isManaged(table);
      var col = managed
          ? th.getAttribute('data-field')
          : (th.dataset.colidx || String(Array.prototype.indexOf.call(table.tHead.rows[0].cells, th)));
      if (!col) return;
      if (state.sort === String(col)) state.dir = state.dir === 'asc' ? 'desc' : 'asc';
      else { state.sort = String(col); state.dir = 'asc'; }
      state.page = 1;
      Array.prototype.forEach.call(table.tHead.rows[0].cells, function(h) { h.classList.remove('sorted'); });
      th.classList.add('sorted');
      load();
    }, true);
    load();
  }
  document.querySelectorAll('table.findings[data-serve="1"]').forEach(makeLoader);
  window.__makeLoader = makeLoader;

  function loadDirtyTables() {
    Array.prototype.forEach.call(
        document.querySelectorAll('table.findings[data-serve="1"]'),
        function(t) {
          if (t.__dirty && t.__reloadFiltered && tableVisible(t)) {
            t.__reloadFiltered();
          }
        });
  }
  window.__loadDirtyTables = loadDirtyTables;

  var filterTimer = null;
  function scheduleFilterLoads() {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(function() {
      Array.prototype.forEach.call(
          document.querySelectorAll('table.findings[data-serve="1"]'),
          function(t) {
            if (t.__reloadFiltered) t.__reloadFiltered();
          });
    }, 300);
  }
  if (filterInput) filterInput.addEventListener('input', scheduleFilterLoads);
  var categoryTabs = document.getElementById('category-tabs');
  if (categoryTabs) {
    categoryTabs.addEventListener('click', function() {
      setTimeout(loadDirtyTables, 0);
    });
  }
  document.addEventListener('app:view', function() {
    setTimeout(loadDirtyTables, 0);
  });

  // ---- on-demand CA coverage analysis ----------------------------------
  var caRun = document.getElementById('ca-run-btn');
  var caUserBtn = document.getElementById('ca-user-btn');
  var caUserInput = document.getElementById('ca-user-input');
  var caCompareBtn = document.getElementById('ca-compare-btn');
  var caPop = document.getElementById('ca-pop');
  var caUsersWrap = document.getElementById('ca-users-wrap');
  function caToggleUsers() {
    if (caUsersWrap && caPop) {
      caUsersWrap.classList.toggle('hidden', caPop.value !== 'list');
    }
  }
  if (caPop) {
    caPop.addEventListener('change', caToggleUsers);
    caToggleUsers();
  }

  // CA view tabs: tenant overview, single user, or two-user comparison
  var caViewTabs = document.querySelectorAll('#ca-view-tabs .drawer-tab');
  if (caViewTabs.length) {
    Array.prototype.forEach.call(caViewTabs, function(tab) {
      tab.addEventListener('click', function() {
        window.__caView = tab.getAttribute('data-caview');
        Array.prototype.forEach.call(caViewTabs, function(t) {
          t.classList.toggle('active', t === tab);
        });
        var activeCat = document.querySelector('#category-tabs .tab-btn.active');
        if (activeCat) activeCat.click();  // re-applies category + view visibility
      });
    });
  }

  if (caRun || caUserBtn) {
    var caStatusEl = document.getElementById('ca-status');
    var caStepsEl = document.getElementById('ca-steps');
    var caResultsEl = document.getElementById('ca-results');
    var caUserStatusEl = document.getElementById('ca-user-status');
    var caUserStepsEl = document.getElementById('ca-user-steps');
    var caUserResultsEl = document.getElementById('ca-user-results');
    var caCompareStatusEl = document.getElementById('ca-compare-status');
    var caCompareStepsEl = document.getElementById('ca-compare-steps');
    var caCompareResultsEl = document.getElementById('ca-compare-results');
    var caTimer = null;
    var caUserTimer = null;
    var caCompareTimer = null;
    var caButtons = [caRun, caUserBtn, caCompareBtn].filter(function(b) { return !!b; });

    function caSetBusy(busy) {
      caButtons.forEach(function(b) { b.disabled = busy; });
    }

    function caStepState(d, stepsEl) {
      if (!stepsEl) return;
      stepsEl.innerHTML = '';
      stepsEl.classList.toggle('error', !!d.error);
      if (d.error) {
        stepsEl.textContent = 'Error: ' + d.error;
        return;
      }
      var steps = d.steps || [];
      var current = null;
      for (var i = 0; i < steps.length; i++) {
        if (steps[i].status === 'running') { current = steps[i]; break; }
      }
      if (!current) {
        for (var j = steps.length - 1; j >= 0; j--) {
          if (steps[j].status === 'done') { current = steps[j]; break; }
        }
      }
      if (!current) {
        stepsEl.textContent = d.status === 'done' ? 'Analysis complete' : 'Starting analysis…';
        return;
      }
      var label = document.createElement('span');
      label.className = 'ca-step-label';
      label.textContent = d.status === 'done' ? 'Analysis complete' : current.label;
      stepsEl.appendChild(label);
      if (current.detail) {
        var detail = document.createElement('span');
        detail.className = 'step-detail';
        detail.textContent = current.detail;
        stepsEl.appendChild(detail);
      }
    }

    function caRenderResults(d, resultsEl, isUser) {
      if (d.status === 'done' && d.result) {
        resultsEl.innerHTML = (d.result.summary_html || '') + (d.result.sections_html || '');
        // these tables are created after load: stamp fresh headers with their
        // column identities so drag-reorder and serve-mode paging stay aligned
        if (window.__stampColumnIds) window.__stampColumnIds();
        Array.prototype.forEach.call(
            resultsEl.querySelectorAll('table.findings'), function(t) {
              if (window.__wireTableSort) window.__wireTableSort(t);
              if (window.__makeColumnsResizable) window.__makeColumnsResizable(t);
              if (window.__makeLoader) window.__makeLoader(t);
            });
        // new loaders read the global filter state; re-apply plain client-side
        // filtering so the visible page matches the filter box
        if (window.__applyCurrentFilter) window.__applyCurrentFilter();
        if (window.__wireTableCollapse) window.__wireTableCollapse(resultsEl);
      }
    }

    function caPoll(mode) {
      var expectedKind = mode === 'single' ? 'single'
        : (mode === 'compare' ? 'compare' : 'main');
      fetch('/api/ca-analysis/status').then(function(r) { return r.json(); })
        .then(function(d) {
          if (!d || !d.steps) {
            caSetBusy(false);
            var idleEl = mode === 'single' ? caUserStatusEl
              : (mode === 'compare' ? caCompareStatusEl : caStatusEl);
            if (idleEl) {
              idleEl.classList.remove('hidden');
              idleEl.classList.add('error');
              idleEl.textContent = 'The analysis job is no longer running. Start it again.';
            }
            return;
          }
          if (d.kind && d.kind !== expectedKind) {
            caSetBusy(false);
            var kindEl = mode === 'single' ? caUserStatusEl
              : (mode === 'compare' ? caCompareStatusEl : caStatusEl);
            if (kindEl) {
              kindEl.classList.remove('hidden');
              kindEl.classList.add('error');
              kindEl.textContent = 'Another CA analysis (' + d.kind + ') is running. Wait for it to finish.';
            }
            return;
          }
          if (mode === 'single') {
            caStepState(d, caUserStepsEl);
            if (d.status === 'running') { caUserTimer = setTimeout(function() { caPoll('single'); }, 600); return; }
            caSetBusy(false);
            caRenderResults(d, caUserResultsEl, true);
          } else if (mode === 'compare') {
            caStepState(d, caCompareStepsEl);
            if (d.status === 'running') { caCompareTimer = setTimeout(function() { caPoll('compare'); }, 600); return; }
            caSetBusy(false);
            caRenderResults(d, caCompareResultsEl, false);
          } else {
            caStepState(d, caStepsEl);
            if (d.status === 'running') { caTimer = setTimeout(function() { caPoll('main'); }, 600); return; }
            caSetBusy(false);
            caRenderResults(d, caResultsEl, false);
          }
        }).catch(function() { caSetBusy(false); });
    }

    function startCa(upn, isUser) {
      if (isUser && !(upn || '').trim()) {
        caUserStatusEl.classList.remove('hidden');
        caUserStepsEl.innerHTML = '<li class="error">Enter a user UPN.</li>';
        if (caUserInput) caUserInput.focus();
        return;
      }
      caSetBusy(true);
      var statusEl = isUser ? caUserStatusEl : caStatusEl;
      var stepsEl = isUser ? caUserStepsEl : caStepsEl;
      var resultsEl = isUser ? caUserResultsEl : caResultsEl;
      // clear the pane this run owns so a single-user run never displays the
      // previous tenant-wide result (or vice versa) while it is running
      resultsEl.innerHTML = '';
      statusEl.classList.remove('hidden');
      stepsEl.innerHTML = '';
      function val(id) {
        var el = document.getElementById(id);
        return el ? el.value.trim() : '';
      }
      var maxScenarios = parseInt(val('ca-max-scenarios') || '0', 10);
      var includeDisabled = document.getElementById('ca-include-disabled');
      var syncedOnly = document.getElementById('ca-synced');
      var payload = {
        upn: upn || '',
        population: val('ca-pop') || 'privileged',
        users: val('ca-users-input'),
        synced_only: !!(syncedOnly && syncedOnly.checked),
        include_disabled: includeDisabled ? !!includeDisabled.checked : true,
        resource: val('ca-resource'),
        client_app: val('ca-client'),
        mode: val('ca-mode') || 'fast',
        max_scenarios: isNaN(maxScenarios) ? 24 : maxScenarios,
        assume_groups: val('ca-assume-groups'),
        assume_roles: val('ca-assume-roles'),
        scenario: {
          platform: val('ca-wi-platform'), client_app: val('ca-wi-client'),
          device_state: val('ca-wi-device'),
          device_filter: val('ca-wi-devfilter'),
          trusted_location: val('ca-wi-location'),
          signin_risk: val('ca-wi-signin'), user_risk: val('ca-wi-userrisk'),
          auth_flow: val('ca-wi-authflow'),
          app_id: val('ca-app-input'), acr: val('ca-acr-input'),
          require: val('ca-wi-require')
        }
      };
      var body = JSON.stringify(payload);
      fetch('/api/ca-analysis', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body
      })
        .then(function(r) {
          return r.json().then(function(d) {
            if (!r.ok) throw new Error((d && d.error) || ('HTTP ' + r.status));
            return d;
          });
        })
        .then(function(d) {
          if (d && d.status === 'running') {
            if (isUser) caUserTimer = setTimeout(function() { caPoll('single'); }, 600);
            else caTimer = setTimeout(function() { caPoll('main'); }, 600);
          } else {
            caSetBusy(false);
          }
        }).catch(function(err) {
          caSetBusy(false);
          statusEl.classList.remove('hidden');
          statusEl.classList.add('error');
          statusEl.textContent = (err && err.message) || 'Could not start CA analysis.';
        });
    }

    function startCaCompare() {
      function val(id) {
        var el = document.getElementById(id);
        return el ? el.value.trim() : '';
      }
      var a = val('ca-compare-a');
      var b = val('ca-compare-b');
      if (!a || !b) {
        caCompareStatusEl.classList.remove('hidden');
        caCompareStepsEl.innerHTML = '<li class="error">Enter both user UPNs.</li>';
        return;
      }
      caSetBusy(true);
      caCompareResultsEl.innerHTML = '';
      caCompareStatusEl.classList.remove('hidden');
      caCompareStepsEl.innerHTML = '';
      var payload = {
        compare_upns: [a, b],
        assume_groups: val('ca-cmp-assume-groups-a'),
        assume_roles: val('ca-cmp-assume-roles-a'),
        assume_groups_b: val('ca-cmp-assume-groups-b'),
        assume_roles_b: val('ca-cmp-assume-roles-b'),
        scenario: {
          platform: val('ca-cmp-platform'), client_app: val('ca-cmp-client'),
          device_state: val('ca-cmp-device'),
          device_filter: val('ca-cmp-devfilter'),
          trusted_location: val('ca-cmp-location'),
          signin_risk: val('ca-cmp-signin'), user_risk: val('ca-cmp-userrisk'),
          auth_flow: val('ca-cmp-authflow'),
          app_id: val('ca-cmp-app'), acr: val('ca-cmp-acr'),
          require: val('ca-cmp-require')
        }
      };
      fetch('/api/ca-analysis', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
        .then(function(r) {
          return r.json().then(function(d) {
            if (!r.ok) throw new Error((d && d.error) || ('HTTP ' + r.status));
            return d;
          });
        })
        .then(function(d) {
          if (d && d.status === 'running') {
            caCompareTimer = setTimeout(function() { caPoll('compare'); }, 600);
          } else {
            caSetBusy(false);
          }
        }).catch(function(err) {
          caSetBusy(false);
          caCompareStatusEl.classList.remove('hidden');
          caCompareStatusEl.classList.add('error');
          caCompareStatusEl.textContent = (err && err.message) || 'Could not start CA comparison.';
        });
    }

    if (caRun) caRun.addEventListener('click', function() { startCa('', false); });
    if (caUserBtn) caUserBtn.addEventListener('click', function() {
      startCa(caUserInput ? caUserInput.value.trim() : '', true);
    });
    if (caUserInput) {
      caUserInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && caUserBtn) caUserBtn.click();
      });
    }
    if (caCompareBtn) caCompareBtn.addEventListener('click', startCaCompare);
    var caCompareB = document.getElementById('ca-compare-b');
    if (caCompareB) {
      caCompareB.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && caCompareBtn) caCompareBtn.click();
      });
    }
  }
})();
(function() {
  function wireSection(section) {
    if (section.dataset.collapseWired) return;
    var h2 = null;
    var headRow = null;
    var scroll = null;
    for (var child = section.firstElementChild; child; child = child.nextElementSibling) {
      if (!headRow && child.classList && child.classList.contains('table-head-row')) {
        headRow = child;
      }
      if (child.tagName === 'H2' && !h2) h2 = child;
      if (!scroll && child.classList && child.classList.contains('table-scroll')
          && child.querySelector('table.findings')) {
        scroll = child;
      }
    }
    if (headRow && !h2) h2 = headRow.querySelector('h2');
    if (!h2 || !scroll) return;
    var table = scroll.querySelector('table.findings');
    section.dataset.collapseWired = '1';
    if (!headRow) {
      headRow = document.createElement('div');
      headRow.className = 'table-head-row';
      section.insertBefore(headRow, h2);
      headRow.appendChild(h2);
    }
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'section-toggle';
    btn.textContent = '\u25be';
    btn.setAttribute('aria-expanded', 'true');
    btn.setAttribute('aria-label', 'Hide table');
    btn.title = 'Hide table';
    if (table && table.id) btn.setAttribute('aria-controls', table.id);
    h2.appendChild(btn);
    var collapsed = false;
    function toggleCollapse() {
      collapsed = !collapsed;
      section.classList.toggle('section-collapsed', collapsed);
      btn.textContent = collapsed ? '\u25b8' : '\u25be';
      var label = collapsed ? 'Show table' : 'Hide table';
      btn.title = label;
      btn.setAttribute('aria-label', label);
      btn.setAttribute('aria-expanded', String(!collapsed));
      if (!collapsed && window.__loadDirtyTables) {
        setTimeout(window.__loadDirtyTables, 0);
      }
    }
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      toggleCollapse();
    });
    h2.classList.add('section-title-toggle');
    h2.addEventListener('click', function(e) {
      if (e.target.closest('.section-toggle')) return;
      if (window.getSelection && String(window.getSelection())) return;
      toggleCollapse();
    });
  }

  function wireTableCollapse(root) {
    if (!root || !root.querySelectorAll) return;
    Array.prototype.forEach.call(root.querySelectorAll('section'), wireSection);
  }
  window.__wireTableCollapse = wireTableCollapse;
  wireTableCollapse(document);
})();
</script>"""
