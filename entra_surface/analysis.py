#!/usr/bin/env python3
"""Runtime analysis job manager and no-database analysis UI.

The analysis pipeline itself lives in entra-surface.py (it needs the graph,
checks, and renderer).  This module owns the background-job state and the
small browser UI used to point the running server at a database.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path

_LOCK = threading.Lock()
_JOB = {
    "status": "idle",
    "db": "",
    "message": "",
    "error": "",
    "started_at": "",
    "finished_at": "",
}


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_status() -> dict:
    with _LOCK:
        return dict(_JOB)


def set_message(text: str) -> None:
    with _LOCK:
        if _JOB["status"] == "running":
            _JOB["message"] = text or ""


def start(db_path: str, runner) -> dict:
    """Start `runner(path)` in the background. Only one analysis may run."""
    path = Path(db_path or "").expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    if not path.exists():
        raise ValueError(f"database not found: {path}")
    if not path.is_file():
        raise ValueError(f"not a file: {path}")

    with _LOCK:
        if _JOB["status"] == "running":
            raise RuntimeError("an analysis is already running")
        _JOB.update({
            "status": "running",
            "db": str(path),
            "message": "Starting analysis...",
            "error": "",
            "started_at": _timestamp(),
            "finished_at": "",
        })

    thread = threading.Thread(target=_worker, args=(path, runner), daemon=True)
    thread.start()
    return get_status()


def _worker(path: Path, runner) -> None:
    try:
        runner(path)
    except Exception as exc:  # surfaced in the Analysis view
        with _LOCK:
            _JOB["status"] = "error"
            _JOB["message"] = ""
            _JOB["error"] = str(exc)
            _JOB["finished_at"] = _timestamp()
        return
    with _LOCK:
        _JOB["status"] = "done"
        _JOB["message"] = "Analysis complete"
        _JOB["error"] = ""
        _JOB["finished_at"] = _timestamp()


def styles_html() -> str:
    return """  .analysis-start {
    background: var(--surface-1); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px 18px; margin: 16px 0 18px;
  }
  .analysis-start h2 { font-size: 15px; margin: 0 0 4px; }
  .analysis-start p { margin: 0; color: var(--text-secondary); font-size: 12px; }
  .analysis-start-controls {
    display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 12px;
  }
  .analysis-start-controls input, .analysis-start-controls select,
  .analysis-start-custom input {
    background: var(--page-plane); color: var(--text-primary);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 8px 10px; font-size: 13px; font-family: inherit;
  }
  .analysis-start-controls input, .analysis-start-controls select {
    flex: 1; min-width: 260px;
  }
  .analysis-start-custom { margin-top: 8px; }
  .analysis-start-custom input { width: 100%; }
  .analysis-cache-check {
    display: flex; align-items: center; gap: 8px; margin-top: 10px;
    color: var(--text-secondary); font-size: 12px; cursor: pointer;
  }
  .analysis-cache-check input { margin: 0; }
  .analysis-status { margin-top: 10px; color: var(--text-secondary); font-size: 12px; }
  .analysis-status.error { color: var(--status-critical); }
"""


def client_js() -> str:
    """Shared browser helper: start analysis and poll until the shell is ready."""
    return r"""<script>
window.ENTRA_ANALYSIS = (function() {
  function poll(onStatus) {
    fetch('/api/analyze/status')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.status === 'running') {
          onStatus(data.message || 'Analyzing...');
          setTimeout(function() { poll(onStatus); }, 1000);
        } else if (data.status === 'done') {
          onStatus('Analysis complete. Reloading...');
          setTimeout(function() { window.location.reload(); }, 400);
        } else if (data.status === 'error') {
          onStatus(data.error || 'Analysis failed.', true);
        }
      })
      .catch(function() {
        onStatus('Could not reach the local server.', true);
      });
  }

  function start(db, onStatus, useCache) {
    onStatus = onStatus || function() {};
    onStatus('Starting analysis...');
    fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ db: db, cache: useCache !== false })
    }).then(function(r) {
      return r.json().then(function(data) {
        if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
        return data;
      });
    }).then(function() {
      poll(onStatus);
    }).catch(function(err) {
      onStatus(err.message || 'Could not start analysis.', true);
    });
  }

  return { start: start };
})();
</script>"""


def start_panel_html() -> str:
    return r"""<section class="analysis-start" id="analysis-start">
  <h2>Start analysis</h2>
  <p>Choose a database from <span class="mono">data/databases</span> or enter a custom path.</p>
  <div class="analysis-start-controls">
    <select id="analysis-db-select" aria-label="Database">
      <option value="">Loading databases...</option>
    </select>
    <button type="button" class="mode-btn" id="analysis-start-btn">Begin analysis</button>
  </div>
  <div class="analysis-start-custom hidden" id="analysis-custom-wrap">
    <input id="analysis-db" type="text" placeholder="Custom path to a SQLite database"
           autocomplete="off" spellcheck="false">
  </div>
  <label class="analysis-cache-check">
    <input type="checkbox" id="analysis-cache" checked>
    <span>Cache analysis</span>
  </label>
  <div class="analysis-status hidden" id="analysis-status"></div>
</section>
<script>
(function() {
  var select = document.getElementById('analysis-db-select');
  var customWrap = document.getElementById('analysis-custom-wrap');
  var input = document.getElementById('analysis-db');
  var cacheEl = document.getElementById('analysis-cache');
  var btn = document.getElementById('analysis-start-btn');
  var status = document.getElementById('analysis-status');
  if (!btn) return;
  var lastSignature = null;

  function setStatus(text, failed) {
    status.textContent = text || '';
    status.classList.toggle('hidden', !text);
    status.classList.toggle('error', !!failed);
  }

  function updateCustom(focus) {
    var custom = select.value === '__custom__';
    customWrap.classList.toggle('hidden', !custom);
    if (custom && focus) input.focus();
  }

  function selectedDatabase() {
    return select.value === '__custom__' ? input.value.trim() : select.value;
  }

  function databaseSignature(databases) {
    return databases.map(function(db) {
      return db.path + ':' + (db.cached ? '1' : '0');
    }).join('\n');
  }

  function loadDatabases() {
    fetch('/api/databases')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var databases = data.databases || [];
        var signature = databaseSignature(databases);
        if (signature !== lastSignature) {
          var previous = select.value;
          select.innerHTML = '';
          databases.forEach(function(db) {
            var option = document.createElement('option');
            option.value = db.path;
            option.textContent = db.name + (db.cached ? '  [cached]' : '');
            option.title = db.cached
              ? db.path + ' (cached ' + (db.cached_at || '') + ')'
              : db.path;
            select.appendChild(option);
          });
          var custom = document.createElement('option');
          custom.value = '__custom__';
          custom.textContent = 'Custom path...';
          select.appendChild(custom);
          var keep = Array.prototype.some.call(
            select.options, function(o) { return o.value === previous; });
          if (previous && keep) select.value = previous;
          else if (databases.length) select.value = databases[0].path;
          else select.value = '__custom__';
          lastSignature = signature;
        }
        updateCustom(false);
      })
      .catch(function() {
        if (!select.options.length) {
          select.innerHTML = '<option value="__custom__">Custom path...</option>';
          select.value = '__custom__';
          updateCustom(false);
        }
      });
  }

  select.addEventListener('change', function() { updateCustom(true); });

  btn.addEventListener('click', function() {
    var db = selectedDatabase();
    if (!db) {
      setStatus(select.value === '__custom__'
        ? 'Enter a database path.' : 'Select a database.', true);
      (select.value === '__custom__' ? input : select).focus();
      return;
    }
    btn.disabled = true;
    setStatus('Starting analysis...', false);
    window.ENTRA_ANALYSIS.start(db, function(text, failed) {
      setStatus(text, failed);
      if (failed) btn.disabled = false;
    }, cacheEl ? cacheEl.checked : true);
  });

  document.addEventListener('DOMContentLoaded', function() {
    var toggle = document.getElementById('reanalyze-btn');
    var wrap = document.getElementById('analysis-start-wrap');
    if (!toggle || !wrap) return;
    toggle.addEventListener('click', function() {
      var nowHidden = wrap.classList.toggle('hidden');
      toggle.classList.toggle('active', !nowHidden);
      if (!nowHidden) {
        loadDatabases();
        var databaseSelect = document.getElementById('analysis-db-select');
        if (databaseSelect) databaseSelect.focus();
        wrap.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    });
  });

  document.addEventListener('app:view', function(e) {
    if (e.detail === 'analysis') loadDatabases();
  });
  loadDatabases();
  setInterval(function() {
    if (!document.hidden) loadDatabases();
  }, 3000);
})();
</script>"""
