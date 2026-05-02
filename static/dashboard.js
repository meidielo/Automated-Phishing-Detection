function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

let allEntries = [];
let verdictChart = null;
let trendsChart  = null;
let loadInFlight = false;

const CHART_DEFAULTS = {
  color: '#94a3b8',
  plugins: { legend: { labels: { color: '#94a3b8', font: { size: 12 }, padding: 14 } } },
};

function vc(v) { return (v || '').toLowerCase().replace(/\s+/g, '_'); }

function scoreColor(s) {
  if (s >= 0.8) return cssVar('--v-phishing');
  if (s >= 0.6) return cssVar('--v-likely');
  if (s >= 0.3) return cssVar('--v-suspicious');
  return cssVar('--v-clean');
}

function fmt(ts) {
  if (!ts) return '-';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function countVerdicts(entries) {
  const c = { clean: 0, suspicious: 0, likely_phishing: 0, confirmed_phishing: 0 };
  for (const e of entries) { const k = vc(e.verdict); if (k in c) c[k]++; }
  return c;
}

const VERDICT_META = [
  ['clean', 'Clean'],
  ['suspicious', 'Suspicious'],
  ['likely_phishing', 'Likely phishing'],
  ['confirmed_phishing', 'Confirmed'],
];

function safeDay(value) {
  const day = String(value || '').slice(0, 10);
  return /^\d{4}-\d{2}-\d{2}$/.test(day) ? day : '';
}

function emptyBuckets(days) {
  const buckets = {};
  for (const day of days) buckets[day] = { day, clean: 0, suspicious: 0, likely_phishing: 0, confirmed_phishing: 0 };
  return buckets;
}

function fillBuckets(buckets, entries) {
  for (const e of entries) {
    const day = safeDay(e.timestamp || e.ts);
    const key = vc(e.verdict);
    if (buckets[day] && key in buckets[day]) buckets[day][key]++;
  }
}

function buildTrendBuckets(entries) {
  const today = new Date();
  const recentDays = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    recentDays.push(d.toISOString().slice(0, 10));
  }

  let buckets = emptyBuckets(recentDays);
  fillBuckets(buckets, entries);
  if (Object.values(buckets).some(b => b.clean + b.suspicious + b.likely_phishing + b.confirmed_phishing > 0) || !entries.length) {
    return recentDays.map(day => buckets[day]);
  }

  const dataDays = Array.from(new Set(entries.map(e => safeDay(e.timestamp || e.ts)).filter(Boolean))).sort().slice(-14);
  buckets = emptyBuckets(dataDays);
  fillBuckets(buckets, entries);
  return dataDays.map(day => buckets[day]);
}

function setFallbackVisible(canvasId, fallbackId, showFallback) {
  const canvas = document.getElementById(canvasId);
  const fallback = document.getElementById(fallbackId);
  if (canvas) canvas.hidden = showFallback;
  if (fallback) fallback.hidden = !showFallback;
}

function renderFallbackCharts(entries) {
  setFallbackVisible('verdictChart', 'verdictFallback', true);
  setFallbackVisible('trendsChart', 'trendsFallback', true);

  const c = countVerdicts(entries);
  renderVerdictLegend(c);
  const total = Math.max(1, entries.length);
  const verdictFallback = document.getElementById('verdictFallback');
  if (verdictFallback) {
    verdictFallback.replaceChildren();
    for (const [key, label] of VERDICT_META) {
      const value = c[key] || 0;
      const width = Math.max(2, Math.round((value / total) * 100));
      const row = el('div', 'fallback-row');
      row.appendChild(el('span', '', label));
      const track = el('span', 'fallback-track');
      const fill = el('span', 'fallback-fill ' + key);
      fill.style.width = width + '%';
      track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(el('strong', '', String(value)));
      verdictFallback.appendChild(row);
    }
  }

  const trendFallback = document.getElementById('trendsFallback');
  if (trendFallback) {
    trendFallback.replaceChildren();
    const buckets = buildTrendBuckets(entries);
    const maxTotal = Math.max(1, ...buckets.map(b => b.clean + b.suspicious + b.likely_phishing + b.confirmed_phishing));
    const bars = el('div', 'trend-bars');
    for (const b of buckets) {
      const totalForDay = b.clean + b.suspicious + b.likely_phishing + b.confirmed_phishing;
      const height = Math.max(totalForDay ? 8 : 4, Math.round((totalForDay / maxTotal) * 170));
      const day = el('div', 'trend-day');
      const stack = el('div', 'trend-stack');
      stack.title = b.day + ': ' + totalForDay;
      stack.style.height = height + 'px';
      for (const [key] of VERDICT_META) {
        const value = b[key] || 0;
        if (!value) continue;
        const seg = el('span', 'trend-seg ' + key);
        seg.style.height = Math.max(8, Math.round((value / totalForDay) * height)) + 'px';
        stack.appendChild(seg);
      }
      day.appendChild(stack);
      day.appendChild(el('span', 'trend-label', b.day.slice(5).replace('-', '/')));
      bars.appendChild(day);
    }
    trendFallback.appendChild(bars);

    const legend = el('div', 'trend-legend');
    for (const [key, label] of VERDICT_META) {
      const item = el('span', 'legend-key');
      item.appendChild(el('span', 'legend-dot trend-seg ' + key));
      item.appendChild(document.createTextNode(label));
      legend.appendChild(item);
    }
    trendFallback.appendChild(legend);
  }
}

function renderVerdictLegend(counts) {
  const legend = document.getElementById('verdictLegend');
  if (!legend) return;

  const total = VERDICT_META.reduce((sum, item) => sum + (counts[item[0]] || 0), 0);
  legend.replaceChildren();
  for (const [key, label] of VERDICT_META) {
    const value = counts[key] || 0;
    const percent = total ? Math.round((value / total) * 100) : 0;
    const row = el('div', 'verdict-legend-row ' + key);
    row.appendChild(el('span', 'verdict-legend-swatch'));
    row.appendChild(el('span', 'verdict-legend-label', label));
    const metric = el('span', 'verdict-legend-value');
    metric.appendChild(document.createTextNode(String(value)));
    metric.appendChild(el('span', 'verdict-legend-percent', ' / ' + percent + '%'));
    row.appendChild(metric);
    legend.appendChild(row);
  }
}

// ── Charts ────────────────────────────────────────────────────────────────────
function initCharts() {
  if (!window.Chart) {
    console.warn('Chart.js unavailable; using fallback dashboard charts');
    return;
  }
  const verdictCanvas = document.getElementById('verdictChart');
  const trendsCanvas = document.getElementById('trendsChart');
  if (!verdictCanvas || !trendsCanvas) {
    console.warn('Dashboard chart canvases missing; skipping chart initialization');
    return;
  }

  Chart.defaults.color = '#94a3b8';

  try {
    verdictChart = new Chart(verdictCanvas, {
      type: 'doughnut',
      data: {
        labels: ['Clean', 'Suspicious', 'Likely Phishing', 'Confirmed Phishing'],
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: ['#166534','#78350f','#9a3412','#991b1b'],
          borderColor: ['#4ade80','#fbbf24','#fb923c','#f87171'],
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        cutout: '62%',
        plugins: { legend: { display: false } }
      }
    });

    trendsChart = new Chart(trendsCanvas, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          { label: 'Phishing/Likely', data: [], borderColor: '#f87171', backgroundColor: 'rgba(248,113,113,.08)', tension: 0.3, fill: true },
          { label: 'Suspicious',      data: [], borderColor: '#fbbf24', backgroundColor: 'rgba(251,191,36,.06)',  tension: 0.3, fill: true },
          { label: 'Clean',           data: [], borderColor: '#4ade80', backgroundColor: 'rgba(74,222,128,.06)',  tension: 0.3, fill: true },
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#94a3b8', font: { size: 12 }, padding: 14 } } },
        scales: {
          x: { ticks: { color: '#4c4f6b' }, grid: { color: '#1e2130' } },
          y: { beginAtZero: true, ticks: { color: '#4c4f6b', stepSize: 1 }, grid: { color: '#1e2130' },
               title: { display: true, text: 'Emails', color: '#4c4f6b' } }
        }
      }
    });
  } catch (err) {
    console.error('chart init failed', err);
    verdictChart = null;
    trendsChart = null;
  }
}

function updateCharts(entries) {
  if (!verdictChart || !trendsChart) {
    renderFallbackCharts(entries);
    return;
  }
  setFallbackVisible('verdictChart', 'verdictFallback', false);
  setFallbackVisible('trendsChart', 'trendsFallback', false);

  const c = countVerdicts(entries);
  renderVerdictLegend(c);
  verdictChart.data.datasets[0].data = [c.clean, c.suspicious, c.likely_phishing, c.confirmed_phishing];
  verdictChart.update();

  const buckets = buildTrendBuckets(entries);
  trendsChart.data.labels = buckets.map(b => b.day.slice(5));
  trendsChart.data.datasets[0].data = buckets.map(b => b.likely_phishing + b.confirmed_phishing);
  trendsChart.data.datasets[1].data = buckets.map(b => b.suspicious);
  trendsChart.data.datasets[2].data = buckets.map(b => b.clean);
  trendsChart.update();
}

// ── Table ─────────────────────────────────────────────────────────────────────
function renderTable() {
  const filter = document.getElementById('filterVerdict').value;
  let rows = allEntries;
  if (filter) rows = rows.filter(e => vc(e.verdict) === filter);
  rows = rows.slice(0, 100);

  const area = document.getElementById('tableArea');
  if (!rows.length) {
    area.replaceChildren(el('div', 'empty', 'No entries match the selected filter.'));
    return;
  }

  const wrapper = el('div', 'table-scroll');
  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  for (const heading of ['Email ID', 'Verdict', 'Score', 'Confidence', 'Timestamp']) {
    headerRow.appendChild(el('th', '', heading));
  }
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');

  for (const e of rows) {
    const cls   = vc(e.verdict);
    const score = typeof e.overall_score === 'number' ? e.overall_score : (typeof e.score === 'number' ? e.score : null);
    const conf  = typeof e.overall_confidence === 'number' ? e.overall_confidence : null;
    const row = document.createElement('tr');

    const idCell = el('td', 'email-id-cell', (e.email_id || '-').slice(0, 32));
    idCell.title = e.email_id || '';
    row.appendChild(idCell);

    const verdictCell = document.createElement('td');
    verdictCell.appendChild(el('span', 'badge ' + cls, (e.verdict || '-').replace(/_/g, ' ')));
    row.appendChild(verdictCell);

    const scoreCell = el('td', 'score-cell');
    if (score !== null) {
      const wrap = el('div', 'bar-wrap');
      const fill = el('div', 'bar-fill');
      fill.style.width = Math.round(score * 100) + '%';
      fill.style.backgroundColor = scoreColor(score);
      wrap.appendChild(fill);
      scoreCell.appendChild(wrap);
      scoreCell.appendChild(el('span', 'score-value', score.toFixed(2)));
    } else {
      scoreCell.textContent = '-';
    }
    row.appendChild(scoreCell);

    row.appendChild(el('td', 'confidence-cell', conf !== null ? conf.toFixed(2) : '-'));
    row.appendChild(el('td', 'timestamp-cell', fmt(e.timestamp || e.ts)));
    tbody.appendChild(row);
  }

  table.appendChild(tbody);
  wrapper.appendChild(table);
  area.replaceChildren(wrapper);
}

// ── Status section ─────────────────────────────────────────────────────────────
function updateStatus(mon, entries) {
  mon = mon || {};
  const imap = document.getElementById('sImap');
  if (!mon.imap_configured) {
    imap.innerHTML = '<span class="dot grey"></span>Not configured';
  } else if (mon.running) {
    imap.innerHTML = '<span class="dot green pulse"></span>Running';
  } else {
    imap.innerHTML = '<span class="dot red"></span>Stopped';
  }

  const cutoff = new Date(Date.now() - 86400000).toISOString();
  document.getElementById('sLast24').textContent      = entries.filter(e => (e.timestamp||e.ts||'') >= cutoff).length;
  const s = mon.stats || {};
  document.getElementById('sQuarantined').textContent = s.quarantined ?? '–';
  document.getElementById('sErrors').textContent      = s.errors      ?? '–';
  document.getElementById('sTime').textContent        = new Date().toLocaleTimeString();
}

// ── Load ───────────────────────────────────────────────────────────────────────
async function requireJson(response, label) {
  let payload = null;
  try { payload = await response.json(); } catch (err) {}
  if (!response.ok) {
    const detail = payload && (payload.detail || payload.error);
    throw new Error(label + ' failed (' + response.status + ')' + (detail ? ': ' + detail : ''));
  }
  return payload || {};
}

async function loadAll() {
  if (loadInFlight) return;
  loadInFlight = true;
  const btn = document.getElementById('btnRefresh');
  btn.disabled = true; btn.classList.add('loading');

  try {
    const [logRes, monRes] = await Promise.all([
      fetch('/api/monitor/log?limit=500&compact=true'),
      fetch('/api/monitor/stats'),
    ]);
    const log = await requireJson(logRes, 'Activity log');
    const mon = await requireJson(monRes, 'Monitor stats');

    allEntries = (Array.isArray(log.entries) ? log.entries : []).sort((a, b) => {
      return (b.timestamp||b.ts||'').localeCompare(a.timestamp||a.ts||'');
    });

    const c = countVerdicts(allEntries);
    document.getElementById('statTotal').textContent  = allEntries.length;
    document.getElementById('statClean').textContent  = c.clean;
    document.getElementById('statSusp').textContent   = c.suspicious;
    document.getElementById('statLikely').textContent = c.likely_phishing;
    document.getElementById('statPhish').textContent  = c.confirmed_phishing;

    updateCharts(allEntries);
    renderTable();
    updateStatus(mon, allEntries);

    document.getElementById('tsLabel').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (err) {
    document.getElementById('tsLabel').textContent = 'Load failed: ' + err.message;
  } finally {
    btn.disabled = false; btn.classList.remove('loading');
    loadInFlight = false;
  }
}

document.addEventListener('DOMContentLoaded', function() {
  const refresh = document.getElementById('btnRefresh');
  const filter = document.getElementById('filterVerdict');
  if (refresh) refresh.addEventListener('click', loadAll);
  if (filter) filter.addEventListener('change', renderTable);
  initCharts();
  loadAll();
  setInterval(loadAll, 30000);
});
