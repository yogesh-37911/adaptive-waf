/**
 * dashboard.js — Real-time polling, Chart.js graphs, live feed
 */

'use strict';

// ── Chart instances ──────────────────────────────────────────────────────────
let rlChart, distChart, timelineChart;
let feedPaused = false;
let feedCount  = 0;

// ── Chart defaults ───────────────────────────────────────────────────────────
Chart.defaults.color            = '#6b7a99';
Chart.defaults.borderColor      = 'rgba(255,255,255,0.06)';
Chart.defaults.font.family      = "'Segoe UI', system-ui, sans-serif";
Chart.defaults.plugins.legend.labels.boxWidth = 10;

const CYBER_GREEN = '#00ff88';
const CYBER_BLUE  = '#00d4ff';
const CYBER_RED   = '#ff3860';
const CYBER_YELLOW= '#ffc107';

// ── Initialise on load ───────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initRLChart();
  initDistChart();
  initTimelineChart();
  initGauge();

  // Poll every 2.5 s
  pollAll();
  setInterval(pollAll, 2500);
});

async function pollAll() {
  await Promise.allSettled([
    pollStats(),
    pollLiveFeed(),
    pollRLRewards(),
    pollAttackDist(),
    pollTimeline(),
    pollRecentAttacks(),
  ]);
}

// ── KPI polling ─────────────────────────────────────────────────────────────
async function pollStats() {
  const d = await safeFetch('/api/stats');
  if (!d) return;
  setKPI('kpi-total',       d.total);
  setKPI('kpi-blocked',     d.blocked);
  setKPI('kpi-allowed',     d.allowed);
  setKPI('kpi-attacks',     d.attacks);
  setKPI('kpi-rl-steps',    d.rl_steps);
  setKPI('kpi-blocked-ips', d.blocked_ips);
  setText('dash-epsilon',   typeof d.rl_epsilon === 'number' ? d.rl_epsilon.toFixed(4) : '—');
  setText('dash-reward',    typeof d.rl_avg_reward === 'number' ? d.rl_avg_reward.toFixed(4) : '—');
  setText('dash-rules',     d.active_rules);
  updateGauge(Math.round(d.sensitivity * 100));
}

function setKPI(id, val) {
  const el = document.getElementById(id);
  if (el && el.textContent != val) {
    el.textContent = val;
    el.classList.add('kpi-flash');
    setTimeout(() => el.classList.remove('kpi-flash'), 600);
  }
}

// ── Live Feed ────────────────────────────────────────────────────────────────
async function pollLiveFeed() {
  if (feedPaused) return;
  const rows = await safeFetch('/api/live-feed');
  if (!rows || !Array.isArray(rows)) return;

  const container = document.getElementById('live-feed');
  if (!container) return;

  // Remove placeholder
  const placeholder = container.querySelector('.feed-placeholder');
  if (placeholder) placeholder.remove();

  // Only add new rows (track last id)
  const lastId = parseInt(container.dataset.lastId || '0');
  const newRows = rows.filter(r => r.id > lastId);
  if (!newRows.length) return;

  container.dataset.lastId = String(Math.max(...newRows.map(r => r.id)));
  feedCount += newRows.length;
  setText('feed-count', `${feedCount} requests`);

  newRows.reverse().forEach(row => {
    const line = buildFeedLine(row);
    container.insertBefore(line, container.firstChild);
  });

  // Keep max 60 lines
  while (container.children.length > 60) container.removeChild(container.lastChild);
}

function buildFeedLine(row) {
  const div = document.createElement('div');
  div.className = 'feed-line';
  const badgeClass = row.action === 'block' ? 'feed-block' : row.action === 'challenge' ? 'feed-challenge' : 'feed-allow';
  const typeColor  = row.attack_type !== 'none' && row.attack_type ? `badge-${row.attack_type}` : '';

  div.innerHTML = `
    <span class="feed-ts">${row.timestamp.slice(11,19)}</span>
    <span class="feed-ip">${row.ip}</span>
    <span class="feed-method">${row.method}</span>
    <span class="feed-path">${escHtml(row.path)}</span>
    ${row.attack_type && row.attack_type !== 'none'
      ? `<span class="attack-badge ${typeColor}">${row.attack_type.toUpperCase()}</span>` : ''}
    <span class="feed-score">${row.score.toFixed(2)}</span>
    <span class="feed-badge ${badgeClass}">${row.action.toUpperCase()}</span>
    ${row.is_sim ? '<span class="feed-badge" style="background:rgba(0,212,255,0.15);color:#00d4ff">SIM</span>' : ''}
  `;
  return div;
}

function toggleFeed() {
  feedPaused = !feedPaused;
  document.getElementById('feed-toggle').textContent = feedPaused ? 'Resume' : 'Pause';
}

// ── RL Reward Chart ──────────────────────────────────────────────────────────
function initRLChart() {
  const ctx = document.getElementById('rlRewardChart');
  if (!ctx) return;
  rlChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        { label: 'Reward',     data: [], borderColor: CYBER_GREEN, backgroundColor: 'rgba(0,255,136,0.05)', borderWidth: 1.5, pointRadius: 0, tension: 0.4, yAxisID: 'y' },
        { label: 'Cumulative', data: [], borderColor: CYBER_BLUE,  backgroundColor: 'rgba(0,212,255,0.05)', borderWidth: 1.5, pointRadius: 0, tension: 0.4, yAxisID: 'y1', borderDash: [5,3] },
        { label: 'Loss',       data: [], borderColor: CYBER_RED,   backgroundColor: 'transparent',          borderWidth: 1,   pointRadius: 0, tension: 0.4, yAxisID: 'y2', borderDash: [2,4] },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: true,
      animation: { duration: 300 },
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { position: 'top' }, tooltip: { backgroundColor: 'rgba(8,12,20,0.9)' } },
      scales: {
        x:  { ticks: { maxTicksLimit: 8, maxRotation: 0 }, grid: { display: false } },
        y:  { position: 'left',  grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { maxTicksLimit: 5 } },
        y1: { position: 'right', grid: { display: false }, ticks: { maxTicksLimit: 5 } },
        y2: { display: false },
      },
    },
  });
}

async function pollRLRewards() {
  const d = await safeFetch('/api/rl-rewards');
  if (!d || !rlChart) return;
  const labels = d.labels.map(l => l.slice(11,19));
  rlChart.data.labels              = labels;
  rlChart.data.datasets[0].data    = d.rewards;
  rlChart.data.datasets[1].data    = d.cumulative;
  rlChart.data.datasets[2].data    = d.losses;
  rlChart.update('none');
}

// ── Attack Distribution Chart ─────────────────────────────────────────────────
function initDistChart() {
  const ctx = document.getElementById('attackDistChart');
  if (!ctx) return;
  distChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: [
      '#ff3860','#ffdd57','#ff8c42','#ffa500','#cc80ff','#ff6b6b','#64b4ff','#00ff88'
    ], borderWidth: 0, hoverOffset: 8 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right', labels: { padding: 12 } },
        tooltip: { backgroundColor: 'rgba(8,12,20,0.9)' },
      },
    },
  });
}

async function pollAttackDist() {
  const d = await safeFetch('/api/attack-dist');
  if (!d || !distChart) return;
  distChart.data.labels            = d.labels;
  distChart.data.datasets[0].data  = d.counts;
  distChart.update('none');
}

// ── Timeline Chart ───────────────────────────────────────────────────────────
function initTimelineChart() {
  const ctx = document.getElementById('timelineChart');
  if (!ctx) return;
  timelineChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [
        { label: 'Total',   data: [], backgroundColor: 'rgba(0,212,255,0.25)', borderColor: CYBER_BLUE,  borderWidth: 1 },
        { label: 'Blocked', data: [], backgroundColor: 'rgba(255,56,96,0.35)', borderColor: CYBER_RED,   borderWidth: 1 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 400 },
      plugins: { legend: { position: 'top' } },
      scales: {
        x: { grid: { display: false }, ticks: { maxTicksLimit: 10, maxRotation: 0 } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true },
      },
    },
  });
}

async function pollTimeline() {
  const d = await safeFetch('/api/timeline');
  if (!d || !timelineChart) return;
  timelineChart.data.labels              = d.labels.map(l => l.slice(11));
  timelineChart.data.datasets[0].data    = d.total;
  timelineChart.data.datasets[1].data    = d.blocked;
  timelineChart.update('none');
}

// ── Gauge ────────────────────────────────────────────────────────────────────
let gaugeValue = 50;

function initGauge() {
  const slider = document.getElementById('sens-slider');
  if (slider) slider.addEventListener('input', e => updateSensitivity(e.target.value));
  drawGauge(gaugeValue);
}

function updateGauge(pct) {
  gaugeValue = pct;
  const slider = document.getElementById('sens-slider');
  if (slider) slider.value = pct;
  setText('gauge-value', pct + '%');
  drawGauge(pct);
}

function drawGauge(pct) {
  const canvas = document.getElementById('sensitivityGauge');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  const cx = W / 2, cy = H * 0.9, r = Math.min(W, H * 1.8) * 0.42;
  const startA = Math.PI, endA = 0;
  const fillA  = startA + (endA - startA) * (pct / 100);

  // Background arc
  ctx.beginPath(); ctx.arc(cx, cy, r, Math.PI, 0);
  ctx.lineWidth = 12; ctx.strokeStyle = 'rgba(255,255,255,0.07)'; ctx.stroke();

  // Fill arc
  const color = pct > 70 ? '#ff3860' : pct > 45 ? '#ffc107' : '#00ff88';
  ctx.beginPath(); ctx.arc(cx, cy, r, Math.PI, fillA);
  ctx.lineWidth = 12; ctx.strokeStyle = color;
  ctx.lineCap = 'round'; ctx.stroke();
}

function updateSensitivity(val) {
  updateGauge(parseInt(val));
  clearTimeout(window._sensDebounce);
  window._sensDebounce = setTimeout(() => setSens(val), 500);
}

async function setSens(pct) {
  updateGauge(parseInt(pct));
  await fetch('/api/firewall/sensitivity', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ level: pct / 100 }),
  });
}

// ── Recent Attacks polling ───────────────────────────────────────────────────
async function pollRecentAttacks() {
  const attacks = await safeFetch('/api/recent-attacks');
  if (!attacks) return;
  const list = document.getElementById('recent-attacks-list');
  if (!list || !attacks.length) return;

  list.innerHTML = attacks.slice(0, 8).map(a => `
    <div class="attack-row severity-${a.severity}">
      <div class="attack-info">
        <span class="attack-badge badge-${a.type}">${a.type.toUpperCase()}</span>
        <code class="text-muted small">${a.ip}</code>
      </div>
      <div class="attack-meta">
        <span class="${a.blocked ? 'text-danger' : 'text-warning'}">
          ${a.blocked ? '⊘ BLOCKED' : '⚠ PASSED'}
        </span>
        <span class="text-muted small">${a.score.toFixed(2)}</span>
      </div>
    </div>
  `).join('');
}

// ── Helpers ──────────────────────────────────────────────────────────────────
async function safeFetch(url) {
  try {
    const r = await fetch(url);
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escHtml(str) {
  return String(str).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
