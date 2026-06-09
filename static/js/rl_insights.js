'use strict';
// rl_insights.js

document.addEventListener('DOMContentLoaded', () => {
  loadCharts();
  loadComparison();
  loadActionDist();
});

async function loadCharts() {
  const data = await safeFetch('/api/rl/performance');
  if (!data) return;
  const ctx1 = document.getElementById('rewardCurveChart');
  if (ctx1) {
    new Chart(ctx1, {
      type: 'line',
      data: { labels: data.steps, datasets: [{ label: 'Reward', data: data.rewards, borderColor: '#00ff88', backgroundColor: 'rgba(0,255,136,0.05)', borderWidth: 1.5, pointRadius: 0, tension: 0.4 }] },
      options: { responsive: true, plugins: { legend: { display: false } }, scales: { x: { display: false }, y: { grid: { color: 'rgba(255,255,255,0.04)' } } } }
    });
  }
  const ctx2 = document.getElementById('lossCurveChart');
  if (ctx2) {
    new Chart(ctx2, {
      type: 'line',
      data: { labels: data.steps, datasets: [
        { label: 'Loss', data: data.losses, borderColor: '#ff3860', backgroundColor: 'rgba(255,56,96,0.05)', borderWidth: 1.5, pointRadius: 0, tension: 0.4 },
        { label: 'Epsilon', data: data.epsilons, borderColor: '#00d4ff', backgroundColor: 'transparent', borderWidth: 1.5, pointRadius: 0, tension: 0.4, borderDash: [4,3] }
      ]},
      options: { responsive: true, scales: { x: { display: false }, y: { grid: { color: 'rgba(255,255,255,0.04)' } } } }
    });
  }
}

async function loadComparison() {
  const data = await safeFetch('/api/rl/comparison');
  if (!data) return;
  const ctx = document.getElementById('comparisonChart');
  if (!ctx) return;
  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Accuracy', 'FP Rate', 'FN Rate'],
      datasets: [
        { label: 'Static WAF', data: [data.static.accuracy*100, data.static.fp_rate*100, data.static.fn_rate*100], backgroundColor: 'rgba(108,117,125,0.6)', borderColor: '#6c757d', borderWidth: 1 },
        { label: 'RL Adaptive WAF', data: [data.rl.accuracy*100, data.rl.fp_rate*100, data.rl.fn_rate*100], backgroundColor: 'rgba(0,255,136,0.5)', borderColor: '#00ff88', borderWidth: 1 }
      ]
    },
    options: {
      responsive: true,
      scales: { x: { grid: { display: false } }, y: { max: 100, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { callback: v => v + '%' } } },
      plugins: { legend: { position: 'top' } }
    }
  });
}

async function loadActionDist() {
  const data = await safeFetch('/api/rl/action-dist');
  if (!data) return;
  const ctx = document.getElementById('actionDistChart');
  if (!ctx) return;
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: Object.keys(data),
      datasets: [{ data: Object.values(data), backgroundColor: ['#00ff88','#ff3860','#ffd700','#ff8c42','#00d4ff','#cc80ff','#ff6b6b'], borderWidth: 0 }]
    },
    options: { responsive: true, plugins: { legend: { position: 'right' } } }
  });
}

async function explainDecision() {
  const id = document.getElementById('xai-log-id').value;
  if (!id) return;
  const result = document.getElementById('xai-result');
  result.innerHTML = '<div class="text-muted">Loading...</div>';
  const data = await safeFetch(`/api/rl/explain/${id}`);
  if (!data || data.error) { result.innerHTML = '<div class="text-danger">Not found</div>'; return; }
  const qvHtml = data.q_values
    ? Object.entries(data.q_values).map(([a, v]) => `<div class="xai-row"><span>${a}</span><span class="text-muted">${v.toFixed(4)}</span></div>`).join('')
    : '<span class="text-muted">N/A</span>';
  result.innerHTML = `
    <div class="xai-card">
      <div class="xai-row"><span>Action</span><span class="${data.action==='block'?'text-danger':'text-success'}">${(data.action||'').toUpperCase()}</span></div>
      <div class="xai-row"><span>Score</span><span>${data.threat_score}</span></div>
      <div class="xai-row"><span>Attack Type</span><span>${data.attack_type||'none'}</span></div>
      <div class="xai-row"><span>RL Decision</span><span>${data.rl_decision||'—'}</span></div>
      <div class="xai-row"><span>Confidence</span><span>${data.rl_confidence||'—'}</span></div>
      <hr class="border-secondary my-2">
      <div class="text-muted small mb-1"><b>Why:</b> ${data.why_blocked||'—'}</div>
      <div class="text-muted small mb-1"><b>Rules:</b> ${(data.triggered_rules||[]).join(', ')||'none'}</div>
      <hr class="border-secondary my-2">
      <div class="text-muted small mb-1">Q-Values:</div>${qvHtml}
    </div>`;
}

async function safeFetch(url) {
  try { const r = await fetch(url); if (!r.ok) return null; return await r.json(); }
  catch { return null; }
}
