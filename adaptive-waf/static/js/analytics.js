'use strict';
/* analytics.js */
document.addEventListener('DOMContentLoaded', () => {
  initPie(); initTimeline(); initHeatmap();
});
async function initPie() {
  const ctx = document.getElementById('attackPieChart'); if (!ctx) return;
  const data = await get('/api/analytics/attack-types'); if (!data) return;
  new Chart(ctx, {
    type: 'doughnut',
    data: { labels: data.map(d => d.attack_type), datasets: [{ data: data.map(d => d.cnt),
      backgroundColor: ['#ff3860','#ffd700','#ff8c42','#ff6b6b','#cc80ff','#00ff88','#00d4ff','#64b4ff'],
      borderWidth: 0, hoverOffset: 10 }] },
    options: { responsive: true, plugins: { legend: { position: 'right' },
      tooltip: { backgroundColor: 'rgba(8,12,20,0.9)' } } }
  });
}
async function initTimeline() {
  const ctx = document.getElementById('bigTimelineChart'); if (!ctx) return;
  const data = await get('/api/analytics/hourly'); if (!data) return;
  new Chart(ctx, {
    type: 'bar',
    data: { labels: data.map(d => (d.hour||'').slice(11)||d.hour||''),
      datasets: [
        { label: 'Total', data: data.map(d => d.total), backgroundColor: 'rgba(0,212,255,0.3)', borderColor: '#00d4ff', borderWidth: 1 },
        { label: 'Blocked', data: data.map(d => d.blocked), backgroundColor: 'rgba(255,56,96,0.4)', borderColor: '#ff3860', borderWidth: 1 }
      ] },
    options: { responsive: true, scales: { x: { grid: { display: false } }, y: { grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true } } }
  });
}
async function initHeatmap() {
  const ctx = document.getElementById('heatmapChart'); if (!ctx) return;
  const data = await get('/api/analytics/hourly'); if (!data) return;
  const vals = data.map(d => d.blocked || 0);
  const mx = Math.max(...vals, 1);
  new Chart(ctx, {
    type: 'bar',
    data: { labels: data.map(d => (d.hour||'').slice(11)),
      datasets: [{ label: 'Blocked', data: vals,
        backgroundColor: vals.map(v => { const i=v/mx; return `rgba(${Math.round(255*i)},${Math.round(56*(1-i))},96,0.8)`; }),
        borderWidth: 0 }] },
    options: { responsive: true, plugins: { legend: { display: false } },
      scales: { x: { grid: { display: false } }, y: { beginAtZero: true } } }
  });
}
async function get(url) {
  try { const r = await fetch(url); return r.ok ? await r.json() : null; } catch { return null; }
}
