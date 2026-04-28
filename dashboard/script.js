// ── State ─────────────────────────────────────────────────────────────────────
let alerts = [];
let blockedIPs = new Set();
let timelineChart = null;

// ── Fetch ─────────────────────────────────────────────────────────────────────
async function fetchAlerts() {
  try {
    const res = await fetch('/alerts');
    if (!res.ok) return;
    alerts = await res.json();
    render();
    document.getElementById('last-update').textContent =
      'UPDATED ' + new Date().toLocaleTimeString();
  } catch (e) {
    console.error('Fetch failed:', e);
  }
}

// ── Render all ────────────────────────────────────────────────────────────────
function render() {
  const attacks   = alerts.filter(a => a.attack_type !== 'Benign').length;
  const blocked   = alerts.filter(a => a.block_status && a.block_status !== 'none').length;
  const lastScore = alerts.length ? alerts[alerts.length - 1].anomaly_score : null;

  document.getElementById('stat-total').textContent   = alerts.length;
  document.getElementById('stat-attacks').textContent = attacks;
  document.getElementById('stat-blocked').textContent = blocked;
  document.getElementById('stat-score').textContent   = lastScore !== null ? lastScore.toFixed(1) : '—';

  blockedIPs = new Set(
    alerts
      .filter(a => a.block_status === 'permanent' || a.block_status === 'temporary')
      .map(a => a.src_ip)
  );

  renderSidebar();
  renderTimeline();
  renderTable();
}

// ── Sidebar: blocked IPs ──────────────────────────────────────────────────────
function renderSidebar() {
  const container = document.getElementById('blocked-list');
  if (blockedIPs.size === 0) {
    container.innerHTML = '<span class="no-blocks">NO ACTIVE BLOCKS</span>';
    return;
  }

  container.innerHTML = [...blockedIPs].map(ip => {
    const latest    = [...alerts].reverse().find(a => a.src_ip === ip);
    const blockType = latest ? latest.block_status : 'temporary';
    const attack    = latest ? (latest.attack_type || '—') : '—';
    const badgeCls  = blockType === 'permanent' ? 'badge-perm' : 'badge-temp';
    const badgeTxt  = blockType.toUpperCase();

    return `<div class="block-card">
      <div class="block-ip">${ip}</div>
      <div class="block-meta">
        <span class="block-attack">${attack}</span>
        <span class="block-type-badge ${badgeCls}">${badgeTxt}</span>
      </div>
      <button class="unblock-btn" onclick="unblockIP('${ip}')">UNBLOCK</button>
    </div>`;
  }).join('');
}

// ── Timeline chart ────────────────────────────────────────────────────────────
function renderTimeline() {
  const buckets = 20;
  const bucketMs = 60 * 1000;
  const now = Date.now();
  const labels = [];
  const data = Array(buckets).fill(0);

  for (let i = buckets - 1; i >= 0; i--) {
    const t = new Date(now - i * bucketMs);
    labels.push(
      t.getHours().toString().padStart(2, '0') + ':' +
      t.getMinutes().toString().padStart(2, '0')
    );
  }

  alerts.forEach(a => {
    if (!a.timestamp) return;
    const ts  = new Date(a.timestamp).getTime();
    const ago = now - ts;
    if (ago < 0 || ago > buckets * bucketMs) return;
    const idx = buckets - 1 - Math.floor(ago / bucketMs);
    if (idx >= 0 && idx < buckets) data[idx]++;
  });

  const ctx = document.getElementById('chart-timeline').getContext('2d');

  if (timelineChart) {
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = data;
    timelineChart.update('none');
    return;
  }

  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data,
        fill: true,
        borderColor: '#88c0d0',
        backgroundColor: 'rgba(136, 192, 208, 0.12)',
        borderWidth: 1.5,
        pointRadius: 0,
        tension: 0.4,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: { label: ctx => `${ctx.parsed.y} alerts` },
          backgroundColor: 'rgba(59, 66, 82, 0.95)',
          borderColor: '#434c5e',
          borderWidth: 1,
          titleColor: '#d8dee9',
          bodyColor: '#eceff4',
          titleFont: { family: 'JetBrains Mono', size: 10 },
          bodyFont:  { family: 'JetBrains Mono', size: 12 },
        }
      },
      scales: {
        x: {
          ticks: { color: '#d8dee9', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 6 },
          grid:  { color: 'rgba(67, 76, 94, 0.6)' },
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#d8dee9', font: { family: 'JetBrains Mono', size: 10 }, stepSize: 1 },
          grid:  { color: 'rgba(67, 76, 94, 0.6)' },
        }
      }
    }
  });
}

// ── Alert table ───────────────────────────────────────────────────────────────
function renderTable() {
  const reversed = [...alerts].reverse();

  if (reversed.length === 0) {
    document.getElementById('table-container').innerHTML =
      '<div class="empty-state"><p>AWAITING TRAFFIC DATA...</p></div>';
    return;
  }

  const rows = reversed.map(a => {
    const score = (a.anomaly_score !== null && a.anomaly_score !== undefined)
                  ? Number(a.anomaly_score) : null;

    const scoreHTML = score !== null
      ? `<div class="score-wrap">
           <span>${score.toFixed(1)}</span>
           <div class="score-bar-bg">
             <div class="score-bar-fill"
                  style="width:${score}%;
                         background:${score >= 70 ? 'var(--danger)' : score >= 40 ? 'var(--warn)' : 'var(--ok)'}">
             </div>
           </div>
         </div>`
      : '<span style="color:var(--text-dim)">—</span>';

    const blockClass = a.block_status === 'permanent' ? 'status-permanent'
                     : a.block_status === 'temporary'  ? 'status-temporary'
                     : 'status-none';
    const blockText  = a.block_status ? a.block_status.toUpperCase() : 'NONE';

    const proto = a.protocol === 6  ? 'TCP'
                : a.protocol === 17 ? 'UDP'
                : a.protocol === 1  ? 'ICMP'
                : (a.protocol ?? '—');

    const ts = a.timestamp ? a.timestamp.replace('T', ' ').slice(0, 19) : '—';

    return `<tr>
      <td class="td-time">${ts}</td>
      <td class="td-ip">${a.src_ip || '—'}</td>
      <td>${a.dst_ip || '—'}</td>
      <td>${proto}</td>
      <td>${badgeHTML(a.attack_type)}</td>
      <td>${scoreHTML}</td>
      <td class="${blockClass}">${blockText}</td>
    </tr>`;
  }).join('');

  document.getElementById('table-container').innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Src IP</th>
          <th>Dst IP</th>
          <th>Proto</th>
          <th>Attack Type</th>
          <th>Anomaly Score</th>
          <th>Block Status</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── Badge helper ──────────────────────────────────────────────────────────────
function badgeHTML(type) {
  if (!type) return '<span class="badge badge-default">UNKNOWN</span>';
  const t = type.toLowerCase();
  const cls = t.includes('ddos')                           ? 'badge-ddos'
            : t.includes('dos')                            ? 'badge-dos'
            : t.includes('portscan') || t.includes('port') ? 'badge-portscan'
            : t.includes('brute')                          ? 'badge-bruteforce'
            : t.includes('benign') || t.includes('normal') ? 'badge-benign'
            : 'badge-default';
  return `<span class="badge ${cls}">${type.toUpperCase()}</span>`;
}

// ── Unblock ───────────────────────────────────────────────────────────────────
async function unblockIP(ip) {
  try {
    const res = await fetch('/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (data.status === 'queued' || data.status === 'already_queued') {
      showToast(`UNBLOCK QUEUED → ${ip}`);
      blockedIPs.delete(ip);
      renderSidebar();
    }
  } catch (e) {
    showToast('ERROR: Could not reach server');
  }
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

// ── Init ──────────────────────────────────────────────────────────────────────
fetchAlerts();
setInterval(fetchAlerts, 5000);
