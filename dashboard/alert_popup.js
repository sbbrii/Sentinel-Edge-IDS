/* ══════════════════════════════════════════════════════════════════════
   alert_popup.js  —  Silent Sentinel IDS  ·  Real-time Alert System
   ──────────────────────────────────────────────────────────────────────
   PUBLIC API
     showAlert(config)  — show popup with optional overrides
       config = {
         title        : string   (default: "⚠ Attack Blocked")
         message      : string   (default: auto from attack_type)
         ip           : string
         attack_type  : string
         anomaly_score: number
         block_status : "permanent" | "temporary"
         timestamp    : string   (ISO)
       }
     hideAlert()  — dismiss popup programmatically

   SOUND
     Web Audio API — no buzzer.mp3 required.
     3 × beep (880 Hz square wave, 480 ms ON / 280 ms OFF).
     AudioContext pre-warmed on first user gesture.
══════════════════════════════════════════════════════════════════════ */

(function (global) {
  'use strict';

  // ── AudioContext (lazy init) ───────────────────────────────────────
  let _audioCtx    = null;
  let _buzzerNodes = [];
  let _audioReady  = false;

  function _ensureAudio() {
    if (_audioCtx) return;
    try {
      _audioCtx   = new (global.AudioContext || global.webkitAudioContext)();
      _audioReady = true;
    } catch (_) {
      _audioReady = false;
    }
  }

  // Pre-warm on first gesture so audio plays immediately on first alert
  ['pointerdown', 'click', 'keydown'].forEach(evt =>
    window.addEventListener(evt, _ensureAudio, { once: false, passive: true })
  );

  // ── Buzzer ────────────────────────────────────────────────────────
  function _playBuzzer() {
    _ensureAudio();
    if (!_audioReady || !_audioCtx) return;

    _stopBuzzer();

    const ctx    = _audioCtx;
    const cycles = 3;
    const onMs   = 480;
    const offMs  = 280;
    const freq   = 880;   // Hz — sharp alarm tone
    const vol    = 0.80;

    const master = ctx.createGain();
    master.gain.setValueAtTime(vol, ctx.currentTime);
    master.connect(ctx.destination);

    let t = ctx.currentTime + 0.02;

    for (let i = 0; i < cycles; i++) {
      const osc = ctx.createOscillator();
      const env = ctx.createGain();

      osc.type            = 'square';
      osc.frequency.value = freq;

      // Smooth envelope to avoid clicks
      env.gain.setValueAtTime(0,   t);
      env.gain.linearRampToValueAtTime(1, t + 0.012);
      env.gain.setValueAtTime(1,   t + onMs / 1000 - 0.012);
      env.gain.linearRampToValueAtTime(0, t + onMs / 1000);

      osc.connect(env);
      env.connect(master);
      osc.start(t);
      osc.stop(t + onMs / 1000);

      _buzzerNodes.push(osc);
      t += (onMs + offMs) / 1000;
    }
  }

  function _stopBuzzer() {
    _buzzerNodes.forEach(n => {
      try { n.stop(); }   catch (_) {}
      try { n.disconnect(); } catch (_) {}
    });
    _buzzerNodes = [];
  }

  // ── State ─────────────────────────────────────────────────────────
  let _isOpen          = false;
  let _dismissTimer    = null;
  let _lastTimestamp   = null;   // ISO string — dedup guard
  const DISMISS_MS     = 6000;

  // ── DOM helpers ───────────────────────────────────────────────────
  const $ = id => document.getElementById(id);

  // ── showAlert(config) ─────────────────────────────────────────────
  function showAlert(cfg) {
    cfg = cfg || {};

    if (_isOpen) return;   // one popup at a time
    _isOpen = true;

    const score      = (cfg.anomaly_score !== null && cfg.anomaly_score !== undefined)
                       ? Number(cfg.anomaly_score) : null;
    const isHigh     = score !== null && score >= 70;
    const isMedium   = score !== null && score >= 40 && score < 70;
    const severity   = isHigh ? 'high' : isMedium ? 'medium' : 'low';

    // ── Populate title & message ──
    const defaultTitle = '⚠ Attack Blocked';
    const defaultMsg   = cfg.attack_type
      ? `A ${cfg.attack_type} attack was detected and blocked by Silent Sentinel.`
      : 'An anomaly was detected and blocked by Silent Sentinel IDS.';

    const titleEl = $('ap-title');
    const msgEl   = $('ap-message');
    if (titleEl) titleEl.textContent = cfg.title   || defaultTitle;
    if (msgEl)   msgEl.textContent   = cfg.message || defaultMsg;

    // ── IP ──
    const ipEl = $('ap-ip');
    if (ipEl) ipEl.textContent = cfg.ip || cfg.src_ip || '—';

    // ── Attack type ──
    const typeEl = $('ap-attack-type');
    if (typeEl) typeEl.textContent = (cfg.attack_type || 'UNKNOWN').toUpperCase();

    // ── Score ──
    const scoreNumEl  = $('ap-score-num');
    const scoreBarEl  = $('ap-score-bar-fill');
    if (scoreNumEl) {
      scoreNumEl.textContent = score !== null ? score.toFixed(1) : '—';
      scoreNumEl.className   = 'ap-score-num '
        + (isHigh ? 'ap-score-high' : isMedium ? 'ap-score-medium' : 'ap-score-low');
    }
    if (scoreBarEl) {
      const pct = score !== null ? Math.min(score, 100) : 0;
      scoreBarEl.style.width      = pct + '%';
      scoreBarEl.style.background = isHigh   ? 'var(--ap-red)'
                                  : isMedium ? 'var(--ap-orange)'
                                  : 'rgba(255,255,255,0.35)';
    }

    // ── Block badge ──
    const blockEl = $('ap-block-badge');
    if (blockEl) {
      const isPerm       = (cfg.block_status || '').toLowerCase() === 'permanent';
      blockEl.textContent = isPerm ? '● PERMANENT' : '● TEMPORARY';
      blockEl.className   = 'ap-badge ' + (isPerm ? 'ap-badge-perm' : 'ap-badge-temp');
    }

    // ── Timestamp ──
    const tsEl = $('ap-timestamp');
    if (tsEl) {
      const ts = cfg.timestamp
        ? new Date(cfg.timestamp).toLocaleTimeString()
        : new Date().toLocaleTimeString();
      tsEl.textContent = ts;
    }

    // ── Apply severity to modal ──
    const modal    = $('ap-modal');
    const backdrop = $('ap-backdrop');
    if (!modal || !backdrop) { _isOpen = false; return; }

    modal.className = severity === 'medium' ? 'ap-severity-medium' : '';

    // ── Reveal backdrop ──
    backdrop.classList.add('ap-visible');

    // ── Shake after entry transition starts ──
    setTimeout(() => modal.classList.add('ap-shake'), 60);
    // Remove shake class so it can fire again on next alert
    setTimeout(() => modal.classList.remove('ap-shake'), 650);

    // ── Countdown timer bar ──
    const timerBar = $('ap-timer-bar');
    if (timerBar) {
      timerBar.style.transition = 'none';
      timerBar.style.transform  = 'scaleX(1)';
      void timerBar.offsetWidth;                            // force reflow
      timerBar.style.transition = `transform ${DISMISS_MS}ms linear`;
      timerBar.style.transform  = 'scaleX(0)';
    }

    // ── Play buzzer (once per alert) ──
    _playBuzzer();

    // ── Auto-dismiss ──
    if (_dismissTimer) clearTimeout(_dismissTimer);
    _dismissTimer = setTimeout(hideAlert, DISMISS_MS);
  }

  // ── hideAlert() ───────────────────────────────────────────────────
  function hideAlert() {
    if (_dismissTimer) { clearTimeout(_dismissTimer); _dismissTimer = null; }
    _stopBuzzer();

    const backdrop = $('ap-backdrop');
    const modal    = $('ap-modal');
    if (backdrop) backdrop.classList.remove('ap-visible');
    if (modal)    modal.className = '';

    const timerBar = $('ap-timer-bar');
    if (timerBar) {
      timerBar.style.transition = 'none';
      timerBar.style.transform  = 'scaleX(1)';
    }

    _isOpen = false;
  }

  // ── Real-time poller ──────────────────────────────────────────────
  // Polls /alerts every 1 s. Triggers popup for NEW blocked attacks only.
  // _lastTimestamp is seeded on first load to avoid popup on page reload.

  async function _poll() {
    try {
      const res = await fetch('/alerts');
      if (!res.ok) return;
      const alerts = await res.json();
      if (!Array.isArray(alerts) || alerts.length === 0) return;

      const latest = alerts[alerts.length - 1];
      const ts     = latest.timestamp || latest.received_at || null;
      if (!ts) return;

      // First run — seed timestamp, no popup
      if (_lastTimestamp === null) {
        _lastTimestamp = ts;
        return;
      }

      if (ts !== _lastTimestamp) {
        _lastTimestamp = ts;

        const isAttack  = latest.attack_type &&
                          latest.attack_type.toLowerCase() !== 'benign';
        const isBlocked = latest.block_status &&
                          latest.block_status !== 'none';

        if (isAttack && isBlocked) {
          showAlert({
            ip:           latest.src_ip,
            attack_type:  latest.attack_type,
            anomaly_score: latest.anomaly_score,
            block_status: latest.block_status,
            timestamp:    latest.timestamp
          });
        }
      }
    } catch (_) { /* silently ignore network errors */ }
  }

  // ── Init ──────────────────────────────────────────────────────────
  function _init() {
    // Wire close button
    const closeBtn   = $('ap-close');
    const dismissBtn = $('ap-dismiss-btn');
    const ackBtn     = $('ap-ack-btn');
    const backdrop   = $('ap-backdrop');

    if (closeBtn)   closeBtn.addEventListener('click',   hideAlert);
    if (dismissBtn) dismissBtn.addEventListener('click', hideAlert);
    if (ackBtn)     ackBtn.addEventListener('click',     hideAlert);

    // Click outside modal to dismiss
    if (backdrop) {
      backdrop.addEventListener('click', e => {
        if (e.target === backdrop) hideAlert();
      });
    }

    // ESC to dismiss
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && _isOpen) hideAlert();
    });

    // Start polling (first call seeds _lastTimestamp)
    _poll();
    setInterval(_poll, 1000);
  }

  // ── Expose public API ─────────────────────────────────────────────
  global.showAlert          = showAlert;
  global.hideAlert          = hideAlert;
  global.showSentinelAlert  = showAlert;   // alias for external callers
  global.__apDemo           = showAlert;   // alias for demo page

  // DOM ready guard
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _init);
  } else {
    _init();
  }

}(window));
