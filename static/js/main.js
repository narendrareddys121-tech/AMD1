/* PhishShield AI — main.js */

/* ─── Session Timeout Warning ─── */
(function () {
  const WARNING_BEFORE_MS = 5 * 60 * 1000;  // warn 5 min before expiry
  const SESSION_MS = 30 * 60 * 1000;        // 30-min session
  const warningEl = document.getElementById('session-warning');
  const countdownEl = document.getElementById('session-countdown');

  if (!warningEl || !countdownEl) return;

  let warningShown = false;
  let remaining = WARNING_BEFORE_MS;

  // Start warning countdown once shown
  function startCountdown() {
    const tick = setInterval(() => {
      remaining -= 1000;
      if (remaining <= 0) {
        clearInterval(tick);
        window.location.href = window.PHISHSHIELD_LOGIN_URL || '/login';
        return;
      }
      const m = Math.floor(remaining / 60000).toString().padStart(2, '0');
      const s = Math.floor((remaining % 60000) / 1000).toString().padStart(2, '0');
      countdownEl.textContent = `${m}:${s}`;
    }, 1000);
  }

  // Show warning 5 min before session expires
  setTimeout(() => {
    warningEl.style.display = 'block';
    warningShown = true;
    startCountdown();
  }, SESSION_MS - WARNING_BEFORE_MS);

  // Reset on user activity
  ['mousemove', 'keypress', 'click', 'scroll'].forEach(evt => {
    document.addEventListener(evt, () => {
      if (!warningShown) return;
      // Activity detected: hide warning, reset
      warningEl.style.display = 'none';
      warningShown = false;
      remaining = WARNING_BEFORE_MS;
    }, { passive: true });
  });
})();

/* ─── Flash auto-dismiss ─── */
document.querySelectorAll('.flash').forEach(el => {
  setTimeout(() => {
    el.style.transition = 'opacity 0.5s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 500);
  }, 6000);
});

/* ─── Password strength meter (standalone pages) ─── */
function updateStrengthMeter(password, barId, labelId) {
  const bar   = document.getElementById(barId);
  const label = document.getElementById(labelId);
  if (!bar || !label) return;

  const checks = [
    password.length >= 8,
    /[A-Z]/.test(password),
    /[a-z]/.test(password),
    /\d/.test(password),
    /[!@#$%^&*(),.?":{}|<>]/.test(password),
  ];
  const score = checks.filter(Boolean).length;

  const levels = [
    { w: '0%',   color: 'transparent', text: '' },
    { w: '20%',  color: '#FF4444',     text: 'Very Weak' },
    { w: '40%',  color: '#FF8C00',     text: 'Weak' },
    { w: '60%',  color: '#FFD700',     text: 'Fair' },
    { w: '80%',  color: '#00BFFF',     text: 'Strong' },
    { w: '100%', color: '#39FF14',     text: 'Very Strong 💪' },
  ];

  bar.style.width      = levels[score].w;
  bar.style.background = levels[score].color;
  label.textContent    = levels[score].text;
  label.style.color    = levels[score].color;
}

/* ─── Toggle password visibility ─── */
function togglePassword(fieldId) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  field.type = field.type === 'password' ? 'text' : 'password';
}

/* ─── CSRF helper for fetch requests ─── */
function getCsrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

/* ─── Animated number counter ─── */
function animateCount(el, target, duration = 1200) {
  const start = performance.now();
  const from  = parseInt(el.textContent, 10) || 0;
  const step  = (now) => {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(from + (target - from) * eased);
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// Animate all stat numbers on page load
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-count]').forEach(el => {
    animateCount(el, parseInt(el.dataset.count, 10));
  });
});

/* ─── Smooth score bar animation ─── */
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.score-fill').forEach(bar => {
    const target = bar.style.width;
    bar.style.width = '0%';
    setTimeout(() => { bar.style.width = target; }, 200);
  });
});

/* ─── File drag & drop helpers ─── */
const dropZone = document.getElementById('drop-zone');
if (dropZone) {
  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drag-active');
    dropZone.style.borderColor = 'var(--neon-blue)';
    dropZone.style.background  = 'rgba(0,217,255,0.04)';
  });
  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-active');
    dropZone.style.borderColor = 'var(--glass-border)';
    dropZone.style.background  = '';
  });
}

/* ─── Copy to clipboard helper ─── */
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(() => { btn.textContent = orig; }, 2000);
  });
}

/* ─── Auto-focus first input in forms ─── */
document.addEventListener('DOMContentLoaded', () => {
  const firstInput = document.querySelector('form input:not([type=hidden])');
  if (firstInput && !firstInput.closest('#drop-zone')) firstInput.focus();
});
