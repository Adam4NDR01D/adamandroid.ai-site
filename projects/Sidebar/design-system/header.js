/* ============================================================
   AdamAndroid Design System — Header behavior
   v1.0  2026-06-15

   Drives the dynamic bits of the two-line header. Pure vanilla,
   no dependencies. Include once per page (defer or end of body):
     <script src="/design-system/header.js" defer></script>

   Opt-in via data attributes — nothing runs unless present:

   Date box:
     <div class="date-pill" data-date-box></div>
       → "MON · JUN 15 · 2026" (3-letter weekday, month + day, year)

   Countdown:
     <span class="countdown" data-countdown="2026-08-01"
           data-countdown-label="AUG 1 GO-LIVE"></span>
       → "AUG 1 GO-LIVE · 47 DAYS"  (adds .urgent at <= 14 days)

   Freshness status (green = fresh, yellow > 24h, red > 72h / missing):
     <span class="status" data-status data-updated="2026.06.15.18:04">
       <span class="status-dot"></span>
       <span class="status-label"></span>
     </span>
       → label becomes "UPDATED 2026.06.15.18:04"

   Theme toggle (persists across visits):
     <span class="theme-toggle" data-theme-toggle>☀ / ☾</span>
   ============================================================ */
(function () {
  var WK = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'];
  var MO = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];

  function fmtDate(d) {
    return WK[d.getDay()] + ' · ' + MO[d.getMonth()] + ' ' + d.getDate() + ' · ' + d.getFullYear();
  }

  // Accepts "YYYY.MM.DD.HH:MM", "YYYY.MM.DD", or any Date.parse-able string
  function parseStamp(s) {
    var m = s.match(/(\d{4})\.(\d{2})\.(\d{2})(?:\.(\d{2}):(\d{2}))?/);
    if (m) return new Date(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0)).getTime();
    var p = Date.parse(s);
    return isNaN(p) ? null : p;
  }

  function initTheme() {
    try {
      if (localStorage.getItem('adamos-theme') === 'light') {
        document.documentElement.classList.add('light-mode');
      }
    } catch (e) {}
  }

  function run() {
    // Date box
    document.querySelectorAll('[data-date-box]').forEach(function (el) {
      el.textContent = fmtDate(new Date());
    });

    // Countdown
    document.querySelectorAll('[data-countdown]').forEach(function (el) {
      var target = parseStamp(el.getAttribute('data-countdown'));
      if (target == null) return;
      var days = Math.ceil((target - Date.now()) / 86400000);
      var label = el.getAttribute('data-countdown-label') || 'GO-LIVE';
      el.textContent = label + ' · ' + days + ' DAY' + (days === 1 ? '' : 'S');
      if (days <= 14) el.classList.add('urgent');
    });

    // Freshness status
    document.querySelectorAll('[data-status]').forEach(function (el) {
      var dot = el.querySelector('.status-dot');
      var lab = el.querySelector('.status-label');
      var raw = el.getAttribute('data-updated');
      var t = raw ? parseStamp(raw) : null;
      if (dot) { dot.classList.remove('stale', 'error'); }
      if (t == null) {
        if (dot) dot.classList.add('error');
        if (lab) lab.textContent = 'NO DATA';
        return;
      }
      var hrs = (Date.now() - t) / 3600000;
      var cls = hrs < 24 ? null : (hrs < 72 ? 'stale' : 'error');
      if (dot && cls) dot.classList.add(cls);
      if (lab) lab.textContent = 'UPDATED ' + raw;
    });

    // Theme toggle — moon in dark mode, sun in light mode
    document.querySelectorAll('[data-theme-toggle]').forEach(function (el) {
      function paint() {
        el.innerHTML = document.documentElement.classList.contains('light-mode')
          ? '☀️'
          : '🌙';
      }
      paint();
      el.addEventListener('click', function () {
        var light = document.documentElement.classList.toggle('light-mode');
        try { localStorage.setItem('adamos-theme', light ? 'light' : 'dark'); } catch (e) {}
        paint();
      });
    });
  }

  initTheme();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run);
  } else {
    run();
  }
})();
