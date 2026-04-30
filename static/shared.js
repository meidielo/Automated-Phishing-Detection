// ── Auth: patch fetch for /api/ calls ─────────────────────────
  (function() {
    function readCookie(name) {
      var parts = document.cookie ? document.cookie.split('; ') : [];
      for (var i = 0; i < parts.length; i++) {
        var pair = parts[i].split('=');
        if (decodeURIComponent(pair[0]) === name) {
          return decodeURIComponent(pair.slice(1).join('='));
        }
      }
      return '';
    }

    var _origFetch = window.fetch;
    window.fetch = function(url, opts) {
      opts = opts || {};
      if (typeof url === 'string' && url.startsWith('/api/')) {
        opts.credentials = opts.credentials || 'same-origin';
        opts.headers = opts.headers || {};
        var method = (opts.method || 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
          var csrf = readCookie('phishdetect_csrf');
          if (csrf) {
            if (opts.headers instanceof Headers) {
              opts.headers.set('X-CSRF-Token', csrf);
            } else {
              opts.headers['X-CSRF-Token'] = csrf;
            }
          }
        }
      }
      return _origFetch.call(window, url, opts).then(function(response) {
        if (response.status === 401 && typeof url === 'string' && url.startsWith('/api/')) {
          window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
        }
        return response;
      });
    };
  })();

  // ── Theme toggle ──────────────────────────────────────────────
  (function() {
    // Default to dark
    var theme = 'dark';
    try { theme = localStorage.getItem('phishdetect-theme') || 'dark'; } catch(e) {}
    document.documentElement.setAttribute('data-theme', theme);

    window.toggleTheme = function() {
      var current = document.documentElement.getAttribute('data-theme') || 'dark';
      var next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('phishdetect-theme', next); } catch(e) {}
      var btn = document.querySelector('.theme-toggle');
      if (btn) btn.textContent = next === 'dark' ? 'Light' : 'Dark';
    };

    document.addEventListener('DOMContentLoaded', function() {
      var nav = document.querySelector('nav');
      if (!nav) return;
      var themeBtn = document.createElement('button');
      themeBtn.className = 'theme-toggle';
      themeBtn.type = 'button';
      themeBtn.textContent = theme === 'dark' ? 'Light' : 'Dark';
      themeBtn.addEventListener('click', window.toggleTheme);
      nav.appendChild(themeBtn);

      var logoutBtn = document.createElement('button');
      logoutBtn.className = 'logout-button';
      logoutBtn.type = 'button';
      logoutBtn.textContent = 'Logout';
      logoutBtn.addEventListener('click', function() {
        fetch('/api/auth/logout', {method: 'POST'})
          .finally(function() {
            window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
          });
      });
      nav.appendChild(logoutBtn);
    });
  })();
