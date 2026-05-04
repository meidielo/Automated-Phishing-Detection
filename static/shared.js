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

    function hasHeader(headers, name) {
      var target = name.toLowerCase();
      if (!headers) return false;
      if (headers instanceof Headers) return headers.has(name);
      return Object.keys(headers).some(function(key) { return key.toLowerCase() === target; });
    }

    function requestPath(url) {
      if (typeof url === 'string') {
        try { return new URL(url, window.location.origin).pathname; } catch(e) { return url; }
      }
      if (url && url.url) {
        try { return new URL(url.url, window.location.origin).pathname; } catch(e) { return url.url; }
      }
      return '';
    }

    var _origFetch = window.fetch;
    window.fetch = function(url, opts) {
      opts = opts || {};
      var path = requestPath(url);
      var isApi = path.startsWith('/api/');
      var isSaasApi = path.startsWith('/api/saas/');
      if (isApi) {
        opts.credentials = opts.credentials || 'same-origin';
        opts.headers = opts.headers || {};
        var method = (opts.method || 'GET').toUpperCase();
        if (!isSaasApi && method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS' && !hasHeader(opts.headers, 'x-csrf-token')) {
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
        if (response.status === 401 && isApi && !isSaasApi) {
          window.location.href = '/admin/login?next=' + encodeURIComponent(window.location.pathname);
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

    function themeIcon(nextTheme) {
      if (nextTheme === 'light') {
        return [
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"',
          ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round"',
          ' aria-hidden="true">',
          '<circle cx="12" cy="12" r="4"></circle>',
          '<path d="M12 2v2"></path>',
          '<path d="M12 20v2"></path>',
          '<path d="m4.93 4.93 1.41 1.41"></path>',
          '<path d="m17.66 17.66 1.41 1.41"></path>',
          '<path d="M2 12h2"></path>',
          '<path d="M20 12h2"></path>',
          '<path d="m6.34 17.66-1.41 1.41"></path>',
          '<path d="m19.07 4.93-1.41 1.41"></path>',
          '</svg>',
        ].join('');
      }
      return [
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"',
        ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round"',
        ' aria-hidden="true">',
        '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"></path>',
        '</svg>',
      ].join('');
    }

    function updateThemeButtons(activeTheme) {
      var nextTheme = activeTheme === 'dark' ? 'light' : 'dark';
      var label = 'Switch to ' + nextTheme + ' mode';
      document.querySelectorAll('.theme-toggle').forEach(function(btn) {
        btn.innerHTML = themeIcon(nextTheme);
        btn.setAttribute('aria-label', label);
        btn.setAttribute('title', label);
      });
    }

    window.toggleTheme = function() {
      var current = document.documentElement.getAttribute('data-theme') || 'dark';
      var next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('phishdetect-theme', next); } catch(e) {}
      updateThemeButtons(next);
    };

    function installFeedback(nav) {
      var previousFocus = null;
      var modal = document.createElement('div');
      modal.className = 'feedback-backdrop';
      modal.id = 'product-feedback-modal';
      modal.setAttribute('role', 'dialog');
      modal.setAttribute('aria-modal', 'true');
      modal.setAttribute('aria-labelledby', 'product-feedback-title');
      modal.innerHTML = [
        '<div class="feedback-modal">',
        '  <div class="feedback-modal-header">',
        '    <div>',
        '      <h2 class="feedback-modal-title" id="product-feedback-title">Send feedback</h2>',
        '      <p class="feedback-modal-subtitle">Report a bug, confusing result, or improvement idea without storing anything on this server.</p>',
        '    </div>',
        '    <button class="feedback-close" type="button" aria-label="Close feedback">&times;</button>',
        '  </div>',
        '  <form class="feedback-form" id="product-feedback-form">',
        '    <div class="feedback-field">',
        '      <label for="product-feedback-category">Type</label>',
        '      <select id="product-feedback-category" name="category">',
        '        <option value="Bug">Bug</option>',
        '        <option value="Confusing result">Confusing result</option>',
        '        <option value="Improvement idea">Improvement idea</option>',
        '        <option value="Security concern">Security concern</option>',
        '      </select>',
        '    </div>',
        '    <div class="feedback-field">',
        '      <label for="product-feedback-message">What happened?</label>',
        '      <textarea id="product-feedback-message" name="message" required></textarea>',
        '    </div>',
        '    <div class="feedback-field">',
        '      <label for="product-feedback-expected">What did you expect?</label>',
        '      <textarea id="product-feedback-expected" name="expected"></textarea>',
        '    </div>',
        '    <div class="feedback-field">',
        '      <label for="product-feedback-contact">Contact email, optional</label>',
        '      <input id="product-feedback-contact" name="contact" type="email" autocomplete="email">',
        '    </div>',
        '    <div class="feedback-privacy">Do not include passwords, API keys, private emails, client data, or payment details. Redact examples before sending.</div>',
        '    <div class="feedback-actions">',
        '      <button class="feedback-secondary" type="button" id="product-feedback-copy">Copy draft</button>',
        '      <button class="feedback-primary" type="submit">Open email draft</button>',
        '    </div>',
        '    <div class="feedback-status" id="product-feedback-status" aria-live="polite"></div>',
        '  </form>',
        '</div>',
      ].join('');
      document.body.appendChild(modal);

      var openBtn = document.createElement('button');
      openBtn.className = 'feedback-button';
      openBtn.id = 'product-feedback-open';
      openBtn.type = 'button';
      openBtn.setAttribute('aria-haspopup', 'dialog');
      openBtn.innerHTML = [
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"',
        ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round"',
        ' aria-hidden="true">',
        '<path d="M21 15a4 4 0 0 1-4 4H8l-5 3V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4z"></path>',
        '</svg>',
        '<span class="feedback-button-text">Feedback</span>',
      ].join('');
      nav.appendChild(openBtn);

      var form = modal.querySelector('#product-feedback-form');
      var closeBtn = modal.querySelector('.feedback-close');
      var copyBtn = modal.querySelector('#product-feedback-copy');
      var messageEl = modal.querySelector('#product-feedback-message');
      var statusEl = modal.querySelector('#product-feedback-status');

      function pageUrl() {
        return window.location.origin + window.location.pathname;
      }

      function feedbackBody() {
        return [
          'Project: PhishAnalyze',
          'Page: ' + pageUrl(),
          'Type: ' + form.category.value,
          '',
          'What happened:',
          form.message.value.trim(),
          '',
          'What I expected:',
          form.expected.value.trim(),
          '',
          'Contact:',
          form.contact.value.trim(),
          '',
          'Privacy reminder: no passwords, API keys, private emails, client data, or payment details.',
        ].join('\n');
      }

      function openModal() {
        previousFocus = document.activeElement;
        modal.classList.add('open');
        openBtn.setAttribute('aria-expanded', 'true');
        statusEl.textContent = '';
        window.setTimeout(function() { messageEl.focus(); }, 0);
      }

      function closeModal() {
        modal.classList.remove('open');
        openBtn.setAttribute('aria-expanded', 'false');
        if (previousFocus && previousFocus.focus) previousFocus.focus();
      }

      openBtn.addEventListener('click', openModal);
      closeBtn.addEventListener('click', closeModal);
      modal.addEventListener('click', function(event) {
        if (event.target === modal) closeModal();
      });
      document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && modal.classList.contains('open')) {
          closeModal();
        }
      });

      copyBtn.addEventListener('click', function() {
        if (!form.message.value.trim()) {
          statusEl.textContent = 'Add a short note first.';
          messageEl.focus();
          return;
        }
        if (!navigator.clipboard || !navigator.clipboard.writeText) {
          statusEl.textContent = 'Clipboard is not available in this browser.';
          return;
        }
        navigator.clipboard.writeText(feedbackBody())
          .then(function() { statusEl.textContent = 'Draft copied.'; })
          .catch(function() { statusEl.textContent = 'Could not copy draft.'; });
      });

      form.addEventListener('submit', function(event) {
        event.preventDefault();
        if (!form.message.value.trim()) {
          statusEl.textContent = 'Add a short note first.';
          messageEl.focus();
          return;
        }
        var subject = 'Feedback: PhishAnalyze - ' + form.category.value;
        var href = 'mailto:meidie@mdpstudio.com.au?subject=' +
          encodeURIComponent(subject) + '&body=' +
          encodeURIComponent(feedbackBody());
        window.location.href = href;
        statusEl.textContent = 'Email draft opened. Review it before sending.';
      });
    }

    function isAnalystPage() {
      return /^\/admin(\/|$)/.test(window.location.pathname);
    }

    function installAnalystLogout(nav) {
      fetch('/api/auth/session', {credentials: 'same-origin'})
        .then(function(response) {
          return response.ok ? response.json() : null;
        })
        .then(function(session) {
          if (!session || !session.auth_enabled || !session.authenticated) return;
          var logoutBtn = document.createElement('button');
          logoutBtn.className = 'logout-button';
          logoutBtn.type = 'button';
          logoutBtn.textContent = 'Logout';
          logoutBtn.addEventListener('click', function() {
            fetch('/api/auth/logout', {method: 'POST'})
              .finally(function() {
                window.location.href = '/admin/login?next=' + encodeURIComponent(window.location.pathname);
              });
          });
          nav.appendChild(logoutBtn);
        })
        .catch(function() {});
    }

    document.addEventListener('DOMContentLoaded', function() {
      var nav = document.querySelector('nav');
      if (!nav) return;
      installFeedback(nav);
      var themeBtn = document.createElement('button');
      themeBtn.className = 'theme-toggle';
      themeBtn.type = 'button';
      themeBtn.addEventListener('click', window.toggleTheme);
      nav.appendChild(themeBtn);
      updateThemeButtons(document.documentElement.getAttribute('data-theme') || 'dark');

      if (isAnalystPage()) installAnalystLogout(nav);
    });
  })();
