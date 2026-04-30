Vendored browser assets used by the dashboard.

Update process:
1. Run `python scripts/vendor_chartjs.py --version VERSION`.
2. Run `python scripts/vendor_chartjs.py --check`.
3. Run `python scripts/dashboard_browser_check.py`.
4. Commit `static/vendor/chart.umd.js`, `static/vendor/chart.umd.js.map`,
   and this README together.

`chart.umd.js`
- Library: Chart.js 4.4.0
- Source: https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js
- SHA256: 321E3A3FA98DA4AAA957D10BE57CBB514DE0989EED8F9D726B5D05902CD01904
- License: MIT, retained in the bundled file header.

`chart.umd.js.map`
- Source: https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.js.map
- SHA256: 31C257F6358DF2343ED3E208D7200181AD1E08B6264E4673AA0E1B70CE8D33EC

The dashboard serves this file from `/static/vendor/chart.umd.js` so the
graphing code works with the project's `script-src 'self'` CSP and does not
depend on a public CDN at runtime.
