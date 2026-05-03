#!/usr/bin/env python3
"""Update or verify the vendored Chart.js browser asset."""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
VENDOR_DIR = ROOT / "static" / "vendor"
README = VENDOR_DIR / "README.md"
ASSETS = ("chart.umd.js", "chart.umd.js.map")


README_TEMPLATE = """Vendored browser assets used by the dashboard.

Update process:
1. Run `python scripts/vendor_chartjs.py --version VERSION`.
2. Run `python scripts/vendor_chartjs.py --check`.
3. Run `python scripts/dashboard_browser_check.py`.
4. Commit `static/vendor/chart.umd.js`, `static/vendor/chart.umd.js.map`,
   and this README together.

`chart.umd.js`
- Library: Chart.js {version}
- Source: https://cdn.jsdelivr.net/npm/chart.js@{version}/dist/chart.umd.js
- SHA256: {js_hash}
- License: MIT, retained in the bundled file header.

`chart.umd.js.map`
- Source: https://cdn.jsdelivr.net/npm/chart.js@{version}/dist/chart.umd.js.map
- SHA256: {map_hash}

The dashboard serves this file from `/static/vendor/chart.umd.js` so the
graphing code works with the project's `script-src 'self'` CSP and does not
depend on a public CDN at runtime.
"""


def _read_current_version() -> str:
    text = README.read_text(encoding="utf-8")
    match = re.search(r"Library: Chart\.js ([0-9]+\.[0-9]+\.[0-9]+)", text)
    if not match:
        raise RuntimeError("could not find current Chart.js version in static/vendor/README.md")
    return match.group(1)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _download(version: str, filename: str) -> bytes:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("version must look like MAJOR.MINOR.PATCH")
    if filename not in ASSETS:
        raise ValueError(f"unexpected Chart.js asset: {filename}")
    url = f"https://cdn.jsdelivr.net/npm/chart.js@{version}/dist/{filename}"
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "cdn.jsdelivr.net":
        raise ValueError(f"unexpected download URL: {url}")
    with urllib.request.urlopen(url, timeout=30) as response:  # nosec B310
        if response.status != 200:
            raise RuntimeError(f"{url} returned HTTP {response.status}")
        return response.read()


def update(version: str) -> None:
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    for filename in ASSETS:
        (VENDOR_DIR / filename).write_bytes(_download(version, filename))

    js_hash = _sha256(VENDOR_DIR / "chart.umd.js")
    map_hash = _sha256(VENDOR_DIR / "chart.umd.js.map")
    README.write_text(
        README_TEMPLATE.format(version=version, js_hash=js_hash, map_hash=map_hash),
        encoding="utf-8",
    )
    print(f"Updated Chart.js {version}")
    print(f"  chart.umd.js     {js_hash}")
    print(f"  chart.umd.js.map {map_hash}")


def check() -> None:
    version = _read_current_version()
    text = README.read_text(encoding="utf-8")
    errors: list[str] = []

    expected = {
        "chart.umd.js": re.search(r"`chart\.umd\.js`.*?SHA256: ([A-F0-9]{64})", text, re.S),
        "chart.umd.js.map": re.search(r"`chart\.umd\.js\.map`.*?SHA256: ([A-F0-9]{64})", text, re.S),
    }
    for filename, match in expected.items():
        path = VENDOR_DIR / filename
        if not path.exists():
            errors.append(f"missing {path}")
            continue
        if not match:
            errors.append(f"README missing SHA256 for {filename}")
            continue
        actual = _sha256(path)
        documented = match.group(1)
        if actual != documented:
            errors.append(f"{filename} hash mismatch: README={documented} actual={actual}")

    dashboard = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
    if "/static/vendor/chart.umd.js" not in dashboard:
        errors.append("dashboard does not reference /static/vendor/chart.umd.js")
    if "cdn.jsdelivr" in dashboard:
        errors.append("dashboard references a CDN Chart.js URL")

    js_header = (VENDOR_DIR / "chart.umd.js").read_text(encoding="utf-8", errors="ignore")[:300]
    if f"Chart.js v{version}" not in js_header:
        errors.append(f"chart.umd.js header does not mention Chart.js v{version}")

    if errors:
        raise RuntimeError("; ".join(errors))
    print(f"Chart.js vendor check passed for {version}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Update or verify vendored Chart.js assets.")
    parser.add_argument("--version", help="Download and vendor this Chart.js version.")
    parser.add_argument("--check", action="store_true", help="Verify README hashes and dashboard reference.")
    args = parser.parse_args()

    try:
        if args.version:
            update(args.version)
        if args.check or not args.version:
            check()
    except Exception as exc:
        print(f"Chart.js vendor check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
