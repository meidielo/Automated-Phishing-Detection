"""
Generate QR code test fixtures programmatically.

This script creates sample QR codes for testing QR code extraction
and analysis components of the phishing detection pipeline.

Usage:
    python tests/fixtures/generate_qr_fixtures.py

Generated files:
    - qr_legitimate_url.png: QR code pointing to trusted domain
    - qr_phishing_url.png: QR code pointing to malicious URL
    - qr_paypal_phishing.png: QR code spoofing PayPal
"""

import os
from pathlib import Path


def generate_qr_fixtures():
    """Generate QR code test fixtures."""
    try:
        import qrcode
        qr_available = True
    except ImportError:
        qr_available = False
        print("Warning: qrcode library not available. Install with: pip install qrcode[pil]")
        return

    fixtures_dir = Path(__file__).parent / "qr_codes"
    fixtures_dir.mkdir(exist_ok=True)

    # Sample 1: Legitimate URL QR code
    if qr_available:
        print("Generating QR code fixtures...")

        # Legitimate URL
        qr_legitimate = qrcode.QRCode(version=1, box_size=10, border=5)
        qr_legitimate.add_data("https://github.com/anthropics/phishing-detection")
        qr_legitimate.make(fit=True)
        img_legitimate = qr_legitimate.make_image(fill_color="black", back_color="white")
        img_legitimate.save(fixtures_dir / "qr_legitimate_url.png")
        print(f"✓ Created {fixtures_dir / 'qr_legitimate_url.png'}")

        # Phishing URL
        qr_phishing = qrcode.QRCode(version=1, box_size=10, border=5)
        qr_phishing.add_data("http://phishing-bank-verify.ru/account/confirm")
        qr_phishing.make(fit=True)
        img_phishing = qr_phishing.make_image(fill_color="black", back_color="white")
        img_phishing.save(fixtures_dir / "qr_phishing_url.png")
        print(f"✓ Created {fixtures_dir / 'qr_phishing_url.png'}")

        # PayPal spoofing QR code
        qr_paypal = qrcode.QRCode(version=1, box_size=10, border=5)
        qr_paypal.add_data("http://paypa1.com/verify-account")
        qr_paypal.make(fit=True)
        img_paypal = qr_paypal.make_image(fill_color="black", back_color="white")
        img_paypal.save(fixtures_dir / "qr_paypal_phishing.png")
        print(f"✓ Created {fixtures_dir / 'qr_paypal_phishing.png'}")

        # URL shortener QR code
        qr_shortener = qrcode.QRCode(version=1, box_size=10, border=5)
        qr_shortener.add_data("https://bit.ly/phishing-link-12345")
        qr_shortener.make(fit=True)
        img_shortener = qr_shortener.make_image(fill_color="black", back_color="white")
        img_shortener.save(fixtures_dir / "qr_shortener_link.png")
        print(f"✓ Created {fixtures_dir / 'qr_shortener_link.png'}")

        print("\nAll QR code fixtures generated successfully!")
    else:
        print("Skipping QR code generation (qrcode library not available)")


def create_placeholder_qr_fixtures():
    """Create placeholder QR code files for testing without qrcode library."""
    fixtures_dir = Path(__file__).parent / "qr_codes"
    fixtures_dir.mkdir(exist_ok=True)

    # Create minimal valid PNG files (1x1 transparent pixel PNG)
    # This allows tests to run without qrcode dependency
    png_minimal = (
        b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00'
        b'\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx'
        b'\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
    )

    qr_files = [
        "qr_legitimate_url.png",
        "qr_phishing_url.png",
        "qr_paypal_phishing.png",
        "qr_shortener_link.png",
    ]

    for qr_file in qr_files:
        file_path = fixtures_dir / qr_file
        file_path.write_bytes(png_minimal)
        print(f"Created placeholder: {file_path}")


if __name__ == "__main__":
    try:
        generate_qr_fixtures()
    except Exception as e:
        print(f"Error generating QR fixtures: {e}")
        print("Creating placeholder fixtures instead...")
        create_placeholder_qr_fixtures()
