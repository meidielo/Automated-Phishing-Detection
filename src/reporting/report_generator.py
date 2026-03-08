"""
Report generation for phishing analysis results.
Produces JSON and human-readable HTML reports with full detail breakdown.
"""
import json
import logging
import base64
from datetime import datetime
from io import BytesIO
from typing import Optional

import qrcode
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from src.models import PipelineResult, Verdict, ExtractedURL


logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates JSON and human-readable reports from pipeline results."""

    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize report generator.

        Args:
            template_dir: Directory containing Jinja2 templates.
                         Defaults to './templates'
        """
        if template_dir is None:
            template_dir = "./templates"

        try:
            self.env = Environment(loader=FileSystemLoader(template_dir))
        except Exception as e:
            logger.warning(f"Could not load templates from {template_dir}: {e}")
            self.env = None

    def generate_json(self, result: PipelineResult) -> dict:
        """
        Generate JSON-serializable report from pipeline result.

        Args:
            result: PipelineResult from the analysis pipeline.

        Returns:
            Dictionary containing structured report data.
        """
        # Analyzer breakdown
        analyzer_breakdown = {}
        for analyzer_name, analyzer_result in result.analyzer_results.items():
            analyzer_breakdown[analyzer_name] = {
                "risk_score": analyzer_result.risk_score,
                "confidence": analyzer_result.confidence,
                "details": analyzer_result.details,
                "errors": analyzer_result.errors,
            }

        # Defang URLs for safe reporting
        defanged_urls = []
        for url_obj in result.extracted_urls:
            defanged_urls.append({
                "original": url_obj.url,
                "defanged": self._defang_url(url_obj.url),
                "source": url_obj.source.value,
                "source_detail": url_obj.source_detail,
                "resolved_url": url_obj.resolved_url,
                "redirect_chain": url_obj.redirect_chain,
            })

        report = {
            "email_id": result.email_id,
            "timestamp": result.timestamp.isoformat(),
            "verdict": result.verdict.value,
            "overall_score": result.overall_score,
            "overall_confidence": result.overall_confidence,
            "reasoning": result.reasoning,
            "analyzer_breakdown": analyzer_breakdown,
            "extracted_urls": defanged_urls,
            "iocs": result.iocs,
        }

        return report

    def generate_human_readable(self, result: PipelineResult) -> str:
        """
        Generate human-readable HTML report using Jinja2 template.

        Args:
            result: PipelineResult from the analysis pipeline.

        Returns:
            HTML string containing formatted report.

        Raises:
            ValueError: If template environment not initialized.
        """
        if self.env is None:
            raise ValueError("Template environment not initialized")

        try:
            template = self.env.get_template("report.html")
        except TemplateNotFound:
            logger.warning("report.html template not found, using fallback")
            return self._generate_fallback_report(result)

        # Prepare template context
        context = self._prepare_template_context(result)

        # Render template
        html = template.render(context)
        return html

    def _prepare_template_context(self, result: PipelineResult) -> dict:
        """Prepare data context for template rendering."""
        # Extract header details
        headers = result.iocs.get("headers", {})
        header_details = {
            "spf": headers.get("spf_pass"),
            "dkim": headers.get("dkim_pass"),
            "dmarc": headers.get("dmarc_pass"),
            "from_reply_to_match": not headers.get("from_reply_to_mismatch", False),
            "display_name_spoofing": headers.get("display_name_spoofing", False),
            "suspicious_received_chain": headers.get("suspicious_received_chain", False),
        }

        # Prepare defanged URLs
        defanged_urls = [
            {
                "original": url.url,
                "defanged": self._defang_url(url.url),
                "source": url.source.value,
                "resolved": url.resolved_url,
            }
            for url in result.extracted_urls
        ]

        # QR codes from IOCs
        qr_codes = result.iocs.get("qr_codes", [])
        qr_code_images = []
        for qr_data in qr_codes:
            if "decoded_content" in qr_data:
                img_base64 = self._generate_qr_image_base64(qr_data.get("raw_image", b""))
                qr_code_images.append({
                    "decoded": qr_data.get("decoded_content"),
                    "source": qr_data.get("source"),
                    "image": img_base64,
                })

        # Score breakdown visualization
        analyzer_scores = []
        for analyzer_name, analyzer_result in result.analyzer_results.items():
            analyzer_scores.append({
                "name": analyzer_name,
                "score": analyzer_result.risk_score,
                "confidence": analyzer_result.confidence,
                "bar_width": int(analyzer_result.risk_score * 100),
            })

        # Verdict styling
        verdict_colors = {
            Verdict.CLEAN: "#28a745",
            Verdict.SUSPICIOUS: "#ffc107",
            Verdict.LIKELY_PHISHING: "#fd7e14",
            Verdict.CONFIRMED_PHISHING: "#dc3545",
        }

        return {
            "email_id": result.email_id,
            "timestamp": result.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "verdict": result.verdict.value,
            "verdict_color": verdict_colors.get(result.verdict, "#999"),
            "overall_score": round(result.overall_score, 3),
            "overall_confidence": round(result.overall_confidence, 3),
            "reasoning": result.reasoning,
            "header_details": header_details,
            "defanged_urls": defanged_urls,
            "qr_codes": qr_code_images,
            "analyzer_scores": analyzer_scores,
            "raw_headers": result.iocs.get("raw_headers", ""),
        }

    def _generate_fallback_report(self, result: PipelineResult) -> str:
        """Generate simple HTML report if template not available."""
        json_data = self.generate_json(result)

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Phishing Analysis Report - {result.email_id}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .verdict {{ font-size: 24px; font-weight: bold; margin: 10px 0; }}
                .clean {{ color: #28a745; }}
                .suspicious {{ color: #ffc107; }}
                .likely-phishing {{ color: #fd7e14; }}
                .confirmed-phishing {{ color: #dc3545; }}
                .score-bar {{ background-color: #e9ecef; height: 20px; border-radius: 3px; overflow: hidden; }}
                .score-fill {{ background-color: #0d6efd; height: 100%; }}
                .section {{ margin: 20px 0; }}
                .analyzer-result {{ margin: 10px 0; padding: 10px; background-color: #f8f9fa; border-left: 4px solid #0d6efd; }}
                pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Phishing Detection Report</h1>
                <p><strong>Email ID:</strong> {result.email_id}</p>
                <p><strong>Analysis Time:</strong> {json_data['timestamp']}</p>
                <div class="verdict {result.verdict.value.lower().replace('_', '-')}">
                    Verdict: {result.verdict.value}
                </div>
            </div>

            <div class="section">
                <h2>Score Breakdown</h2>
                <p><strong>Overall Score:</strong> {json_data['overall_score']:.3f}</p>
                <p><strong>Overall Confidence:</strong> {json_data['overall_confidence']:.3f}</p>
                <div class="score-bar">
                    <div class="score-fill" style="width: {json_data['overall_score'] * 100}%"></div>
                </div>
            </div>

            <div class="section">
                <h2>Analyzer Results</h2>
                {self._generate_analyzer_html(json_data)}
            </div>

            <div class="section">
                <h2>Extracted URLs (Defanged)</h2>
                {self._generate_urls_html(json_data)}
            </div>

            <div class="section">
                <h2>Reasoning</h2>
                <p>{result.reasoning}</p>
            </div>

            <div class="section">
                <h2>Raw Data</h2>
                <pre>{json.dumps(json_data, indent=2)}</pre>
            </div>
        </body>
        </html>
        """
        return html

    def _generate_analyzer_html(self, json_data: dict) -> str:
        """Generate HTML for analyzer results section."""
        html = ""
        for analyzer_name, result in json_data.get("analyzer_breakdown", {}).items():
            bar_width = int(result["risk_score"] * 100)
            html += f"""
            <div class="analyzer-result">
                <strong>{analyzer_name}</strong><br>
                Score: {result['risk_score']:.3f} | Confidence: {result['confidence']:.3f}
                <div class="score-bar" style="margin-top: 5px;">
                    <div class="score-fill" style="width: {bar_width}%"></div>
                </div>
            </div>
            """
        return html

    def _generate_urls_html(self, json_data: dict) -> str:
        """Generate HTML for extracted URLs section."""
        if not json_data.get("extracted_urls"):
            return "<p>No URLs extracted.</p>"

        html = "<ul>"
        for url_obj in json_data["extracted_urls"]:
            html += f"""
            <li>
                <strong>Defanged:</strong> <code>{url_obj['defanged']}</code><br>
                <strong>Source:</strong> {url_obj['source']}<br>
            </li>
            """
        html += "</ul>"
        return html

    @staticmethod
    def _defang_url(url: str) -> str:
        """
        Defang URL for safe display in reports.

        Args:
            url: URL to defang.

        Returns:
            Defanged URL with [.] instead of . and hxxp instead of http.
        """
        if not isinstance(url, str):
            return str(url)

        # Replace http:// with hxxp://
        url = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
        # Replace dots with [.]
        url = url.replace(".", "[.]")
        return url

    @staticmethod
    def _generate_qr_image_base64(image_data: bytes) -> str:
        """
        Convert QR code image bytes to base64 data URI.

        Args:
            image_data: Raw image bytes.

        Returns:
            Base64 data URI string suitable for HTML img src.
        """
        if not image_data:
            return ""

        try:
            base64_data = base64.b64encode(image_data).decode("utf-8")
            return f"data:image/png;base64,{base64_data}"
        except Exception as e:
            logger.error(f"Error encoding QR image: {e}")
            return ""

    @staticmethod
    def generate_qr_code(data: str) -> bytes:
        """
        Generate QR code image as PNG bytes.

        Args:
            data: Data to encode in QR code.

        Returns:
            PNG image bytes.
        """
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            img_bytes = BytesIO()
            img.save(img_bytes, format="PNG")
            img_bytes.seek(0)
            return img_bytes.getvalue()
        except Exception as e:
            logger.error(f"Error generating QR code: {e}")
            return b""
