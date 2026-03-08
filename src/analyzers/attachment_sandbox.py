"""
AttachmentSandboxAnalyzer: Analyze attachments using sandboxing and YARA rules.
Classifies files by magic bytes and submits to sandbox for dynamic analysis.
"""
import logging
from typing import Optional

from src.models import AnalyzerResult, AttachmentObject, AttachmentRisk

logger = logging.getLogger(__name__)


class AttachmentSandboxAnalyzer:
    """
    Analyze email attachments using multiple techniques.

    Capabilities:
    - Magic byte classification (executable, document, archive, etc.)
    - Sandbox submission (HybridAnalysis, AnyRun, JoeSandbox)
    - YARA rule scanning
    - Archive content analysis
    - Macro detection
    - Nested file analysis
    """

    # Magic byte signatures for file type detection
    FILE_SIGNATURES = {
        "executable": {
            b"MZ": "PE executable (Windows)",
            b"\x7fELF": "ELF executable (Linux)",
            b"\xca\xfe\xba\xbe": "Mach-O executable (macOS)",
        },
        "document": {
            b"%PDF": "PDF",
            b"PK\x03\x04": "Office document (docx, xlsx, etc.)",
            b"\xd0\xcf\x11\xe0": "Office 97-2003 (doc, xls, etc.)",
            b"{\x5c\x72\x74": "RTF document",
        },
        "archive": {
            b"PK\x03\x04": "ZIP archive",
            b"Rar!": "RAR archive",
            b"\x1f\x8b\x08": "GZIP archive",
            b"7z\xbc\xaf": "7z archive",
        },
        "script": {
            b"#!": "Script file",
            b"MZ": "Batch/Script executable",
        },
        "image": {
            b"\x89PNG": "PNG image",
            b"\xff\xd8\xff": "JPEG image",
            b"GIF8": "GIF image",
        },
    }

    def __init__(
        self,
        sandbox_client: Optional[object] = None,
        yara_engine: Optional[object] = None,
    ):
        """
        Initialize attachment sandbox analyzer with dependency injection.

        Args:
            sandbox_client: Sandbox submission client (HybridAnalysis, AnyRun, JoeSandbox)
            yara_engine: YARA rule engine for signature scanning
        """
        self.sandbox_client = sandbox_client
        self.yara_engine = yara_engine

    def _classify_by_magic_bytes(self, content: bytes) -> tuple[str, str]:
        """
        Classify file type by magic bytes.

        Args:
            content: File content bytes

        Returns:
            Tuple of (file_category, description)
        """
        for category, signatures in self.FILE_SIGNATURES.items():
            for signature, description in signatures.items():
                if content.startswith(signature):
                    return category, description

        return "unknown", "Unknown file type"

    def _calculate_file_risk(
        self,
        attachment: AttachmentObject,
        file_category: str,
    ) -> tuple[float, str]:
        """
        Calculate risk score based on file characteristics.

        Args:
            attachment: Attachment object
            file_category: File category from magic byte analysis

        Returns:
            Tuple of (risk_score, reason)
        """
        risk_score = 0.0
        reasons = []

        # File extension analysis
        filename_lower = attachment.filename.lower()

        # High-risk extensions
        dangerous_extensions = [
            ".exe", ".com", ".bat", ".cmd", ".scr", ".vbs", ".js",
            ".msi", ".dll", ".sys", ".pif", ".pge", ".ade", ".adp",
            ".app", ".bas", ".crt", ".csh", ".fxp", ".lnk", ".mda",
            ".mdb", ".mde", ".mdt", ".mdw", ".mht", ".mhtml", ".ops",
            ".pcd", ".prg", ".ps1", ".ps2", ".psc1", ".psc2", ".pst",
            ".sct", ".shb", ".shs", ".tmp", ".vb", ".wsh", ".wsf",
        ]

        if any(filename_lower.endswith(ext) for ext in dangerous_extensions):
            risk_score = max(risk_score, 0.8)
            reasons.append("dangerous_extension")

        # Suspicious patterns in filename
        suspicious_patterns = [
            "invoice", "receipt", "payment", "urgent", "confirm",
            "resume", "application", "scan", "document"
        ]

        if any(pattern in filename_lower for pattern in suspicious_patterns):
            risk_score = max(risk_score, 0.3)
            reasons.append("suspicious_filename")

        # File size analysis
        if attachment.size_bytes == 0:
            risk_score = max(risk_score, 0.5)
            reasons.append("zero_size")
        elif attachment.size_bytes > 10 * 1024 * 1024:  # > 10 MB
            risk_score = max(risk_score, 0.3)
            reasons.append("unusually_large")

        # Archive analysis
        if attachment.is_archive:
            risk_score = max(risk_score, 0.5)
            reasons.append("is_archive")

        # Macro analysis
        if attachment.has_macros:
            risk_score = max(risk_score, 0.7)
            reasons.append("contains_macros")

        # File category-based risk
        if file_category == "executable":
            risk_score = max(risk_score, 0.9)
            reasons.append("executable_file")
        elif file_category == "script":
            risk_score = max(risk_score, 0.7)
            reasons.append("script_file")
        elif file_category == "archive":
            if "nested_files" not in reasons:
                risk_score = max(risk_score, 0.5)
                reasons.append("archive_file")

        # Nested files analysis
        if attachment.nested_files:
            risk_score = max(risk_score, 0.6)
            reasons.append(f"nested_files_count_{len(attachment.nested_files)}")

        # Content type mismatch
        if attachment.content_type and not attachment.magic_type:
            if "application" in attachment.content_type and file_category == "unknown":
                risk_score = max(risk_score, 0.4)
                reasons.append("content_type_mismatch")

        return risk_score, ",".join(reasons)

    async def _submit_to_sandbox(self, attachment: AttachmentObject) -> tuple[float, float, dict]:
        """
        Submit attachment to sandbox for dynamic analysis.

        Args:
            attachment: Attachment object to analyze

        Returns:
            Tuple of (risk_score, confidence, details)
        """
        if not self.sandbox_client:
            return 0.0, 0.0, {}

        try:
            submission = await self.sandbox_client.submit(
                attachment.content,
                attachment.filename,
            )

            submission_id = submission.get("submission_id")
            if not submission_id:
                return 0.0, 0.0, {"submission_error": "no_submission_id"}

            # Poll for results (in production, this would be async)
            results = await self.sandbox_client.get_results(submission_id)

            risk_score = 0.0
            confidence = 0.5

            # Parse sandbox results
            verdict = results.get("verdict", "undetected")
            if verdict == "malicious":
                risk_score = 0.95
                confidence = 1.0
            elif verdict == "suspicious":
                risk_score = 0.6
                confidence = 0.8
            elif verdict == "benign":
                risk_score = 0.05
                confidence = 0.9

            details = {
                "submission_id": submission_id,
                "verdict": verdict,
                "detected_by": results.get("detected_by", 0),
                "behaviors": results.get("behaviors", []),
                "extracted_files": results.get("extracted_files", []),
                "contacted_urls": results.get("contacted_urls", []),
                "dns_requests": results.get("dns_requests", []),
            }

            return risk_score, confidence, {"sandbox_results": details}

        except Exception as e:
            logger.warning(f"Sandbox submission failed: {e}")
            return 0.0, 0.0, {"sandbox_error": str(e)}

    async def _scan_with_yara(self, content: bytes) -> tuple[float, float, dict]:
        """
        Scan attachment with YARA rules.

        Args:
            content: File content bytes

        Returns:
            Tuple of (risk_score, confidence, details)
        """
        if not self.yara_engine:
            return 0.0, 0.0, {}

        try:
            matches = await self.yara_engine.scan(content)

            if not matches:
                return 0.0, 0.9, {"yara_matches": []}

            risk_score = 0.0
            details = {
                "yara_matches": []
            }

            for match in matches:
                rule_name = match.get("rule", "unknown")
                severity = match.get("severity", "medium")

                details["yara_matches"].append({
                    "rule": rule_name,
                    "severity": severity,
                })

                # Risk mapping by severity
                if severity == "critical":
                    risk_score = max(risk_score, 0.95)
                elif severity == "high":
                    risk_score = max(risk_score, 0.8)
                elif severity == "medium":
                    risk_score = max(risk_score, 0.5)
                elif severity == "low":
                    risk_score = max(risk_score, 0.2)

            confidence = 0.9 if risk_score > 0.5 else 0.7

            return risk_score, confidence, {"yara": details}

        except Exception as e:
            logger.warning(f"YARA scanning failed: {e}")
            return 0.0, 0.0, {"yara_error": str(e)}

    async def analyze(self, attachments: list[AttachmentObject]) -> AnalyzerResult:
        """
        Analyze email attachments for malware and suspicious content.

        Args:
            attachments: List of attachment objects to analyze

        Returns:
            AnalyzerResult with risk score and confidence
        """
        analyzer_name = "attachment_sandbox"

        try:
            if not attachments:
                return AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.0,
                    confidence=1.0,
                    details={"message": "no_attachments"},
                )

            attachment_results: dict[str, dict] = {}
            max_risk_score = 0.0
            max_confidence = 0.0

            for attachment in attachments:
                try:
                    # Classify by magic bytes
                    file_category, file_desc = self._classify_by_magic_bytes(
                        attachment.content
                    )

                    # Calculate static risk
                    static_risk, static_reason = self._calculate_file_risk(
                        attachment, file_category
                    )

                    # Sandbox analysis (if available)
                    sandbox_risk, sandbox_conf, sandbox_details = await self._submit_to_sandbox(
                        attachment
                    )

                    # YARA scanning (if available)
                    yara_risk, yara_conf, yara_details = await self._scan_with_yara(
                        attachment.content
                    )

                    # Combine scores: max across all techniques
                    per_attachment_risk = max(static_risk, sandbox_risk, yara_risk)
                    per_attachment_confidence = max(
                        0.7,  # Static always at least 0.7 confidence
                        sandbox_conf,
                        yara_conf,
                    )

                    # Determine verdict
                    if per_attachment_risk >= 0.8:
                        verdict = AttachmentRisk.MALICIOUS
                    elif per_attachment_risk >= 0.5:
                        verdict = AttachmentRisk.SUSPICIOUS
                    elif per_attachment_risk >= 0.2:
                        verdict = AttachmentRisk.SUSPICIOUS
                    else:
                        verdict = AttachmentRisk.BENIGN if sandbox_risk == 0.0 else AttachmentRisk.UNKNOWN

                    attachment_results[attachment.filename] = {
                        "risk_score": per_attachment_risk,
                        "confidence": per_attachment_confidence,
                        "verdict": verdict.value,
                        "static_analysis": {
                            "file_category": file_category,
                            "file_description": file_desc,
                            "risk_score": static_risk,
                            "reasons": static_reason,
                            "has_macros": attachment.has_macros,
                            "is_archive": attachment.is_archive,
                            "size_bytes": attachment.size_bytes,
                        },
                        "sandbox": sandbox_details,
                        "yara": yara_details,
                    }

                    max_risk_score = max(max_risk_score, per_attachment_risk)
                    max_confidence = max(max_confidence, per_attachment_confidence)

                except Exception as e:
                    logger.error(f"Error analyzing attachment {attachment.filename}: {e}")
                    attachment_results[attachment.filename] = {
                        "error": str(e),
                    }

            logger.info(
                f"Attachment sandbox analysis complete: "
                f"attachments={len(attachments)}, "
                f"risk={max_risk_score:.2f}, "
                f"confidence={max_confidence:.2f}"
            )

            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=max_risk_score,
                confidence=max_confidence,
                details={
                    "attachment_count": len(attachments),
                    "attachments_analyzed": attachment_results,
                },
            )

        except Exception as e:
            logger.error(f"Attachment sandbox analysis failed: {e}")
            return AnalyzerResult(
                analyzer_name=analyzer_name,
                risk_score=0.0,
                confidence=0.0,
                details={},
                errors=[str(e)],
            )
