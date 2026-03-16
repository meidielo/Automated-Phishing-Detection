"""
Central orchestration of the phishing detection pipeline.
Coordinates extraction, analysis, and decision phases with concurrency control.
"""
import asyncio
import json
import logging
from datetime import datetime
from typing import Optional

from src.models import EmailObject, PipelineResult, Verdict, AnalyzerResult
from src.config import PipelineConfig
from src.scoring.blocklist_allowlist import BlocklistAllowlistChecker, ListCheckResult


logger = logging.getLogger(__name__)


class PhishingPipeline:
    """
    Central coordinator for phishing detection analysis.

    Three-phase architecture:
    1. Extraction (sequential): Parse headers, URLs, QR codes, attachments
    2. Analysis (concurrent): Run all analyzers simultaneously
    3. Decision (sequential): Compute weighted score and verdict
    """

    def __init__(self, config: PipelineConfig, db_session_factory=None):
        """
        Initialize pipeline with configuration.

        Args:
            config: PipelineConfig instance with all API keys and parameters.
            db_session_factory: Optional async session factory for blocklist/allowlist.
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Global semaphore for concurrent API calls
        self.global_semaphore = asyncio.Semaphore(
            config.max_concurrent_analyzers
        )

        # Per-API rate limiters
        self.rate_limiters = {
            "virustotal": asyncio.Semaphore(4),  # 4 concurrent VT requests
            "urlscan": asyncio.Semaphore(2),     # 2 concurrent URLscan requests
            "abuseipdb": asyncio.Semaphore(3),   # 3 concurrent AbuseIPDB requests
            "sandbox": asyncio.Semaphore(config.max_concurrent_browser),
        }

        # Lazy-loaded analyzer instances
        self._analyzers = {}
        self._extractors = {}

        # Blocklist/allowlist checker
        self.list_checker = BlocklistAllowlistChecker(db_session_factory)

    @classmethod
    def from_config(cls, config: PipelineConfig) -> "PhishingPipeline":
        """
        Factory method to create pipeline from config.

        Args:
            config: PipelineConfig instance.

        Returns:
            Initialized PhishingPipeline.
        """
        return cls(config)

    @classmethod
    def from_env(cls) -> "PhishingPipeline":
        """
        Factory method to create pipeline from environment variables.

        Returns:
            Initialized PhishingPipeline.
        """
        config = PipelineConfig.from_env()
        return cls(config)

    async def analyze(self, email: EmailObject) -> PipelineResult:
        """
        Execute full analysis pipeline on email.

        Phases:
        1. Extract URLs, headers, QR codes, attachments (sequential)
        2. Analyze with all analyzers concurrently
        3. Compute verdict from weighted scores

        Args:
            email: EmailObject to analyze.

        Returns:
            PipelineResult with verdict and detailed breakdown.

        Raises:
            TimeoutError: If analysis exceeds pipeline_timeout.
        """
        start_time = datetime.utcnow()

        try:
            # Phase 1: Extraction (sequential)
            self.logger.info(
                f"Phase 1: Extracting IOCs from email {email.email_id}"
            )
            iocs, extracted_urls = await self._phase_extraction(email)

            # Phase 1.5: Blocklist/Allowlist check (fast-path)
            list_result = await self.list_checker.check(email, extracted_urls)
            if list_result.override_verdict is not None:
                self.logger.info(
                    f"Blocklist/allowlist override for {email.email_id}: "
                    f"{list_result.override_verdict.value} — {list_result.override_reason}"
                )
                elapsed_seconds = (datetime.utcnow() - start_time).total_seconds()
                override_score = 1.0 if list_result.override_verdict == Verdict.CONFIRMED_PHISHING else 0.0
                return PipelineResult(
                    email_id=email.email_id,
                    verdict=list_result.override_verdict,
                    overall_score=override_score,
                    overall_confidence=1.0,
                    analyzer_results={},
                    extracted_urls=extracted_urls,
                    iocs=iocs,
                    reasoning=list_result.override_reason,
                    timestamp=datetime.utcnow(),
                )

            # Phase 2: Analysis (concurrent)
            self.logger.info(
                f"Phase 2: Running concurrent analyzers for email {email.email_id}"
            )
            analyzer_results = await asyncio.wait_for(
                self._phase_analysis(email, iocs, extracted_urls),
                timeout=self.config.pipeline_timeout
            )

            # Phase 3: Decision
            self.logger.info(
                f"Phase 3: Computing verdict for email {email.email_id}"
            )
            verdict, overall_score, overall_confidence, reasoning = (
                self._phase_decision(analyzer_results)
            )

            # Log completion
            elapsed_seconds = (datetime.utcnow() - start_time).total_seconds()
            self.logger.info(
                f"Analysis complete for {email.email_id}: "
                f"verdict={verdict.value}, score={overall_score:.3f}, "
                f"elapsed={elapsed_seconds:.2f}s"
            )

            # Structured JSON logging for audit trail
            self._log_analysis_json(
                email.email_id,
                verdict,
                overall_score,
                overall_confidence,
                elapsed_seconds
            )

            return PipelineResult(
                email_id=email.email_id,
                verdict=verdict,
                overall_score=overall_score,
                overall_confidence=overall_confidence,
                analyzer_results=analyzer_results,
                extracted_urls=extracted_urls,
                iocs=iocs,
                reasoning=reasoning,
                timestamp=datetime.utcnow(),
            )

        except TimeoutError as e:
            self.logger.error(f"Pipeline timeout for {email.email_id}:")
            elapsed_seconds = (datetime.utcnow() - start_time).total_seconds()
            return PipelineResult(
                email_id=email.email_id,
                verdict=Verdict.SUSPICIOUS,
                overall_score=0.5,
                overall_confidence=0.0,
                analyzer_results={},
                extracted_urls=[],
                iocs={},
                reasoning=["Analysis timed out; partial result returned."],
                timestamp=datetime.utcnow(),
            )
        except Exception as e:
            self.logger.error(f"Pipeline error for {email.email_id}: {e}", exc_info=True)
            raise

    async def _phase_extraction(
        self, email: EmailObject
    ) -> tuple[dict, list]:
        """
        Phase 1: Extract IOCs from email (sequential).

        Extracts:
        - Email headers (SPF, DKIM, DMARC)
        - URLs from body
        - QR codes from attachments and rendered HTML
        - Attachment classifications

        Args:
            email: EmailObject to extract from.

        Returns:
            Tuple of (IOCs dict, extracted URLs list).
        """
        iocs = {
            "headers": {},
            "raw_headers": json.dumps(dict(email.raw_headers), default=str),
            "malicious_urls": [],
            "malicious_domains": [],
            "malicious_ips": [],
            "file_hashes": {},
            "qr_codes": [],
        }

        extracted_urls = []

        try:
            # Extract header authentication
            if "header_analyzer" not in self._extractors:
                from src.extractors.header_analyzer import HeaderAnalyzer
                self._extractors["header_analyzer"] = HeaderAnalyzer()

            header_analyzer = self._extractors["header_analyzer"]
            header_result = header_analyzer.analyze(email)
            iocs["headers"] = header_result

        except Exception as e:
            self.logger.warning(f"Header extraction failed: {e}")
            iocs["headers"]["error"] = str(e)

        try:
            # Extract URLs from body
            if "url_extractor" not in self._extractors:
                from src.extractors.url_extractor import URLExtractor
                self._extractors["url_extractor"] = URLExtractor()

            url_extractor = self._extractors["url_extractor"]
            extracted_urls = url_extractor.extract_all(
                plaintext=email.body_plain or "",
                html=email.body_html or "",
            )

        except Exception as e:
            self.logger.warning(f"URL extraction failed: {e}")

        try:
            # Extract QR codes from attachments
            qr_codes = await self._extract_qr_codes(email)
            iocs["qr_codes"] = qr_codes
            for qr_url in qr_codes:
                if isinstance(qr_url, str):
                    from src.models import ExtractedURL, URLSource
                    extracted_urls.append(ExtractedURL(
                        url=qr_url,
                        source=URLSource.QR_CODE,
                        source_detail="qr_extraction",
                    ))

        except Exception as e:
            self.logger.warning(f"QR code extraction failed: {e}")

        return iocs, extracted_urls

    async def _phase_analysis(
        self, email: EmailObject, iocs: dict, extracted_urls: list
    ) -> dict[str, AnalyzerResult]:
        """
        Phase 2: Run all analyzers concurrently.

        Each analyzer runs with:
        - Global semaphore limit on concurrent API calls
        - Per-API rate limiting
        - 30s timeout (configurable)
        - Graceful degradation on failure

        Args:
            email: EmailObject to analyze.
            iocs: Extracted IOCs from phase 1.
            extracted_urls: Extracted URLs from phase 1.

        Returns:
            Dictionary of analyzer results keyed by analyzer name.
        """
        # Load all analyzers
        analyzer_tasks = []
        analyzer_names = [
            "header_analysis",
            "url_reputation",
            "domain_intelligence",
            "url_detonation",
            "brand_impersonation",
            "attachment_analysis",
            "nlp_intent",
            "sender_profiling",
        ]

        for analyzer_name in analyzer_names:
            try:
                analyzer = await self._load_analyzer(analyzer_name)
                if analyzer:
                    task = asyncio.create_task(
                        self._run_analyzer_with_limits(
                            analyzer_name, analyzer, email, iocs, extracted_urls
                        )
                    )
                    analyzer_tasks.append((analyzer_name, task))
            except Exception as e:
                self.logger.warning(f"Failed to load analyzer {analyzer_name}: {e}")

        # Run all concurrently with timeouts
        results = {}
        for analyzer_name, task in analyzer_tasks:
            try:
                result = await asyncio.wait_for(
                    task,
                    timeout=self.config.url_detonation_timeout
                    if "detonation" in analyzer_name
                    else 60 if analyzer_name in ("url_reputation", "domain_intelligence")
                    else 15
                )
                results[analyzer_name] = result
                self.logger.debug(
                    f"Analyzer {analyzer_name} completed: score={result.risk_score:.3f}"
                )

                # After url_detonation completes, store screenshots in iocs
                # so brand_impersonation can use them
                if analyzer_name == "url_detonation" and result.details:
                    screenshots_b64 = result.details.get("screenshots", {})
                    if screenshots_b64:
                        import base64
                        iocs["detonation_screenshots"] = {
                            url: base64.b64decode(b64_data)
                            for url, b64_data in screenshots_b64.items()
                        }

            except asyncio.TimeoutError:
                self.logger.warning(f"Analyzer {analyzer_name} timed out")
                results[analyzer_name] = AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.5,
                    confidence=0.0,
                    details={"error": "timeout"},
                    errors=["Analyzer timed out"],
                )
            except Exception as e:
                self.logger.error(f"Analyzer {analyzer_name} failed: {e}")
                results[analyzer_name] = AnalyzerResult(
                    analyzer_name=analyzer_name,
                    risk_score=0.5,
                    confidence=0.0,
                    details={"error": str(e)},
                    errors=[str(e)],
                )

        return results

    async def _run_analyzer_with_limits(
        self, name: str, analyzer, email: EmailObject, iocs: dict, urls: list
    ) -> AnalyzerResult:
        """
        Run analyzer with rate limiting and semaphore.

        Args:
            name: Analyzer name.
            analyzer: Analyzer instance.
            email: EmailObject to analyze.
            iocs: Extracted IOCs.
            urls: Extracted URLs.

        Returns:
            AnalyzerResult.
        """
        async def run_analyzer():
            # Call analyzer with the correct arguments based on its type
            if name == "header_analysis":
                # HeaderAnalyzer.analyze() is synchronous — call without await
                detail = analyzer.analyze(email)
                # Convert HeaderAnalysisDetail → AnalyzerResult
                # Weighted scoring: not all failures are equal
                risk_score = 0.0
                # Auth failures (moderate weight)
                if detail.spf_pass is False:
                    risk_score += 0.15
                if detail.dkim_pass is False:
                    risk_score += 0.15
                if detail.dmarc_pass is False:
                    risk_score += 0.15
                # Reply-To mismatch (HIGH weight — strong phishing indicator)
                if detail.from_reply_to_mismatch:
                    risk_score += 0.30
                # Display name spoofing (moderate-high weight)
                if detail.display_name_spoofing:
                    risk_score += 0.20
                # Envelope mismatch (moderate weight)
                if detail.envelope_from_mismatch:
                    risk_score += 0.15
                # Suspicious received chain (moderate weight)
                if detail.suspicious_received_chain:
                    risk_score += 0.15
                risk_score = min(risk_score, 1.0)
                auth_checks = sum([
                    detail.spf_pass is not None,
                    detail.dkim_pass is not None,
                    detail.dmarc_pass is not None,
                ])
                confidence = 0.5 + (auth_checks / 3.0) * 0.5
                return AnalyzerResult(
                    analyzer_name="header_analysis",
                    risk_score=risk_score,
                    confidence=confidence,
                    details={
                        "spf_pass": detail.spf_pass,
                        "dkim_pass": detail.dkim_pass,
                        "dmarc_pass": detail.dmarc_pass,
                        "from_reply_to_mismatch": detail.from_reply_to_mismatch,
                        "display_name_spoofing": detail.display_name_spoofing,
                        "envelope_from_mismatch": detail.envelope_from_mismatch,
                        "suspicious_received_chain": detail.suspicious_received_chain,
                    },
                )
            elif name == "url_reputation":
                return await analyzer.analyze(urls)
            elif name == "domain_intelligence":
                return await analyzer.analyze(urls)
            elif name == "url_detonation":
                return await analyzer.analyze(urls)
            elif name == "brand_impersonation":
                # Pass email object for content-based analysis + detonation screenshots
                screenshots = iocs.get("detonation_screenshots", {})
                return await analyzer.analyze(
                    email=email,
                    detonation_screenshots=screenshots if screenshots else None,
                    extracted_urls=urls,
                )
            elif name == "attachment_analysis":
                # Extract attachments from email
                attachments = email.attachments if hasattr(email, 'attachments') else []
                return await analyzer.analyze(attachments)
            elif name == "nlp_intent":
                return await analyzer.analyze(email)
            elif name == "sender_profiling":
                return await analyzer.analyze(email)
            else:
                # Fallback: try calling with just email
                return await analyzer.analyze(email)

        async with self.global_semaphore:
            # Apply per-API rate limiter
            api_name = self._get_api_name(name)
            if api_name in self.rate_limiters:
                async with self.rate_limiters[api_name]:
                    return await run_analyzer()
            else:
                return await run_analyzer()

    def _phase_decision(
        self, analyzer_results: dict[str, AnalyzerResult]
    ) -> tuple[Verdict, float, float, str]:
        """
        Phase 3: Compute weighted verdict from analyzer results.

        Uses weights from config.scoring.weights to compute overall score.
        Maps score ranges to verdicts based on config thresholds.

        Args:
            analyzer_results: Dictionary of analyzer results.

        Returns:
            Tuple of (Verdict, overall_score, overall_confidence, reasoning).
        """
        weights = self.config.scoring.weights
        thresholds = self.config.scoring.thresholds

        # Compute weighted score
        total_weight = 0.0
        weighted_sum = 0.0
        confidence_sum = 0.0
        analyzer_details = []

        for analyzer_name, result in analyzer_results.items():
            weight = weights.get(analyzer_name, 0.0)
            if weight > 0:
                # Skip analyzers that produced no data (confidence == 0 means
                # the analyzer couldn't run, e.g. missing API key). Including
                # them with score=0 would artificially drag the average down.
                if result.confidence == 0.0:
                    # Determine the actual reason for zero confidence
                    skip_reason = getattr(result, "skip_reason", None)
                    if not skip_reason:
                        # Infer reason from details
                        details = result.details or {}
                        errors = getattr(result, "errors", None) or []
                        if details.get("message") == "not_implemented":
                            skip_reason = "not implemented yet"
                        elif details.get("message") == "no_clients_configured":
                            skip_reason = "no API key configured"
                        elif details.get("message") == "no_urls_to_analyze":
                            skip_reason = "no URLs found in email"
                        elif errors:
                            skip_reason = f"API error: {errors[0][:100]}"
                        else:
                            skip_reason = "no data returned from services"
                    self.logger.debug(
                        f"Skipping {analyzer_name} in scoring (confidence=0: {skip_reason})"
                    )
                    analyzer_details.append(
                        f"{analyzer_name}: skipped ({skip_reason})"
                    )
                    continue

                weighted_sum += result.risk_score * weight
                confidence_sum += result.confidence * weight
                total_weight += weight

                analyzer_details.append(
                    f"{analyzer_name}: {result.risk_score:.3f} (conf: {result.confidence:.3f})"
                )

        # Normalize over analyzers that actually ran
        if total_weight > 0:
            overall_score = weighted_sum / total_weight
            overall_confidence = confidence_sum / total_weight
        else:
            # No analyzer produced usable data — treat as uncertain
            overall_score = 0.5
            overall_confidence = 0.0

        # Map score to verdict
        verdict = Verdict.CLEAN
        for v in [
            Verdict.CONFIRMED_PHISHING,
            Verdict.LIKELY_PHISHING,
            Verdict.SUSPICIOUS,
            Verdict.CLEAN,
        ]:
            score_range = thresholds.get(v.value, (0.0, 1.0))
            if score_range[0] <= overall_score <= score_range[1]:
                verdict = v
                break

        # Generate reasoning
        reasoning = (
            f"Analyzed with {len(analyzer_results)} analyzers. "
            f"Weighted score: {overall_score:.3f}. "
            f"Verdict: {verdict.value}. "
            f"Analyzer breakdown: {'; '.join(analyzer_details)}"
        )

        return verdict, overall_score, overall_confidence, reasoning

    async def _load_analyzer(self, name: str):
        """
        Lazy-load analyzer instance.

        Args:
            name: Analyzer name.

        Returns:
            Analyzer instance or None if unavailable.
        """
        if name in self._analyzers:
            return self._analyzers[name]

        try:
            if name == "header_analysis":
                from src.extractors.header_analyzer import HeaderAnalyzer
                analyzer = HeaderAnalyzer()
            elif name == "url_reputation":
                from src.analyzers.url_reputation import URLReputationAnalyzer
                from src.analyzers.clients.virustotal import VirusTotalClient
                from src.analyzers.clients.google_safebrowsing import GoogleSafeBrowsingClient
                from src.analyzers.clients.urlscan import URLScanClient
                from src.analyzers.clients.abuseipdb import AbuseIPDBClient
                api = self.config.api
                analyzer = URLReputationAnalyzer(
                    virustotal_client=VirusTotalClient(api.virustotal_key) if api.virustotal_key else None,
                    safe_browsing_client=GoogleSafeBrowsingClient(api.google_safebrowsing_key) if api.google_safebrowsing_key else None,
                    urlscan_client=URLScanClient(api.urlscan_key) if api.urlscan_key else None,
                    abuseipdb_client=AbuseIPDBClient(api.abuseipdb_key) if api.abuseipdb_key else None,
                )
            elif name == "domain_intelligence":
                from src.analyzers.domain_intel import DomainIntelAnalyzer
                from src.analyzers.clients.whois_client import WhoisClient
                analyzer = DomainIntelAnalyzer(whois_client=WhoisClient())
            elif name == "url_detonation":
                # Try loading the real Playwright-based detonation analyzer first,
                # falling back to the stub if Playwright is not installed.
                try:
                    from src.analyzers.url_detonation import URLDetonationAnalyzer as RealDetonator
                    import playwright  # noqa: F401
                    analyzer = RealDetonator(
                        timeout_ms=self.config.url_detonation_timeout * 1000,
                    )
                    self.logger.info("URL detonation: using Playwright-based analyzer")
                except (ImportError, Exception) as _det_err:
                    from src.analyzers.url_detonator import URLDetonationAnalyzer
                    analyzer = URLDetonationAnalyzer(browser_client=None)
                    self.logger.info(f"URL detonation: stub mode ({_det_err})")
            elif name == "brand_impersonation":
                from src.analyzers.brand_impersonation import BrandImpersonationAnalyzer
                analyzer = BrandImpersonationAnalyzer()
            elif name == "attachment_analysis":
                from src.analyzers.attachment_sandbox import AttachmentSandboxAnalyzer
                from src.analyzers.clients.sandbox_client import SandboxClient
                api = self.config.api
                sandbox_providers = {}
                if api.hybrid_analysis_key:
                    sandbox_providers["hybrid_analysis"] = {"api_key": api.hybrid_analysis_key}
                if api.anyrun_key:
                    sandbox_providers["anyrun"] = {"api_key": api.anyrun_key}
                if api.joesandbox_key:
                    sandbox_providers["joesandbox"] = {"api_key": api.joesandbox_key}
                sandbox_client = SandboxClient(sandbox_providers) if sandbox_providers else None
                analyzer = AttachmentSandboxAnalyzer(sandbox_client=sandbox_client)
            elif name == "nlp_intent":
                from src.analyzers.nlp_intent import NLPIntentAnalyzer
                llm_client = None
                if self.config.api.anthropic_key:
                    from src.analyzers.clients.anthropic_client import AnthropicLLMClient
                    llm_client = AnthropicLLMClient(self.config.api.anthropic_key)
                analyzer = NLPIntentAnalyzer(llm_client=llm_client)
            elif name == "sender_profiling":
                from src.analyzers.sender_profiling import SenderProfileAnalyzer
                analyzer = SenderProfileAnalyzer()
            else:
                return None

            self._analyzers[name] = analyzer
            return analyzer

        except Exception as e:
            self.logger.warning(f"Failed to load analyzer {name}: {e}")
            return None

    async def _extract_qr_codes(self, email: EmailObject) -> list:
        """
        Extract QR codes from attachments and render HTML.

        Args:
            email: EmailObject to extract QR codes from.

        Returns:
            List of extracted QR code data.
        """
        qr_codes = []

        try:
            from src.extractors.qr_decoder import QRDecoder
            qr_decoder = QRDecoder()
            qr_codes = await qr_decoder.decode_all(email)
        except Exception as e:
            self.logger.warning(f"QR code extraction failed: {e}")

        return qr_codes

    @staticmethod
    def _get_api_name(analyzer_name: str) -> str:
        """Map analyzer name to API name for rate limiting."""
        mapping = {
            "url_reputation": "virustotal",
            "domain_intelligence": "abuseipdb",
            "url_detonation": "sandbox",
            "attachment_analysis": "sandbox",
        }
        return mapping.get(analyzer_name, analyzer_name)

    @staticmethod
    def _log_analysis_json(
        email_id: str,
        verdict: Verdict,
        score: float,
        confidence: float,
        elapsed_seconds: float,
    ):
        """Log analysis result as structured JSON for audit trail."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "email_id": email_id,
            "verdict": verdict.value,
            "overall_score": score,
            "overall_confidence": confidence,
            "elapsed_seconds": elapsed_seconds,
        }
        logger.info(f"ANALYSIS_RESULT: {json.dumps(log_entry)}")
