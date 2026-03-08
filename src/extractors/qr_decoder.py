"""
QR code decoding pipeline for phishing detection.

Extracts URLs from QR codes embedded in:
- Inline email images
- Image attachments (PNG, JPG, GIF, BMP)
- PDF attachments (embedded images + full-page renders)
- DOCX attachments (word/media/ extraction)
- HTML content (heuristic detection + optional Playwright render)

Core decoder: PIL + pyzbar + OpenCV for robustness.
Image preprocessing includes 2x resize, adaptive thresholding, sharpening, contrast.
"""

import io
import logging
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import numpy as np

from src.models import AttachmentObject, EmailObject, ExtractedURL, URLSource

logger = logging.getLogger(__name__)

# Optional dependencies with graceful fallback
try:
    from PIL import Image, ImageEnhance, ImageFilter
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    logger.warning("PIL not available; image-based QR decoding will be skipped")

try:
    from pyzbar import pyzbar
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False
    logger.warning("pyzbar not available; QR code detection will be limited")

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False
    logger.warning("OpenCV (cv2) not available; advanced image preprocessing will be skipped")

try:
    import fitz  # PyMuPDF
    HAS_FITZ = True
except ImportError:
    HAS_FITZ = False
    logger.warning("PyMuPDF (fitz) not available; PDF QR extraction will be skipped")


@dataclass
class DecodingConfig:
    """Configuration for QR decoding behavior."""
    # Image preprocessing
    resize_factor: int = 2
    enable_adaptive_threshold: bool = True
    enable_sharpening: bool = True
    enable_contrast: bool = True
    enable_invert: bool = True

    # PDF extraction
    pdf_dpi: int = 200
    extract_pdf_images: bool = True
    extract_pdf_renders: bool = True

    # URL filtering
    min_url_length: int = 5
    max_url_length: int = 2048

    # Deduplication
    deduplicate_by_resolved: bool = True


class QRDecoder:
    """
    Production-grade QR code decoder for phishing detection.

    Handles multiple image sources with robust error handling,
    preprocessing, and URL validation.
    """

    def __init__(self, config: Optional[DecodingConfig] = None):
        """
        Initialize the QR decoder.

        Args:
            config: DecodingConfig instance; uses defaults if None.
        """
        self.config = config or DecodingConfig()
        self._validate_dependencies()

    def _validate_dependencies(self) -> None:
        """Log available/missing dependencies for transparency."""
        deps_status = {
            "PIL": HAS_PIL,
            "pyzbar": HAS_PYZBAR,
            "OpenCV": HAS_CV2,
            "PyMuPDF": HAS_FITZ,
        }
        missing = [name for name, available in deps_status.items() if not available]
        if missing:
            logger.warning(f"Optional dependencies not available: {', '.join(missing)}")

    async def decode_all(self, email: EmailObject) -> list[ExtractedURL]:
        """
        Extract all URLs from QR codes in an email.

        Async orchestrator that calls synchronous decoders for all sources.
        Deduplicates results by resolved_url.

        Args:
            email: EmailObject to process.

        Returns:
            Deduplicated list of ExtractedURL objects.
        """
        all_urls: list[ExtractedURL] = []

        # Extract from inline images
        try:
            all_urls.extend(self.decode_from_inline_images(email))
        except Exception as e:
            logger.error(f"Error decoding inline images: {e}", exc_info=True)

        # Extract from image attachments
        try:
            all_urls.extend(self.decode_from_image_attachments(email))
        except Exception as e:
            logger.error(f"Error decoding image attachments: {e}", exc_info=True)

        # Extract from PDF attachments
        try:
            all_urls.extend(self.decode_from_pdf_attachments(email))
        except Exception as e:
            logger.error(f"Error decoding PDF attachments: {e}", exc_info=True)

        # Extract from DOCX attachments
        try:
            all_urls.extend(self.decode_from_docx_attachments(email))
        except Exception as e:
            logger.error(f"Error decoding DOCX attachments: {e}", exc_info=True)

        # Extract from HTML (heuristic + optional render)
        try:
            html_urls = await self.decode_from_html_rendered(email.body_html)
            all_urls.extend(html_urls)
        except Exception as e:
            logger.error(f"Error decoding HTML: {e}", exc_info=True)

        # Deduplicate and return
        return self._deduplicate(all_urls)

    def decode_from_image_bytes(
        self, image_bytes: bytes, source_detail: str
    ) -> list[ExtractedURL]:
        """
        Decode QR codes from raw image bytes.

        Core decoder that handles multiple preprocessing strategies.

        Args:
            image_bytes: Raw image data (PNG, JPG, GIF, BMP).
            source_detail: Human-readable source identifier (e.g., "inline_image_0").

        Returns:
            List of ExtractedURL objects found in the image.
        """
        if not HAS_PIL or not HAS_PYZBAR:
            logger.warning(
                "PIL or pyzbar unavailable; skipping image bytes decoding"
            )
            return []

        urls: list[ExtractedURL] = []

        try:
            image = Image.open(io.BytesIO(image_bytes))
            image_array = np.array(image)

            # Generate preprocessed variants
            preprocessed_images = self._preprocess_image(image_array)

            # Try decoding from each variant
            for variant_idx, processed_array in enumerate(preprocessed_images):
                try:
                    decoded_objects = pyzbar.decode(processed_array)
                    for obj in decoded_objects:
                        raw_data = obj.data.decode("utf-8", errors="ignore")
                        if self._is_url_like(raw_data):
                            urls.append(
                                ExtractedURL(
                                    url=raw_data,
                                    source=URLSource.QR_CODE,
                                    source_detail=f"{source_detail}_variant_{variant_idx}",
                                )
                            )
                except Exception as e:
                    logger.debug(
                        f"Decode attempt on variant {variant_idx} failed: {e}"
                    )
                    continue

        except Exception as e:
            logger.error(f"Error decoding image bytes: {e}", exc_info=True)

        return urls

    def decode_from_inline_images(self, email: EmailObject) -> list[ExtractedURL]:
        """
        Extract QR codes from inline email images.

        Args:
            email: EmailObject with inline_images list.

        Returns:
            List of ExtractedURL objects.
        """
        urls: list[ExtractedURL] = []

        for idx, image_bytes in enumerate(email.inline_images):
            decoded = self.decode_from_image_bytes(
                image_bytes, f"inline_image_{idx}"
            )
            urls.extend(decoded)

        logger.debug(f"Decoded {len(urls)} URLs from {len(email.inline_images)} inline images")
        return urls

    def decode_from_image_attachments(self, email: EmailObject) -> list[ExtractedURL]:
        """
        Extract QR codes from image file attachments.

        Filters attachments by MIME type and magic type.

        Args:
            email: EmailObject with attachments.

        Returns:
            List of ExtractedURL objects.
        """
        urls: list[ExtractedURL] = []
        image_mimetypes = {"image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp"}

        for attachment in email.attachments:
            # Check both MIME type and magic type
            if (attachment.content_type in image_mimetypes or
                    attachment.magic_type.startswith("image")):

                try:
                    decoded = self.decode_from_image_bytes(
                        attachment.content, f"attachment_{attachment.filename}"
                    )
                    urls.extend(decoded)
                except Exception as e:
                    logger.warning(
                        f"Error decoding image attachment {attachment.filename}: {e}"
                    )

        logger.debug(f"Decoded {len(urls)} URLs from image attachments")
        return urls

    def decode_from_pdf_attachments(self, email: EmailObject) -> list[ExtractedURL]:
        """
        Extract QR codes from PDF attachments.

        Two strategies:
        1. Extract embedded images from PDF objects
        2. Render full pages at 200 DPI and scan for QR codes

        Args:
            email: EmailObject with attachments.

        Returns:
            List of ExtractedURL objects.
        """
        if not HAS_FITZ:
            logger.warning("PyMuPDF not available; skipping PDF QR extraction")
            return []

        urls: list[ExtractedURL] = []

        for attachment in email.attachments:
            if attachment.content_type != "application/pdf" and not attachment.magic_type.startswith("PDF"):
                continue

            try:
                pdf_doc = fitz.open(stream=attachment.content, filetype="pdf")

                # Strategy 1: Extract embedded images
                if self.config.extract_pdf_images:
                    for page_num in range(len(pdf_doc)):
                        try:
                            page = pdf_doc[page_num]
                            images = page.get_images(full=True)

                            for img_index, img_ref in enumerate(images):
                                try:
                                    xref = img_ref[0]
                                    pix = fitz.Pixmap(pdf_doc, xref)

                                    if pix.n - pix.alpha < 4:  # GRAY or RGB
                                        image_bytes = pix.tobytes("png")
                                    else:  # CMYK
                                        rgb_pix = fitz.Pixmap(fitz.csRGB, pix)
                                        image_bytes = rgb_pix.tobytes("png")

                                    decoded = self.decode_from_image_bytes(
                                        image_bytes,
                                        f"pdf_{attachment.filename}_page_{page_num}_img_{img_index}",
                                    )
                                    urls.extend(decoded)
                                except Exception as e:
                                    logger.debug(
                                        f"Failed to extract image {img_index} from PDF page {page_num}: {e}"
                                    )
                        except Exception as e:
                            logger.debug(f"Failed to process PDF page {page_num}: {e}")

                # Strategy 2: Render full pages
                if self.config.extract_pdf_renders:
                    for page_num in range(len(pdf_doc)):
                        try:
                            page = pdf_doc[page_num]
                            pix = page.get_pixmap(dpi=self.config.pdf_dpi)
                            image_bytes = pix.tobytes("png")

                            decoded = self.decode_from_image_bytes(
                                image_bytes,
                                f"pdf_{attachment.filename}_page_{page_num}_render",
                            )
                            urls.extend(decoded)
                        except Exception as e:
                            logger.debug(f"Failed to render PDF page {page_num}: {e}")

                pdf_doc.close()

            except Exception as e:
                logger.warning(f"Error processing PDF attachment {attachment.filename}: {e}")

        logger.debug(f"Decoded {len(urls)} URLs from PDF attachments")
        return urls

    def decode_from_docx_attachments(self, email: EmailObject) -> list[ExtractedURL]:
        """
        Extract QR codes from DOCX attachments.

        DOCX files are ZIP archives; extracts images from word/media/ directory.

        Args:
            email: EmailObject with attachments.

        Returns:
            List of ExtractedURL objects.
        """
        urls: list[ExtractedURL] = []

        for attachment in email.attachments:
            if (attachment.content_type != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" and
                    not attachment.magic_type.startswith("DOCX") and
                    not attachment.magic_type.startswith("ZIP")):
                continue

            if not attachment.filename.lower().endswith(".docx"):
                continue

            try:
                docx_zip = zipfile.ZipFile(io.BytesIO(attachment.content))

                # Extract all files in word/media/
                for name in docx_zip.namelist():
                    if not name.startswith("word/media/"):
                        continue

                    try:
                        image_bytes = docx_zip.read(name)
                        decoded = self.decode_from_image_bytes(
                            image_bytes,
                            f"docx_{attachment.filename}_{Path(name).name}",
                        )
                        urls.extend(decoded)
                    except Exception as e:
                        logger.debug(f"Failed to extract image from DOCX {name}: {e}")

            except Exception as e:
                logger.warning(f"Error processing DOCX attachment {attachment.filename}: {e}")

        logger.debug(f"Decoded {len(urls)} URLs from DOCX attachments")
        return urls

    async def decode_from_html_rendered(self, html_content: str) -> list[ExtractedURL]:
        """
        Extract QR codes from HTML content.

        Uses heuristic detection for inline images in HTML tables/divs.
        Placeholder for Playwright-based full render (JS disabled) if needed.

        Args:
            html_content: Raw HTML string.

        Returns:
            List of ExtractedURL objects.
        """
        urls: list[ExtractedURL] = []

        # Heuristic: Look for data: URIs and embedded base64 images
        # Pattern: src="data:image/*;base64,..."
        data_uri_pattern = r'src=["\'](data:image/[^;]+;base64,[^"\']+)["\']'
        matches = re.finditer(data_uri_pattern, html_content, re.IGNORECASE)

        for match in matches:
            data_uri = match.group(1)
            try:
                # Extract base64 portion
                parts = data_uri.split(",", 1)
                if len(parts) != 2:
                    continue

                base64_data = parts[1]
                import base64
                image_bytes = base64.b64decode(base64_data)

                decoded = self.decode_from_image_bytes(
                    image_bytes, f"html_embedded_{len(urls)}"
                )
                urls.extend(decoded)
            except Exception as e:
                logger.debug(f"Failed to decode HTML embedded image: {e}")

        # TODO: Playwright-based full HTML render with JS disabled
        # This would require:
        # - Playwright browser instance
        # - Screenshot of rendered page
        # - QR decoding from screenshot
        # For now, only heuristic extraction is implemented.

        logger.debug(f"Decoded {len(urls)} URLs from HTML content")
        return urls

    def _preprocess_image(self, image: np.ndarray) -> list[np.ndarray]:
        """
        Generate multiple preprocessed variants of an image for robust QR decoding.

        Strategies:
        1. Original (2x resized)
        2. Adaptive thresholded (if CV2 available)
        3. Sharpened + high contrast
        4. Inverted
        5. Combined (threshold + sharpen + contrast)

        Args:
            image: Numpy array (from PIL Image).

        Returns:
            List of preprocessed numpy arrays.
        """
        variants: list[np.ndarray] = []

        try:
            # Variant 0: Original with 2x resize
            if HAS_PIL and HAS_CV2:
                pil_image = Image.fromarray(image.astype('uint8'))
                size = (
                    pil_image.width * self.config.resize_factor,
                    pil_image.height * self.config.resize_factor,
                )
                pil_image = pil_image.resize(size, Image.LANCZOS)
                variants.append(np.array(pil_image))
            else:
                variants.append(image)

            # Variant 1: Adaptive threshold (requires CV2 and grayscale)
            if HAS_CV2 and self.config.enable_adaptive_threshold:
                try:
                    gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
                    thresholded = cv2.adaptiveThreshold(
                        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                        cv2.THRESH_BINARY, 11, 2
                    )
                    if self.config.resize_factor > 1 and HAS_PIL:
                        pil_thresh = Image.fromarray(thresholded)
                        size = (
                            pil_thresh.width * self.config.resize_factor,
                            pil_thresh.height * self.config.resize_factor,
                        )
                        pil_thresh = pil_thresh.resize(size, Image.LANCZOS)
                        variants.append(np.array(pil_thresh))
                    else:
                        variants.append(thresholded)
                except Exception as e:
                    logger.debug(f"Adaptive threshold preprocessing failed: {e}")

            # Variant 2: Sharpened + contrast
            if HAS_PIL and self.config.enable_sharpening:
                try:
                    pil_image = Image.fromarray(image.astype('uint8'))
                    size = (
                        pil_image.width * self.config.resize_factor,
                        pil_image.height * self.config.resize_factor,
                    )
                    pil_image = pil_image.resize(size, Image.LANCZOS)

                    if self.config.enable_contrast:
                        enhancer = ImageEnhance.Contrast(pil_image)
                        pil_image = enhancer.enhance(2.0)

                    enhancer = ImageEnhance.Sharpness(pil_image)
                    pil_image = enhancer.enhance(2.0)

                    variants.append(np.array(pil_image))
                except Exception as e:
                    logger.debug(f"Sharpening preprocessing failed: {e}")

            # Variant 3: Inverted
            if self.config.enable_invert:
                try:
                    inverted = 255 - image
                    if HAS_PIL:
                        pil_inverted = Image.fromarray(inverted.astype('uint8'))
                        size = (
                            pil_inverted.width * self.config.resize_factor,
                            pil_inverted.height * self.config.resize_factor,
                        )
                        pil_inverted = pil_inverted.resize(size, Image.LANCZOS)
                        variants.append(np.array(pil_inverted))
                    else:
                        variants.append(inverted)
                except Exception as e:
                    logger.debug(f"Inversion preprocessing failed: {e}")

            # Variant 4: All together
            if HAS_PIL and HAS_CV2 and self.config.enable_adaptive_threshold:
                try:
                    gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
                    thresholded = cv2.adaptiveThreshold(
                        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                        cv2.THRESH_BINARY, 11, 2
                    )

                    pil_combined = Image.fromarray(thresholded)
                    size = (
                        pil_combined.width * self.config.resize_factor,
                        pil_combined.height * self.config.resize_factor,
                    )
                    pil_combined = pil_combined.resize(size, Image.LANCZOS)

                    if self.config.enable_sharpening:
                        enhancer = ImageEnhance.Sharpness(pil_combined)
                        pil_combined = enhancer.enhance(2.0)

                    if self.config.enable_contrast:
                        enhancer = ImageEnhance.Contrast(pil_combined)
                        pil_combined = enhancer.enhance(1.5)

                    variants.append(np.array(pil_combined))
                except Exception as e:
                    logger.debug(f"Combined preprocessing failed: {e}")

        except Exception as e:
            logger.error(f"Image preprocessing failed; returning original: {e}")
            variants = [image]

        return variants if variants else [image]

    def _is_url_like(self, data: str) -> bool:
        """
        Validate that decoded QR data is URL-like.

        Checks for:
        - http:// or https:// schemes
        - data: URIs
        - tel: and mailto: schemes
        - Common TLDs
        - Length constraints

        Args:
            data: Decoded string from QR code.

        Returns:
            True if data appears to be a URL.
        """
        if not data or len(data) < self.config.min_url_length or len(data) > self.config.max_url_length:
            return False

        data_lower = data.lower().strip()

        # Explicit schemes
        if data_lower.startswith(("http://", "https://", "data:", "tel:", "mailto:")):
            return True

        # Heuristic: Check for domain-like pattern (domain.tld)
        # Must contain at least one dot and have a reasonable TLD
        common_tlds = {
            "com", "org", "net", "edu", "gov", "uk", "de", "fr", "cn", "ru",
            "jp", "in", "br", "au", "ca", "io", "co", "info", "biz", "ws",
            "me", "tv", "cc", "app", "dev", "tech", "online", "site",
        }

        try:
            # Try to parse as URL (will fail if no scheme, but we can infer one)
            if "://" not in data_lower:
                # Add a dummy scheme for parsing
                test_url = f"http://{data_lower}"
            else:
                test_url = data_lower

            parsed = urlparse(test_url)
            if parsed.netloc:
                parts = parsed.netloc.split(".")
                if len(parts) >= 2:
                    tld = parts[-1].lower()
                    if tld in common_tlds or len(tld) >= 2:
                        return True
        except Exception as e:
            logger.debug(f"URL-like validation failed for '{data}': {e}")

        return False

    def _deduplicate(self, urls: list[ExtractedURL]) -> list[ExtractedURL]:
        """
        Deduplicate URLs by resolved_url or raw url.

        Prefers entries with resolved_url filled in.

        Args:
            urls: List of ExtractedURL objects.

        Returns:
            Deduplicated list.
        """
        if not urls:
            return []

        seen: dict[str, ExtractedURL] = {}

        for url_obj in urls:
            # Use resolved_url if available, else raw url
            key = url_obj.resolved_url or url_obj.url

            if key not in seen:
                seen[key] = url_obj
            else:
                # Merge redirect chains if present
                if url_obj.redirect_chain:
                    existing_chain = seen[key].redirect_chain or []
                    seen[key].redirect_chain = list(set(existing_chain + url_obj.redirect_chain))

        result = list(seen.values())
        logger.debug(f"Deduplicated {len(urls)} URLs to {len(result)}")
        return result
