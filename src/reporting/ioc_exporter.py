"""
IOC (Indicator of Compromise) export functionality.
Generates STIX 2.1 bundles for sharing threat intelligence.
"""
import json
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from stix2 import (
    Bundle,
    Campaign,
    Indicator,
    Relationship,
    Sighting,
    Note,
    File,
    URL,
    DomainName,
    IPv4Address,
)

from src.models import PipelineResult, Verdict


logger = logging.getLogger(__name__)


class IOCExporter:
    """Export analysis results as STIX 2.1 threat intelligence bundles."""

    # STIX object type mappings
    STIX_PATTERN_IPV4 = "[ipv4-addr:value = '{ip}']"
    STIX_PATTERN_DOMAIN = "[domain-name:value = '{domain}']"
    STIX_PATTERN_URL = "[url:value = '{url}']"
    STIX_PATTERN_FILE_HASH = "[file:hashes.MD5 = '{hash}']"

    def __init__(self, organization_name: str = "Phishing Detection System"):
        """
        Initialize IOC exporter.

        Args:
            organization_name: Name of organization exporting IOCs for attribution.
        """
        self.organization_name = organization_name

    def export_stix(self, result: PipelineResult) -> str:
        """
        Generate STIX 2.1 bundle from pipeline result.

        Creates Indicator, Observable, Relationship, Sighting, and Note objects
        for all extracted IOCs.

        Args:
            result: PipelineResult from the analysis pipeline.

        Returns:
            JSON string containing STIX 2.1 bundle.
        """
        objects = []
        ioc_refs = []  # Track created IOC object IDs

        # Create campaign object
        campaign = self._create_campaign(result)
        objects.append(campaign)

        # Extract and create indicators for each IOC type
        iocs_data = result.iocs

        # Process URLs
        urls = self._extract_urls_from_iocs(result)
        for url in urls:
            indicator, observable, relationship, note = self._create_url_ioc(
                url, result, campaign.id
            )
            objects.extend([indicator, observable, relationship])
            if note:
                objects.append(note)
            ioc_refs.append(indicator.id)

        # Process domains
        domains = self._extract_domains_from_iocs(iocs_data)
        for domain in domains:
            indicator, observable, relationship, note = self._create_domain_ioc(
                domain, result, campaign.id
            )
            objects.extend([indicator, observable, relationship])
            if note:
                objects.append(note)
            ioc_refs.append(indicator.id)

        # Process IPs
        ips = iocs_data.get("malicious_ips", [])
        for ip in ips:
            if isinstance(ip, dict):
                ip_addr = ip.get("ip")
            else:
                ip_addr = ip

            indicator, observable, relationship, note = self._create_ip_ioc(
                ip_addr, result, campaign.id
            )
            objects.extend([indicator, observable, relationship])
            if note:
                objects.append(note)
            ioc_refs.append(indicator.id)

        # Process file hashes
        file_hashes = iocs_data.get("file_hashes", {})
        for hash_type, hash_value in file_hashes.items():
            indicator, observable, relationship, note = self._create_file_ioc(
                hash_value, hash_type, result, campaign.id
            )
            objects.extend([indicator, observable, relationship])
            if note:
                objects.append(note)
            ioc_refs.append(indicator.id)

        # Create sightings for verdict confidence
        if ioc_refs and result.verdict in [Verdict.LIKELY_PHISHING, Verdict.CONFIRMED_PHISHING]:
            sighting = self._create_sighting(ioc_refs, result)
            objects.append(sighting)

        # Create bundle
        bundle = Bundle(objects=objects, allow_custom=True)

        return bundle.serialize(pretty=True)

    def export_json(self, result: PipelineResult) -> str:
        """
        Export IOCs as structured JSON.

        Args:
            result: PipelineResult from the analysis pipeline.

        Returns:
            JSON string with IOC inventory.
        """
        iocs_inventory = {
            "email_id": result.email_id,
            "analysis_time": result.timestamp.isoformat(),
            "verdict": result.verdict.value,
            "confidence": result.overall_confidence,
            "iocs": {
                "urls": self._extract_urls_from_iocs(result),
                "domains": self._extract_domains_from_iocs(result.iocs),
                "ips": result.iocs.get("malicious_ips", []),
                "file_hashes": result.iocs.get("file_hashes", {}),
                "headers": result.iocs.get("headers", {}),
            },
        }

        return json.dumps(iocs_inventory, indent=2, default=str)

    def _create_campaign(self, result: PipelineResult) -> Campaign:
        """Create STIX Campaign object for the phishing campaign."""
        return Campaign(
            name=f"Phishing Campaign - {result.email_id}",
            created_by_ref="identity--" + self._generate_identity_id(),
            description=f"Automated phishing detection campaign. Verdict: {result.verdict.value}",
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

    def _create_url_ioc(
        self, url: str, result: PipelineResult, campaign_id: str
    ) -> tuple:
        """
        Create STIX objects for a malicious URL.

        Returns:
            Tuple of (Indicator, Observable, Relationship, Note) objects.
        """
        # Create observable
        observable = Observable(
            object_type="url",
            object_path="0",
            url=url,
            allow_custom=True,
        )

        # Create indicator
        pattern = self.STIX_PATTERN_URL.format(url=url)
        indicator = Indicator(
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc),
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        # Create relationship
        relationship = Relationship(
            source_ref=campaign_id,
            target_ref=indicator.id,
            relationship_type="uses",
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        # Create note
        note_text = f"Detected in email {result.email_id}. Overall phishing score: {result.overall_score:.3f}"
        note = Note(
            abstract="URL Indicator",
            content=note_text,
            object_refs=[indicator.id],
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        return indicator, observable, relationship, note

    def _create_domain_ioc(
        self, domain: str, result: PipelineResult, campaign_id: str
    ) -> tuple:
        """
        Create STIX objects for a malicious domain.

        Returns:
            Tuple of (Indicator, Observable, Relationship, Note) objects.
        """
        # Create observable
        observable = Observable(
            object_type="domain-name",
            object_path="0",
            value=domain,
            allow_custom=True,
        )

        # Create indicator
        pattern = self.STIX_PATTERN_DOMAIN.format(domain=domain)
        indicator = Indicator(
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc),
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        # Create relationship
        relationship = Relationship(
            source_ref=campaign_id,
            target_ref=indicator.id,
            relationship_type="uses",
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        # Create note
        note_text = f"Detected in email {result.email_id}. Overall phishing score: {result.overall_score:.3f}"
        note = Note(
            abstract="Domain Indicator",
            content=note_text,
            object_refs=[indicator.id],
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        return indicator, observable, relationship, note

    def _create_ip_ioc(
        self, ip: str, result: PipelineResult, campaign_id: str
    ) -> tuple:
        """
        Create STIX objects for a malicious IP address.

        Returns:
            Tuple of (Indicator, Observable, Relationship, Note) objects.
        """
        # Create observable
        observable = Observable(
            object_type="ipv4-addr",
            object_path="0",
            value=ip,
            allow_custom=True,
        )

        # Create indicator
        pattern = self.STIX_PATTERN_IPV4.format(ip=ip)
        indicator = Indicator(
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc),
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        # Create relationship
        relationship = Relationship(
            source_ref=campaign_id,
            target_ref=indicator.id,
            relationship_type="targets",
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        # Create note
        note_text = f"Detected in email {result.email_id}. Overall phishing score: {result.overall_score:.3f}"
        note = Note(
            abstract="IP Address Indicator",
            content=note_text,
            object_refs=[indicator.id],
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        return indicator, observable, relationship, note

    def _create_file_ioc(
        self, hash_value: str, hash_type: str, result: PipelineResult, campaign_id: str
    ) -> tuple:
        """
        Create STIX objects for a file hash.

        Returns:
            Tuple of (Indicator, Observable, Relationship, Note) objects.
        """
        # Create observable
        observable = Observable(
            object_type="file",
            object_path="0",
            hashes={hash_type.upper(): hash_value},
            allow_custom=True,
        )

        # Create indicator
        pattern = self.STIX_PATTERN_FILE_HASH.format(hash=hash_value)
        indicator = Indicator(
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc),
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        # Create relationship
        relationship = Relationship(
            source_ref=campaign_id,
            target_ref=indicator.id,
            relationship_type="uses",
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        # Create note
        note_text = (
            f"File hash ({hash_type}): {hash_value}\n"
            f"Detected in email {result.email_id}. Overall phishing score: {result.overall_score:.3f}"
        )
        note = Note(
            abstract="File Hash Indicator",
            content=note_text,
            object_refs=[indicator.id],
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

        return indicator, observable, relationship, note

    def _create_sighting(self, ioc_refs: list[str], result: PipelineResult) -> Sighting:
        """Create STIX Sighting for malicious IOCs."""
        return Sighting(
            sighting_of_ref=ioc_refs[0] if ioc_refs else None,
            observed_data_refs=ioc_refs,
            count=1,
            first_seen=result.timestamp,
            last_seen=result.timestamp,
            created_by_ref="identity--" + self._generate_identity_id(),
            created=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            allow_custom=True,
        )

    @staticmethod
    def _extract_urls_from_iocs(result: PipelineResult) -> list[str]:
        """Extract unique URLs from analysis results."""
        urls = set()

        # From extracted URLs
        for url_obj in result.extracted_urls:
            urls.add(url_obj.url)

        # From IOCs
        iocs = result.iocs
        urls.update(iocs.get("malicious_urls", []))

        return list(urls)

    @staticmethod
    def _extract_domains_from_iocs(iocs: dict) -> list[str]:
        """Extract unique domains from IOCs."""
        domains = set()
        domains.update(iocs.get("malicious_domains", []))
        return list(domains)

    @staticmethod
    def _generate_identity_id() -> str:
        """Generate a UUID for identity objects."""
        return str(uuid4())
