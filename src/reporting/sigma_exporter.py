"""
Sigma rule export for phishing detection results.

Mirrors `ioc_exporter.py` but produces Sigma detection content instead of STIX
threat intelligence. STIX answers "what IOCs did we see?"; Sigma answers
"what should other operators look for to catch this campaign?".

Two outputs are produced from a single PipelineResult:

1. A campaign-scoped Sigma rule, generated from the IOCs that this run
   actually observed (subject regex, sender domain, URL pattern, file hash).
   Useful for narrow per-incident sharing.

2. A reference to the static rule library in `sigma_rules/`, which is the
   curated set of broader behavioral rules the project ships. Those rules
   are written by hand and version-controlled — this exporter doesn't
   regenerate them, it just tells consumers they exist.

YAML is hand-emitted (no PyYAML dependency) because the Sigma schema is small
and we need predictable key order to match the Sigma spec.
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from src.models import PipelineResult, Verdict, IntentCategory


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# ATT&CK technique mapping per analyzer.
# Keep this in sync with docs/MITRE_ATTACK_MAPPING.md — that doc is the
# authoritative source; this dict is a machine-readable mirror.
# ─────────────────────────────────────────────────────────────────────────────
#
# Keys MUST match the canonical analyzer-name keys used by the orchestrator
# in `src/orchestrator/pipeline.py` (analyzer_names list around line 321),
# NOT the per-file `analyzer_name = "..."` strings inside each analyzer
# module — the orchestrator dict-keys are what end up on PipelineResult.
ANALYZER_ATTACK_TAGS: dict[str, list[str]] = {
    "header_analysis":     ["attack.initial_access", "attack.t1566.001", "attack.t1566.002", "attack.t1656"],
    "url_reputation":      ["attack.initial_access", "attack.t1566.002", "attack.t1204.001"],
    "domain_intelligence": ["attack.resource_development", "attack.t1583.001"],
    "url_detonation":      ["attack.initial_access", "attack.t1566.002", "attack.t1204.001", "attack.t1027.006"],
    "brand_impersonation": ["attack.defense_evasion", "attack.t1656", "attack.t1036.005"],
    "nlp_intent":          ["attack.initial_access", "attack.t1534", "attack.t1656"],
    "attachment_analysis": ["attack.initial_access", "attack.t1566.001", "attack.t1204.002"],
    "sender_profiling":    ["attack.initial_access", "attack.t1078"],
}

VERDICT_LEVEL = {
    Verdict.CLEAN:              "informational",
    Verdict.SUSPICIOUS:         "low",
    Verdict.LIKELY_PHISHING:    "high",
    Verdict.CONFIRMED_PHISHING: "critical",
}

# Sigma `status` field. Campaign-scoped rules from a live result are
# experimental until an operator promotes them.
DEFAULT_STATUS = "experimental"


class SigmaExporter:
    """
    Export pipeline analysis results as Sigma detection rules.

    Two entry points:
        export_campaign_rule(result)  -> single rule string for one PipelineResult
        export_bundle(result)         -> multi-rule string covering all detected IOCs
    """

    def __init__(self, author: str = "Automated Phishing Detection Pipeline"):
        self.author = author

    # ─── public API ──────────────────────────────────────────────────────────

    def export_campaign_rule(self, result: PipelineResult) -> str:
        """
        Emit a single Sigma rule scoped to one campaign (one PipelineResult).

        Selection logic combines whatever observable signals exist: sender
        domain, subject pattern, URL substrings, file hashes. Multiple
        selections are combined with `1 of selection_*` so a hit on any one
        observable triggers the rule — this matches how operators actually
        deploy Sigma against a phishing campaign feed.
        """
        if result.verdict == Verdict.CLEAN:
            logger.debug("Skipping Sigma export for CLEAN verdict %s", result.email_id)
            return ""

        rule_id = self._stable_uuid(result.email_id)
        title = self._build_title(result)
        description = self._build_description(result)
        tags = self._collect_tags(result)
        level = VERDICT_LEVEL.get(result.verdict, "medium")

        selections, condition = self._build_detection_block(result)
        if not selections:
            logger.info("No emittable selectors for email %s — skipping Sigma rule", result.email_id)
            return ""

        # Hand-emit YAML in the exact Sigma key order.
        lines: list[str] = []
        lines.append(f"title: {title}")
        lines.append(f"id: {rule_id}")
        lines.append(f"status: {DEFAULT_STATUS}")
        lines.append("description: |")
        for dline in description.splitlines():
            lines.append(f"  {dline}")
        lines.append(f"author: {self.author}")
        lines.append(f"date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}")
        lines.append("references:")
        lines.append("  - https://attack.mitre.org/techniques/T1566/")
        lines.append("logsource:")
        lines.append("  category: email")
        lines.append("  # Adapt product/service to your mail telemetry source")
        lines.append("  # (e.g. product: m365, service: message_trace; product: proofpoint).")
        lines.append("detection:")
        for sel_name, sel_body in selections.items():
            lines.append(f"  {sel_name}:")
            for k, v in sel_body.items():
                if isinstance(v, list):
                    lines.append(f"    {k}:")
                    for item in v:
                        lines.append(f"      - {self._yaml_scalar(item)}")
                else:
                    lines.append(f"    {k}: {self._yaml_scalar(v)}")
        lines.append(f"  condition: {condition}")
        lines.append("fields:")
        lines.append("  - sender_address")
        lines.append("  - recipient_address")
        lines.append("  - subject")
        lines.append("  - url")
        lines.append("  - attachment_hash")
        lines.append("falsepositives:")
        for fp in self._falsepositives_for(result):
            lines.append(f"  - {fp}")
        lines.append(f"level: {level}")
        if tags:
            lines.append("tags:")
            for tag in tags:
                lines.append(f"  - {tag}")

        return "\n".join(lines) + "\n"

    def export_bundle(self, result: PipelineResult) -> str:
        """
        Emit a multi-document YAML bundle: one rule per IOC type detected.

        Useful when an operator wants per-IOC granularity (separate URL rule,
        separate sender rule, separate hash rule) rather than one big OR.
        """
        rules: list[str] = []
        builders = (
            self._build_sender_rule,
            self._build_subject_rule,
            self._build_url_rule,
            self._build_hash_rule,
        )
        for builder in builders:
            rule = builder(result)
            if rule:
                rules.append(rule)

        if not rules:
            return ""

        return "\n---\n".join(rules)

    # ─── detection block construction ───────────────────────────────────────

    def _build_detection_block(self, result: PipelineResult) -> tuple[dict, str]:
        """
        Build the Sigma `detection:` block.

        Returns (selections_dict, condition_string).
        """
        selections: dict[str, dict] = {}

        sender_sel = self._sender_selection(result)
        if sender_sel:
            selections["selection_sender"] = sender_sel

        subject_sel = self._subject_selection(result)
        if subject_sel:
            selections["selection_subject"] = subject_sel

        url_sel = self._url_selection(result)
        if url_sel:
            selections["selection_url"] = url_sel

        hash_sel = self._hash_selection(result)
        if hash_sel:
            selections["selection_hash"] = hash_sel

        if not selections:
            return {}, ""

        # Single selection → just reference it; multiple → "1 of selection_*"
        if len(selections) == 1:
            condition = next(iter(selections.keys()))
        else:
            condition = "1 of selection_*"

        return selections, condition

    def _sender_selection(self, result: PipelineResult) -> Optional[dict]:
        headers = result.iocs.get("headers") if result.iocs else None
        if not headers:
            return None
        # `headers` may be a HeaderAnalysisDetail dataclass dict-ified or a plain dict
        from_addr = self._extract_from_addr(headers)
        if not from_addr:
            return None
        domain = from_addr.split("@")[-1].strip().lower() if "@" in from_addr else None
        if not domain:
            return None
        return {"sender_address|endswith": f"@{domain}"}

    def _subject_selection(self, result: PipelineResult) -> Optional[dict]:
        headers = result.iocs.get("headers") if result.iocs else None
        subject = None
        if isinstance(headers, dict):
            subject = headers.get("subject")
        if not subject:
            return None
        # Extract content keywords — strip common noise
        keywords = self._subject_keywords(subject)
        if not keywords:
            return None
        return {"subject|contains": keywords}

    def _url_selection(self, result: PipelineResult) -> Optional[dict]:
        urls = self._collect_urls(result)
        if not urls:
            return None
        # Extract distinguishing path/host fragments rather than full URLs
        fragments = sorted({self._url_fragment(u) for u in urls if self._url_fragment(u)})
        if not fragments:
            return None
        return {"url|contains": fragments[:10]}  # cap for rule sanity

    def _hash_selection(self, result: PipelineResult) -> Optional[dict]:
        hashes = result.iocs.get("file_hashes") if result.iocs else None
        if not hashes:
            return None
        if isinstance(hashes, dict):
            values = [v for v in hashes.values() if v]
        elif isinstance(hashes, list):
            values = list(hashes)
        else:
            return None
        if not values:
            return None
        return {"attachment_hash": values[:10]}

    # ─── per-IOC standalone rules (for bundle mode) ─────────────────────────

    def _build_sender_rule(self, result: PipelineResult) -> str:
        sel = self._sender_selection(result)
        if not sel:
            return ""
        return self._wrap_single_selection(
            result,
            kind="sender",
            selection=sel,
            description_extra="Triggers on the sender domain observed in this campaign.",
        )

    def _build_subject_rule(self, result: PipelineResult) -> str:
        sel = self._subject_selection(result)
        if not sel:
            return ""
        return self._wrap_single_selection(
            result,
            kind="subject",
            selection=sel,
            description_extra="Triggers on subject keywords distinctive to this campaign.",
        )

    def _build_url_rule(self, result: PipelineResult) -> str:
        sel = self._url_selection(result)
        if not sel:
            return ""
        return self._wrap_single_selection(
            result,
            kind="url",
            selection=sel,
            description_extra="Triggers on URL fragments observed in this campaign.",
        )

    def _build_hash_rule(self, result: PipelineResult) -> str:
        sel = self._hash_selection(result)
        if not sel:
            return ""
        return self._wrap_single_selection(
            result,
            kind="hash",
            selection=sel,
            description_extra="Triggers on attachment hashes observed in this campaign.",
        )

    def _wrap_single_selection(
        self,
        result: PipelineResult,
        kind: str,
        selection: dict,
        description_extra: str,
    ) -> str:
        rule_id = self._stable_uuid(f"{result.email_id}:{kind}")
        title = f"{self._build_title(result)} ({kind})"
        tags = self._collect_tags(result)
        level = VERDICT_LEVEL.get(result.verdict, "medium")

        lines: list[str] = []
        lines.append(f"title: {title}")
        lines.append(f"id: {rule_id}")
        lines.append(f"status: {DEFAULT_STATUS}")
        lines.append("description: |")
        lines.append(f"  {self._build_description(result)}")
        lines.append(f"  {description_extra}")
        lines.append(f"author: {self.author}")
        lines.append(f"date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}")
        lines.append("logsource:")
        lines.append("  category: email")
        lines.append("detection:")
        lines.append(f"  selection:")
        for k, v in selection.items():
            if isinstance(v, list):
                lines.append(f"    {k}:")
                for item in v:
                    lines.append(f"      - {self._yaml_scalar(item)}")
            else:
                lines.append(f"    {k}: {self._yaml_scalar(v)}")
        lines.append("  condition: selection")
        lines.append(f"level: {level}")
        if tags:
            lines.append("tags:")
            for tag in tags:
                lines.append(f"  - {tag}")
        return "\n".join(lines) + "\n"

    # ─── helpers ─────────────────────────────────────────────────────────────

    def _build_title(self, result: PipelineResult) -> str:
        intent = self._extract_intent(result)
        if intent and intent != IntentCategory.UNKNOWN.value:
            human = intent.replace("_", " ").title()
            return f"Phishing Campaign - {human} ({result.verdict.value})"
        return f"Phishing Campaign - {result.verdict.value} ({result.email_id[:12]})"

    def _build_description(self, result: PipelineResult) -> str:
        score = f"{result.overall_score:.2f}"
        confidence = f"{result.overall_confidence:.2f}"
        return (
            f"Auto-generated from phishing-detection pipeline run on email "
            f"{result.email_id}. Verdict={result.verdict.value} "
            f"score={score} confidence={confidence}. "
            f"See PipelineResult.reasoning for analyzer breakdown."
        )

    def _collect_tags(self, result: PipelineResult) -> list[str]:
        """Collect ATT&CK tags from analyzers that contributed to the verdict."""
        tags: set[str] = set()
        for name, ar in (result.analyzer_results or {}).items():
            if ar.confidence > 0 and ar.risk_score > 0.3:
                for tag in ANALYZER_ATTACK_TAGS.get(name, []):
                    tags.add(tag)
        # Always include the umbrella tactic if any analyzer fired
        if tags:
            tags.add("attack.initial_access")
        return sorted(tags)

    def _falsepositives_for(self, result: PipelineResult) -> list[str]:
        fps = ["Legitimate transactional mail from the same sender domain"]
        intent = self._extract_intent(result)
        if intent == IntentCategory.BEC_WIRE_FRAUD.value:
            fps.append("Legitimate finance team correspondence about wires or invoices")
        if intent == IntentCategory.CREDENTIAL_HARVESTING.value:
            fps.append("Legitimate password reset or SSO migration emails")
        return fps

    def _extract_intent(self, result: PipelineResult) -> Optional[str]:
        ar = (result.analyzer_results or {}).get("nlp_intent")
        if not ar or not ar.details:
            return None
        intent = ar.details.get("intent_classification")
        if isinstance(intent, dict):
            return intent.get("category")
        return None

    def _extract_from_addr(self, headers) -> Optional[str]:
        if isinstance(headers, dict):
            return headers.get("from_address") or headers.get("from")
        return None

    def _collect_urls(self, result: PipelineResult) -> list[str]:
        urls = set()
        for u in (result.extracted_urls or []):
            if hasattr(u, "url"):
                urls.add(u.url)
        if result.iocs:
            urls.update(result.iocs.get("malicious_urls", []) or [])
            for entry in result.iocs.get("urls", []) or []:
                if isinstance(entry, dict) and entry.get("url"):
                    urls.add(entry["url"])
        return sorted(urls)

    @staticmethod
    def _url_fragment(url: str) -> str:
        """Pick a distinguishing substring from a URL — host or first path token."""
        m = re.match(r"https?://([^/]+)(/[^?#]*)?", url)
        if not m:
            return ""
        host = m.group(1)
        path = (m.group(2) or "").strip("/")
        if path:
            first = path.split("/")[0]
            return f"{host}/{first}" if first else host
        return host

    @staticmethod
    def _subject_keywords(subject: str) -> list[str]:
        # Strip RE:/FW: prefixes and common noise, then keep words ≥4 chars
        cleaned = re.sub(r"^(re:|fwd?:)\s*", "", subject.strip(), flags=re.IGNORECASE)
        words = re.findall(r"[A-Za-z][A-Za-z0-9'\-]{3,}", cleaned)
        # Deduplicate preserving order
        seen: set[str] = set()
        out: list[str] = []
        for w in words:
            wl = w.lower()
            if wl in seen:
                continue
            seen.add(wl)
            out.append(w)
        return out[:6]

    @staticmethod
    def _yaml_scalar(value) -> str:
        """Render a scalar inline. Quote if it contains YAML-significant chars."""
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        s = str(value)
        if any(c in s for c in ":#&*!|>%@`'\"") or s.strip() != s:
            return "'" + s.replace("'", "''") + "'"
        return s

    @staticmethod
    def _stable_uuid(seed: str) -> str:
        """Deterministic UUIDv5 so re-running emits the same rule id."""
        digest = hashlib.sha1(seed.encode("utf-8"), usedforsecurity=False).hexdigest()
        return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
