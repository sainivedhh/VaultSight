"""Sensitive data detection engine driven by YAML rules, checksums, and entropy analysis."""

import re
from pathlib import Path
from typing import List, Optional
import yaml

from vaultsight.detectors.models import Finding, DetectorCategory
from vaultsight.detectors.checksums import validate_verhoeff, validate_luhn
from vaultsight.detectors.entropy import calculate_shannon_entropy
from vaultsight.detectors.redact import redact_secret, has_context_keywords, is_allowlisted_placeholder


class DetectionEngine:
    """Core DSPM detection engine for discovering sensitive data across unstructured and structured content."""

    def __init__(self, rules_path: Optional[str] = None):
        if rules_path is None:
            rules_path = str(Path(__file__).parent / "rules.yaml")
        self.rules_path = rules_path
        self.rules = []
        self._load_rules()

    def _load_rules(self) -> None:
        """Load and compile detector rules from YAML configuration."""
        with open(self.rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        
        raw_rules = data.get("rules", [])
        self.rules = []
        for r in raw_rules:
            # Pre-compile regex for performance
            compiled = re.compile(r["pattern"])
            rule_entry = {**r, "_compiled": compiled}
            self.rules.append(rule_entry)

    def scan_text(self, text: str, location: str = "text:input") -> List[Finding]:
        """Scan a string of text and return all detected findings.
        
        Applies:
        - Regex pattern matching
        - Allowlist/placeholder filtering (drastically lowers FPs)
        - Algorithmic checksums (Verhoeff for Aadhaar, Luhn for credit cards)
        - Shannon entropy thresholding for generic secrets
        - Proximity context keywords weighting
        - Redaction for safe previewing
        """
        if not text:
            return []

        findings_with_spans = []

        for rule in self.rules:
            rule_id = rule["id"]
            category = DetectorCategory(rule["category"])
            compiled_re: re.Pattern = rule["_compiled"]
            context_keywords = rule.get("context_keywords", [])
            base_conf = float(rule.get("base_confidence", 0.7))
            context_boost = float(rule.get("context_boost", 0.15))
            checksum_boost = float(rule.get("checksum_boost", 0.0))
            allowlist = rule.get("allowlist", [])

            capture_group = rule.get("capture_group")
            for match in compiled_re.finditer(text):
                # For regexes with designated capture groups (e.g. generic secret assignment), extract the secret part
                if capture_group is not None and match.groups() and len(match.groups()) >= capture_group:
                    raw_val = match.group(capture_group)
                    start_pos, end_pos = match.start(capture_group), match.end(capture_group)
                else:
                    raw_val = match.group(0)
                    start_pos, end_pos = match.start(), match.end()

                # Step 1: Filter out allowlist/placeholders
                if is_allowlisted_placeholder(raw_val, allowlist):
                    continue

                # Step 2: Algorithmic validation if rule requires checksum
                passed_checksum = None
                if rule.get("checksum") == "verhoeff":
                    clean_digits = "".join(ch for ch in raw_val if ch.isdigit())
                    if len(clean_digits) != 12:
                        continue
                    if not validate_verhoeff(clean_digits):
                        # Strict rejection for invalid Aadhaar checksum
                        continue
                    passed_checksum = True

                elif rule.get("checksum") == "luhn":
                    clean_digits = "".join(ch for ch in raw_val if ch.isdigit())
                    if not validate_luhn(clean_digits):
                        # Strict rejection for invalid credit card checksum
                        continue
                    passed_checksum = True

                # Step 3: Entropy evaluation for generic secrets
                if "entropy" in rule:
                    min_ent = float(rule["entropy"].get("min_entropy", 3.5))
                    ent = calculate_shannon_entropy(raw_val)
                    if ent < min_ent:
                        continue

                # Step 4: Proximity Context Keyword analysis
                has_ctx = has_context_keywords(text, start_pos, end_pos, context_keywords)

                # Special constraint for Indian mobile numbers:
                # 10 digit numbers match many generic IDs/timestamps, require either context or +91 prefix
                if rule_id == "indian_mobile":
                    has_explicit_code = raw_val.startswith("+91") or raw_val.startswith("91")
                    if not has_ctx and not has_explicit_code:
                        continue

                # Step 5: Confidence Calculation
                confidence = base_conf
                if passed_checksum is True and checksum_boost > 0:
                    confidence += checksum_boost
                if has_ctx:
                    confidence += context_boost
                confidence = min(1.0, max(0.0, round(confidence, 2)))

                # Step 6: Safe Redacted Preview
                preview = redact_secret(raw_val)

                # Step 7: Build Finding
                # Calculate line and column if location doesn't specify
                line_no = text[:start_pos].count("\n") + 1
                item_loc = f"{location}:L{line_no}" if ":" in location else f"{location}:L{line_no}"

                findings_with_spans.append({
                    "start": start_pos,
                    "end": end_pos,
                    "detector": rule_id,
                    "finding": Finding(
                        detector=rule_id,
                        category=category,
                        confidence=confidence,
                        location=item_loc,
                        redacted_preview=preview,
                        details={
                            "rule_name": rule["name"],
                            "checksum_verified": passed_checksum is True,
                            "context_keyword_matched": has_ctx,
                            "length": len(raw_val),
                        }
                    )
                })

        # Suppress generic/lower-priority detectors if a higher-order structured detector matches the same span
        # e.g., db_connection_string contains user:password@host which can match email regex
        db_spans = [
            (f["start"], f["end"]) for f in findings_with_spans
            if f["detector"] == "db_connection_string"
        ]
        specific_spans = [
            (f["start"], f["end"]) for f in findings_with_spans
            if f["detector"] not in ("generic_high_entropy_secret",)
        ]

        final_findings = []
        for item in findings_with_spans:
            det = item["detector"]
            s, e = item["start"], item["end"]
            if det == "email":
                if any(db_s <= s and e <= db_e for db_s, db_e in db_spans):
                    continue
            if det == "generic_high_entropy_secret":
                # Check if span overlaps with any specific detector
                if any(max(s, spec_s) < min(e, spec_e) for spec_s, spec_e in specific_spans):
                    continue
            final_findings.append(item["finding"])

        return final_findings
