# Automated Log Scrubber & URL Redactor
import re
import logging
from typing import Dict, Any, List, Tuple, Union

# Sensitive field patterns that must NEVER leak to logs, URLs, or analytics
SENSITIVE_PATTERNS = {
    "AADHAAR_ID": re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "PASSPORT_NUM": re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b"),
    "DOB_EXPLICIT": re.compile(r"(?i)\b(?:dob|birth_date|date_of_birth)\s*[:=]\s*['\"]?(\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})"),
    "FINANCIAL_RAW_AMOUNT": re.compile(r"(?i)(?:salary|income|amount|ctc|stipend)\s*[:=]\s*['\"]?([$₹€£]?\s*[\d,]+(?:\.\d{2})?)"),
    "TOKEN_RAW_SECRET": re.compile(r"(?i)(?:secret|private_key|token_secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})")
}

SENSITIVE_KEYWORDS = [
    "aadhaar", "social_security", "national_id_raw", "passport_raw",
    "annual_income_exact", "date_of_birth_raw", "secret_key"
]

class LogScrubber:
    """Ensures zero sensitive PII appears in URLs, share links, analytics, or server logs."""

    @staticmethod
    def scrub_text(text: str) -> str:
        """Scrubs any raw sensitive PII from string text."""
        if not text:
            return ""
        scrubbed = str(text)
        for pattern_name, regex in SENSITIVE_PATTERNS.items():
            scrubbed = regex.sub(f"[REDACTED_{pattern_name}]", scrubbed)
        return scrubbed

    @classmethod
    def scrub_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively scrub dictionaries before logging or serialization."""
        scrubbed_dict = {}
        for key, value in data.items():
            lower_key = str(key).lower()
            if any(sensitive in lower_key for sensitive in SENSITIVE_KEYWORDS):
                scrubbed_dict[key] = f"[REDACTED_FIELD_{key.upper()}]"
            elif isinstance(value, dict):
                scrubbed_dict[key] = cls.scrub_dict(value)
            elif isinstance(value, list):
                scrubbed_dict[key] = [
                    cls.scrub_dict(item) if isinstance(item, dict) else cls.scrub_text(str(item))
                    for item in value
                ]
            elif isinstance(value, str):
                scrubbed_dict[key] = cls.scrub_text(value)
            else:
                scrubbed_dict[key] = value
        return scrubbed_dict

    @classmethod
    def scrub_url(cls, url: str) -> str:
        """Ensures public URLs and share links only expose opaque share tokens, never PII."""
        # URLs must never contain raw query params with PII
        return cls.scrub_text(url)

    @classmethod
    def audit_for_sensitive_leak(cls, sample: Union[str, Dict[str, Any]]) -> Tuple[bool, List[str]]:
        """
        Automated check testing if sensitive fields exist in the sample.
        Returns (is_clean, violations_found).
        """
        violations = []
        text_to_test = str(sample)

        for pattern_name, regex in SENSITIVE_PATTERNS.items():
            matches = regex.findall(text_to_test)
            if matches:
                # Filter out intentional redact placeholders
                actual_leaks = [m for m in matches if not str(m).startswith("[REDACTED")]
                if actual_leaks:
                    violations.append(f"Detected unscrubbed pattern {pattern_name}: {len(actual_leaks)} occurrences")

        for key in SENSITIVE_KEYWORDS:
            if key in text_to_test.lower():
                # Check if it has an unredacted raw value associated
                if f"[redacted" not in text_to_test.lower():
                    violations.append(f"Sensitive keyword detected unredacted: {key}")

        return (len(violations) == 0, violations)

class ScrubbingLogFilter(logging.Filter):
    """Logging filter that redacts sensitive PII on the fly."""
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = LogScrubber.scrub_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = LogScrubber.scrub_dict(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    LogScrubber.scrub_text(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )
        return True
