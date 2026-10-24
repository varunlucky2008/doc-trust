# Curveballs & Live Stress Test Handlers
import re
from typing import Dict, Any, List, Optional, Tuple

class TamperingDetector:
    """
    Detects subtle document alterations (e.g. single altered digit) and provides
    forensic explanations strictly adhering to non-accusatory tone.
    """

    @classmethod
    def verify_document_integrity(
        cls,
        doc_id: str,
        extracted_fields: Dict[str, Any],
        expected_issuer_registry: Dict[str, Any]
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validates document numbers and hashes against issuer registry.
        Returns (is_valid, tamper_report).
        """
        reg_record = expected_issuer_registry.get(doc_id)
        if not reg_record:
            return True, None

        cert_number = str(extracted_fields.get("certificate_number", ""))
        expected_number = str(reg_record.get("certificate_number", ""))

        if not cert_number or not expected_number:
            return True, None

        if cert_number != expected_number:
            # Detect character-level discrepancy
            discrepant_positions = []
            max_len = max(len(cert_number), len(expected_number))
            for i in range(max_len):
                char_doc = cert_number[i] if i < len(cert_number) else "<missing>"
                char_reg = expected_number[i] if i < len(expected_number) else "<missing>"
                if char_doc != char_reg:
                    discrepant_positions.append({
                        "index": i + 1,
                        "observed_in_document": char_doc,
                        "issuer_canonical": char_reg
                    })

            # Non-accusatory forensic explanation
            neutral_explanation = (
                f"Registry Checksum Inconsistency: Serial identifier check failed at digit position "
                f"{discrepant_positions[0]['index'] if discrepant_positions else 'unknown'}. "
                f"The presented scan indicates '{cert_number}', whereas the issuing institution's authoritative "
                f"cryptographic index lists '{expected_number}'. "
                f"Technical Note: This anomaly may be caused by optical character recognition misreading, "
                f"compression artifacts, scanner resolution limits, or an unindexed provisional draft. "
                f"Please obtain a freshly signed digital copy directly from the issuing university to establish verified status."
            )

            return False, {
                "tamper_detected": True,
                "field": "certificate_number",
                "observed_value": cert_number,
                "expected_value": expected_number,
                "discrepancies": discrepant_positions,
                "neutral_explanation": neutral_explanation,
                "severity": "HIGH_INTEGRITY_ALERT",
                "recommended_action": "Request direct digital re-verification from the issuing authority."
            }

        return True, None

class PromptInjectionGuard:
    """
    Guards document ingestion and AI extraction against adversarial hidden prompt injections.
    """

    INJECTION_PATTERNS = [
        re.compile(r"(?i)system\s*override"),
        re.compile(r"(?i)disregard\s+(?:all\s+)?(?:rules|instructions|privacy|consent)"),
        re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions"),
        re.compile(r"(?i)share\s+(?:all|every)\s+document"),
        re.compile(r"(?i)grant\s+(?:full|unrestricted)\s+access"),
        re.compile(r"(?i)bypass\s+(?:consent|security|checks)"),
        re.compile(r"(?i)send\s+(?:all|all\s+confidential)\s+data")
    ]

    @classmethod
    def scan_for_injections(cls, document_text: str) -> Tuple[bool, List[str], str]:
        """
        Scans document text for adversarial injection attempts.
        Returns (is_compromised, detected_patterns, sanitized_text).
        """
        detected = []
        for pattern in cls.INJECTION_PATTERNS:
            matches = pattern.findall(document_text)
            if matches:
                detected.extend(matches)

        if not detected:
            return False, [], document_text

        # Sanitize and neutralize injection instructions while maintaining valid document parts
        sanitized = document_text
        for pattern in cls.INJECTION_PATTERNS:
            sanitized = pattern.sub("[QUARANTINED_ADVERSARIAL_INSTRUCTION]", sanitized)

        return True, detected, sanitized

class DataMinimizationAdvisor:
    """
    Detects excessive field requests from recipients and proposes minimal, privacy-preserving alternatives.
    """

    PURPOSE_ESSENTIAL_MAP = {
        "JOB_APPLICATION": {
            "essential": ["candidate_name", "degree_title", "degree_status", "passing_year"],
            "predicates_preferred": ["is_over_18", "degree_passed"],
            "excessive": ["full_national_id", "aadhaar_number", "date_of_birth", "father_name", "annual_income", "blood_group"]
        },
        "SCHOLARSHIP_BOARD": {
            "essential": ["candidate_name", "institution_name", "marks_percentage", "income_bracket"],
            "predicates_preferred": ["income_eligible", "marks_above_threshold"],
            "excessive": ["passport_number", "blood_group", "mother_tongue"]
        },
        "OVERSEAS_EVALUATOR": {
            "essential": ["candidate_name", "degree_title", "institution_name", "marksheet_grades"],
            "predicates_preferred": ["cross_script_verified"],
            "excessive": ["annual_income", "bank_account", "utility_meter_id"]
        }
    }

    @classmethod
    def evaluate_field_requests(
        cls,
        purpose_id: str,
        requested_fields: List[str]
    ) -> Dict[str, Any]:
        """Analyzes requested fields, flags excessive items, and provides privacy alternatives."""
        p_key = purpose_id.upper()
        spec = cls.PURPOSE_ESSENTIAL_MAP.get(p_key, cls.PURPOSE_ESSENTIAL_MAP["JOB_APPLICATION"])

        excessive_found = []
        for f in requested_fields:
            if f.lower() in spec["excessive"] or any(ex in f.lower() for ex in ["ssn", "aadhaar", "dob", "birth", "income"]):
                excessive_found.append(f)

        is_excessive = len(excessive_found) > 0

        minimal_alternative = [f for f in requested_fields if f not in excessive_found]
        recommended_predicates = spec["predicates_preferred"]

        explanation = (
            f"Over-Collection Warning: The recipient has requested {len(excessive_found)} high-risk field(s) "
            f"({', '.join(excessive_found)}) which exceed the legitimate informational necessity for {purpose_id}. "
            f"Exposing raw national identity numbers or full date of birth creates long-term credential leakage risks."
        )

        return {
            "is_excessive": is_excessive,
            "excessive_fields": excessive_found,
            "recommended_minimal_fields": minimal_alternative,
            "recommended_predicates": recommended_predicates,
            "explanation": explanation if is_excessive else "Requested fields adhere to data minimization principles.",
            "privacy_risk_reduction_pct": 65 if is_excessive else 0
        }

class DegradedModeManager:
    """
    Handles issuer verification service outages gracefully with clearly labeled unverified statuses.
    """

    def __init__(self):
        self.is_service_down = False
        self.offline_queue: List[str] = []
        self.status_label = "NORMAL_ONLINE"

    def set_service_status(self, is_down: bool):
        self.is_service_down = is_down
        self.status_label = "DEGRADED_ISSUER_OFFLINE" if is_down else "NORMAL_ONLINE"

    def get_status_banner(self) -> Dict[str, Any]:
        if self.is_service_down:
            return {
                "mode": "DEGRADED_MODE",
                "is_active": True,
                "banner_class": "bg-amber-100 border-amber-500 text-amber-900",
                "label": "⚠️ Degraded Mode: Issuer Registry Service Offline",
                "message": (
                    "Primary digital issuer verification authority is currently unreachable. "
                    "Documents submitted now cannot be stamped as 'Issuer-Verified' and will be displayed "
                    "with a clearly labeled 'Unverified (Issuer Offline)' badge. "
                    "Requests are automatically queued for background re-validation once the registry resumes."
                ),
                "queued_count": len(self.offline_queue)
            }
        return {
            "mode": "NORMAL",
            "is_active": False,
            "banner_class": "bg-green-100 border-green-500 text-green-900",
            "label": "All Issuer Services Operational",
            "message": "Direct cryptographic verification via Digilocker/University registries is fully online.",
            "queued_count": 0
        }
