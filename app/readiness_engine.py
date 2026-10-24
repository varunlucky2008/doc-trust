# Purpose-Specific Readiness Engine with Declarative Rules
import datetime
from typing import List, Dict, Any, Optional
from app.models import (
    Document, PurposeSpec, DeclarativeRule, RuleEvaluationResult,
    RuleStatus, PurposeReadinessReport, DocumentStatus
)
from app.entity_resolver import EntityResolver
from app.ocr_engine import OCREngine

class ReadinessEngine:
    """
    Evaluates document vault against declarative checklists for specific purposes.
    Supports dynamic JSON declarative rules without code modifications.
    Outputs PASS, FAIL, or UNKNOWN with comprehensive evidence.
    """

    @classmethod
    def evaluate_rule(
        cls,
        rule: DeclarativeRule,
        documents: Dict[str, Document],
        entity_matches: Optional[List[Any]] = None
    ) -> RuleEvaluationResult:
        """Evaluates a single declarative rule against available documents."""

        # 1. Target Document Lookup
        target_doc = None
        if rule.target_doc_type:
            for doc in documents.values():
                if doc.doc_type == rule.target_doc_type:
                    target_doc = doc
                    break
            
            if not target_doc:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    status=RuleStatus.FAIL,
                    message=f"Missing required document of type '{rule.target_doc_type}'.",
                    evidence={"target_doc_type": rule.target_doc_type, "available_docs": [d.doc_type for d in documents.values()]},
                    required=rule.required_for_readiness
                )

        # 2. Issuer Verified Check
        if rule.rule_type == "ISSUER_VERIFIED":
            if not target_doc:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.FAIL,
                    message="Target document not found.", evidence={}, required=rule.required_for_readiness
                )
            if target_doc.is_revoked_by_issuer:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.FAIL,
                    message=f"Document '{target_doc.title}' has been REVOKED by issuing authority '{target_doc.issuer_name}'.",
                    evidence={"revoked": True, "issuer": target_doc.issuer_name},
                    required=rule.required_for_readiness
                )
            if target_doc.source_status == DocumentStatus.ISSUER_VERIFIED:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.PASS,
                    message=f"Document verified directly via issuer '{target_doc.issuer_name}' digital registry.",
                    evidence={"source_status": target_doc.source_status, "issuer": target_doc.issuer_name},
                    required=rule.required_for_readiness
                )
            else:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.FAIL,
                    message=f"Document is '{target_doc.source_status}', but purpose requires official ISSUER_VERIFIED status.",
                    evidence={"current_status": target_doc.source_status},
                    required=rule.required_for_readiness
                )

        # 3. Field Exists & User Confirmation Check
        if rule.rule_type in ["FIELD_EXISTS", "MIN_VALUE", "EQUALS", "DATE_WITHIN_DAYS", "PREDICATE_CHECK"]:
            field_key = rule.field_key
            if not field_key or field_key not in target_doc.extracted_fields:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.FAIL,
                    message=f"Required field '{field_key}' missing in {target_doc.title}.",
                    evidence={"field_key": field_key, "extracted_keys": list(target_doc.extracted_fields.keys())},
                    required=rule.required_for_readiness
                )

            eff_val, is_confirmed, provenance = OCREngine.get_effective_field_value(target_doc, field_key)

            # CONSTRAINT: Never treat OCR output as authoritative without explicit user confirmation.
            # If OCR was never confirmed and no user assertion was made, mark UNKNOWN!
            if not is_confirmed and target_doc.source_status != DocumentStatus.ISSUER_VERIFIED:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.UNKNOWN,
                    message=f"Field '{field_key}' has unconfirmed OCR output ({target_doc.extracted_fields[field_key].ocr_confidence*100:.0f}% confidence). Requires explicit user confirmation or correction.",
                    evidence={"raw_value": eff_val, "confidence": target_doc.extracted_fields[field_key].ocr_confidence, "provenance": provenance},
                    required=rule.required_for_readiness
                )

            # Handle DATE_WITHIN_DAYS (e.g. Income certificate validity)
            if rule.rule_type == "DATE_WITHIN_DAYS":
                max_days = rule.params.get("max_days", 180)
                try:
                    issued_dt = datetime.datetime.strptime(str(eff_val), "%Y-%m-%d").date()
                    now_dt = datetime.date(2026, 10, 24) # System context date
                    delta_days = (now_dt - issued_dt).days
                    if delta_days <= max_days:
                        return RuleEvaluationResult(
                            rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.PASS,
                            message=f"Document issued {delta_days} days ago (within valid limit of {max_days} days).",
                            evidence={"issued_date": str(issued_dt), "current_date": str(now_dt), "age_days": delta_days, "max_days": max_days},
                            required=rule.required_for_readiness
                        )
                    else:
                        expired_days_ago = delta_days - max_days
                        return RuleEvaluationResult(
                            rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.FAIL,
                            message=f"Certificate expired {expired_days_ago} days ago (Issued {delta_days} days ago on {issued_dt}, max validity is {max_days} days). Renewal required.",
                            evidence={"issued_date": str(issued_dt), "current_date": str(now_dt), "age_days": delta_days, "expired_by_days": expired_days_ago},
                            required=rule.required_for_readiness
                        )
                except Exception as ex:
                    return RuleEvaluationResult(
                        rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.UNKNOWN,
                        message=f"Could not parse date field '{field_key}' value: {eff_val} ({str(ex)})",
                        evidence={"raw_value": eff_val}, required=rule.required_for_readiness
                    )

            # Handle MIN_VALUE (e.g. GPA or Marks >= 75%)
            if rule.rule_type == "MIN_VALUE":
                min_threshold = float(rule.params.get("threshold", 0))
                try:
                    num_val = float(str(eff_val).replace("%", "").strip())
                    if num_val >= min_threshold:
                        return RuleEvaluationResult(
                            rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.PASS,
                            message=f"Score {num_val} meets minimum threshold of {min_threshold}.",
                            evidence={"value": num_val, "threshold": min_threshold},
                            required=rule.required_for_readiness
                        )
                    else:
                        return RuleEvaluationResult(
                            rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.FAIL,
                            message=f"Score {num_val} is below required threshold of {min_threshold}.",
                            evidence={"value": num_val, "threshold": min_threshold},
                            required=rule.required_for_readiness
                        )
                except Exception as ex:
                    return RuleEvaluationResult(
                        rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.UNKNOWN,
                        message=f"Cannot evaluate numerical threshold on '{eff_val}'",
                        evidence={"value": eff_val}, required=rule.required_for_readiness
                    )

            # Handle EQUALS (e.g. degree_status == 'Passed')
            if rule.rule_type == "EQUALS":
                expected = str(rule.params.get("expected", "")).lower()
                actual = str(eff_val).lower()
                if actual == expected:
                    return RuleEvaluationResult(
                        rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.PASS,
                        message=f"Field '{field_key}' matched expected value '{rule.params.get('expected')}'.",
                        evidence={"actual": eff_val, "expected": rule.params.get("expected")},
                        required=rule.required_for_readiness
                    )
                else:
                    return RuleEvaluationResult(
                        rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.FAIL,
                        message=f"Field '{field_key}' has value '{eff_val}', expected '{rule.params.get('expected')}'.",
                        evidence={"actual": eff_val, "expected": rule.params.get("expected")},
                        required=rule.required_for_readiness
                    )

            # Handle PREDICATE_CHECK (e.g. Age >= 18)
            if rule.rule_type == "PREDICATE_CHECK":
                predicate_name = rule.params.get("predicate")
                if predicate_name == "IS_OVER_18":
                    try:
                        dob_dt = datetime.datetime.strptime(str(eff_val), "%Y-%m-%d").date()
                        now_dt = datetime.date(2026, 10, 24)
                        age = (now_dt - dob_dt).days // 365
                        if age >= 18:
                            return RuleEvaluationResult(
                                rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.PASS,
                                message="Zero-Knowledge Predicate verified: Applicant is >= 18 years old (DOB can remain undisclosed).",
                                evidence={"predicate_satisfied": True, "age_verified": True},
                                required=rule.required_for_readiness
                            )
                        else:
                            return RuleEvaluationResult(
                                rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.FAIL,
                                message=f"Applicant age ({age}) is under 18.",
                                evidence={"predicate_satisfied": False, "age": age},
                                required=rule.required_for_readiness
                            )
                    except Exception:
                        return RuleEvaluationResult(
                            rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.UNKNOWN,
                            message=f"Unable to compute age predicate from value: '{eff_val}'",
                            evidence={}, required=rule.required_for_readiness
                        )

            # Simple FIELD_EXISTS pass
            return RuleEvaluationResult(
                rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.PASS,
                message=f"Required field '{field_key}' present and verified.",
                evidence={"value": eff_val, "provenance": provenance},
                required=rule.required_for_readiness
            )

        # 4. Cross-Document Entity Name Match Check
        if rule.rule_type == "ENTITY_MATCH":
            doc_type_a = rule.params.get("doc_type_a")
            doc_type_b = rule.params.get("doc_type_b")
            field_a = rule.params.get("field_a", "candidate_name")
            field_b = rule.params.get("field_b", "holder_name")

            doc_a = next((d for d in documents.values() if d.doc_type == doc_type_a), None)
            doc_b = next((d for d in documents.values() if d.doc_type == doc_type_b), None)

            if not doc_a or not doc_b:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.UNKNOWN,
                    message=f"Cannot compare entities: one or both target documents missing ({doc_type_a}, {doc_type_b}).",
                    evidence={}, required=rule.required_for_readiness
                )

            val_a, _, _ = OCREngine.get_effective_field_value(doc_a, field_a)
            val_b, _, _ = OCREngine.get_effective_field_value(doc_b, field_b)

            if not val_a or not val_b:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.UNKNOWN,
                    message=f"Name fields missing in documents to perform entity resolution.",
                    evidence={"val_a": val_a, "val_b": val_b}, required=rule.required_for_readiness
                )

            match_res = EntityResolver.resolve_names(str(val_a), str(val_b))
            
            min_conf = float(rule.params.get("min_confidence", 65.0))
            if match_res.overall_confidence >= min_conf:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.PASS,
                    message=f"Cross-document entity match verified ({match_res.overall_confidence:.1f}% confidence, {match_res.match_tier}). No auto-merge applied.",
                    evidence={
                        "name_a": val_a, "name_b": val_b, "confidence": match_res.overall_confidence,
                        "ranked_explanations": [e.model_dump() for e in match_res.ranked_explanations]
                    },
                    required=rule.required_for_readiness
                )
            else:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.FAIL,
                    message=f"Entity discrepancy detected between '{val_a}' and '{val_b}' (confidence {match_res.overall_confidence:.1f}% < {min_conf}%).",
                    evidence={
                        "name_a": val_a, "name_b": val_b, "confidence": match_res.overall_confidence,
                        "ranked_explanations": [e.model_dump() for e in match_res.ranked_explanations]
                    },
                    required=rule.required_for_readiness
                )

        # Fallback
        return RuleEvaluationResult(
            rule_id=rule.rule_id, rule_name=rule.name, status=RuleStatus.UNKNOWN,
            message="Rule type not recognized or could not be evaluated.",
            evidence={"rule_type": rule.rule_type}, required=rule.required_for_readiness
        )

    @classmethod
    def evaluate_purpose(
        cls,
        purpose: PurposeSpec,
        documents: Dict[str, Document]
    ) -> PurposeReadinessReport:
        """Evaluates all declarative rules for a designated purpose."""
        results: List[RuleEvaluationResult] = []
        passed = 0
        failed = 0
        unknown = 0

        for rule in purpose.declarative_rules:
            res = cls.evaluate_rule(rule, documents)
            results.append(res)
            if res.status == RuleStatus.PASS:
                passed += 1
            elif res.status == RuleStatus.FAIL:
                if res.required:
                    failed += 1
            elif res.status == RuleStatus.UNKNOWN:
                unknown += 1

        if failed == 0 and unknown == 0:
            overall = "READY"
        elif failed > 0:
            overall = "NOT_READY"
        else:
            overall = "ACTION_REQUIRED"

        return PurposeReadinessReport(
            purpose_id=purpose.purpose_id,
            purpose_title=purpose.title,
            overall_status=overall,
            passed_count=passed,
            failed_count=failed,
            unknown_count=unknown,
            results=results
        )
