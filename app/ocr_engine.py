# OCR Engine, Side-by-Side Visualizer & Immutable Provenance Assertion Layer
import hashlib
import datetime
from typing import Dict, Any, List, Optional, Tuple
from app.models import Document, ExtractedField, UserAssertion, DocumentStatus

class OCREngine:
    """
    Manages OCR data extraction, per-field confidence, immutability of source documents,
    and the user assertion correction layer with cryptographic provenance hashes.
    """

    @staticmethod
    def generate_provenance_hash(
        doc_id: str, field_key: str, old_val: Any, new_val: Any, user_id: str, reason: str, timestamp: str
    ) -> str:
        payload = f"{doc_id}:{field_key}:{str(old_val)}:{str(new_val)}:{user_id}:{reason}:{timestamp}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def apply_user_assertion(
        cls,
        doc: Document,
        field_key: str,
        asserted_value: Any,
        reason: str,
        user_id: str = "user_graduate_01"
    ) -> UserAssertion:
        """
        Creates a separate correction layer assertion.
        Source document and raw OCR values remain strictly immutable!
        """
        if field_key not in doc.extracted_fields:
            raise KeyError(f"Field key '{field_key}' not found in document extracted fields.")

        target_field = doc.extracted_fields[field_key]
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        prov_hash = cls.generate_provenance_hash(
            doc.doc_id, field_key, target_field.raw_ocr_value, asserted_value, user_id, reason, now_ts
        )

        assertion = UserAssertion(
            assertion_id=f"asrt_{len(doc.user_assertions) + 1}_{field_key}",
            doc_id=doc.doc_id,
            field_key=field_key,
            original_ocr_value=target_field.raw_ocr_value,
            asserted_value=asserted_value,
            confidence_assessed=1.0, # Human user assertion is 100% authoritative for the user
            justification=reason,
            user_id=user_id,
            timestamp=now_ts,
            provenance_hash=prov_hash
        )

        doc.user_assertions.append(assertion)
        target_field.has_user_assertion = True
        target_field.latest_assertion = assertion
        target_field.current_effective_value = asserted_value
        target_field.is_confirmed_by_user = True

        # Upgrade document status to USER_CORRECTED if it wasn't already issuer-verified
        if doc.source_status != DocumentStatus.ISSUER_VERIFIED:
            doc.source_status = DocumentStatus.USER_CORRECTED

        return assertion

    @classmethod
    def confirm_ocr_field(cls, doc: Document, field_key: str) -> ExtractedField:
        """
        Explicit user confirmation of raw OCR output.
        CONSTRAINT: Never treat OCR output as authoritative without explicit user confirmation.
        """
        if field_key not in doc.extracted_fields:
            raise KeyError(f"Field key '{field_key}' not found in document.")

        field = doc.extracted_fields[field_key]
        field.is_confirmed_by_user = True
        if field.current_effective_value is None:
            field.current_effective_value = field.raw_ocr_value
        return field

    @classmethod
    def get_effective_field_value(cls, doc: Document, field_key: str) -> Tuple[Any, bool, str]:
        """
        Returns (effective_value, is_confirmed, provenance_source).
        Provenance source: 'ISSUER_AUTHORITATIVE', 'USER_ASSERTION', 'CONFIRMED_OCR', 'UNCONFIRMED_OCR'.
        """
        if field_key not in doc.extracted_fields:
            return None, False, "FIELD_MISSING"

        field = doc.extracted_fields[field_key]
        if doc.source_status == DocumentStatus.ISSUER_VERIFIED:
            return field.raw_ocr_value, True, "ISSUER_AUTHORITATIVE"

        if field.has_user_assertion and field.latest_assertion:
            return field.latest_assertion.asserted_value, True, "USER_ASSERTION"

        if field.is_confirmed_by_user:
            return field.raw_ocr_value, True, "CONFIRMED_OCR"

        return field.raw_ocr_value, False, "UNCONFIRMED_OCR"

    @classmethod
    def build_side_by_side_view(cls, doc: Document) -> List[Dict[str, Any]]:
        """
        Generates structured data for side-by-side source-versus-extracted comparison.
        """
        view_items = []
        for key, field in doc.extracted_fields.items():
            eff_val, is_conf, prov = cls.get_effective_field_value(doc, key)
            view_items.append({
                "field_key": key,
                "label": field.label,
                "raw_ocr_value": field.raw_ocr_value,
                "ocr_confidence": round(field.ocr_confidence * 100, 1),
                "is_confirmed_by_user": field.is_confirmed_by_user,
                "current_effective_value": eff_val,
                "has_user_assertion": field.has_user_assertion,
                "provenance_status": prov,
                "assertion_details": field.latest_assertion.model_dump() if field.latest_assertion else None,
                "confidence_grade": "High" if field.ocr_confidence >= 0.85 else ("Medium" if field.ocr_confidence >= 0.70 else "Low (Needs Review)")
            })
        return view_items
