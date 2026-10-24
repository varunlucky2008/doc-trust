# SecureDoc / TrustVault Data Models
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
import datetime

class DocumentStatus(str, Enum):
    ISSUER_VERIFIED = "ISSUER_VERIFIED"
    USER_UPLOADED = "USER_UPLOADED"
    USER_CORRECTED = "USER_CORRECTED"

class VerificationMode(str, Enum):
    NORMAL = "NORMAL"
    DEGRADED_ISSUER_OFFLINE = "DEGRADED_ISSUER_OFFLINE"

class RuleStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"

class UserAssertion(BaseModel):
    assertion_id: str
    doc_id: str
    field_key: str
    original_ocr_value: Any
    asserted_value: Any
    confidence_assessed: float = 1.0
    justification: str
    user_id: str = "user_graduate_01"
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    provenance_hash: str

class ExtractedField(BaseModel):
    key: str
    label: str
    raw_ocr_value: Any
    ocr_confidence: float # 0.0 to 1.0
    is_confirmed_by_user: bool = False
    current_effective_value: Any = None
    has_user_assertion: bool = False
    latest_assertion: Optional[UserAssertion] = None

class Document(BaseModel):
    doc_id: str
    title: str
    doc_type: str # e.g. "DEGREE_CERTIFICATE", "PASSPORT_ID", "MARKSHEET", "INCOME_CERTIFICATE"
    source_status: DocumentStatus
    issuer_name: str
    issued_date: str # YYYY-MM-DD
    expiry_date: Optional[str] = None
    file_name: str
    file_hash: str
    raw_text: str
    extracted_fields: Dict[str, ExtractedField]
    user_assertions: List[UserAssertion] = []
    is_immutable_source: bool = True
    tamper_detected: bool = False
    tamper_details: Optional[Dict[str, Any]] = None
    injection_detected: bool = False
    injection_details: Optional[Dict[str, Any]] = None
    is_revoked_by_issuer: bool = False
    issuer_superseded_by: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

class EntityMatchExplanation(BaseModel):
    factor: str
    description: str
    score_impact: float # e.g. +30.0, -10.0

class EntityMatchResult(BaseModel):
    entity_a_value: str
    entity_b_value: str
    entity_type: str # "PERSON_NAME", "IDENTIFIER", "ADDRESS"
    overall_confidence: float # 0 to 100
    rank: int
    ranked_explanations: List[EntityMatchExplanation]
    match_tier: str # "HIGH_CONFIDENCE_MATCH", "PROBABLE_MATCH", "POSSIBLE_DISCREPANCY", "MISMATCH"
    auto_merged: bool = False # Must ALWAYS be False
    user_confirmed: Optional[bool] = None

class DeclarativeRule(BaseModel):
    rule_id: str
    name: str
    rule_type: str # "FIELD_EXISTS", "DATE_WITHIN_DAYS", "MIN_VALUE", "EQUALS", "PREDICATE_CHECK", "ISSUER_VERIFIED", "ENTITY_MATCH"
    target_doc_type: Optional[str] = None
    field_key: Optional[str] = None
    params: Dict[str, Any] = {}
    failure_message: str
    required_for_readiness: bool = True

class PurposeSpec(BaseModel):
    purpose_id: str
    title: str
    recipient_type: str # "EMPLOYER", "SCHOLARSHIP_BOARD", "OVERSEAS_EVALUATOR", "CUSTOM"
    description: str
    allowed_fields: List[str]
    predicate_rules: List[str]
    declarative_rules: List[DeclarativeRule]
    excessive_fields_blacklisted: List[str] = []

class RuleEvaluationResult(BaseModel):
    rule_id: str
    rule_name: str
    status: RuleStatus # PASS, FAIL, UNKNOWN
    message: str
    evidence: Dict[str, Any]
    required: bool

class PurposeReadinessReport(BaseModel):
    purpose_id: str
    purpose_title: str
    overall_status: str # "READY", "NOT_READY", "ACTION_REQUIRED"
    passed_count: int
    failed_count: int
    unknown_count: int
    results: List[RuleEvaluationResult]
    evaluated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

class ShareGrantRequest(BaseModel):
    purpose_id: str
    recipient_id: str
    recipient_name: str
    allowed_field_keys: List[str]
    predicates_enabled: Dict[str, bool] # e.g. {"is_over_18": True, "degree_passed": True}
    expiry_days: int = 7
    allow_download: bool = False

class ShareReceipt(BaseModel):
    receipt_id: str
    consent_id: str
    recipient_name: str
    recipient_id: str
    purpose_id: str
    purpose_title: str
    disclosed_attributes: List[str]
    predicate_disclosures: Dict[str, Any]
    issued_at: str
    expires_at: str
    digital_signature: str
    share_url: str
    watermark_token: str
    honesty_disclaimer: str

class ConsentLedgerEntry(BaseModel):
    consent_id: str
    recipient_id: str
    recipient_name: str
    purpose_id: str
    purpose_title: str
    disclosed_fields: List[str]
    predicate_claims: Dict[str, Any]
    issued_at: str
    expires_at: str
    watermark_token: str
    share_token: str
    access_count: int = 0
    is_revoked: bool = False
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None
    verifiable_revocation_hash: Optional[str] = None
    access_logs: List[Dict[str, Any]] = []

class LeakedLinkTraceResult(BaseModel):
    token_queried: str
    found: bool
    recipient_id: Optional[str] = None
    recipient_name: Optional[str] = None
    purpose_title: Optional[str] = None
    access_count: int = 0
    is_revoked: bool = False
    leak_source_assessment: str
    other_active_shares_unaffected_count: int = 0
    surgical_kill_available: bool = True
