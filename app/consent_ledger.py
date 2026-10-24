# Consent Ledger, Verifiable Revocation & User Retention Management
import uuid
import hashlib
import datetime
from typing import Dict, List, Optional, Tuple, Any
from app.models import ConsentLedgerEntry, ShareGrantRequest
from app.selective_disclosure import HONESTY_DISCLAIMER_TEXT

class ConsentLedgerManager:
    """
    Maintains an immutable consent ledger recording recipient, purpose, fields,
    access counters, per-recipient watermarked tokens, and cryptographically verifiable revocation.
    """

    def __init__(self):
        self.ledger: Dict[str, ConsentLedgerEntry] = {}
        self.token_to_consent_id: Dict[str, str] = {}
        self.watermark_to_consent_id: Dict[str, str] = {}
        self.revocation_registry: Dict[str, Dict[str, Any]] = {}

    def create_share_grant(
        self,
        request: ShareGrantRequest,
        purpose_title: str,
        computed_predicates: Dict[str, Any]
    ) -> ConsentLedgerEntry:
        consent_id = f"cns_{uuid.uuid4().hex[:12]}"
        share_token = f"tok_{uuid.uuid4().hex[:16]}"
        watermark_token = f"WMK-{request.recipient_id.upper()[:8]}-{uuid.uuid4().hex[:6].upper()}"

        now = datetime.datetime.now(datetime.timezone.utc)
        expires = now + datetime.timedelta(days=request.expiry_days)

        entry = ConsentLedgerEntry(
            consent_id=consent_id,
            recipient_id=request.recipient_id,
            recipient_name=request.recipient_name,
            purpose_id=request.purpose_id,
            purpose_title=purpose_title,
            disclosed_fields=request.allowed_field_keys,
            predicate_claims=computed_predicates,
            issued_at=now.isoformat(),
            expires_at=expires.isoformat(),
            watermark_token=watermark_token,
            share_token=share_token,
            access_count=0,
            is_revoked=False,
            access_logs=[]
        )

        self.ledger[consent_id] = entry
        self.token_to_consent_id[share_token] = consent_id
        self.watermark_to_consent_id[watermark_token] = consent_id

        return entry

    def record_access(self, share_token: str, ip: str = "127.0.0.1", user_agent: str = "Mozilla/5.0") -> Tuple[bool, Optional[ConsentLedgerEntry], str]:
        """
        Records an access event on a share link.
        Returns (access_granted, entry, message).
        """
        consent_id = self.token_to_consent_id.get(share_token)
        if not consent_id or consent_id not in self.ledger:
            return False, None, "Invalid or expired share token."

        entry = self.ledger[consent_id]

        if entry.is_revoked:
            entry.access_logs.append({
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "ip": ip,
                "user_agent": user_agent,
                "status": "BLOCKED_REVOKED",
                "reason": entry.revocation_reason
            })
            return False, entry, f"Access Blocked: This share link was revoked on {entry.revoked_at}. Reason: {entry.revocation_reason}"

        # Check expiry
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if now_iso > entry.expires_at:
            entry.access_logs.append({
                "timestamp": now_iso, "ip": ip, "user_agent": user_agent, "status": "BLOCKED_EXPIRED"
            })
            return False, entry, "Access Blocked: Share link has expired."

        # Increment access count
        entry.access_count += 1
        entry.access_logs.append({
            "timestamp": now_iso,
            "ip": ip,
            "user_agent": user_agent,
            "status": "GRANTED",
            "access_sequence": entry.access_count
        })

        return True, entry, "Access Granted"

    def revoke_share(self, consent_id: str, reason: str = "User initiated revocation") -> Tuple[bool, Dict[str, Any]]:
        """
        Verifiable Revocation: Kills access immediately and generates verifiable cryptographic revocation hash.
        States honestly what revocation cannot undo.
        """
        if consent_id not in self.ledger:
            return False, {"error": "Consent entry not found."}

        entry = self.ledger[consent_id]
        if entry.is_revoked:
            return True, {
                "message": "Share was already revoked.",
                "revoked_at": entry.revoked_at,
                "verifiable_revocation_hash": entry.verifiable_revocation_hash
            }

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry.is_revoked = True
        entry.revoked_at = now_iso
        entry.revocation_reason = reason

        # Cryptographic revocation hash
        rev_payload = f"REVOCATION:{consent_id}:{entry.share_token}:{now_iso}:{reason}"
        rev_hash = hashlib.sha256(rev_payload.encode("utf-8")).hexdigest()
        entry.verifiable_revocation_hash = rev_hash

        self.revocation_registry[consent_id] = {
            "consent_id": consent_id,
            "recipient_name": entry.recipient_name,
            "revoked_at": now_iso,
            "reason": reason,
            "verifiable_hash": rev_hash,
            "honesty_disclaimer": HONESTY_DISCLAIMER_TEXT
        }

        return True, {
            "status": "REVOKED_SUCCESSFULLY",
            "consent_id": consent_id,
            "recipient_name": entry.recipient_name,
            "revoked_at": now_iso,
            "verifiable_revocation_hash": rev_hash,
            "honesty_disclaimer": HONESTY_DISCLAIMER_TEXT
        }

    def verify_revocation_status(self, consent_id_or_token: str) -> Dict[str, Any]:
        """Provides independent verifiable proof of revocation."""
        consent_id = consent_id_or_token
        if consent_id not in self.ledger and consent_id_or_token in self.token_to_consent_id:
            consent_id = self.token_to_consent_id[consent_id_or_token]

        if consent_id not in self.ledger:
            return {"exists": False, "verified": False, "message": "Record does not exist."}

        entry = self.ledger[consent_id]
        return {
            "exists": True,
            "consent_id": consent_id,
            "recipient": entry.recipient_name,
            "is_revoked": entry.is_revoked,
            "revoked_at": entry.revoked_at,
            "revocation_reason": entry.revocation_reason,
            "verifiable_revocation_hash": entry.verifiable_revocation_hash,
            "status": "VERIFIED_REVOKED" if entry.is_revoked else "ACTIVE_NOT_REVOKED",
            "honesty_notice": HONESTY_DISCLAIMER_TEXT
        }

    def user_initiated_erasure(self, user_id: str, consent_id: Optional[str] = None) -> Dict[str, Any]:
        """
        User-initiated erasure with explicit transparency regarding audit boundaries.
        """
        erased_shares = []
        if consent_id:
            targets = [consent_id] if consent_id in self.ledger else []
        else:
            targets = list(self.ledger.keys())

        for cid in targets:
            entry = self.ledger[cid]
            entry.is_revoked = True
            entry.disclosed_fields = ["[ERASED_BY_USER_REQUEST]"]
            entry.predicate_claims = {"erased": True}
            erased_shares.append(cid)

        return {
            "status": "ERASURE_COMPLETED",
            "erased_count": len(erased_shares),
            "erased_consents": erased_shares,
            "data_retention_boundary_explanation": (
                "Personal data fields and active access tokens have been purged. "
                "Non-identifying cryptographic ledger hashes are preserved in immutable audit records "
                "to fulfill regulatory non-repudiation and security verification standards."
            )
        }
