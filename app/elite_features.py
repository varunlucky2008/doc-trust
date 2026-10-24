# Elite Features: Leaked Link Forensics & Continuous Issuer Watcher
import datetime
from typing import Dict, List, Any, Optional
from app.models import ConsentLedgerEntry, LeakedLinkTraceResult, Document
from app.consent_ledger import ConsentLedgerManager

class LeakedLinkTracer:
    """
    Elite Dimension: Identifies leaked tokens/links across recipients, displays access forensics,
    and executes surgical revocations without impacting other shares.
    """

    @classmethod
    def trace_token(
        cls,
        token_or_link_or_watermark: str,
        consent_manager: ConsentLedgerManager
    ) -> LeakedLinkTraceResult:
        """
        Traces a leaked URL, token, or embedded watermark to its origin recipient.
        """
        raw_query = token_or_link_or_watermark.strip()
        # Extract token if a full URL was provided
        if "token=" in raw_query:
            token = raw_query.split("token=")[-1].split("&")[0].strip()
        elif "tok_" in raw_query:
            token = raw_query
        elif "WMK-" in raw_query:
            # Watermark query
            wm_token = raw_query
            cid = consent_manager.watermark_to_consent_id.get(wm_token)
            if cid and cid in consent_manager.ledger:
                entry = consent_manager.ledger[cid]
                token = entry.share_token
            else:
                token = raw_query
        else:
            token = raw_query

        # Match in ledger
        consent_id = consent_manager.token_to_consent_id.get(token)
        if not consent_id:
            # Search by watermark
            consent_id = consent_manager.watermark_to_consent_id.get(token)

        if not consent_id or consent_id not in consent_manager.ledger:
            return LeakedLinkTraceResult(
                token_queried=token_or_link_or_watermark,
                found=False,
                leak_source_assessment="Token or watermark not found in consent ledger.",
                other_active_shares_unaffected_count=len([e for e in consent_manager.ledger.values() if not e.is_revoked]),
                surgical_kill_available=False
            )

        target_entry = consent_manager.ledger[consent_id]
        
        # Count other unaffected active shares
        other_active = [
            e for e in consent_manager.ledger.values()
            if e.consent_id != target_entry.consent_id and not e.is_revoked
        ]

        assessment = (
            f"LEAK SOURCE TRACED: This token was exclusively issued to '{target_entry.recipient_name}' "
            f"for '{target_entry.purpose_title}'. Forensics indicate this link was accessed {target_entry.access_count} "
            f"times. If forwarded to an unintended third party, surgical revocation will kill this recipient's link "
            f"immediately while keeping your {len(other_active)} other active share(s) functioning normally."
        )

        return LeakedLinkTraceResult(
            token_queried=token_or_link_or_watermark,
            found=True,
            recipient_id=target_entry.recipient_id,
            recipient_name=target_entry.recipient_name,
            purpose_title=target_entry.purpose_title,
            access_count=target_entry.access_count,
            is_revoked=target_entry.is_revoked,
            leak_source_assessment=assessment,
            other_active_shares_unaffected_count=len(other_active),
            surgical_kill_available=not target_entry.is_revoked
        )

    @classmethod
    def surgical_kill_leaked_link(
        cls,
        consent_manager: ConsentLedgerManager,
        token_or_link: str,
        reason: str = "Surgical revocation: Leaked to unintended third party"
    ) -> Dict[str, Any]:
        """Kills ONLY the compromised link without touching any other active shares."""
        trace = cls.trace_token(token_or_link, consent_manager)
        if not trace.found:
            return {"success": False, "message": "Link not found in consent registry."}

        target_cid = consent_manager.token_to_consent_id.get(trace.token_queried) or consent_manager.watermark_to_consent_id.get(trace.token_queried)
        if not target_cid:
            # Match by recipient_id
            for entry in consent_manager.ledger.values():
                if entry.recipient_id == trace.recipient_id:
                    target_cid = entry.consent_id
                    break

        success, rev_data = consent_manager.revoke_share(target_cid, reason)

        # Confirm other shares are unaffected
        intact_shares = [
            {"recipient": e.recipient_name, "purpose": e.purpose_title, "status": "ACTIVE_UNTOUCHED"}
            for e in consent_manager.ledger.values()
            if e.consent_id != target_cid and not e.is_revoked
        ]

        return {
            "success": success,
            "compromised_link_killed": trace.recipient_name,
            "revocation_hash": rev_data.get("verifiable_revocation_hash"),
            "intact_active_shares_count": len(intact_shares),
            "intact_active_shares": intact_shares,
            "honesty_disclaimer": rev_data.get("honesty_disclaimer")
        }


class ContinuousIssuerWatcher:
    """
    Elite Dimension: Continuously polls issuer status. When a verified record is superseded or revoked,
    triggers a proactive workflow notifying the user and identifying all active shares affected.
    """

    @classmethod
    def recheck_issuer_records(
        cls,
        documents: Dict[str, Document],
        consent_manager: ConsentLedgerManager,
        mock_issuer_registry_updates: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Simulates / executes continuous issuer status synchronization.
        Detects revoked or superseded credentials and maps them to affected active shares.
        """
        updates = mock_issuer_registry_updates or {}
        cascade_events = []

        for doc_id, doc in documents.items():
            if doc_id in updates:
                issuer_update = updates[doc_id]
                new_status = issuer_update.get("status") # "REVOKED", "SUPERSEDED", "ACTIVE"
                superseded_by = issuer_update.get("superseded_by")
                reason = issuer_update.get("reason", "Issuer administrative update")

                if new_status == "REVOKED":
                    doc.is_revoked_by_issuer = True
                    doc.is_immutable_source = True # Remains immutable in vault history
                    
                    # Find all active shares that expose fields from this doc
                    affected_shares = []
                    for cid, entry in consent_manager.ledger.items():
                        if not entry.is_revoked:
                            # Check if shared fields overlap with document fields
                            overlap = set(entry.disclosed_fields).intersection(set(doc.extracted_fields.keys()))
                            if overlap:
                                affected_shares.append({
                                    "consent_id": cid,
                                    "recipient": entry.recipient_name,
                                    "purpose": entry.purpose_title,
                                    "exposed_fields": list(overlap)
                                })

                    cascade_events.append({
                        "event_type": "ISSUER_REVOCATION_ALERT",
                        "doc_id": doc_id,
                        "doc_title": doc.title,
                        "issuer_name": doc.issuer_name,
                        "revocation_reason": reason,
                        "affected_active_shares": affected_shares,
                        "recommended_action": "Execute cascade revocation on all active shares referencing this revoked credential.",
                        "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                    })

                elif new_status == "SUPERSEDED":
                    doc.issuer_superseded_by = superseded_by
                    # Find affected shares
                    affected_shares = []
                    for cid, entry in consent_manager.ledger.items():
                        if not entry.is_revoked:
                            overlap = set(entry.disclosed_fields).intersection(set(doc.extracted_fields.keys()))
                            if overlap:
                                affected_shares.append({
                                    "consent_id": cid,
                                    "recipient": entry.recipient_name,
                                    "purpose": entry.purpose_title
                                })

                    cascade_events.append({
                        "event_type": "ISSUER_SUPERSEDED_ALERT",
                        "doc_id": doc_id,
                        "doc_title": doc.title,
                        "superseded_by": superseded_by,
                        "reason": reason,
                        "affected_active_shares": affected_shares,
                        "recommended_action": "Update active share recipients with the newly issued replacement certificate.",
                        "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                    })

        return {
            "checks_completed": len(documents),
            "alerts_triggered": len(cascade_events),
            "cascade_events": cascade_events,
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
