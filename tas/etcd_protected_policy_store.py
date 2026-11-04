#
# TEE Attestation Service - etcd-Protected Policy Store
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import hashlib
import json
import re
import time
import uuid
from collections.abc import Generator, Sequence
from dataclasses import dataclass
from typing import Optional

from .etcd_client import EtcdClient, EtcdKV
from .policy_store import (
    ApprovedPolicy,
    PolicyAlreadyExists,
    PolicyApproval,
    PolicyAuthorizationDenied,
    PolicyStore,
    PolicyStoreUnavailable,
    validate_policy_namespace,
)
from .publication_store import PublicationKey, PublicationStore
from .tas_logging import get_logger

# Rollback protection overview
# ============================
#
# Threat: someone who controls the policy database (Redis or PostgreSQL) can
# restore an old backup. Without protection, TAS would then serve a policy
# that was deleted or replaced, for example one that still trusts revoked
# firmware.
#
# Design: split each policy into two parts held in different places.
#
#   etcd (trusted, must not roll back)       Redis / PostgreSQL (untrusted)
#   ----------------------------------       ------------------------------
#   /tas/policy-auth/<ns>/<policy-id>        publication <ns, id, pub-id>
#     {                                        = the policy document,
#       "format_version": 1,                     written once, never
#       "publication_id": <uuid>,  ----------->  updated in place
#       "status": "pending" | "active",
#       "document_digest": sha256(document)
#     }
#
# The etcd approval record says which publication is current and what its
# SHA-256 digest must be. The database only holds documents. Every create
# uses a new random publication ID, so a replaced policy never reuses an
# old ID.
#
# Read path (load_approved / list):
#
#   etcd approval --missing or pending--> "not found"
#        |
#        | active: publication_id + digest + mod_revision
#        v
#   publication store --missing--> 503 policy_integrity_error
#        |
#        | document
#        v
#   sha256(document) == digest and metadata.policy_id matches?
#        |-- no  --> 503 policy_integrity_error
#        '-- yes --> ApprovedPolicy(document, PolicyApproval(mod_revision))
#
# Why a database rollback is caught:
#
#   time  etcd approval for P           database rows for P
#   ----  -------------------------     ---------------------------
#   t1    active -> pub A (digest dA)   A
#   t2    active -> pub B (digest dB)   A, B   (P replaced)
#   t3    (unchanged)                   B      (A cleaned up)
#   t4    attacker restores t1 backup   A      (B lost)
#
#   At t4 etcd still names pub B, which is missing, so TAS returns 503
#   instead of serving A. If P had been deleted, etcd has no approval, so
#   the restored A is never served ("not found"). Old rows can exist in the
#   database, but nothing in etcd points to them.
#
# Final check (check_approvals): attestation can take seconds. Callers keep
# each approval's etcd mod_revision and, just before releasing a secret or
# signing a certificate, ask etcd in one read-only transaction whether every
# revision is unchanged. A delete or replace during attestation changes the
# revision, so the request is denied.
#
# Writes use etcd compare-and-swap transactions (put_if_absent,
# put_if_revision, delete_if_revision) instead of locks, so several TAS
# instances can share one etcd without a leader. See create() and delete()
# for the step-by-step workflows and their error handling.
#
# Limit: this only protects against rollback of the database. If etcd
# itself is restored to an old state, its old approvals become current
# again. Deployments must keep etcd somewhere that cannot be rolled back.
logger = get_logger(__name__)

POLICY_AUTH_PREFIX = b"/tas/policy-auth/"
POLICY_AUTH_FORMAT_KEY = b"/tas/control/policy-auth-format"
POLICY_AUTH_FORMAT = b"1"
RECORD_FORMAT_VERSION = 1
_POLICY_ID_RE = re.compile(r"[A-Za-z0-9._-]+\Z")
_DIGEST_RE = re.compile(r"[a-f0-9]{64}\Z")


@dataclass(frozen=True)
class _ApprovalRecord:
    publication_id: str
    status: str
    document_digest: str


def _encode_record(record: _ApprovalRecord) -> bytes:
    return json.dumps(
        {
            "format_version": RECORD_FORMAT_VERSION,
            "publication_id": record.publication_id,
            "status": record.status,
            "document_digest": record.document_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _decode_record(raw: bytes) -> _ApprovalRecord:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyStoreUnavailable(
            "Policy approval record is malformed",
            reason_code="policy_integrity_error",
        ) from exc
    format_version = value.get("format_version") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or isinstance(format_version, bool)
        or format_version != RECORD_FORMAT_VERSION
    ):
        raise PolicyStoreUnavailable(
            "Policy approval record has an unsupported format",
            reason_code="policy_integrity_error",
        )
    publication_id = value.get("publication_id")
    status = value.get("status")
    digest = value.get("document_digest")
    try:
        parsed_id = uuid.UUID(publication_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise PolicyStoreUnavailable(
            "Policy approval record has an invalid publication ID",
            reason_code="policy_integrity_error",
        ) from exc
    if (
        str(parsed_id) != publication_id
        or status not in ("pending", "active")
        or not isinstance(digest, str)
        or not _DIGEST_RE.fullmatch(digest)
    ):
        raise PolicyStoreUnavailable(
            "Policy approval record has invalid fields",
            reason_code="policy_integrity_error",
        )
    return _ApprovalRecord(publication_id, status, digest)


def _document_digest(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


class EtcdProtectedPolicyStore(PolicyStore):
    """PolicyStore that authorizes immutable publications through etcd.

    The unprotected policy store is used in the supported
    ``TAS_POLICY_AUTHORIZATION=none`` mode, without etcd rollback protection.
    In protected mode, it supplies the backend name and reachability check and
    removes documents stored in mode ``none`` during deletion.
    """

    def __init__(
        self,
        etcd: EtcdClient,
        publications: PublicationStore,
        unprotected_policy_store: PolicyStore,
        operation_timeout_seconds: int = 20,
    ):
        self._etcd = etcd
        self._publications = publications
        self._unprotected_policy_store = unprotected_policy_store
        self._operation_timeout = float(operation_timeout_seconds)
        self.backend_name = unprotected_policy_store.backend_name

        marker = self._etcd.get(POLICY_AUTH_FORMAT_KEY)
        if marker is None or marker.value != POLICY_AUTH_FORMAT:
            raise RuntimeError(
                "The policy authorization format marker is missing or invalid; "
                "provision /tas/control/policy-auth-format with value '1'"
            )

    @staticmethod
    def _identity(namespace: str, policy_id: str) -> tuple[bytes, PublicationKey]:
        validate_policy_namespace(namespace)
        if not isinstance(policy_id, str) or not _POLICY_ID_RE.fullmatch(policy_id):
            raise ValueError("Invalid policy ID")
        return POLICY_AUTH_PREFIX + namespace.encode("utf-8") + b"/" + policy_id.encode(
            "utf-8"
        ), (namespace, policy_id, "")

    @classmethod
    def _approval_key(cls, namespace: str, policy_id: str) -> bytes:
        key, _ = cls._identity(namespace, policy_id)
        return key

    @staticmethod
    def _deadline(timeout: float) -> float:
        return time.monotonic() + timeout

    @staticmethod
    def _check_deadline(deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise PolicyStoreUnavailable(
                "Policy operation exceeded its configured deadline",
                reason_code="policy_operation_timeout",
            )

    @staticmethod
    def _read_record(
        etcd: EtcdClient, key: bytes
    ) -> tuple[EtcdKV, _ApprovalRecord] | None:
        item = etcd.get(key)
        if item is None:
            return None
        return item, _decode_record(item.value)

    @staticmethod
    def _same_target(first: EtcdKV, second: EtcdKV) -> bool:
        try:
            first_record = _decode_record(first.value)
            second_record = _decode_record(second.value)
        except PolicyStoreUnavailable:
            return first.value == second.value
        return first_record.publication_id == second_record.publication_id

    def _reserve(
        self,
        key: bytes,
        value: bytes,
        namespace: str,
        policy_id: str,
        publication_id: str,
        deadline: float,
    ) -> int:
        self._check_deadline(deadline)
        try:
            succeeded, _ = self._etcd.put_if_absent(key, value)
        except PolicyStoreUnavailable:
            # The write may have committed before its response was lost.
            # Read back the record rather than assuming it failed. If the read
            # fails too, its error propagates.
            current = self._read_record(self._etcd, key)
            if current is None:
                # The reservation cannot be confirmed; propagate the error.
                raise
            item, record = current
            if record.publication_id != publication_id or record.status != "pending":
                # A different publication, or a non-pending record, owns the ID.
                raise PolicyAlreadyExists(namespace, policy_id) from None
            # Our pending reservation exists; use its revision for activation.
            return item.mod_revision

        if not succeeded:
            # The key existed when etcd compared it. If it disappeared before
            # this read, report an uncertain outcome rather than a conflict.
            current = self._etcd.get(key)
            if current is None:
                raise PolicyStoreUnavailable(
                    "Policy reservation outcome is uncertain",
                    reason_code="authority_unavailable",
                )
            raise PolicyAlreadyExists(namespace, policy_id)

        # A concurrent delete or replacement may have changed the record
        # since the write. Only activate our own pending reservation.
        current = self._etcd.get(key)
        if current is None:
            raise PolicyStoreUnavailable(
                "Policy reservation is missing after commit",
                reason_code="authority_unavailable",
            )
        record = _decode_record(current.value)
        if record.publication_id != publication_id or record.status != "pending":
            raise PolicyStoreUnavailable(
                "Policy reservation changed after commit",
                reason_code="policy_integrity_error",
            )
        return current.mod_revision

    def _remove_owned_reservation(self, key: bytes, revision: int) -> None:
        # Do not delete a newer reservation. If cleanup fails, a later delete
        # can try to remove the pending record.
        try:
            self._etcd.delete_if_revision(key, revision)
        except PolicyStoreUnavailable:
            logger.warning(
                "Could not remove pending policy approval; delete can recover it"
            )

    def create(self, namespace: str, policy_id: str, document: str) -> None:
        # Create spans two stores: reserve the policy ID in etcd as pending,
        # store the document, then activate the approval. Pending approvals
        # are not served, so an interrupted create cannot expose partial data.
        #
        #   1. etcd  put_if_absent(key, pending)  --exists--> 409
        #   2. db    insert(pub-id, document)     --fails---> remove reservation
        #   3. etcd  put_if_revision(key, rev, active)
        #              '--revision changed (concurrent delete)--> drop pub, 409
        #
        # Every error path first reads back the current state, because an
        # error response can follow a write that actually committed.
        key = self._approval_key(namespace, policy_id)
        publication_id = str(uuid.uuid4())
        digest = _document_digest(document)
        deadline = self._deadline(self._operation_timeout)
        pending = _encode_record(_ApprovalRecord(publication_id, "pending", digest))

        # A conflict or authority error stops the create before a publication
        # is written, although an uncertain write can leave a pending record.
        try:
            pending_revision = self._reserve(
                key, pending, namespace, policy_id, publication_id, deadline
            )
        except PolicyAlreadyExists:
            raise
        except PolicyStoreUnavailable:
            raise

        # Store the document separately while the etcd approval is still pending.
        publication_key = (namespace, policy_id, publication_id)
        # A deadline error here may leave the reservation pending; a later
        # delete can try to clean it up.
        self._check_deadline(deadline)
        try:
            inserted = self._publications.insert(
                namespace, policy_id, publication_id, document
            )
        except PolicyStoreUnavailable:
            # The insert may have succeeded despite the error. If read-back
            # also fails, its error propagates and the reservation may remain.
            stored = self._publications.get(namespace, policy_id, publication_id)
            if stored != document:
                # No matching document: try to remove our reservation, then
                # propagate the original insert error.
                self._remove_owned_reservation(key, pending_revision)
                raise
            inserted = True
        if not inserted:
            # An existing key is safe to reuse only if its document matches.
            # A missing or different document is an integrity error. A failed
            # read propagates and may leave the reservation pending.
            stored = self._publications.get(namespace, policy_id, publication_id)
            if stored != document:
                self._remove_owned_reservation(key, pending_revision)
                raise PolicyStoreUnavailable(
                    "Publication ID collision has different content",
                    reason_code="policy_integrity_error",
                )

        # Activate only if the reservation still has the expected revision;
        # this prevents a stale create from undoing a concurrent delete.
        # A deadline error stops retries and may leave a pending approval.
        active = _encode_record(_ApprovalRecord(publication_id, "active", digest))
        while True:
            self._check_deadline(deadline)
            try:
                succeeded, _ = self._etcd.put_if_revision(key, pending_revision, active)
            except PolicyStoreUnavailable:
                # Activation may have committed despite the error. If this
                # read also fails, propagate that error without guessing.
                current = self._read_record(self._etcd, key)
                if current is None:
                    # The approval disappeared. Remove our unapproved document
                    # and propagate the error; cleanup errors also propagate.
                    self._publications.delete(*publication_key)
                    raise
                item, record = current
                if record.publication_id != publication_id:
                    # Another publication owns the policy ID. Discard ours and
                    # report a conflict instead of replacing that approval.
                    self._publications.delete(*publication_key)
                    raise PolicyAlreadyExists(namespace, policy_id) from None
                if record.status == "active":
                    # Our approval is already active, so the create succeeded.
                    return
                # It is still our pending approval; retry with its latest revision.
                pending_revision = item.mod_revision
                continue

            if succeeded:
                return

            # A failed comparison means the reservation changed or disappeared.
            # Our active record is success; our pending record can be retried.
            # If the read fails, its error propagates and the document may remain.
            current = self._read_record(self._etcd, key)
            if current is not None:
                item, record = current
                if record.publication_id == publication_id:
                    if record.status == "active":
                        return
                    pending_revision = item.mod_revision
                    continue
            # A missing or different reservation means this create lost the
            # race. Remove our publication and report a conflict; a cleanup
            # error propagates instead.
            self._publications.delete(*publication_key)
            raise PolicyAlreadyExists(namespace, policy_id)

    def load_approved(self, namespace: str, policy_id: str) -> ApprovedPolicy | None:
        key = self._approval_key(namespace, policy_id)
        item_record = self._read_record(self._etcd, key)
        if item_record is None:
            return None
        item, record = item_record
        if record.status != "active":
            return None

        document = self._publications.get(namespace, policy_id, record.publication_id)
        if document is None:
            raise PolicyStoreUnavailable(
                "Active policy publication is missing",
                reason_code="policy_integrity_error",
            )
        if _document_digest(document) != record.document_digest:
            raise PolicyStoreUnavailable(
                "Active policy publication digest does not match",
                reason_code="policy_integrity_error",
            )
        self._validate_document_identity(document, policy_id)
        return ApprovedPolicy(
            document,
            PolicyApproval(namespace, policy_id, item.mod_revision),
        )

    def check_approvals(self, approvals: Sequence[PolicyApproval]) -> None:
        revisions = [
            (
                self._approval_key(approval.namespace, approval.policy_id),
                approval.revision,
            )
            for approval in approvals
        ]
        # Check all revisions together so a concurrent policy change denies
        # the operation before it releases a secret or signs a certificate.
        if not self._etcd.check_revisions(revisions):
            raise PolicyAuthorizationDenied(
                "Policy approval changed before the final authorization check"
            )

    def get(self, namespace: str, policy_id: str) -> Optional[str]:
        approved = self.load_approved(namespace, policy_id)
        return approved.document if approved is not None else None

    @staticmethod
    def _validate_document_identity(document: str, policy_id: str) -> None:
        try:
            parsed = json.loads(document)
        except json.JSONDecodeError as exc:
            raise PolicyStoreUnavailable(
                "Active policy publication is invalid JSON",
                reason_code="policy_integrity_error",
            ) from exc
        metadata = parsed.get("metadata") if isinstance(parsed, dict) else None
        if not isinstance(metadata, dict) or metadata.get("policy_id") != policy_id:
            raise PolicyStoreUnavailable(
                "Active policy publication identity does not match",
                reason_code="policy_integrity_error",
            )

    def list(self, namespace: str) -> Generator[str, None, None]:
        validate_policy_namespace(namespace)
        prefix = POLICY_AUTH_PREFIX + namespace.encode("utf-8") + b"/"
        records: list[tuple[str, EtcdKV, _ApprovalRecord]] = []
        for item in self._etcd.range_prefix(prefix):
            if not item.key.startswith(prefix):
                raise PolicyStoreUnavailable(
                    "etcd returned a key outside the policy prefix",
                    reason_code="authority_invalid_response",
                )
            try:
                raw_id = item.key[len(prefix) :].decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise PolicyStoreUnavailable(
                    "Policy approval has an invalid identity",
                    reason_code="policy_integrity_error",
                ) from exc
            if not _POLICY_ID_RE.fullmatch(raw_id):
                raise PolicyStoreUnavailable(
                    "Policy approval has an invalid identity",
                    reason_code="policy_integrity_error",
                )
            record = _decode_record(item.value)
            if record.status == "active":
                records.append((raw_id, item, record))

        publication_keys = [
            (namespace, policy_id, record.publication_id)
            for policy_id, _, record in records
        ]
        documents = self._publications.get_many(publication_keys)
        result = []
        for policy_id, _, record in records:
            publication_key = (namespace, policy_id, record.publication_id)
            document = documents.get(publication_key)
            if document is None or _document_digest(document) != record.document_digest:
                raise PolicyStoreUnavailable(
                    f"Active policy publication '{policy_id}' is missing or corrupt",
                    reason_code="policy_integrity_error",
                )
            self._validate_document_identity(document, policy_id)
            result.append(document)

        def generate():
            yield from result

        return generate()

    def delete(self, namespace: str, policy_id: str) -> bool:
        # Delete has two phases:
        #
        #   1. Revoke: delete the etcd approval. Later protected reads cannot
        #      find it, and requests holding its revision fail check_approvals.
        #   2. Clean up: delete publications and any policy stored in mode
        #      "none". Protected reads ignore documents without an approval,
        #      but mode "none" does not check etcd.
        #
        # Revocation must target the record this call saw, not a newer one.
        # A concurrent create may re-create the policy during the delete;
        # that new policy must survive:
        #
        #   delete reads the approval: rev 10, pub A
        #   meanwhile, either:
        #     a) create activates pub A   -> rev 11, same pub:  retry at rev 11
        #     b) another delete, then a
        #        new create of pub B      -> rev 12, other pub: stop, keep B
        key = self._approval_key(namespace, policy_id)
        deadline = self._deadline(self._operation_timeout)
        removed_authority = False
        first = self._etcd.get(key)

        while first is not None:
            self._check_deadline(deadline)
            try:
                deleted = self._etcd.delete_if_revision(key, first.mod_revision)
            except PolicyStoreUnavailable:
                # The delete may have committed before the response was lost.
                current = self._etcd.get(key)
                if current is None:
                    # Gone: treat our delete as successful.
                    removed_authority = True
                    break
                if not self._same_target(first, current):
                    # A different publication now owns the ID: a newer
                    # create, which this delete must not remove.
                    break
                # Same publication, possibly pending -> active; try again.
                first = current
                continue
            if deleted:
                removed_authority = True
                break

            # The revision no longer matched. Re-read and decide as above.
            current = self._etcd.get(key)
            if current is None:
                # Another delete removed it first; it is not ours to count.
                break
            if not self._same_target(first, current):
                break
            first = current

        # Cleanup runs even if this call did not remove the approval, so a
        # repeated delete can finish an earlier delete's interrupted cleanup.
        try:
            self._check_deadline(deadline)
            publication_ids = self._publications.list_ids(namespace, policy_id)
            # Never delete the publication of a policy that is active (or
            # being created) now; a concurrent create may own it.
            current = self._etcd.get(key)
            current_publication_id = None
            if current is not None:
                try:
                    record = _decode_record(current.value)
                    current_publication_id = record.publication_id
                except PolicyStoreUnavailable:
                    current_publication_id = None

            removed_publication = False
            for publication_id in publication_ids:
                self._check_deadline(deadline)
                if publication_id == current_publication_id:
                    continue
                removed_publication = (
                    self._publications.delete(namespace, policy_id, publication_id)
                    or removed_publication
                )
            # Also remove any document stored in mode "none", so switching
            # back to that mode cannot serve a revoked policy.
            self._check_deadline(deadline)
            removed_unprotected_policy = self._unprotected_policy_store.delete(
                namespace, policy_id
            )
        except PolicyStoreUnavailable as exc:
            # Revocation in phase 1 still stands; report the partial cleanup
            # so the operator can repeat the delete.
            raise PolicyStoreUnavailable(
                "Policy revocation succeeded but cleanup is incomplete",
                reason_code="cleanup_incomplete",
            ) from exc

        # True if an approval, publication, or mode "none" policy was removed.
        return removed_authority or removed_publication or removed_unprotected_policy

    def is_reachable(self) -> bool:
        try:
            marker = self._etcd.get(POLICY_AUTH_FORMAT_KEY)
            return (
                marker is not None
                and marker.value == POLICY_AUTH_FORMAT
                and self._publications.is_reachable()
                and self._unprotected_policy_store.is_reachable()
            )
        except PolicyStoreUnavailable:
            return False
