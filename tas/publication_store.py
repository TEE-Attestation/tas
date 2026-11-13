#
# TEE Attestation Service - Immutable Policy Publication Storage
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Optional

from .policy_store import validate_policy_namespace

PublicationKey = tuple[str, str, str]


class PublicationStore(ABC):
    """Store immutable versions of policy documents.

    In rollback-protected mode, ``EtcdProtectedPolicyStore`` records in
    etcd which publication is active. This store holds the document itself,
    keyed by namespace, policy ID and publication ID. It does not decide
    whether a policy ID is new or active.

    ``insert`` is write-once: it must not replace a document already stored
    under the same publication key. The caller handles an existing key by
    reading it back and checking that it matches the document being written.
    """

    @abstractmethod
    def insert(
        self, namespace: str, policy_id: str, publication_id: str, document: str
    ) -> bool:
        """Insert a document once; return False without changing an existing key."""

    @abstractmethod
    def get(self, namespace: str, policy_id: str, publication_id: str) -> Optional[str]:
        """Read a publication by its complete key."""

    @abstractmethod
    def get_many(self, keys: Sequence[PublicationKey]) -> dict[PublicationKey, str]:
        """Read a set of complete publication keys in one backend batch."""

    @abstractmethod
    def list_ids(self, namespace: str, policy_id: str) -> list[str]:
        """List publication IDs for one policy."""

    @abstractmethod
    def delete(self, namespace: str, policy_id: str, publication_id: str) -> bool:
        """Delete a publication by its complete key."""

    @abstractmethod
    def is_reachable(self) -> bool:
        """Return whether the backend responds to a connectivity check."""


def validate_publication_key(
    namespace: str, policy_id: str, publication_id: str
) -> None:
    validate_policy_namespace(namespace)
    if not isinstance(policy_id, str) or not policy_id or "/" in policy_id:
        raise ValueError("Invalid policy ID")
    if not isinstance(publication_id, str) or not publication_id:
        raise ValueError("Invalid publication ID")
