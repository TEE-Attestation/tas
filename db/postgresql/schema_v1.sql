--
-- TEE Attestation Service - PostgreSQL Policy Storage Schema (v1)
--
-- Copyright 2026 Hewlett Packard Enterprise Development LP.
-- SPDX-License-Identifier: MIT
--
-- This file is part of the TEE Attestation Service.
--
-- Apply this schema to an empty PostgreSQL database before starting TAS with
-- TAS_POLICY_BACKEND=postgresql:
--
--   psql "$TAS_POSTGRES_DSN" -v ON_ERROR_STOP=1 -f db/postgresql/schema_v1.sql
--

BEGIN;

CREATE TABLE IF NOT EXISTS tas_policies (
    namespace  TEXT NOT NULL CHECK (namespace IN ('policy', 'certify-policy', 'domain-policy')),
    policy_id  TEXT NOT NULL,
    document   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (namespace, policy_id)
);

CREATE TABLE IF NOT EXISTS tas_schema_version (
    version INTEGER PRIMARY KEY
);
INSERT INTO tas_schema_version (version) VALUES (1)
ON CONFLICT (version) DO NOTHING;

COMMIT;
