from __future__ import annotations

from typing import Any

from .constants import ENVELOPE_SCHEMA, KEYRING_SCHEMA, PUBLIC_KEY_SCHEMA
from .errors import DataLockErrorCode


def make_v1_compatibility_manifest() -> dict[str, Any]:
    return {
        "schema": "hxdl.compatibilityManifest.v1",
        "cases": [
            {
                "id": "v1-keyring-document",
                "kind": "keyring",
                "producer": "fixture",
                "consumers": ["python", "typescript", "android-kotlin"],
                "documents": [
                    {
                        "schema": KEYRING_SCHEMA,
                        "document": "Keyring",
                    }
                ],
            },
            {
                "id": "v1-public-key-document",
                "kind": "publicKeyDocument",
                "producer": "fixture",
                "consumers": ["python", "typescript"],
                "documents": [
                    {
                        "schema": PUBLIC_KEY_SCHEMA,
                        "document": "Public Key Document",
                    }
                ],
            },
            {
                "id": "v1-data-envelope-document",
                "kind": "dataEnvelope",
                "producer": "fixture",
                "consumers": ["python", "typescript", "android-kotlin"],
                "documents": [
                    {
                        "schema": ENVELOPE_SCHEMA,
                        "document": "Data Envelope",
                    }
                ],
            },
            {
                "id": "v1-expected-failure-codes",
                "kind": "failureModes",
                "producer": "fixture",
                "consumers": ["python", "typescript", "android-kotlin"],
                "expectations": [
                    {
                        "failure": "wrong-master-password-or-tampered-keyring",
                        "expectedCode": DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING.value,
                    },
                    {
                        "failure": "envelope-recipient-mismatch",
                        "expectedCode": DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH.value,
                    },
                    {
                        "failure": "tampered-envelope",
                        "expectedCode": DataLockErrorCode.TAMPERED_ENVELOPE.value,
                    },
                    {
                        "failure": "unsupported-schema",
                        "expectedCode": DataLockErrorCode.UNSUPPORTED_SCHEMA.value,
                    },
                    {
                        "failure": "unsupported-algorithm",
                        "expectedCode": DataLockErrorCode.UNSUPPORTED_ALGORITHM.value,
                    },
                ],
            },
        ],
    }
