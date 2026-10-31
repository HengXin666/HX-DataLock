"""Publicly verifiable Ed25519 bindings.

v1 Data Envelopes stay unchanged. An attestation is a separate document that
signs the stable JSON digest of an envelope together with an application
context (object path, version, or other location). Anyone can check it with
the signer public key; HMAC manifest keys are not required.

hxdl.signedManifest.v2 is the same idea for an arbitrary JSON payload. The
HMAC hxdl.signedManifest.v1 prototype remains a script and is not this format.
"""

from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .constants import ATTESTATION_SCHEMA, SIGNED_MANIFEST_V2_SCHEMA
from .crypto_codec import b64, from_b64, sha256_base64url, utc_now
from .documents import DataEnvelope
from .errors import DataLockError, DataLockErrorCode
from .json import dumps_stable_json


def generate_attestation_key() -> tuple[Ed25519PrivateKey, bytes]:
    """Return a new signing key and its SPKI public bytes."""
    private_key = Ed25519PrivateKey.generate()
    public_spki = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_spki


def attestation_key_id(public_spki: bytes) -> str:
    return f"ed25519:{sha256_base64url(public_spki)[:22]}"


def attestation_message(envelope_sha256: str, recipient_key_id: str, context: str) -> bytes:
    if "\n" in context or "\n" in envelope_sha256 or "\n" in recipient_key_id:
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "attestation fields must not contain newlines")
    return (
        f"{ATTESTATION_SCHEMA}\n{envelope_sha256}\n{recipient_key_id}\n{context}\n"
    ).encode("utf-8")


def envelope_sha256(envelope: DataEnvelope) -> str:
    return sha256_base64url(envelope.serialize().encode("utf-8"))


def sign_envelope(
    private_key: Ed25519PrivateKey,
    envelope: DataEnvelope,
    *,
    context: str = "",
) -> dict[str, Any]:
    if not isinstance(context, str):
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "attestation context must be a string")
    envelope.verify()
    public_spki = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = envelope_sha256(envelope)
    recipient = envelope.raw["recipientKeyId"]
    signature = private_key.sign(attestation_message(digest, recipient, context))
    return {
        "schema": ATTESTATION_SCHEMA,
        "createdAt": utc_now(),
        "envelopeSha256": digest,
        "context": context,
        "recipientKeyId": recipient,
        "signer": {
            "alg": "Ed25519",
            "keyId": attestation_key_id(public_spki),
            "publicKey": b64(public_spki),
        },
        "signature": b64(signature),
    }


def verify_attestation(
    attestation: dict[str, Any],
    envelope: DataEnvelope,
    *,
    context: str | None = None,
    expected_signer_key_id: str | None = None,
) -> None:
    if not isinstance(attestation, dict) or attestation.get("schema") != ATTESTATION_SCHEMA:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "attestation schema must be hxdl.attestation.v1")
    envelope.verify()
    digest = envelope_sha256(envelope)
    if attestation.get("envelopeSha256") != digest:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "attestation does not match this Data Envelope")
    if attestation.get("recipientKeyId") != envelope.raw["recipientKeyId"]:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "attestation recipient does not match the Data Envelope")
    bound_context = attestation.get("context")
    if not isinstance(bound_context, str):
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "attestation context must be a string")
    if context is not None and bound_context != context:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "attestation context does not match")
    signer = attestation.get("signer")
    if not isinstance(signer, dict) or signer.get("alg") != "Ed25519":
        raise DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "attestation signer must use Ed25519")
    public_spki = from_b64(
        signer.get("publicKey"),
        "signer.publicKey",
        error_code=DataLockErrorCode.INVALID_ATTESTATION,
        max_length=128,
    )
    key_id = attestation_key_id(public_spki)
    if signer.get("keyId") != key_id:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "attestation signer keyId does not match the public key")
    if expected_signer_key_id is not None and key_id != expected_signer_key_id:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "attestation signer is not the expected key")
    signature = from_b64(
        attestation.get("signature"),
        "signature",
        error_code=DataLockErrorCode.INVALID_ATTESTATION,
        exact_length=64,
    )
    try:
        loaded = serialization.load_der_public_key(public_spki)
    except Exception as exc:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "attestation public key is invalid") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "attestation public key is not Ed25519")
    try:
        loaded.verify(signature, attestation_message(digest, envelope.raw["recipientKeyId"], bound_context))
    except InvalidSignature as exc:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "attestation signature is invalid") from exc


def sign_manifest(private_key: Ed25519PrivateKey, payload: dict[str, Any], *, issuer: str) -> dict[str, Any]:
    """Sign a JSON payload as hxdl.signedManifest.v2. The payload is not encrypted."""
    if not isinstance(payload, dict):
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "manifest payload must be an object")
    if not isinstance(issuer, str) or not issuer:
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "manifest issuer is required")
    public_spki = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signature = private_key.sign(dumps_stable_json(payload).encode("utf-8"))
    return {
        "schema": SIGNED_MANIFEST_V2_SCHEMA,
        "signedAt": utc_now(),
        "issuer": issuer,
        "signer": {
            "alg": "Ed25519",
            "keyId": attestation_key_id(public_spki),
            "publicKey": b64(public_spki),
        },
        "payload": payload,
        "signature": b64(signature),
    }


def verify_signed_manifest(
    document: dict[str, Any],
    *,
    expected_signer_key_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema") != SIGNED_MANIFEST_V2_SCHEMA:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "signed manifest schema must be hxdl.signedManifest.v2")
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "signed manifest payload must be an object")
    signer = document.get("signer")
    if not isinstance(signer, dict) or signer.get("alg") != "Ed25519":
        raise DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "signed manifest signer must use Ed25519")
    public_spki = from_b64(
        signer.get("publicKey"),
        "signer.publicKey",
        error_code=DataLockErrorCode.INVALID_ATTESTATION,
        max_length=128,
    )
    key_id = attestation_key_id(public_spki)
    if signer.get("keyId") != key_id:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "signed manifest signer keyId does not match the public key")
    if expected_signer_key_id is not None and key_id != expected_signer_key_id:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "signed manifest signer is not the expected key")
    signature = from_b64(
        document.get("signature"),
        "signature",
        error_code=DataLockErrorCode.INVALID_ATTESTATION,
        exact_length=64,
    )
    try:
        loaded = serialization.load_der_public_key(public_spki)
    except Exception as exc:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "signed manifest public key is invalid") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise DataLockError(DataLockErrorCode.UNSUPPORTED_ALGORITHM, "signed manifest public key is not Ed25519")
    try:
        loaded.verify(signature, dumps_stable_json(payload).encode("utf-8"))
    except InvalidSignature as exc:
        raise DataLockError(DataLockErrorCode.INVALID_ATTESTATION, "signed manifest signature is invalid") from exc
    return payload


def parse_attestation_private_key(pkcs8: bytes) -> Ed25519PrivateKey:
    loaded = serialization.load_der_private_key(pkcs8, password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise DataLockError(DataLockErrorCode.INVALID_ARGUMENT, "private key is not Ed25519")
    return loaded


def attestation_private_pkcs8(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
