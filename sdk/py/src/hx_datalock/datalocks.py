from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

from typing import Any, BinaryIO

from cryptography.hazmat.primitives import serialization

from .constants import MAX_V1_FILE_BYTES
from .crypto_codec import lock_bytes_with_public_key_raw, open_envelope_payload
from .documents import DataEnvelope, Keyring, PublicKeyDocument
from .errors import DataLockError, DataLockErrorCode
from .json import write_private_bytes


@dataclass(frozen=True)
class SenderDataLock:
    public_key_document: PublicKeyDocument

    def lockBytes(self, payload_bytes: bytes | bytearray | memoryview) -> DataEnvelope:
        payload_bytes = _payload_bytes(payload_bytes)
        # Enforce the v1 limit here, not only in lockFile: otherwise lockBytes can
        # produce a Full Data Envelope that every SDK then refuses to open.
        if len(payload_bytes) > MAX_V1_FILE_BYTES:
            raise DataLockError(
                DataLockErrorCode.OVERSIZED_FILE,
                "V1 Full Data Envelopes support payloads up to 25 MB",
            )
        self.public_key_document.verify()
        return DataEnvelope(
            lock_bytes_with_public_key_raw(
                self.public_key_document.key_id,
                self.public_key_document.public_write_key,
                payload_bytes,
            )
        )

    def lockText(self, text: str) -> DataEnvelope:
        if not isinstance(text, str):
            raise DataLockError(DataLockErrorCode.INVALID_UTF8, "lockText requires text input")
        try:
            payload_bytes = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise DataLockError(DataLockErrorCode.INVALID_UTF8, "Text is not valid UTF-8") from exc
        return self.lockBytes(payload_bytes)

    def lockFile(self, input_path: str | Path, output_path: str | Path) -> DataEnvelope:
        input_file = Path(input_path)
        if input_file.stat().st_size > MAX_V1_FILE_BYTES:
            raise DataLockError(
                DataLockErrorCode.OVERSIZED_FILE,
                "V1 Full Data Envelopes support local files up to 25 MB",
            )
        envelope = self.lockBytes(input_file.read_bytes())
        envelope.write(output_path)
        return envelope

    def lockStream(self, src: BinaryIO, dst: BinaryIO, **kwargs: Any) -> dict[str, Any]:
        from .stream import lock_stream

        self.public_key_document.verify()
        public = self.public_key_document.public_write_key
        return lock_stream(
            key_id=self.public_key_document.key_id,
            public_key=public,
            src=src,
            dst=dst,
            **kwargs,
        )


@dataclass
class UserDataLock:
    keyring: Keyring
    _read_key: x25519.X25519PrivateKey | None

    def _require_open_read_key(self) -> x25519.X25519PrivateKey:
        if self._read_key is None:
            raise DataLockError(
                DataLockErrorCode.DATALOCK_CLOSED,
                "User DataLock is closed",
            )
        return self._read_key

    def openBytes(self, envelope: DataEnvelope) -> bytes:
        read_key = self._require_open_read_key()
        self.keyring.verify()
        if isinstance(envelope, dict):
            envelope = DataEnvelope(envelope)
        if not isinstance(envelope, DataEnvelope):
            raise DataLockError(DataLockErrorCode.TAMPERED_ENVELOPE, "openBytes requires a Data Envelope")

        envelope.verify()
        if envelope.raw.get("recipientKeyId") != self.keyring.key_id:
            raise DataLockError(
                DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH,
                "Data Envelope recipient does not match the Keyring",
            )
        return open_envelope_payload(
            self.keyring.key_id,
            read_key,
            envelope.raw,
            envelope.decoded_fields(),
        )

    def openText(self, envelope: DataEnvelope) -> str:
        try:
            return self.openBytes(envelope).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise DataLockError(DataLockErrorCode.INVALID_UTF8, "Data Envelope payload is not valid UTF-8") from exc

    def openFile(self, input_path: str | Path, output_path: str | Path) -> bytes:
        plaintext = self.openBytes(DataEnvelope.read(input_path))
        if len(plaintext) > MAX_V1_FILE_BYTES:
            raise DataLockError(
                DataLockErrorCode.OVERSIZED_FILE,
                "V1 Full Data Envelopes support local files up to 25 MB",
            )
        # Decrypted payloads are as sensitive as the Keyring, so they must not
        # inherit a permissive umask the way a plain write_bytes would.
        write_private_bytes(output_path, plaintext)
        return plaintext

    def lockBytes(self, payload_bytes: bytes | bytearray | memoryview) -> DataEnvelope:
        self._require_open_read_key()
        payload_bytes = _payload_bytes(payload_bytes)
        if len(payload_bytes) > MAX_V1_FILE_BYTES:
            raise DataLockError(
                DataLockErrorCode.OVERSIZED_FILE,
                "V1 Full Data Envelopes support payloads up to 25 MB",
            )
        self.keyring.verify()
        return DataEnvelope(
            lock_bytes_with_public_key_raw(
                self.keyring.key_id,
                self.keyring.public_write_key,
                payload_bytes,
            )
        )

    def lockText(self, text: str) -> DataEnvelope:
        if not isinstance(text, str):
            raise DataLockError(DataLockErrorCode.INVALID_UTF8, "lockText requires text input")
        try:
            payload_bytes = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise DataLockError(DataLockErrorCode.INVALID_UTF8, "Text is not valid UTF-8") from exc
        return self.lockBytes(payload_bytes)

    def lockFile(self, input_path: str | Path, output_path: str | Path) -> DataEnvelope:
        input_file = Path(input_path)
        if input_file.stat().st_size > MAX_V1_FILE_BYTES:
            raise DataLockError(
                DataLockErrorCode.OVERSIZED_FILE,
                "V1 Full Data Envelopes support local files up to 25 MB",
            )
        envelope = self.lockBytes(input_file.read_bytes())
        envelope.write(output_path)
        return envelope

    def lockStream(self, src: BinaryIO, dst: BinaryIO, **kwargs: Any) -> dict[str, Any]:
        from .stream import lock_stream

        self._require_open_read_key()
        self.keyring.verify()
        return lock_stream(
            key_id=self.keyring.key_id,
            public_key=self.keyring.public_write_key,
            src=src,
            dst=dst,
            **kwargs,
        )

    def openStream(self, src: BinaryIO, dst: BinaryIO) -> dict[str, Any]:
        from .stream import open_stream

        read_key = self._require_open_read_key()
        self.keyring.verify()
        public = self.keyring.public_write_key
        recipient_spki = public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return open_stream(
            key_id=self.keyring.key_id,
            read_key=read_key,
            recipient_spki=recipient_spki,
            src=src,
            dst=dst,
        )

    def close(self) -> None:
        self._read_key = None

    def __enter__(self) -> "UserDataLock":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def _payload_bytes(payload_bytes: bytes | bytearray | memoryview) -> bytes:
    if isinstance(payload_bytes, memoryview):
        payload_bytes = payload_bytes.tobytes()
    elif isinstance(payload_bytes, bytearray):
        payload_bytes = bytes(payload_bytes)
    if not isinstance(payload_bytes, bytes):
        raise DataLockError(
            DataLockErrorCode.INVALID_ARGUMENT,
            "lockBytes requires bytes, bytearray, or memoryview; use lockText for text",
        )
    return payload_bytes
