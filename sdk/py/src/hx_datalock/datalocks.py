from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

from .constants import MAX_V1_FILE_BYTES
from .crypto_codec import lock_bytes_with_public_key_raw, open_envelope_payload
from .documents import DataEnvelope, Keyring, PublicKeyDocument
from .errors import DataLockError, DataLockErrorCode


@dataclass(frozen=True)
class SenderDataLock:
    public_key_document: PublicKeyDocument

    def lockBytes(self, payload_bytes: bytes) -> DataEnvelope:
        if not isinstance(payload_bytes, bytes):
            raise TypeError("payload_bytes must be bytes")
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


@dataclass
class UserDataLock:
    keyring: Keyring
    _read_key: x25519.X25519PrivateKey | None

    def _require_open_read_key(self) -> x25519.X25519PrivateKey:
        if self._read_key is None:
            raise DataLockError(
                DataLockErrorCode.WRONG_MASTER_PASSWORD_OR_TAMPERED_KEYRING,
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

        raw = envelope.raw
        envelope.verify()
        if raw.get("recipientKeyId") != self.keyring.key_id:
            raise DataLockError(
                DataLockErrorCode.ENVELOPE_RECIPIENT_MISMATCH,
                "Data Envelope recipient does not match the Keyring",
            )
        return open_envelope_payload(self.keyring.key_id, read_key, raw)

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
        Path(output_path).write_bytes(plaintext)
        return plaintext

    def lockBytes(self, payload_bytes: bytes) -> DataEnvelope:
        self._require_open_read_key()
        if not isinstance(payload_bytes, bytes):
            raise TypeError("payload_bytes must be bytes")
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

    def close(self) -> None:
        self._read_key = None
