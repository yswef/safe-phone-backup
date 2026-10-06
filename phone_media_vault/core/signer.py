"""Ed25519 manifest signing with protected, app-local private-key storage.

Only the public key and detached signature are written into a backup. The
private key is kept under the user's application-data directory, never inside a
backup folder. Password-encrypted PEM is supported on every platform; on
Windows the no-password mode uses current-user DPAPI. If DPAPI is unavailable,
no plaintext private key is written.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError as exc:  # pragma: no cover - exercised when dependencies absent
    raise ImportError(
        "Phone Media Vault signing requires the 'cryptography' package. "
        "Install the project requirements before using backup signing."
    ) from exc


SIGNATURE_FILE = "manifest.sig"
PUBLIC_KEY_FILE = "public_key.pem"
_SIGNATURE_VERSION = 1
_KEY_MAGIC = b"PHONE-MEDIA-VAULT-ED25519-KEY-V1\n"
_PASSWORD_MARKER = b"PASSWORD\n"
_DPAPI_MARKER = b"DPAPI\n"
_DPAPI_ENTROPY = b"PhoneMediaVault:Ed25519:private-key:v1"


class SigningError(RuntimeError):
    """Signing failure with a user-facing Arabic message."""

    def __init__(self, message_ar: str, details: str | None = None) -> None:
        super().__init__(message_ar)
        self.message_ar = message_ar
        self.details = details

    def __str__(self) -> str:
        return f"{self.message_ar}\n{self.details}" if self.details else self.message_ar


class KeyPasswordRequiredError(SigningError):
    def __init__(self) -> None:
        super().__init__("يتطلب مفتاح التوقيع كلمة المرور التي حُفظ بها.")


class KeyProtectionError(SigningError):
    def __init__(self, details: str | None = None) -> None:
        super().__init__(
            "تعذّر حماية المفتاح الخاص. لم يُحفظ المفتاح كنص صريح.", details
        )


class KeyStoreCorruptError(SigningError):
    def __init__(self, details: str | None = None) -> None:
        super().__init__("ملف مفتاح التوقيع تالف أو بتنسيق غير معروف.", details)


class KeyStore(Protocol):
    @property
    def key_path(self) -> Path: ...

    def load_or_create(self, password: str | None = None) -> Ed25519PrivateKey: ...


class DataProtector(Protocol):
    def available(self) -> bool: ...

    def protect(self, data: bytes) -> bytes: ...

    def unprotect(self, data: bytes) -> bytes: ...


def app_data_directory(app_name: str = "PhoneMediaVault") -> Path:
    """Return a per-user application-data directory (without creating it)."""

    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / app_name
        return Path.home() / "AppData" / "Local" / app_name

    xdg_home = os.environ.get("XDG_DATA_HOME")
    if xdg_home:
        return Path(xdg_home) / app_name
    return Path.home() / ".local" / "share" / app_name


def atomic_write_bytes(path: str | os.PathLike[str], data: bytes) -> None:
    """Write bytes atomically in the target directory, using private POSIX mode."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


class WindowsDpapiProtector:
    """Thin current-user DPAPI wrapper using CryptProtectData/UnprotectData."""

    def available(self) -> bool:
        return os.name == "nt"

    @staticmethod
    def _crypt(data: bytes, *, protect: bool) -> bytes:
        if os.name != "nt":
            raise KeyProtectionError("Windows DPAPI is unavailable on this platform.")

        from ctypes import wintypes

        class DataBlob(ctypes.Structure):
            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
            ]

        def make_blob(value: bytes):
            buffer = ctypes.create_string_buffer(value, len(value))
            blob = DataBlob(
                len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
            )
            return blob, buffer

        input_blob, input_buffer = make_blob(data)
        entropy_blob, entropy_buffer = make_blob(_DPAPI_ENTROPY)
        output_blob = DataBlob()
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        local_free = kernel32.LocalFree
        local_free.argtypes = [ctypes.c_void_p]
        local_free.restype = ctypes.c_void_p

        description = None
        if protect:
            function = crypt32.CryptProtectData
            function.argtypes = [
                ctypes.POINTER(DataBlob),
                wintypes.LPCWSTR,
                ctypes.POINTER(DataBlob),
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(DataBlob),
            ]
            function.restype = wintypes.BOOL
            success = function(
                ctypes.byref(input_blob),
                "Phone Media Vault signing key",
                ctypes.byref(entropy_blob),
                None,
                None,
                0x1,  # CRYPTPROTECT_UI_FORBIDDEN
                ctypes.byref(output_blob),
            )
        else:
            description = wintypes.LPWSTR()
            function = crypt32.CryptUnprotectData
            function.argtypes = [
                ctypes.POINTER(DataBlob),
                ctypes.POINTER(wintypes.LPWSTR),
                ctypes.POINTER(DataBlob),
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(DataBlob),
            ]
            function.restype = wintypes.BOOL
            success = function(
                ctypes.byref(input_blob),
                ctypes.byref(description),
                ctypes.byref(entropy_blob),
                None,
                None,
                0x1,  # CRYPTPROTECT_UI_FORBIDDEN
                ctypes.byref(output_blob),
            )

        # Keep ctypes buffers alive through the native call.
        _ = input_buffer, entropy_buffer
        if not success:
            code = ctypes.get_last_error()
            raise KeyProtectionError(f"Windows DPAPI error {code}.")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            local_free(output_blob.pbData)
            if not protect and description is not None and description.value:
                local_free(ctypes.cast(description, ctypes.c_void_p))

    def protect(self, data: bytes) -> bytes:
        return self._crypt(data, protect=True)

    def unprotect(self, data: bytes) -> bytes:
        return self._crypt(data, protect=False)


class PrivateKeyStore:
    """Create/load an Ed25519 key in protected app-data storage."""

    def __init__(
        self,
        key_path: str | os.PathLike[str] | None = None,
        *,
        protector: DataProtector | None = None,
    ) -> None:
        self._key_path = (
            Path(key_path)
            if key_path is not None
            else app_data_directory() / "keys" / "ed25519-private.key"
        )
        self._protector = protector or WindowsDpapiProtector()

    @property
    def key_path(self) -> Path:
        return self._key_path

    @property
    def protection_mode(self) -> str | None:
        """Return the stored key's protection mode without decrypting it."""

        if not self._key_path.exists():
            return None
        try:
            payload = self._key_path.read_bytes()
        except OSError as exc:
            raise KeyStoreCorruptError(str(exc)) from exc
        if not payload.startswith(_KEY_MAGIC):
            return "unknown"
        body = payload[len(_KEY_MAGIC) :]
        if body.startswith(_PASSWORD_MARKER):
            return "password"
        if body.startswith(_DPAPI_MARKER):
            return "dpapi"
        return "unknown"

    def load_or_create(self, password: str | None = None) -> Ed25519PrivateKey:
        if self._key_path.exists():
            return self._load_existing(password)
        return self._create(password)

    def _create(self, password: str | None) -> Ed25519PrivateKey:
        key = Ed25519PrivateKey.generate()
        if password:
            private_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    password.encode("utf-8")
                ),
            )
            envelope = _KEY_MAGIC + _PASSWORD_MARKER + private_pem
        else:
            if not self._protector.available():
                raise KeyProtectionError(
                    "عيّن كلمة مرور للمفتاح أو استخدم Windows مع DPAPI."
                )
            private_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            try:
                protected = self._protector.protect(private_pem)
            except Exception as exc:
                raise KeyProtectionError(str(exc)) from exc
            envelope = _KEY_MAGIC + _DPAPI_MARKER + protected
        atomic_write_bytes(self._key_path, envelope)
        return key

    def _load_existing(self, password: str | None) -> Ed25519PrivateKey:
        try:
            payload = self._key_path.read_bytes()
        except OSError as exc:
            raise KeyStoreCorruptError(str(exc)) from exc
        if not payload.startswith(_KEY_MAGIC):
            raise KeyStoreCorruptError("Missing key-file version header.")

        body = payload[len(_KEY_MAGIC) :]
        try:
            if body.startswith(_PASSWORD_MARKER):
                encrypted_pem = body[len(_PASSWORD_MARKER) :]
                if not password:
                    raise KeyPasswordRequiredError()
                private_pem = encrypted_pem
                pem_password = password.encode("utf-8")
            elif body.startswith(_DPAPI_MARKER):
                if not self._protector.available():
                    raise KeyProtectionError(
                        "يتطلب هذا المفتاح Windows DPAPI للحساب الذي أنشأه."
                    )
                protected = body[len(_DPAPI_MARKER) :]
                private_pem = self._protector.unprotect(protected)
                pem_password = None
            else:
                raise KeyStoreCorruptError("Unknown key protection mode.")

            loaded = serialization.load_pem_private_key(
                private_pem, password=pem_password
            )
            if not isinstance(loaded, Ed25519PrivateKey):
                raise KeyStoreCorruptError("Stored key is not an Ed25519 key.")
            return loaded
        except (KeyPasswordRequiredError, KeyProtectionError, KeyStoreCorruptError):
            raise
        except (TypeError, ValueError) as exc:
            raise SigningError(
                "تعذّر فتح مفتاح التوقيع؛ تحقق من كلمة المرور أو سلامة الملف."
            ) from exc


@dataclass(frozen=True)
class SignatureArtifacts:
    manifest_sha256: str
    signature_path: Path
    public_key_path: Path
    public_key_fingerprint: str


class ManifestSigner:
    """Sign the SHA-256 digest of exact manifest bytes with Ed25519."""

    def __init__(
        self,
        key_store: KeyStore | None = None,
        *,
        app_data_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        if key_store is not None and app_data_dir is not None:
            raise ValueError("Pass either key_store or app_data_dir, not both.")
        self.key_store: KeyStore = key_store or PrivateKeyStore(
            Path(app_data_dir) / "keys" / "ed25519-private.key"
            if app_data_dir is not None
            else None
        )

    @property
    def key_path(self) -> Path:
        return self.key_store.key_path

    @staticmethod
    def _public_key_pem(private_key: Ed25519PrivateKey) -> bytes:
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def ensure_key(self, password: str | None = None) -> Ed25519PrivateKey:
        return self.key_store.load_or_create(password)

    @property
    def trusted_public_key_path(self) -> Path:
        return self.key_path.with_name("ed25519-public.pem")

    def _trust_public_key(self, public_pem: bytes) -> bytes:
        trust_path = self.trusted_public_key_path
        if trust_path.exists():
            if trust_path.read_bytes() != public_pem:
                raise SigningError(
                    "المفتاح العام المحلي لا يطابق مفتاح التوقيع الخاص؛ "
                    "لن يتم استبدال مرجع الثقة تلقائياً."
                )
        else:
            atomic_write_bytes(trust_path, public_pem)
        return public_pem

    def public_key_bytes(self, password: str | None = None) -> bytes:
        return self._trust_public_key(
            self._public_key_pem(self.ensure_key(password))
        )

    def sign_manifest(
        self,
        manifest_bytes: bytes,
        backup_directory: str | os.PathLike[str],
        *,
        password: str | None = None,
    ) -> SignatureArtifacts:
        backup_dir = Path(backup_directory).resolve()
        key_path = self.key_path
        key_path_inside = False
        try:
            key_path.absolute().relative_to(backup_dir.absolute())
            key_path_inside = True
        except ValueError:
            pass
        try:
            key_path.resolve(strict=False).relative_to(backup_dir)
            key_path_inside = True
        except ValueError:
            pass
        if key_path_inside:
            raise SigningError(
                "ملف المفتاح الخاص يجب أن يبقى خارج مجلد النسخة الاحتياطية."
            )

        backup_dir.mkdir(parents=True, exist_ok=True)
        private_key = self.ensure_key(password)
        public_key = private_key.public_key()
        public_pem = self._trust_public_key(self._public_key_pem(private_key))
        public_path = backup_dir / PUBLIC_KEY_FILE
        if public_path.exists() and public_path.read_bytes() != public_pem:
            raise SigningError(
                "المفتاح العام الموجود في النسخة لا يطابق مفتاح التوقيع المحلي."
            )

        digest = hashlib.sha256(manifest_bytes).digest()
        signature = private_key.sign(digest)
        signature_document = {
            "format_version": _SIGNATURE_VERSION,
            "algorithm": "Ed25519",
            "manifest_sha256": digest.hex(),
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }
        signature_bytes = (
            json.dumps(
                signature_document,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")

        atomic_write_bytes(public_path, public_pem)
        atomic_write_bytes(backup_dir / SIGNATURE_FILE, signature_bytes)
        return SignatureArtifacts(
            manifest_sha256=digest.hex(),
            signature_path=backup_dir / SIGNATURE_FILE,
            public_key_path=public_path,
            public_key_fingerprint=hashlib.sha256(
                public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ).hexdigest(),
        )

    @staticmethod
    def verify_manifest(
        manifest_bytes: bytes,
        signature_bytes: bytes,
        public_key_bytes: bytes,
        trusted_public_key_bytes: bytes | None = None,
    ) -> bool:
        """Validate the recorded manifest digest and its Ed25519 signature."""

        try:
            signature_document = json.loads(signature_bytes.decode("ascii"))
            if not isinstance(signature_document, dict):
                return False
            if signature_document.get("format_version") != _SIGNATURE_VERSION:
                return False
            if signature_document.get("algorithm") != "Ed25519":
                return False
            expected_hash = signature_document["manifest_sha256"]
            signature = base64.b64decode(
                signature_document["signature_base64"], validate=True
            )
            digest = hashlib.sha256(manifest_bytes).digest()
            if not isinstance(expected_hash, str) or not hmac.compare_digest(
                expected_hash.lower(), digest.hex()
            ):
                return False
            if trusted_public_key_bytes is not None and not hmac.compare_digest(
                public_key_bytes, trusted_public_key_bytes
            ):
                return False
            public_key = serialization.load_pem_public_key(public_key_bytes)
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            public_key.verify(signature, digest)
            return True
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, InvalidSignature):
            return False

    @classmethod
    def verify_backup_directory(
        cls,
        backup_directory: str | os.PathLike[str],
        *,
        trusted_public_key_bytes: bytes | None = None,
    ) -> bool:
        backup_dir = Path(backup_directory)
        try:
            manifest = (backup_dir / "manifest.json").read_bytes()
            signature = (backup_dir / SIGNATURE_FILE).read_bytes()
            public_key = (backup_dir / PUBLIC_KEY_FILE).read_bytes()
        except OSError:
            return False
        return cls.verify_manifest(
            manifest,
            signature,
            public_key,
            trusted_public_key_bytes=trusted_public_key_bytes,
        )
