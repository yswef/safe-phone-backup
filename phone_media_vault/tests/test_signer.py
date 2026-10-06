from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phone_media_vault.core.signer import (
    KeyPasswordRequiredError,
    KeyProtectionError,
    ManifestSigner,
    PrivateKeyStore,
    SigningError,
)


def raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class FakeProtector:
    """Test-only reversible adapter; production Windows uses DPAPI."""

    def available(self) -> bool:
        return True

    def protect(self, data: bytes) -> bytes:
        return bytes(byte ^ 0xA5 for byte in data)

    def unprotect(self, data: bytes) -> bytes:
        return bytes(byte ^ 0xA5 for byte in data)


class UnavailableProtector:
    def available(self) -> bool:
        return False

    def protect(self, data: bytes) -> bytes:
        raise AssertionError("protect must not be called when unavailable")

    def unprotect(self, data: bytes) -> bytes:
        raise AssertionError("unprotect must not be called when unavailable")


class PrivateKeyStoreTests(unittest.TestCase):
    def test_no_password_uses_protector_and_round_trips_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            key_path = Path(temporary) / "app-data" / "ed25519-private.key"
            store = PrivateKeyStore(key_path, protector=FakeProtector())

            created = store.load_or_create()
            stored_bytes = key_path.read_bytes()
            self.assertEqual(store.protection_mode, "dpapi")
            loaded = store.load_or_create()

            self.assertEqual(
                raw_public_key(created),
                raw_public_key(loaded),
            )
            self.assertNotIn(b"PRIVATE KEY", stored_bytes)
            self.assertTrue(stored_bytes.startswith(b"PHONE-MEDIA-VAULT-ED25519-KEY-V1\nDPAPI\n"))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)

    def test_password_protects_key_and_wrong_password_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            key_path = Path(temporary) / "ed25519-private.key"
            store = PrivateKeyStore(key_path, protector=UnavailableProtector())
            key = store.load_or_create("vault passphrase")

            self.assertEqual(store.protection_mode, "password")
            self.assertNotIn(b"BEGIN PRIVATE KEY", key_path.read_bytes())
            reopened = store.load_or_create("vault passphrase")
            self.assertEqual(
                raw_public_key(key),
                raw_public_key(reopened),
            )
            with self.assertRaises(SigningError):
                store.load_or_create("incorrect passphrase")
            with self.assertRaises(KeyPasswordRequiredError):
                store.load_or_create()

    def test_fails_closed_without_password_or_dpapi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            key_path = Path(temporary) / "private.key"
            store = PrivateKeyStore(key_path, protector=UnavailableProtector())
            with self.assertRaises(KeyProtectionError):
                store.load_or_create()
            self.assertFalse(key_path.exists())


class ManifestSignatureTests(unittest.TestCase):
    def test_signature_detects_manifest_and_signature_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = PrivateKeyStore(
                root / "app-data" / "private.key", protector=FakeProtector()
            )
            signer = ManifestSigner(store)
            backup = root / "backup"
            backup.mkdir()
            manifest = b'{"schema_version":1,"files":[]}\n'
            (backup / "manifest.json").write_bytes(manifest)

            signer.sign_manifest(manifest, backup)
            trusted_public_key = signer.public_key_bytes()
            self.assertTrue(ManifestSigner.verify_backup_directory(backup))
            self.assertTrue(
                ManifestSigner.verify_backup_directory(
                    backup, trusted_public_key_bytes=trusted_public_key
                )
            )
            self.assertFalse(
                ManifestSigner.verify_backup_directory(
                    backup, trusted_public_key_bytes=b"different trusted key"
                )
            )

            tampered_manifest = manifest + b" "
            self.assertFalse(
                ManifestSigner.verify_manifest(
                    tampered_manifest,
                    (backup / "manifest.sig").read_bytes(),
                    (backup / "public_key.pem").read_bytes(),
                )
            )
            tampered_signature = bytearray((backup / "manifest.sig").read_bytes())
            tampered_signature[-4] ^= 1
            self.assertFalse(
                ManifestSigner.verify_manifest(
                    manifest,
                    bytes(tampered_signature),
                    (backup / "public_key.pem").read_bytes(),
                )
            )

    def test_private_key_is_outside_backup_and_only_public_key_is_copied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key_path = root / "user-data" / "keys" / "private.key"
            signer = ManifestSigner(
                PrivateKeyStore(key_path, protector=FakeProtector())
            )
            backup = root / "backup"
            backup.mkdir()
            manifest = b"{}\n"
            (backup / "manifest.json").write_bytes(manifest)

            signer.sign_manifest(manifest, backup)

            self.assertTrue(key_path.is_file())
            self.assertTrue((backup / "public_key.pem").is_file())
            self.assertTrue((backup / "manifest.sig").is_file())
            self.assertFalse((backup / key_path.name).exists())
            forbidden_key_path = backup / "private.key"
            with self.assertRaises(SigningError):
                ManifestSigner(
                    PrivateKeyStore(forbidden_key_path, protector=FakeProtector())
                ).sign_manifest(manifest, backup)
            self.assertFalse(forbidden_key_path.exists())


if __name__ == "__main__":
    unittest.main()
