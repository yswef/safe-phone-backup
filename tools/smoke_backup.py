#!/usr/bin/env python3
"""Run a real-device, one-folder Phone Media Vault backup smoke test.

Run from the repository root, for example:
    python tools/smoke_backup.py /sdcard/DCIM/Camera \
        --destination "D:/PhoneMediaVault-Smoke/camera-run-01"

The script backs up at most ten files, keeps the app signing key in per-user
application data, verifies each copied file, validates the manifest signature,
and tests tamper detection on a temporary duplicate so the backup is not left
corrupted.
"""

from __future__ import annotations

import argparse
import getpass
import hmac
import os
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phone_media_vault.core.adb_manager import AdbError, AdbManager  # noqa: E402
from phone_media_vault.core.backup_engine import (  # noqa: E402
    BackupEngine,
    BackupError,
    sha256_file,
)
from phone_media_vault.core.models import ScanResult, ScannedFile  # noqa: E402
from phone_media_vault.core.scanner import custom_source, scan_sources  # noqa: E402
from phone_media_vault.core.signer import (  # noqa: E402
    KeyPasswordRequiredError,
    KeyProtectionError,
    ManifestSigner,
    PrivateKeyStore,
    SigningError,
    WindowsDpapiProtector,
)


MAX_ALLOWED_FILES = 10


def select_first_files(
    files: list[ScannedFile], limit: int = MAX_ALLOWED_FILES
) -> list[ScannedFile]:
    """Choose a stable, deterministic prefix while never exceeding ten files."""

    if limit < 1 or limit > MAX_ALLOWED_FILES:
        raise ValueError(f"--max-files must be between 1 and {MAX_ALLOWED_FILES}.")
    return sorted(
        files,
        key=lambda item: (item.phone_path.casefold(), item.phone_path),
    )[:limit]


def verify_file_entry(local_path: Path, entry: dict[str, object]) -> bool:
    """Check a copied file against its signed manifest size and SHA-256."""

    expected_hash = entry.get("sha256")
    expected_size = entry.get("size")
    if (
        not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or type(expected_size) is not int
        or expected_size < 0
    ):
        return False
    try:
        if (
            local_path.is_symlink()
            or not local_path.is_file()
            or local_path.stat().st_size != expected_size
        ):
            return False
        return hmac.compare_digest(sha256_file(local_path), expected_hash.lower())
    except OSError:
        return False


def manifest_local_path(
    backup_directory: Path, relative_path: object
) -> Path:
    """Resolve a generated manifest path while rejecting traversal."""

    if not isinstance(relative_path, str):
        raise ValueError("Manifest entry has no valid relative_path.")
    relative = PurePosixPath(relative_path)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"Unsafe manifest relative path: {relative_path!r}")
    destination = backup_directory.joinpath(*relative.parts)
    try:
        destination.resolve(strict=False).relative_to(
            backup_directory.resolve(strict=False)
        )
    except ValueError as exc:
        raise ValueError(f"Manifest path escapes backup directory: {relative_path!r}") from exc
    return destination


def _tamper_test_copy(source: Path, entry: dict[str, object]) -> tuple[bool, str]:
    """Modify a temporary copy and confirm the manifest hash check rejects it."""

    if not verify_file_entry(source, entry):
        return False, "The original backup file did not match its manifest before tampering."

    try:
        with tempfile.TemporaryDirectory(prefix="phone-media-vault-tamper-") as temp_dir:
            tampered_copy = Path(temp_dir) / f"tampered-{source.name}"
            shutil.copyfile(source, tampered_copy)
            with tampered_copy.open("r+b") as stream:
                first_byte = stream.read(1)
                if first_byte:
                    stream.seek(0)
                    stream.write(bytes((first_byte[0] ^ 0x01,)))
                else:
                    stream.write(b"\x00")
                stream.flush()
                os.fsync(stream.fileno())
            if verify_file_entry(tampered_copy, entry):
                return False, "The manifest file check accepted a modified copy."
    except OSError as exc:
        return False, f"Could not perform the isolated tamper test: {exc}"
    return True, "A modified temporary copy was rejected; the backup file was left untouched."


def test_dpapi_key_protection() -> tuple[bool, str]:
    """Round-trip an Ed25519 key through current-user Windows DPAPI."""

    protector = WindowsDpapiProtector()
    if os.name != "nt" or not protector.available():
        return False, "Windows DPAPI is unavailable on this operating system."

    try:
        with tempfile.TemporaryDirectory(prefix="phone-media-vault-dpapi-") as temp_dir:
            test_key_path = Path(temp_dir) / "dpapi-test-private.key"
            test_store = PrivateKeyStore(test_key_path, protector=protector)
            created = test_store.load_or_create()
            if test_store.protection_mode != "dpapi":
                return False, "The temporary test key was not stored in DPAPI mode."
            protected_bytes = test_key_path.read_bytes()
            if b"PRIVATE KEY" in protected_bytes:
                return False, "The protected test file unexpectedly contains PEM key text."
            reopened = test_store.load_or_create()
            created_raw = created.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            reopened_raw = reopened.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            if not hmac.compare_digest(created_raw, reopened_raw):
                return False, "DPAPI unprotected a different Ed25519 key."
    except Exception as exc:
        return False, f"DPAPI protect/unprotect round-trip failed: {exc}"
    return True, "DPAPI protected and successfully reloaded a temporary Ed25519 key."


def _ask_for_new_password() -> str:
    password = getpass.getpass(
        "DPAPI is unavailable. Enter a passphrase for the encrypted key fallback: "
    )
    if not password:
        raise SigningError("A non-empty passphrase is required for key protection.")
    confirmation = getpass.getpass("Confirm the passphrase: ")
    if password != confirmation:
        raise SigningError("The passphrases did not match; no backup was started.")
    return password


def _ask_for_existing_password() -> str:
    password = getpass.getpass("Enter the passphrase for the existing signing key: ")
    if not password:
        raise KeyPasswordRequiredError()
    return password


def configure_app_signer(dpapi_test_passed: bool) -> tuple[ManifestSigner, str | None, str]:
    """Use the persistent app-data key; use password encryption if needed."""

    store = PrivateKeyStore()
    signer = ManifestSigner(store)
    prior_mode = store.protection_mode
    signing_password: str | None = None

    try:
        if prior_mode == "password":
            signing_password = _ask_for_existing_password()
            signer.public_key_bytes(signing_password)
        elif prior_mode == "dpapi":
            signer.public_key_bytes()
        elif prior_mode is None and dpapi_test_passed:
            try:
                signer.public_key_bytes()
            except KeyProtectionError:
                signing_password = _ask_for_new_password()
                signer.public_key_bytes(signing_password)
        elif prior_mode is None:
            signing_password = _ask_for_new_password()
            signer.public_key_bytes(signing_password)
        else:
            # Let the key store report a useful corruption/format error.
            signer.public_key_bytes()
    except KeyPasswordRequiredError:
        signing_password = _ask_for_existing_password()
        signer.public_key_bytes(signing_password)

    mode = store.protection_mode
    if mode not in {"dpapi", "password"}:
        raise KeyProtectionError(f"Unexpected stored key protection mode: {mode!r}")
    return signer, signing_password, mode


def _print_scan_warnings(scan: ScanResult) -> None:
    print(f"Scan warnings: {len(scan.warnings)}")
    for warning in scan.warnings[:5]:
        location = f" ({warning.phone_path})" if warning.phone_path else ""
        detail = f" — {warning.detail}" if warning.detail else ""
        print(f"  - {warning.message_ar}{location}{detail}")
    if len(scan.warnings) > 5:
        print(f"  - ... and {len(scan.warnings) - 5} more warning(s)")
    print(
        "Symlinks: not followed; "
        f"{scan.skipped_symlink_count} symlink(s) found and skipped."
    )


def _check_destination_is_new(path: Path) -> Path:
    destination = path.expanduser().resolve(strict=False)
    if destination.exists():
        raise ValueError(
            f"Backup destination already exists; choose a new empty run folder: {destination}"
        )
    return destination


def _print_file_hash_comparisons(
    adb: AdbManager,
    serial: str,
    backup_directory: Path,
    entries: list[dict[str, object]],
) -> bool:
    all_match = True
    for entry in entries:
        phone_path = entry.get("original_phone_path")
        local_path = manifest_local_path(backup_directory, entry.get("relative_path"))
        expected_hash = entry.get("sha256")
        method = entry.get("verification_method")
        label = repr(phone_path)
        if not isinstance(phone_path, str) or not isinstance(expected_hash, str):
            print(f"{label}: invalid manifest entry; FAIL")
            all_match = False
            continue

        if not verify_file_entry(local_path, entry):
            print(f"{label}: laptop file does not match the manifest; FAIL")
            all_match = False
            continue
        laptop_hash = sha256_file(local_path)

        try:
            phone_hash = adb.remote_sha256(serial, phone_path)
        except AdbError as exc:
            print(f"{label}: phone SHA-256 query failed: {exc}; FAIL")
            all_match = False
            continue

        if phone_hash is not None:
            matches = hmac.compare_digest(phone_hash, laptop_hash)
            print(
                f"{label}\n"
                f"  phone SHA-256:  {phone_hash}\n"
                f"  laptop SHA-256: {laptop_hash}\n"
                f"  comparison:     {'MATCH' if matches else 'MISMATCH'}"
            )
            all_match = all_match and matches and hmac.compare_digest(
                expected_hash.lower(), laptop_hash
            )
        elif method == "verified-by-double-pull":
            matches = hmac.compare_digest(expected_hash.lower(), laptop_hash)
            print(
                f"{label}\n"
                "  phone SHA-256:  unavailable (device sha256sum not available)\n"
                f"  laptop SHA-256: {laptop_hash}\n"
                f"  double-pull/manifest comparison: {'PASS' if matches else 'FAIL'}"
            )
            all_match = all_match and matches
        else:
            print(
                f"{label}: phone SHA-256 unavailable, and the manifest does not "
                "record double-pull verification; FAIL"
            )
            all_match = False
    return all_match


def _run(args: argparse.Namespace) -> int:
    if args.max_files < 1 or args.max_files > MAX_ALLOWED_FILES:
        raise ValueError(f"--max-files must be between 1 and {MAX_ALLOWED_FILES}.")

    source = custom_source(args.phone_folder)
    destination = _check_destination_is_new(args.destination)

    adb = AdbManager()
    device = adb.get_device_info(args.serial)
    print(f"Phone model: {device.model}")
    print(f"Android version: {device.android_version}")
    print("Connection: authorized ADB device detected.")

    dpapi_ok, dpapi_message = test_dpapi_key_protection()
    print(f"Windows DPAPI key-protection test: {'PASS' if dpapi_ok else 'FAIL'}")
    print(f"  {dpapi_message}")
    if not dpapi_ok:
        print("  No plaintext fallback will be used; password-encrypted storage is required.")

    signer, signing_password, actual_key_mode = configure_app_signer(dpapi_ok)
    print(f"App signing-key protection mode: {actual_key_mode.upper()}")
    print(f"App-data private key path: {signer.key_path}")

    scan = scan_sources(adb, device.serial, [source])
    _print_scan_warnings(scan)
    selected_files = select_first_files(scan.files, args.max_files)
    print(f"Files found in the supplied folder: {scan.total_files}")
    print(f"Files selected for this smoke backup: {len(selected_files)} (limit {args.max_files})")
    if not selected_files:
        raise RuntimeError("No regular files were found in the supplied phone folder.")

    limited_scan = ScanResult(
        files=selected_files,
        warnings=list(scan.warnings),
        sources_scanned=list(scan.sources_scanned),
        skipped_symlink_paths=list(scan.skipped_symlink_paths),
    )

    key_path = signer.key_path.resolve(strict=False)
    try:
        key_path.relative_to(destination.resolve(strict=False))
    except ValueError:
        private_key_outside_backup = True
    else:
        private_key_outside_backup = False
    if not private_key_outside_backup:
        raise SigningError("The private key path is inside the chosen backup directory.")

    print("WhatsApp policy: media folders only; Databases and Backups are excluded.")
    print("Starting read-only phone backup...")
    result = BackupEngine(adb, signer).backup(
        device.serial,
        device,
        limited_scan,
        destination,
        hash_serial=True,
        signing_password=signing_password,
    )

    print(f"Manifest path: {result.manifest_path}")
    print(f"Verified files: {result.verified_count}/{result.files_total}")
    print(f"Failed files: {result.failed_count}")
    print(
        "Backup fully verified (no scan warnings): "
        f"{'YES' if result.fully_verified else 'NO'}"
    )
    print(f"Private key outside backup folder: {'PASS' if private_key_outside_backup else 'FAIL'}")
    print(
        "Public signing artifacts present: "
        f"{'PASS' if (destination / 'public_key.pem').is_file() and (destination / 'manifest.sig').is_file() else 'FAIL'}"
    )

    trusted_public_key = signer.public_key_bytes(signing_password)
    signature_valid = ManifestSigner.verify_backup_directory(
        destination,
        trusted_public_key_bytes=trusted_public_key,
    )
    print(f"Manifest signature valid (trusted local key): {'YES' if signature_valid else 'NO'}")

    manifest_entries = result.manifest.get("files", [])
    verified_entries = [
        entry
        for entry in manifest_entries
        if isinstance(entry, dict) and entry.get("status") == "verified"
    ] if isinstance(manifest_entries, list) else []
    hashes_match = _print_file_hash_comparisons(
        adb,
        device.serial,
        destination,
        verified_entries,
    )

    tamper_detected = False
    if verified_entries:
        smallest_entry = min(
            verified_entries,
            key=lambda entry: int(entry.get("size", 0))
            if type(entry.get("size")) is int
            else 0,
        )
        original_copy = manifest_local_path(
            destination, smallest_entry.get("relative_path")
        )
        tamper_detected, tamper_message = _tamper_test_copy(
            original_copy, smallest_entry
        )
        print(f"Tamper test: {'PASS' if tamper_detected else 'FAIL'}")
        print(f"  {tamper_message}")
    else:
        print("Tamper test: FAIL (there is no verified copied file to test).")

    checks_passed = (
        dpapi_ok
        and actual_key_mode in {"dpapi", "password"}
        and private_key_outside_backup
        and signature_valid
        and result.failed_count == 0
        and len(verified_entries) == len(selected_files)
        and hashes_match
        and tamper_detected
    )
    if checks_passed:
        print("SMOKE TEST RESULT: PASS")
        return 0
    if (
        not dpapi_ok
        and actual_key_mode == "password"
        and private_key_outside_backup
        and signature_valid
        and result.failed_count == 0
        and len(verified_entries) == len(selected_files)
        and hashes_match
        and tamper_detected
    ):
        print("SMOKE TEST RESULT: PASS WITH PASSWORD FALLBACK (DPAPI did not pass).")
        return 0

    print("SMOKE TEST RESULT: FAIL — review the checks above before reporting.")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Back up at most ten files from one Android shared-storage folder, "
            "then test signing, hashes, key protection, and tamper detection."
        )
    )
    parser.add_argument(
        "phone_folder",
        help="One absolute shared-storage folder, e.g. /sdcard/DCIM/Camera",
    )
    parser.add_argument(
        "--destination",
        type=Path,
        required=True,
        help="A new, non-existing folder on this computer for this smoke-test run",
    )
    parser.add_argument(
        "--serial",
        help="ADB serial if more than one device is connected (optional for one phone)",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=MAX_ALLOWED_FILES,
        help=f"Number of files to back up (1-{MAX_ALLOWED_FILES}; default: {MAX_ALLOWED_FILES})",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return _run(args)
    except KeyboardInterrupt:
        print("Smoke test cancelled by user.", file=sys.stderr)
        return 130
    except (AdbError, BackupError, SigningError, OSError, ValueError, RuntimeError) as exc:
        print(f"SMOKE TEST FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
