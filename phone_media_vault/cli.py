"""Command-line interface for Phone Media Vault.

Examples (from the repository root)::

    python -m phone_media_vault.cli devices
    python -m phone_media_vault.cli sources
    python -m phone_media_vault.cli backup --source folder:dcim --destination D:/Vault/MyPhone
    python -m phone_media_vault.cli verify D:/Vault/MyPhone --report report.html
    python -m phone_media_vault.cli restore D:/Vault/MyPhone --target /sdcard/Restored
    python -m phone_media_vault.cli wipe D:/Vault/MyPhone --dry-run
    python -m phone_media_vault.cli export D:/Vault/MyPhone E:/MyPhone.zip

Add ``--demo`` before the command to use the built-in simulated phone.
The signing-key passphrase is read from ``PMV_KEY_PASSWORD`` or prompted.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__
from .core.adb_manager import AdbError, AdbManager
from .core.adb_writer import AdbWriter
from .core.backup_engine import BackupEngine, BackupError
from .core.report import human_size, write_verification_report
from .core.restore import DEFAULT_RESTORE_FOLDER, RestoreEngine, RestoreError
from .core.scanner import custom_source, discover_sources, scan_sources
from .core.signer import (
    KeyPasswordRequiredError,
    ManifestSigner,
    PrivateKeyStore,
    SigningError,
    WindowsDpapiProtector,
)
from .core.verifier import verify_backup
from .core.wipe import WIPE_CONFIRMATION_PHRASES, SafeWipe, WipeError


def _print_progress(prefix: str, done: int, total: int, extra: str = "") -> None:
    width = 30
    filled = int(width * done / total) if total else width
    bar = "#" * filled + "-" * (width - filled)
    sys.stdout.write(f"\r{prefix} [{bar}] {done}/{total} {extra[:60]:<60}")
    sys.stdout.flush()
    if done >= total:
        sys.stdout.write("\n")


class Context:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        if args.demo:
            from .app.demo import DemoPhone

            phone = DemoPhone(args.demo_root) if args.demo_root else DemoPhone()
            self.adb = phone
            self.writer = phone
            print(f"[demo] simulated phone at {phone.root}")
        else:
            self.adb = AdbManager(args.adb) if args.adb else AdbManager()
            self.writer = AdbWriter(self.adb)
        key_path = Path(args.key_dir) / "ed25519-private.key" if args.key_dir else None
        self.store = PrivateKeyStore(key_path)
        self.signer = ManifestSigner(self.store)
        self.password: str | None = None

    def device(self):
        return self.adb.get_device_info(self.args.serial)

    def trusted_key(self) -> bytes | None:
        path = self.signer.trusted_public_key_path
        return path.read_bytes() if path.is_file() else None

    def unlock_signer(self) -> None:
        mode = self.store.protection_mode
        env_password = os.environ.get("PMV_KEY_PASSWORD") or None
        if mode == "dpapi":
            self.signer.public_key_bytes()
            return
        if mode == "password":
            self.password = env_password or getpass.getpass("Signing-key passphrase: ")
            self.signer.public_key_bytes(self.password)
            return
        if WindowsDpapiProtector().available() and not env_password:
            self.signer.public_key_bytes()
            return
        password = env_password
        if not password:
            password = getpass.getpass("Create a signing-key passphrase (8+ chars): ")
            if len(password) < 8 or password != getpass.getpass("Confirm passphrase: "):
                raise SigningError("Passphrase too short or confirmation mismatch.")
        self.password = password
        self.signer.public_key_bytes(password)


def cmd_devices(ctx: Context) -> int:
    devices = ctx.adb.list_devices()
    if not devices:
        print("No Android devices found.")
        return 1
    for device in devices:
        print(f"{device.serial}\t{device.state}\t{device.model}\t{device.status_ar}")
    return 0


def cmd_sources(ctx: Context) -> int:
    device = ctx.device()
    for source in discover_sources(ctx.adb, device.serial):
        print(f"{source.source_id:<28} {source.root_path:<55} {source.label_en}")
    return 0


def _selected_sources(ctx: Context, serial: str):
    available = {s.source_id: s for s in discover_sources(ctx.adb, serial)}
    selected = []
    for source_id in ctx.args.source or []:
        if source_id not in available:
            raise ValueError(f"Unknown source id: {source_id} (run 'sources')")
        selected.append(available[source_id])
    for folder in ctx.args.folder or []:
        selected.append(custom_source(folder))
    if not selected:
        raise ValueError("Pass at least one --source ID or --folder PATH.")
    return selected


def cmd_scan(ctx: Context) -> int:
    device = ctx.device()
    result = scan_sources(ctx.adb, device.serial, _selected_sources(ctx, device.serial))
    print(f"Files: {result.total_files} ({human_size(result.total_bytes)})")
    print(f"  photos: {result.photo_count} ({human_size(result.photo_bytes)})")
    print(f"  videos: {result.video_count} ({human_size(result.video_bytes)})")
    print(f"  other:  {result.other_count} ({human_size(result.other_bytes)})")
    print(f"Warnings: {len(result.warnings)}; symlinks skipped: {result.skipped_symlink_count}")
    return 0


def cmd_backup(ctx: Context) -> int:
    device = ctx.device()
    scan = scan_sources(ctx.adb, device.serial, _selected_sources(ctx, device.serial))
    print(f"Scanned {scan.total_files} files ({human_size(scan.total_bytes)}).")
    if not scan.files:
        print("Nothing to back up.")
        return 1
    ctx.unlock_signer()
    engine = BackupEngine(ctx.adb, ctx.signer, app_version=__version__, max_retries=ctx.args.retries)
    result = engine.backup(
        device.serial, device, scan, Path(ctx.args.destination).expanduser(),
        hash_serial=ctx.args.hash_serial, signing_password=ctx.password,
        progress_callback=lambda p: _print_progress("backup", p.files_done, p.files_total, p.current_phone_path or ""),
    )
    print(f"Verified: {result.verified_count}/{result.files_total} (skipped unchanged: {result.skipped_count})")
    print(f"Failed: {result.failed_count}")
    for failure in result.failed_files[:20]:
        print(f"  ! {failure['phone_path']}: {failure['error']}")
    print(f"Backup folder: {result.backup_directory}")
    print("FULLY VERIFIED" if result.fully_verified else "NOT fully verified — review warnings/failures.")
    return 0 if result.fully_verified else 2


def cmd_verify(ctx: Context) -> int:
    report = verify_backup(
        Path(ctx.args.backup).expanduser(),
        trusted_public_key_bytes=None if ctx.args.no_trust_check else ctx.trusted_key(),
        check_hashes=not ctx.args.quick,
        progress_callback=lambda p: _print_progress("verify", p.files_done, p.files_total, p.current_relative_path or ""),
    )
    print(report.verdict_ar)
    print(f"signature valid: {report.signature_valid}; key trusted: {report.public_key_trusted}")
    print(f"ok: {report.ok_count}; damaged/missing: {len(report.damaged_checks)}; "
          f"not backed up: {report.not_backed_up_count}; extra files: {len(report.extra_files)}")
    for check in report.damaged_checks[:30]:
        print(f"  ! {check.status_ar}: {check.phone_path}")
    if ctx.args.report and report.manifest_present:
        path = write_verification_report(report, ctx.args.report, app_version=__version__)
        print(f"HTML report: {path}")
    return 0 if report.intact else 2


def cmd_restore(ctx: Context) -> int:
    device = ctx.device()
    engine = RestoreEngine(ctx.writer, trusted_public_key_bytes=ctx.trusted_key())
    plan = engine.plan(
        Path(ctx.args.backup).expanduser(),
        mode="original" if ctx.args.to_original else "folder",
        target_root=ctx.args.target,
    )
    print(f"Files to restore: {len(plan.items)} ({human_size(plan.total_bytes)})")
    if not plan.items:
        return 1
    if not ctx.args.yes:
        answer = input("Write these files to the phone? Existing files are never overwritten. [y/N] ")
        if answer.strip().lower() not in {"y", "yes", "نعم"}:
            print("Cancelled.")
            return 1
    result = engine.restore(
        device.serial, plan,
        conflict_policy="rename" if ctx.args.rename_conflicts else "skip",
        progress_callback=lambda p: _print_progress("restore", p.files_done, p.files_total, p.current_phone_path or ""),
    )
    print(f"Restored: {result.restored_count}; already present: {result.already_present_count}; "
          f"conflicts skipped: {result.conflict_count}; failed: {result.failed_count}")
    return 0 if result.failed_count == 0 else 2


def cmd_wipe(ctx: Context) -> int:
    device = ctx.device()
    wiper = SafeWipe(ctx.writer, trusted_public_key_bytes=ctx.trusted_key())
    plan = wiper.plan(device.serial, Path(ctx.args.backup).expanduser(),
                      progress_callback=lambda p: _print_progress("check", p.files_done, p.files_total, p.current_phone_path or ""))
    print(f"Eligible for deletion: {len(plan.eligible)} ({human_size(plan.eligible_bytes)})")
    print(f"Kept on phone: {len(plan.rejected)}")
    for rejection in plan.rejected[:20]:
        print(f"  - {rejection.phone_path}: {rejection.reason_ar}")
    if ctx.args.dry_run or not plan.eligible:
        return 0
    phrase = ctx.args.confirm or input(f"Type '{WIPE_CONFIRMATION_PHRASES[1]}' to delete: ")
    result = wiper.execute(plan, phrase)
    print(f"Deleted: {len(result.deleted)} (freed {human_size(result.freed_bytes)}); "
          f"skipped: {len(result.skipped)}; failed: {len(result.failed)}")
    return 0 if not result.failed else 2


def cmd_export(ctx: Context) -> int:
    from .core.archive import export_encrypted_archive

    password = os.environ.get("PMV_ARCHIVE_PASSWORD") or getpass.getpass("Archive password (8+ chars): ")
    if not os.environ.get("PMV_ARCHIVE_PASSWORD") and password != getpass.getpass("Confirm: "):
        print("Passwords do not match.")
        return 1
    result = export_encrypted_archive(
        Path(ctx.args.backup).expanduser(), Path(ctx.args.archive).expanduser(), password,
        trusted_public_key_bytes=ctx.trusted_key(),
        progress_callback=lambda p: _print_progress("export", p.files_done, p.files_total, p.current or ""),
    )
    print(f"Encrypted archive: {result.archive_path} ({result.files_archived} files)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phone_media_vault", description="Phone Media Vault CLI")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--demo", action="store_true", help="use the simulated demo phone")
    parser.add_argument("--demo-root", help="folder for the demo phone (default: temp)")
    parser.add_argument("--serial", help="ADB serial when several phones are connected")
    parser.add_argument("--adb", help="explicit path to adb executable or platform-tools folder")
    parser.add_argument("--key-dir", help="override the signing-key folder (advanced/testing)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("devices", help="list ADB devices")
    sub.add_parser("sources", help="list storage sources on the phone")
    for name in ("scan", "backup"):
        p = sub.add_parser(name, help=f"{name} selected sources")
        p.add_argument("--source", action="append", help="source id from 'sources' (repeatable)")
        p.add_argument("--folder", action="append", help="custom shared-storage folder (repeatable)")
        if name == "backup":
            p.add_argument("--destination", required=True)
            p.add_argument("--hash-serial", action="store_true")
            p.add_argument("--retries", type=int, default=3)
    p = sub.add_parser("verify", help="verify a backup folder offline")
    p.add_argument("backup")
    p.add_argument("--report", help="write an HTML report to this path")
    p.add_argument("--quick", action="store_true", help="check sizes only (no hashing)")
    p.add_argument("--no-trust-check", action="store_true", help="skip local public-key trust check")
    p = sub.add_parser("restore", help="restore a backup to the phone")
    p.add_argument("backup")
    p.add_argument("--to-original", action="store_true", help="restore to original phone paths")
    p.add_argument("--target", default=DEFAULT_RESTORE_FOLDER, help="phone folder for restored files")
    p.add_argument("--rename-conflicts", action="store_true")
    p.add_argument("--yes", action="store_true")
    p = sub.add_parser("wipe", help="delete phone files proven to be in the backup")
    p.add_argument("backup")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--confirm", help="confirmation phrase (non-interactive)")
    p = sub.add_parser("export", help="export an AES-256 encrypted ZIP")
    p.add_argument("backup")
    p.add_argument("archive")
    return parser


COMMANDS = {
    "devices": cmd_devices, "sources": cmd_sources, "scan": cmd_scan, "backup": cmd_backup,
    "verify": cmd_verify, "restore": cmd_restore, "wipe": cmd_wipe, "export": cmd_export,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # Arabic messages on Windows consoles
        except (AttributeError, ValueError):
            pass
    try:
        return COMMANDS[args.command](Context(args))
    except (AdbError, BackupError, SigningError, RestoreError, WipeError, KeyPasswordRequiredError) as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
