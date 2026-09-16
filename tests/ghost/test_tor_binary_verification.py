"""
Tests for Step 9.1: Bundled Tor Binary Verification & Packaging Integrity.

Verifies:
1. Expected tor.exe exists in tools/tor/
2. Expected PE architecture is x86_64 (IMAGE_FILE_MACHINE_AMD64)
3. Manifest integrity: tools/tor/manifest.json matches actual files and hashes
4. Rejection of unexpected executables (only tor.exe allowed in tools/tor/)
5. Execution verification: tor.exe --version succeeds and reports Tor version
6. Preserved required data files (geoip, geoip6) and redistribution notices

DOES NOT test live Tor network connectivity or bootstrap.
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TOR_DIR = os.path.join(REPO_ROOT, "tools", "tor")
TOR_EXE = os.path.join(TOR_DIR, "tor.exe")
MANIFEST_PATH = os.path.join(TOR_DIR, "manifest.json")


class TestTorBinaryVerification(unittest.TestCase):
    """Integrity and security verification for the official bundled Tor binary."""

    def test_01_tor_executable_exists(self):
        """[INTEGRITY] Verify that tools/tor/tor.exe exists and is accessible as a file."""
        self.assertTrue(
            os.path.isdir(TOR_DIR),
            f"Tools directory missing: {TOR_DIR}"
        )
        self.assertTrue(
            os.path.isfile(TOR_EXE),
            f"Bundled Tor executable missing: {TOR_EXE}"
        )
        self.assertGreater(
            os.path.getsize(TOR_EXE),
            5 * 1024 * 1024,
            "tor.exe size appears suspiciously small (< 5 MB)"
        )

    def test_02_tor_pe_architecture_x86_64(self):
        """[SECURITY] Verify that tor.exe is a valid PE32+ 64-bit executable (IMAGE_FILE_MACHINE_AMD64)."""
        with open(TOR_EXE, "rb") as f:
            dos_header = f.read(64)
            self.assertEqual(dos_header[:2], b"MZ", "Missing DOS 'MZ' header magic")

            # Extract e_lfanew offset to PE signature
            e_lfanew = struct.unpack("<I", dos_header[60:64])[0]
            f.seek(e_lfanew)

            pe_sig = f.read(4)
            self.assertEqual(pe_sig, b"PE\x00\x00", "Missing 'PE\\0\\0' NT signature")

            # Read COFF File Header (20 bytes)
            file_header = f.read(20)
            machine = struct.unpack("<H", file_header[0:2])[0]
            num_sections = struct.unpack("<H", file_header[2:4])[0]
            opt_header_size = struct.unpack("<H", file_header[16:18])[0]

            # 0x8664 = IMAGE_FILE_MACHINE_AMD64
            self.assertEqual(
                machine,
                0x8664,
                f"Architecture mismatch: expected 0x8664 (AMD64/x86_64), got 0x{machine:04x}"
            )
            self.assertGreater(num_sections, 0, "No sections in PE header")

            # Read Optional Header Magic (2 bytes)
            opt_header = f.read(opt_header_size)
            magic = struct.unpack("<H", opt_header[0:2])[0]
            # 0x20b = PE32+ (64-bit)
            self.assertEqual(
                magic,
                0x20b,
                f"PE magic mismatch: expected 0x20b (PE32+ 64-bit), got 0x{magic:04x}"
            )

            # Check Subsystem at offset 68 (2 bytes): 3 = IMAGE_SUBSYSTEM_WINDOWS_CUI (Console)
            subsystem = struct.unpack("<H", opt_header[68:70])[0]
            self.assertEqual(
                subsystem,
                3,
                f"Subsystem mismatch: expected 3 (Windows Console/CUI), got {subsystem}"
            )

    def test_03_manifest_integrity_and_checksums(self):
        """[PROVENANCE] Verify tools/tor/manifest.json matches disk files and official upstream metadata."""
        self.assertTrue(os.path.isfile(MANIFEST_PATH), f"Manifest missing: {MANIFEST_PATH}")

        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # Validate mandatory metadata fields
        self.assertEqual(manifest.get("release_identifier"), "15.0.23")
        self.assertEqual(manifest.get("archive_filename"), "tor-expert-bundle-windows-x86_64-15.0.23.tar.gz")
        self.assertEqual(
            manifest.get("archive_sha256"),
            "231dad6b9cb401a54c260db7046965ef04e4f72ff071b140d423fb5da281ab1e"
        )
        self.assertEqual(
            manifest.get("signing_key_fingerprint"),
            "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
        )
        self.assertIn("0.4.9.12", manifest.get("tor_daemon_version", ""))

        packaged_files = manifest.get("packaged_files", {})
        self.assertIn("tor.exe", packaged_files)
        self.assertIn("geoip", packaged_files)
        self.assertIn("geoip6", packaged_files)

        # Verify each packaged file against disk
        for rel_path, meta in packaged_files.items():
            full_path = os.path.join(TOR_DIR, *rel_path.split("/"))
            self.assertTrue(os.path.isfile(full_path), f"Packaged file not found on disk: {rel_path}")

            disk_size = os.path.getsize(full_path)
            self.assertEqual(
                disk_size,
                meta["size_bytes"],
                f"Size mismatch for {rel_path}: expected {meta['size_bytes']}, got {disk_size}"
            )

            with open(full_path, "rb") as fp:
                disk_sha256 = hashlib.sha256(fp.read()).hexdigest()

            self.assertEqual(
                disk_sha256.lower(),
                meta["sha256"].lower(),
                f"SHA-256 digest mismatch for {rel_path}: expected {meta['sha256']}, got {disk_sha256}"
            )

    def test_04_no_unexpected_executables(self):
        """[SECURITY] Verify no unexpected or unvetted executables/scripts reside in tools/tor/."""
        executable_extensions = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".msi"}
        allowed_executables = {"tor.exe"}

        found_executables = set()
        for root, dirs, files in os.walk(TOR_DIR):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in executable_extensions:
                    found_executables.add(f)

        unexpected = found_executables - allowed_executables
        self.assertEqual(
            unexpected,
            set(),
            f"Unexpected executable files detected in tools/tor/: {unexpected}"
        )

    def test_05_tor_version_command_succeeds(self):
        """[EXECUTION] Verify tor.exe --version succeeds and exits normally without network activity."""
        cmd = [TOR_EXE, "--version"]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )

        self.assertEqual(
            proc.returncode,
            0,
            f"tor.exe --version exited with non-zero code {proc.returncode}. Stderr: {proc.stderr}"
        )
        self.assertIn(
            "Tor version 0.4.9.12",
            proc.stdout,
            f"Version output does not contain expected Tor daemon version. Stdout: {proc.stdout}"
        )
        self.assertIn(
            "Windows",
            proc.stdout,
            f"Version output does not identify Windows platform. Stdout: {proc.stdout}"
        )

    def test_06_required_notices_and_geoip_present(self):
        """[COMPLIANCE] Verify required GeoIP databases and redistribution license notices are present."""
        self.assertTrue(os.path.isfile(os.path.join(TOR_DIR, "geoip")), "geoip database missing")
        self.assertTrue(os.path.isfile(os.path.join(TOR_DIR, "geoip6")), "geoip6 database missing")
        self.assertTrue(
            os.path.isfile(os.path.join(TOR_DIR, "THIRD_PARTY_NOTICES.txt")),
            "THIRD_PARTY_NOTICES.txt missing"
        )
        self.assertTrue(
            os.path.isfile(os.path.join(TOR_DIR, "docs", "tor.txt")),
            "docs/tor.txt license notice missing"
        )


if __name__ == "__main__":
    unittest.main()
