# SPDX-License-Identifier: MIT

import argparse
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from clawrtc import cli


class StrictLegacyStdout:
    """Minimal stdout that fails like a strict legacy Windows code page."""

    encoding = "cp850"

    def __init__(self):
        self.parts = []

    def write(self, text):
        text.encode(self.encoding, errors="strict")
        self.parts.append(text)
        return len(text)

    def flush(self):
        return None

    @property
    def text(self):
        return "".join(self.parts)


class FakePublicKey:
    def public_bytes(self, encoding, public_format):
        return b"q" * 32


class FakePrivateKey:
    @classmethod
    def generate(cls):
        return cls()

    def public_key(self):
        return FakePublicKey()

    def private_bytes(self, encoding, private_format, encryption):
        return b"p" * 32


class FakeEncoding:
    Raw = object()


class FakeNoEncryption:
    pass


class FakePrivateFormat:
    Raw = object()


class FakePublicFormat:
    Raw = object()


class WalletCreateEncodingTests(unittest.TestCase):
    def test_wallet_create_survives_legacy_stdout_encoding(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            wallet_dir = base / "wallets"
            install_dir = base / "install"
            wallet_file = wallet_dir / "default.json"
            install_dir.mkdir()

            stdout = StrictLegacyStdout()
            fake_ed25519 = (
                FakePrivateKey,
                FakeEncoding,
                FakeNoEncryption,
                FakePrivateFormat,
                FakePublicFormat,
            )

            with mock.patch.object(cli, "WALLET_DIR", str(wallet_dir)):
                with mock.patch.object(cli, "WALLET_FILE", str(wallet_file)):
                    with mock.patch.object(cli, "INSTALL_DIR", str(install_dir)):
                        with mock.patch.object(cli, "_get_ed25519", return_value=fake_ed25519):
                            with mock.patch("sys.stdout", stdout):
                                cli._wallet_create(argparse.Namespace(force=False))

            self.assertTrue(wallet_file.exists())
            self.assertTrue((install_dir / ".wallet").exists())

            wallet = json.loads(wallet_file.read_text())
            self.assertTrue(wallet["address"].startswith("RTC"))
            self.assertIn("RTC WALLET CREATED", stdout.text)


if __name__ == "__main__":
    unittest.main()
