"""Tests for cert/manager.py — CertManager trust store operations."""
from __future__ import annotations

import datetime
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scruxy.cert.manager import CertManager, _LINUX_CA_DIR


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def cert_dir(tmp_path: Path) -> Path:
    """Temporary directory simulating ~/.mitmproxy."""
    d = tmp_path / ".mitmproxy"
    d.mkdir()
    return d


@pytest.fixture
def windows_cert(cert_dir: Path) -> Path:
    """Create a fake Windows cert file."""
    cert = cert_dir / "mitmproxy-ca-cert.cer"
    cert.write_text("FAKE CERT DATA")
    return cert


@pytest.fixture
def pem_cert(cert_dir: Path) -> Path:
    """Create a fake PEM cert file (macOS / Linux)."""
    cert = cert_dir / "mitmproxy-ca-cert.pem"
    cert.write_text("FAKE PEM CERT DATA")
    return cert


@pytest.fixture
def real_pem_cert(tmp_path: Path) -> Path:
    """Generate a real self-signed PEM certificate for expiry tests."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "test-ca.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path


@pytest.fixture
def expiring_pem_cert(tmp_path: Path) -> Path:
    """Generate a PEM cert that expires in 10 days (triggers warning)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expiring CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expiring CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=355))
        .not_valid_after(now + datetime.timedelta(days=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "expiring-ca.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path


@pytest.fixture
def expired_pem_cert(tmp_path: Path) -> Path:
    """Generate a PEM cert that is already expired."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expired CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expired CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=400))
        .not_valid_after(now - datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "expired-ca.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path


def _make_manager(cert_dir: Path, platform: str, auto_uninstall: bool = True) -> CertManager:
    """Build a CertManager with a patched platform string."""
    mgr = CertManager(cert_dir=str(cert_dir), auto_uninstall_on_exit=auto_uninstall)
    mgr._platform = platform
    return mgr


# ---------------------------------------------------------------------------
# get_cert_path / cert_exists / fingerprint
# ---------------------------------------------------------------------------


class TestCertPaths:
    def test_get_cert_path_windows(self, cert_dir: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        assert mgr.get_cert_path() == cert_dir / "mitmproxy-ca-cert.cer"

    def test_get_cert_path_darwin(self, cert_dir: Path) -> None:
        mgr = _make_manager(cert_dir, "Darwin")
        assert mgr.get_cert_path() == cert_dir / "mitmproxy-ca-cert.pem"

    def test_get_cert_path_linux(self, cert_dir: Path) -> None:
        mgr = _make_manager(cert_dir, "Linux")
        assert mgr.get_cert_path() == cert_dir / "mitmproxy-ca-cert.pem"

    def test_cert_exists_true(self, cert_dir: Path, windows_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        assert mgr.cert_exists() is True

    def test_cert_exists_false(self, cert_dir: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        assert mgr.cert_exists() is False

    def test_fingerprint_returns_hex_when_file_exists(
        self, cert_dir: Path, windows_cert: Path
    ) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        fp = mgr.get_cert_fingerprint()
        assert fp is not None
        assert len(fp) == 64  # SHA-256 hex digest

    def test_fingerprint_returns_none_when_missing(self, cert_dir: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        assert mgr.get_cert_fingerprint() is None


# ---------------------------------------------------------------------------
# is_cert_installed
# ---------------------------------------------------------------------------


class TestIsCertInstalled:
    def test_windows_installed(self, cert_dir: Path, windows_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        expected_sha1 = mgr._get_cert_sha1_fingerprint()
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=f"Cert Hash(sha1): {expected_sha1}")
            assert mgr.is_cert_installed() is True
            mock_run.assert_called_once()
            args = mock_run.call_args
            assert "certutil" in args[0][0]
            assert "-store" in args[0][0]

    def test_windows_not_installed(self, cert_dir: Path, windows_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert mgr.is_cert_installed() is False

    def test_darwin_installed(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Darwin")
        expected_sha1 = mgr._get_cert_sha1_fingerprint()
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=f"SHA-1 hash: {expected_sha1}")
            assert mgr.is_cert_installed() is True
            args = mock_run.call_args
            assert "security" in args[0][0]

    def test_darwin_not_installed(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Darwin")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert mgr.is_cert_installed() is False

    def test_linux_installed(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Linux")
        with patch.object(type(mgr._linux_ca_dest), "is_file", return_value=True):
            assert mgr.is_cert_installed() is True

    def test_linux_not_installed(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Linux")
        # The PEM cert exists in cert_dir, but _linux_ca_dest does not
        assert mgr.is_cert_installed() is False

    def test_no_cert_file_returns_false(self, cert_dir: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        assert mgr.is_cert_installed() is False

    def test_subprocess_timeout_returns_false(
        self, cert_dir: Path, windows_cert: Path
    ) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("certutil", 30)
            assert mgr.is_cert_installed() is False

    def test_subprocess_file_not_found_returns_false(
        self, cert_dir: Path, windows_cert: Path
    ) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("certutil not found")
            assert mgr.is_cert_installed() is False

    def test_windows_uses_cert_cn(self, cert_dir: Path, windows_cert: Path) -> None:
        """Verify certutil uses the configured CN, not hardcoded 'mitmproxy'."""
        mgr = CertManager(
            cert_dir=str(cert_dir), cert_path=windows_cert, cert_cn="Scruxy PII Proxy CA"
        )
        mgr._platform = "Windows"
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=f"Cert Hash(sha1): {mgr._get_cert_sha1_fingerprint()}",
            )
            mgr.is_cert_installed()
            cmd = mock_run.call_args[0][0]
            assert cmd == ["certutil", "-store", "root", "Scruxy PII Proxy CA"]

    def test_darwin_uses_cert_cn(self, cert_dir: Path, pem_cert: Path) -> None:
        """Verify security command uses the configured CN."""
        mgr = CertManager(
            cert_dir=str(cert_dir), cert_path=pem_cert, cert_cn="Scruxy PII Proxy CA"
        )
        mgr._platform = "Darwin"
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=f"SHA-1 hash: {mgr._get_cert_sha1_fingerprint()}",
            )
            mgr.is_cert_installed()
            cmd = mock_run.call_args[0][0]
            assert "Scruxy PII Proxy CA" in cmd
            assert "-Z" in cmd

    def test_windows_mismatched_fingerprint_returns_false(self, cert_dir: Path, windows_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Cert Hash(sha1): DEADBEEF")
            assert mgr.is_cert_installed() is False


# ---------------------------------------------------------------------------
# install_cert
# ---------------------------------------------------------------------------


class TestInstallCert:
    def test_install_windows_success(self, cert_dir: Path, windows_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert mgr.install_cert() is True
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "certutil"
            assert cmd[1] == "-addstore"
            assert cmd[2] == "root"
            assert str(windows_cert) in cmd[3]

    def test_install_windows_failure(self, cert_dir: Path, windows_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="access denied")
            assert mgr.install_cert() is False

    def test_install_darwin_success(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Darwin")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert mgr.install_cert() is True
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "security"
            assert "add-trusted-cert" in cmd

    def test_install_darwin_failure(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Darwin")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="error")
            assert mgr.install_cert() is False

    def test_install_linux_success(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Linux")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            with patch("scruxy.cert.manager.shutil.copy2") as mock_copy:
                with patch("scruxy.cert.manager._LINUX_CA_DIR") as mock_dir:
                    mock_dir.mkdir = MagicMock()
                    assert mgr.install_cert() is True
                    mock_copy.assert_called_once()
                    # update-ca-certificates should be called
                    mock_run.assert_called_once()
                    assert "update-ca-certificates" in mock_run.call_args[0][0]

    def test_install_linux_failure(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Linux")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="permission denied")
            with patch("scruxy.cert.manager.shutil.copy2"):
                with patch("scruxy.cert.manager._LINUX_CA_DIR") as mock_dir:
                    mock_dir.mkdir = MagicMock()
                    assert mgr.install_cert() is False

    def test_install_linux_failure_removes_partial_file(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Linux")
        mock_dest = MagicMock()
        mock_dest.is_file.return_value = True

        with patch.object(type(mgr), "_linux_ca_dest", new_callable=lambda: property(lambda self: mock_dest)):
            with patch("scruxy.cert.manager.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stderr="permission denied")
                with patch("scruxy.cert.manager.shutil.copy2"):
                    with patch("scruxy.cert.manager._LINUX_CA_DIR") as mock_dir:
                        mock_dir.mkdir = MagicMock()
                        assert mgr.install_cert() is False

        mock_dest.unlink.assert_called_once()

    def test_install_no_cert_file(self, cert_dir: Path) -> None:
        """install_cert returns False when the cert file does not exist."""
        mgr = _make_manager(cert_dir, "Windows")
        assert mgr.install_cert() is False

    def test_install_unsupported_platform(self, cert_dir: Path, windows_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "FreeBSD")
        # The cert file name falls through to default (.pem), which doesn't exist.
        # But let's create one to test the platform branch.
        pem = cert_dir / "mitmproxy-ca-cert.pem"
        pem.write_text("FAKE")
        assert mgr.install_cert() is False

    def test_install_registers_atexit_on_success(
        self, cert_dir: Path, windows_cert: Path
    ) -> None:
        mgr = _make_manager(cert_dir, "Windows", auto_uninstall=True)
        assert mgr._cleanup_registered is False

        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            with patch("scruxy.cert.manager.atexit.register") as mock_atexit:
                mgr.install_cert()
                mock_atexit.assert_called_once()
                assert mgr._cleanup_registered is True

    def test_install_no_atexit_when_disabled(
        self, cert_dir: Path, windows_cert: Path
    ) -> None:
        mgr = _make_manager(cert_dir, "Windows", auto_uninstall=False)

        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            with patch("scruxy.cert.manager.atexit.register") as mock_atexit:
                mgr.install_cert()
                mock_atexit.assert_not_called()

    def test_install_subprocess_timeout(
        self, cert_dir: Path, windows_cert: Path
    ) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("certutil", 30)
            assert mgr.install_cert() is False


# ---------------------------------------------------------------------------
# uninstall_cert
# ---------------------------------------------------------------------------


class TestUninstallCert:
    def test_uninstall_windows_success(self, cert_dir: Path, windows_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert mgr.uninstall_cert() is True
            cmd = mock_run.call_args[0][0]
            assert cmd == ["certutil", "-delstore", "root", "mitmproxy"]

    def test_uninstall_windows_failure(self, cert_dir: Path, windows_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="not found")
            assert mgr.uninstall_cert() is False

    def test_uninstall_windows_uses_cert_cn(self, cert_dir: Path, windows_cert: Path) -> None:
        """Verify uninstall uses custom CN."""
        mgr = CertManager(
            cert_dir=str(cert_dir), cert_path=windows_cert, cert_cn="Scruxy PII Proxy CA"
        )
        mgr._platform = "Windows"
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            mgr.uninstall_cert()
            cmd = mock_run.call_args[0][0]
            assert cmd == ["certutil", "-delstore", "root", "Scruxy PII Proxy CA"]

    def test_uninstall_darwin_success(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Darwin")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert mgr.uninstall_cert() is True
            cmd = mock_run.call_args[0][0]
            assert cmd[0] == "security"
            assert "remove-trusted-cert" in cmd

    def test_uninstall_darwin_failure(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Darwin")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="error")
            assert mgr.uninstall_cert() is False

    def test_uninstall_linux_success(self, cert_dir: Path, pem_cert: Path) -> None:
        mgr = _make_manager(cert_dir, "Linux")
        mock_dest = MagicMock()
        mock_dest.is_file.return_value = True

        with patch.object(type(mgr), "_linux_ca_dest", new_callable=lambda: property(lambda self: mock_dest)):
            with patch("scruxy.cert.manager.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                assert mgr.uninstall_cert() is True
                mock_dest.unlink.assert_called_once()
                assert "update-ca-certificates" in mock_run.call_args[0][0]

    def test_uninstall_linux_no_dest_file(self, cert_dir: Path, pem_cert: Path) -> None:
        """If the system cert file doesn't exist, still run update-ca-certificates."""
        mgr = _make_manager(cert_dir, "Linux")
        mock_dest = MagicMock()
        mock_dest.is_file.return_value = False

        with patch.object(type(mgr), "_linux_ca_dest", new_callable=lambda: property(lambda self: mock_dest)):
            with patch("scruxy.cert.manager.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                assert mgr.uninstall_cert() is True
                mock_dest.unlink.assert_not_called()

    def test_uninstall_subprocess_timeout(
        self, cert_dir: Path, windows_cert: Path
    ) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("certutil", 30)
            assert mgr.uninstall_cert() is False


# ---------------------------------------------------------------------------
# atexit cleanup
# ---------------------------------------------------------------------------


class TestAtexitCleanup:
    def test_atexit_cleanup_calls_uninstall(
        self, cert_dir: Path, windows_cert: Path
    ) -> None:
        mgr = _make_manager(cert_dir, "Windows")
        with patch.object(mgr, "uninstall_cert") as mock_uninstall:
            mgr._atexit_cleanup()
            mock_uninstall.assert_called_once()

    def test_atexit_cleanup_handles_exception(
        self, cert_dir: Path, windows_cert: Path
    ) -> None:
        """atexit handler must not raise — it logs and swallows exceptions."""
        mgr = _make_manager(cert_dir, "Windows")
        with patch.object(mgr, "uninstall_cert", side_effect=RuntimeError("boom")):
            # Should not raise
            mgr._atexit_cleanup()

    def test_cleanup_registered_only_once(
        self, cert_dir: Path, windows_cert: Path
    ) -> None:
        mgr = _make_manager(cert_dir, "Windows", auto_uninstall=True)
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            with patch("scruxy.cert.manager.atexit.register") as mock_atexit:
                mgr.install_cert()
                mgr.install_cert()  # second call
                # Only registered once
                assert mock_atexit.call_count == 1


# ---------------------------------------------------------------------------
# Constructor defaults
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_default_cert_dir(self) -> None:
        mgr = CertManager()
        assert mgr.cert_dir == Path.home() / ".mitmproxy"

    def test_custom_cert_dir(self, tmp_path: Path) -> None:
        mgr = CertManager(cert_dir=str(tmp_path))
        assert mgr.cert_dir == tmp_path

    def test_auto_uninstall_default_true(self) -> None:
        mgr = CertManager()
        assert mgr._auto_uninstall_on_exit is True

    def test_auto_uninstall_false(self) -> None:
        mgr = CertManager(auto_uninstall_on_exit=False)
        assert mgr._auto_uninstall_on_exit is False


# ---------------------------------------------------------------------------
# Generic CertManager (cert_path + cert_cn)
# ---------------------------------------------------------------------------


class TestCertManagerGeneric:
    """Verify cert_path and cert_cn parameters work correctly."""

    def test_cert_path_overrides_filename_convention(self, tmp_path: Path) -> None:
        custom_cert = tmp_path / "my-ca.pem"
        custom_cert.write_text("CUSTOM CERT")
        mgr = CertManager(cert_dir=str(tmp_path), cert_path=custom_cert)
        assert mgr.get_cert_path() == custom_cert
        assert mgr.cert_exists() is True

    def test_cert_path_none_falls_back_to_convention(self, cert_dir: Path) -> None:
        mgr = CertManager(cert_dir=str(cert_dir))
        # Should use platform filename convention
        path = mgr.get_cert_path()
        assert path.parent == cert_dir

    def test_cert_cn_default_is_mitmproxy(self) -> None:
        mgr = CertManager()
        assert mgr._cert_cn == "mitmproxy"

    def test_cert_cn_custom(self) -> None:
        mgr = CertManager(cert_cn="Scruxy PII Proxy CA")
        assert mgr._cert_cn == "Scruxy PII Proxy CA"

    def test_cert_path_as_string(self, tmp_path: Path) -> None:
        custom_cert = tmp_path / "my-ca.pem"
        custom_cert.write_text("CUSTOM CERT")
        mgr = CertManager(cert_dir=str(tmp_path), cert_path=str(custom_cert))
        assert mgr.get_cert_path() == custom_cert

    def test_fingerprint_with_cert_path(self, tmp_path: Path) -> None:
        custom_cert = tmp_path / "my-ca.pem"
        custom_cert.write_text("CUSTOM CERT DATA")
        mgr = CertManager(cert_dir=str(tmp_path), cert_path=custom_cert)
        fp = mgr.get_cert_fingerprint()
        assert fp is not None
        assert len(fp) == 64

    def test_linux_ca_dest_parameterized_by_cn(self) -> None:
        mgr = CertManager(cert_cn="Scruxy PII Proxy CA")
        mgr._platform = "Linux"
        dest = mgr._linux_ca_dest
        assert dest.parent == _LINUX_CA_DIR
        assert "scruxy-pii-proxy-ca" in dest.name

    def test_linux_ca_dest_default_mitmproxy(self) -> None:
        mgr = CertManager()
        mgr._platform = "Linux"
        dest = mgr._linux_ca_dest
        assert dest.name == "mitmproxy-ca.crt"


# ---------------------------------------------------------------------------
# get_cert_expiry
# ---------------------------------------------------------------------------


class TestGetCertExpiry:
    def test_returns_datetime_for_valid_pem(self, tmp_path: Path, real_pem_cert: Path) -> None:
        mgr = CertManager(cert_dir=str(tmp_path), cert_path=real_pem_cert)
        expiry = mgr.get_cert_expiry()
        assert expiry is not None
        assert isinstance(expiry, datetime.datetime)
        # Should be about 365 days from now
        delta = expiry - datetime.datetime.now(datetime.timezone.utc)
        assert 360 < delta.days <= 366

    def test_returns_none_for_missing_cert(self, tmp_path: Path) -> None:
        mgr = CertManager(cert_dir=str(tmp_path), cert_path=tmp_path / "nonexistent.pem")
        assert mgr.get_cert_expiry() is None

    def test_returns_none_for_invalid_pem(self, tmp_path: Path) -> None:
        bad_cert = tmp_path / "bad.pem"
        bad_cert.write_text("NOT A VALID CERT")
        mgr = CertManager(cert_dir=str(tmp_path), cert_path=bad_cert)
        assert mgr.get_cert_expiry() is None

    def test_expiring_cert(self, tmp_path: Path, expiring_pem_cert: Path) -> None:
        mgr = CertManager(cert_dir=str(tmp_path), cert_path=expiring_pem_cert)
        expiry = mgr.get_cert_expiry()
        assert expiry is not None
        delta = expiry - datetime.datetime.now(datetime.timezone.utc)
        assert 0 < delta.days <= 11

    def test_expired_cert(self, tmp_path: Path, expired_pem_cert: Path) -> None:
        mgr = CertManager(cert_dir=str(tmp_path), cert_path=expired_pem_cert)
        expiry = mgr.get_cert_expiry()
        assert expiry is not None
        delta = expiry - datetime.datetime.now(datetime.timezone.utc)
        assert delta.total_seconds() < 0


# ---------------------------------------------------------------------------
# get_cert_info
# ---------------------------------------------------------------------------


class TestGetCertInfo:
    def test_info_with_valid_cert(self, tmp_path: Path, real_pem_cert: Path) -> None:
        mgr = CertManager(
            cert_dir=str(tmp_path),
            cert_path=real_pem_cert,
            cert_cn="Test CA",
        )
        mgr._platform = "Windows"
        expected_sha1 = mgr._get_cert_sha1_fingerprint()
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=f"Cert Hash(sha1): {expected_sha1}")
            info = mgr.get_cert_info()

        assert info["exists"] is True
        assert info["installed"] is True
        assert info["fingerprint"] is not None
        assert info["cn"] == "Test CA"
        assert info["expiry_date"] is not None
        assert info["days_until_expiry"] > 300
        assert info["expired"] is False
        assert info["expiry_warning"] is False
        assert info["error"] is None
        assert info["cert_path"] == str(real_pem_cert)

    def test_info_with_missing_cert(self, tmp_path: Path) -> None:
        mgr = CertManager(
            cert_dir=str(tmp_path),
            cert_path=tmp_path / "missing.pem",
            cert_cn="Test",
        )
        info = mgr.get_cert_info()
        assert info["exists"] is False
        assert info["installed"] is False
        assert info["fingerprint"] is None
        assert info["expiry_date"] is None

    def test_info_expiry_warning(self, tmp_path: Path, expiring_pem_cert: Path) -> None:
        mgr = CertManager(
            cert_dir=str(tmp_path),
            cert_path=expiring_pem_cert,
            cert_cn="Expiring CA",
        )
        mgr._platform = "Windows"
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            info = mgr.get_cert_info()

        assert info["exists"] is True
        assert info["expiry_warning"] is True
        assert info["expired"] is False
        assert 0 < info["days_until_expiry"] < 30

    def test_info_expired(self, tmp_path: Path, expired_pem_cert: Path) -> None:
        mgr = CertManager(
            cert_dir=str(tmp_path),
            cert_path=expired_pem_cert,
            cert_cn="Expired CA",
        )
        mgr._platform = "Windows"
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            info = mgr.get_cert_info()

        assert info["exists"] is True
        assert info["expired"] is True
        assert info["expiry_warning"] is False

    def test_info_not_installed(self, tmp_path: Path, real_pem_cert: Path) -> None:
        mgr = CertManager(
            cert_dir=str(tmp_path),
            cert_path=real_pem_cert,
            cert_cn="Test CA",
        )
        mgr._platform = "Windows"
        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            info = mgr.get_cert_info()

        assert info["exists"] is True
        assert info["installed"] is False

    def test_info_expiry_warning_with_less_than_one_day_remaining(self, tmp_path: Path, real_pem_cert: Path) -> None:
        mgr = CertManager(
            cert_dir=str(tmp_path),
            cert_path=real_pem_cert,
            cert_cn="Soon Expiring CA",
        )
        mgr._platform = "Windows"
        soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=12)
        with patch.object(mgr, "get_cert_expiry", return_value=soon):
            with patch("scruxy.cert.manager.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1)
                info = mgr.get_cert_info()

        assert info["expired"] is False
        assert info["expiry_warning"] is True
        assert info["days_until_expiry"] == 0


# ---------------------------------------------------------------------------
# cleanup_old_certs
# ---------------------------------------------------------------------------


class TestCleanupOldCerts:
    def test_windows_removes_multiple(self) -> None:
        mgr = CertManager(cert_cn="Scruxy PII Proxy CA")
        mgr._platform = "Windows"

        # Simulate 3 store checks + deletions, then a final not-present check.
        returns = [
            MagicMock(returncode=0),
            MagicMock(returncode=0),
            MagicMock(returncode=0),
            MagicMock(returncode=0),
            MagicMock(returncode=0),
            MagicMock(returncode=0),
            MagicMock(returncode=1),
        ]
        with patch("scruxy.cert.manager.subprocess.run", side_effect=returns) as mock_run:
            removed = mgr.cleanup_old_certs()

        assert removed == 3
        assert mock_run.call_count == 7
        assert mock_run.call_args_list[0][0][0] == ["certutil", "-verifystore", "root", "Scruxy PII Proxy CA"]
        assert mock_run.call_args_list[1][0][0] == ["certutil", "-f", "-delstore", "root", "Scruxy PII Proxy CA"]

    def test_windows_none_to_remove(self) -> None:
        mgr = CertManager(cert_cn="Scruxy PII Proxy CA")
        mgr._platform = "Windows"

        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            removed = mgr.cleanup_old_certs()

        assert removed == 0
        mock_run.assert_called_once_with(
            ["certutil", "-verifystore", "root", "Scruxy PII Proxy CA"],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_windows_max_iterations(self) -> None:
        """Should stop after 10 iterations even if all succeed."""
        mgr = CertManager(cert_cn="Test")
        mgr._platform = "Windows"

        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            removed = mgr.cleanup_old_certs()

        assert removed == 10
        assert mock_run.call_count == 20

    def test_darwin_removes_one(self) -> None:
        mgr = CertManager(cert_cn="Scruxy PII Proxy CA")
        mgr._platform = "Darwin"

        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            removed = mgr.cleanup_old_certs()

        assert removed == 1
        cmd = mock_run.call_args[0][0]
        assert cmd == ["security", "delete-certificate", "-c", "Scruxy PII Proxy CA"]

    def test_darwin_nothing_to_remove(self) -> None:
        mgr = CertManager(cert_cn="Scruxy PII Proxy CA")
        mgr._platform = "Darwin"

        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            removed = mgr.cleanup_old_certs()

        assert removed == 0

    def test_linux_removes_file(self, tmp_path: Path) -> None:
        mgr = CertManager(cert_cn="Test CA")
        mgr._platform = "Linux"

        mock_dest = MagicMock()
        mock_dest.is_file.return_value = True

        with patch.object(type(mgr), "_linux_ca_dest", new_callable=lambda: property(lambda self: mock_dest)):
            with patch("scruxy.cert.manager.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                removed = mgr.cleanup_old_certs()

        assert removed == 1
        mock_dest.unlink.assert_called_once()

    def test_linux_no_file(self) -> None:
        mgr = CertManager(cert_cn="Test CA")
        mgr._platform = "Linux"

        mock_dest = MagicMock()
        mock_dest.is_file.return_value = False

        with patch.object(type(mgr), "_linux_ca_dest", new_callable=lambda: property(lambda self: mock_dest)):
            removed = mgr.cleanup_old_certs()

        assert removed == 0

    def test_handles_subprocess_error(self) -> None:
        mgr = CertManager(cert_cn="Test")
        mgr._platform = "Windows"

        with patch("scruxy.cert.manager.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("certutil", 30)
            removed = mgr.cleanup_old_certs()

        assert removed == 0
