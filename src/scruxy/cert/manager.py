"""Auto certificate install/uninstall per platform with atexit cleanup.

Manages CA certificate lifecycle: checking trust store status, installing to /
removing from the system trust store, and registering cleanup handlers so the
cert is removed on shutdown even after unexpected exits.

Supports both mitmproxy CA certs (filename convention) and explicit cert paths
(e.g. Scruxy's own CA).  The ``cert_cn`` parameter controls the Common Name
used for trust store lookups.

Platform-specific commands (from design doc):
  Windows:  certutil -addstore / -delstore
  macOS:    security add-trusted-cert / remove-trusted-cert
  Linux:    copy to /usr/local/share/ca-certificates + update-ca-certificates
"""
from __future__ import annotations

import atexit
import datetime
import hashlib
import logging
import platform
import re
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Platform-specific cert file names produced by mitmproxy
_CERT_FILENAMES: dict[str, str] = {
    "Windows": "mitmproxy-ca-cert.cer",
    "Darwin": "mitmproxy-ca-cert.pem",
    "Linux": "mitmproxy-ca-cert.pem",
}

# Linux system cert destination
_LINUX_CA_DIR = Path("/usr/local/share/ca-certificates")
_LINUX_CA_DEST = _LINUX_CA_DIR / "mitmproxy-ca.crt"

# Expiry warning threshold (days)
_EXPIRY_WARNING_DAYS = 30


class CertManager:
    """Manage a CA certificate in the OS trust store.

    Parameters
    ----------
    cert_dir:
        Directory where the CA files are stored.
        Defaults to ``~/.mitmproxy``.
    auto_uninstall_on_exit:
        If ``True``, register an ``atexit`` handler that calls
        :meth:`uninstall_cert` when the process exits.
    cert_path:
        Explicit path to the certificate file.  When set, overrides the
        filename convention derived from ``cert_dir``.
    cert_cn:
        Common Name used for trust store lookups (``certutil -verifystore``,
        ``security find-certificate -c``).  Defaults to ``"mitmproxy"``.
    """

    def __init__(
        self,
        cert_dir: str = "~/.mitmproxy",
        auto_uninstall_on_exit: bool = True,
        *,
        cert_path: Path | str | None = None,
        cert_cn: str = "mitmproxy",
    ) -> None:
        self.cert_dir = Path(cert_dir).expanduser()
        self._platform = platform.system()  # "Windows", "Darwin", "Linux"
        self._auto_uninstall_on_exit = auto_uninstall_on_exit
        self._cleanup_registered = False
        self._cert_path = Path(cert_path) if cert_path is not None else None
        self._cert_cn = cert_cn

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_cert_path(self) -> Path:
        """Return the path to the CA certificate file.

        If ``cert_path`` was provided at construction, returns that path.
        Otherwise falls back to the mitmproxy filename convention.
        """
        if self._cert_path is not None:
            return self._cert_path
        filename = _CERT_FILENAMES.get(self._platform, "mitmproxy-ca-cert.pem")
        return self.cert_dir / filename

    def cert_exists(self) -> bool:
        """Return ``True`` if the CA cert file exists on disk."""
        return self.get_cert_path().is_file()

    def get_cert_fingerprint(self) -> str | None:
        """Return the SHA-256 fingerprint of the CA cert, or ``None``."""
        cert_path = self.get_cert_path()
        if not cert_path.is_file():
            return None
        data = cert_path.read_bytes()
        return hashlib.sha256(data).hexdigest()

    def _get_cert_sha1_fingerprint(self) -> str | None:
        """Return the SHA-1 fingerprint of the parsed certificate (DER bytes).

        OS trust-store tools (certutil, security) report hashes of the
        DER-encoded certificate, not the raw PEM file.
        """
        cert_path = self.get_cert_path()
        if not cert_path.is_file():
            return None
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization

            pem_data = cert_path.read_bytes()
            cert = x509.load_pem_x509_certificate(pem_data)
            der_bytes = cert.public_bytes(serialization.Encoding.DER)
            return hashlib.sha1(der_bytes).hexdigest().upper()
        except Exception:
            # Fallback: hash PEM bytes (won't match OS tools but won't crash)
            data = cert_path.read_bytes()
            return hashlib.sha1(data).hexdigest().upper()

    @staticmethod
    def _extract_sha1_fingerprints(output: str) -> set[str]:
        normalized = output.upper()
        # Match colon-separated (XX:XX:...), continuous (XXXX..40..), and
        # space-separated (XX XX XX ..) SHA-1 fingerprints.
        matches = re.findall(
            r"[0-9A-F]{2}(?::[0-9A-F]{2}){19}"    # colon-separated
            r"|[0-9A-F]{40}"                        # continuous
            r"|[0-9A-F]{2}(?: [0-9A-F]{2}){19}",   # space-separated
            normalized,
        )
        return {match.replace(":", "").replace(" ", "") for match in matches}

    @staticmethod
    def _coerce_command_output(result: subprocess.CompletedProcess) -> str:
        stdout = result.stdout if isinstance(result.stdout, str) else ""
        stderr = result.stderr if isinstance(result.stderr, str) else ""
        return stdout + stderr

    def is_cert_installed(self) -> bool:
        """Check whether the CA cert is installed in the system trust store.

        Uses platform-specific commands to query the trust store.  Returns
        ``False`` if the cert file does not exist or the check command fails.
        """
        cert_path = self.get_cert_path()
        if not cert_path.is_file():
            return False

        try:
            if self._platform == "Windows":
                expected_sha1 = self._get_cert_sha1_fingerprint()
                if expected_sha1 is None:
                    return False
                result = subprocess.run(
                    ["certutil", "-store", "root", self._cert_cn],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                output = self._coerce_command_output(result)
                return (
                    result.returncode == 0
                    and expected_sha1 in self._extract_sha1_fingerprints(output)
                )

            if self._platform == "Darwin":
                expected_sha1 = self._get_cert_sha1_fingerprint()
                if expected_sha1 is None:
                    return False
                result = subprocess.run(
                    [
                        "security",
                        "find-certificate",
                        "-Z",
                        "-c",
                        self._cert_cn,
                        "/Library/Keychains/System.keychain",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                output = self._coerce_command_output(result)
                return (
                    result.returncode == 0
                    and expected_sha1 in self._extract_sha1_fingerprints(output)
                )

            if self._platform == "Linux":
                return self._linux_ca_dest.is_file()

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning("Failed to check cert installation status: %s", exc)

        return False

    def install_cert(self) -> bool:
        """Install the CA certificate into the system trust store.

        Returns ``True`` on success, ``False`` otherwise.  Logs warnings on
        failure.  Registers an atexit cleanup handler on success if
        ``auto_uninstall_on_exit`` was set.
        """
        cert_path = self.get_cert_path()
        if not cert_path.is_file():
            logger.error("CA cert not found at %s", cert_path)
            return False

        success = False
        try:
            if self._platform == "Windows":
                success = self._install_windows(cert_path)
            elif self._platform == "Darwin":
                success = self._install_macos(cert_path)
            elif self._platform == "Linux":
                success = self._install_linux(cert_path)
            else:
                logger.error("Unsupported platform for cert install: %s", self._platform)
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.error("Cert install failed: %s", exc)
            return False

        if success:
            fingerprint = self.get_cert_fingerprint()
            logger.info(
                "CA cert installed (platform=%s, fingerprint=%s)", self._platform, fingerprint
            )
            self._register_cleanup()

        return success

    def uninstall_cert(self) -> bool:
        """Remove the CA certificate from the system trust store.

        Returns ``True`` on success, ``False`` otherwise.
        """
        cert_path = self.get_cert_path()

        try:
            if self._platform == "Windows":
                return self._uninstall_windows()
            if self._platform == "Darwin":
                return self._uninstall_macos(cert_path)
            if self._platform == "Linux":
                return self._uninstall_linux()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.error("Cert uninstall failed: %s", exc)

        return False

    def cleanup_old_certs(self) -> int:
        """Remove certs matching ``cert_cn`` from the trust store.

        Useful for clearing stale or duplicate CA entries before a fresh
        install.  Returns the number of certs removed.

        Windows: loops ``certutil -delstore`` up to 10 times.
        macOS: ``security delete-certificate -c``.
        Linux: removes the known destination file derived from ``cert_cn``
               and runs ``update-ca-certificates``.  Stale files with
               different naming conventions are not detected — only the
               current CN-derived filename is cleaned up.
        """
        removed = 0
        try:
            if self._platform == "Windows":
                for _ in range(10):
                    if not self._windows_store_has_cert():
                        break
                    result = subprocess.run(
                        ["certutil", "-f", "-delstore", "root", self._cert_cn],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if result.returncode != 0:
                        break
                    removed += 1
                    logger.debug("Removed stale cert #%d for CN=%s", removed, self._cert_cn)

            elif self._platform == "Darwin":
                result = subprocess.run(
                    ["security", "delete-certificate", "-c", self._cert_cn],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    removed = 1

            elif self._platform == "Linux":
                dest = self._linux_ca_dest
                if dest.is_file():
                    dest.unlink()
                    subprocess.run(
                        ["update-ca-certificates"],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    removed = 1

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning("Error during cert cleanup: %s", exc)

        if removed:
            logger.info("Cleaned up %d old cert(s) for CN=%s", removed, self._cert_cn)
        return removed

    def get_cert_expiry(self) -> datetime.datetime | None:
        """Parse the PEM certificate and return its ``not_valid_after_utc``.

        Returns ``None`` if the cert file is missing or cannot be parsed.
        Requires the ``cryptography`` library.
        """
        cert_path = self.get_cert_path()
        if not cert_path.is_file():
            return None
        try:
            from cryptography import x509

            pem_data = cert_path.read_bytes()
            cert = x509.load_pem_x509_certificate(pem_data)
            return cert.not_valid_after_utc
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse cert expiry from %s: %s", cert_path, exc)
            return None

    def get_cert_info(self) -> dict:
        """Return a dict describing the current CA certificate status.

        Keys: ``exists``, ``installed``, ``expiry_date``, ``days_until_expiry``,
        ``expired``, ``expiry_warning``, ``fingerprint``, ``cn``, ``cert_path``,
        ``error``.
        """
        info: dict = {
            "exists": False,
            "installed": False,
            "expiry_date": None,
            "days_until_expiry": None,
            "expired": False,
            "expiry_warning": False,
            "fingerprint": None,
            "cn": self._cert_cn,
            "cert_path": str(self.get_cert_path()),
            "error": None,
        }

        try:
            info["exists"] = self.cert_exists()
            if not info["exists"]:
                return info

            info["fingerprint"] = self.get_cert_fingerprint()
            info["installed"] = self.is_cert_installed()

            expiry = self.get_cert_expiry()
            if expiry is not None:
                info["expiry_date"] = expiry.isoformat()
                now = datetime.datetime.now(datetime.timezone.utc)
                delta = expiry - now
                info["days_until_expiry"] = delta.days
                info["expired"] = delta.total_seconds() <= 0
                warning_window_seconds = _EXPIRY_WARNING_DAYS * 24 * 60 * 60
                info["expiry_warning"] = 0 < delta.total_seconds() < warning_window_seconds

        except Exception as exc:  # noqa: BLE001
            info["error"] = str(exc)
            logger.warning("Error gathering cert info: %s", exc)

        return info

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def _linux_ca_dest(self) -> Path:
        """Linux system cert destination, parameterized by CN."""
        # Sanitize CN to a safe filename slug
        slug = re.sub(r"[^a-zA-Z0-9_-]", "-", self._cert_cn).strip("-").lower()
        return _LINUX_CA_DIR / f"{slug}-ca.crt"

    # ------------------------------------------------------------------
    # Platform-specific install helpers
    # ------------------------------------------------------------------

    def _install_windows(self, cert_path: Path) -> bool:
        result = subprocess.run(
            ["certutil", "-addstore", "root", str(cert_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.error("certutil -addstore failed: %s", result.stderr)
        return result.returncode == 0

    def _install_macos(self, cert_path: Path) -> bool:
        result = subprocess.run(
            [
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
                str(cert_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.error("security add-trusted-cert failed: %s", result.stderr)
        return result.returncode == 0

    def _windows_store_has_cert(self) -> bool:
        """Return True if the Windows root store still contains the target CN."""
        result = subprocess.run(
            ["certutil", "-verifystore", "root", self._cert_cn],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0

    def _install_linux(self, cert_path: Path) -> bool:
        # Copy cert to system CA directory
        _LINUX_CA_DIR.mkdir(parents=True, exist_ok=True)
        dest = self._linux_ca_dest
        shutil.copy2(str(cert_path), str(dest))
        result = subprocess.run(
            ["update-ca-certificates"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            logger.error("update-ca-certificates failed: %s", result.stderr)
            try:
                if dest.is_file():
                    dest.unlink()
            except OSError as exc:
                logger.warning("Failed to remove partially installed Linux cert %s: %s", dest, exc)
        return result.returncode == 0

    # ------------------------------------------------------------------
    # Platform-specific uninstall helpers
    # ------------------------------------------------------------------

    def _uninstall_windows(self) -> bool:
        result = subprocess.run(
            ["certutil", "-delstore", "root", self._cert_cn],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.warning("certutil -delstore failed: %s", result.stderr)
        return result.returncode == 0

    def _uninstall_macos(self, cert_path: Path) -> bool:
        result = subprocess.run(
            ["security", "remove-trusted-cert", "-d", str(cert_path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.warning("security remove-trusted-cert failed: %s", result.stderr)
        return result.returncode == 0

    def _uninstall_linux(self) -> bool:
        dest = self._linux_ca_dest
        if dest.is_file():
            dest.unlink()
        result = subprocess.run(
            ["update-ca-certificates"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            logger.warning("update-ca-certificates (uninstall) failed: %s", result.stderr)
        return result.returncode == 0

    # ------------------------------------------------------------------
    # Cleanup registration
    # ------------------------------------------------------------------

    def _register_cleanup(self) -> None:
        """Register an atexit handler to uninstall the cert on process exit."""
        if self._auto_uninstall_on_exit and not self._cleanup_registered:
            atexit.register(self._atexit_cleanup)
            self._cleanup_registered = True
            logger.debug("Registered atexit cert cleanup handler")

    def _atexit_cleanup(self) -> None:
        """Atexit callback — best-effort cert removal."""
        logger.info("Cleaning up CA cert from trust store on exit")
        try:
            self.uninstall_cert()
        except Exception:  # noqa: BLE001 — must not raise in atexit
            logger.exception("Failed to uninstall cert during atexit cleanup")
