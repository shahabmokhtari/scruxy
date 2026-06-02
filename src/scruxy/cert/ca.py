"""Self-signed CA and per-host certificate generation for TLS MITM.

Generates a root CA key+cert on first run, then creates per-host leaf
certificates signed by the CA on demand.  Leaf certs are cached in memory
for the lifetime of the process.
"""
from __future__ import annotations

import datetime
import ipaddress
import logging
import os
from pathlib import Path
from typing import NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

# CA cert validity: 10 years.
_CA_VALIDITY_DAYS = 3650
# Leaf cert validity: 1 year.
_LEAF_VALIDITY_DAYS = 365
# Maximum entries in the per-host leaf-cert cache.  At ~4 KB per entry
# this caps cache memory at ~4 MB; anything beyond is evicted in LRU
# order.  Most deployments only need a handful of provider hostnames.
_HOST_CACHE_MAX = 1024


class CertKeyPair(NamedTuple):
    """A certificate and its private key, both PEM-encoded bytes."""

    cert_pem: bytes
    key_pem: bytes


class CertificateAuthority:
    """Manages a self-signed CA and generates per-host leaf certificates.

    On first instantiation the CA key+cert are either loaded from
    ``cert_dir`` or generated fresh and written to disk.  Per-host certs
    are generated on demand and cached in memory.
    """

    def __init__(self, cert_dir: str | Path) -> None:
        self._cert_dir = Path(cert_dir)
        self._cert_dir.mkdir(parents=True, exist_ok=True)

        self._ca_key_path = self._cert_dir / "scruxy-ca.key"
        self._ca_cert_path = self._cert_dir / "scruxy-ca.pem"

        # Bounded LRU cache: hostname -> CertKeyPair.  Mutated from
        # worker threads (``asyncio.to_thread`` in the forward proxy's
        # MITM path), so all access is serialized through ``_host_cache_lock``.
        from collections import OrderedDict
        import threading as _threading
        self._host_cache: "OrderedDict[str, CertKeyPair]" = OrderedDict()
        self._host_cache_max = _HOST_CACHE_MAX
        self._host_cache_lock = _threading.Lock()
        # Per-hostname locks prevent thundering-herd RSA generation when
        # many concurrent CONNECTs arrive for the same hostname.
        self._host_gen_locks: dict[str, _threading.Lock] = {}
        self._host_gen_meta_lock = _threading.Lock()

        self._ca_key: rsa.RSAPrivateKey
        self._ca_cert: x509.Certificate
        self._ca_key, self._ca_cert = self._load_or_generate_ca()

    # ------------------------------------------------------------------
    # CA management
    # ------------------------------------------------------------------

    def _load_or_generate_ca(self) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Load existing CA from disk or generate a new one."""
        if self._ca_key_path.exists() and self._ca_cert_path.exists():
            return self._load_ca()
        return self._generate_ca()

    def _load_ca(self) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Load the CA key and certificate from disk."""
        logger.info("Loading CA cert from %s", self._ca_cert_path)
        key_pem = self._ca_key_path.read_bytes()
        cert_pem = self._ca_cert_path.read_bytes()

        key = serialization.load_pem_private_key(key_pem, password=None)
        cert = x509.load_pem_x509_certificate(cert_pem)

        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("CA key is not RSA")

        # R70-12 fix: verify the loaded private key actually matches
        # the loaded certificate.  Without this check, an operator who
        # partially overwrites only one file (or whose CA generation
        # was interrupted) silently signs leaf certs that won't
        # validate against the cert distributed to clients → MITM
        # tunnels fail with opaque TLS errors instead of a clear
        # "regenerate the CA" message.
        cert_pub = cert.public_key()
        key_pub = key.public_key()
        if (
            not isinstance(cert_pub, rsa.RSAPublicKey)
            or cert_pub.public_numbers() != key_pub.public_numbers()
        ):
            raise ValueError(
                f"CA private key at {self._ca_key_path} does not match "
                f"certificate at {self._ca_cert_path}.  Delete both files "
                "and restart to regenerate a fresh CA."
            )

        return key, cert

    def _generate_ca(self) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Generate a new CA key+cert and persist to disk."""
        logger.info("Generating new CA cert in %s", self._cert_dir)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Scruxy PII Proxy CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Scruxy"),
        ])

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=_CA_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        # Write to disk with restricted permissions from the start.
        # Use os.open + os.fdopen to create key file with 0o600 on Unix,
        # avoiding the race window of write-then-chmod.
        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        import sys
        try:
            if sys.platform != "win32":
                # R71-11 fix: even with ``O_CREAT|O_TRUNC|0o600`` the
                # file mode is only applied when the file is created
                # NEW.  An existing wider-permission file keeps its
                # old mode → world-readable window for the duration of
                # this run.  Explicitly chmod after open to close the
                # window unconditionally.
                fd = os.open(str(self._ca_key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                except (AttributeError, OSError):
                    # fchmod not on all platforms; fall back to chmod
                    try:
                        os.chmod(str(self._ca_key_path), 0o600)
                    except OSError:
                        pass
                with os.fdopen(fd, "wb") as f:
                    f.write(key_bytes)
            else:
                self._ca_key_path.write_bytes(key_bytes)
        except OSError:
            # Fallback: write normally then chmod
            self._ca_key_path.write_bytes(key_bytes)
            if sys.platform != "win32":
                try:
                    os.chmod(self._ca_key_path, 0o600)
                except OSError:
                    pass

        self._ca_cert_path.write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )

        # Additional permission hardening (best-effort)
        try:
            if sys.platform == "win32":
                # On Windows, os.chmod only affects read-only bit.
                # Use icacls to restrict to current user only.
                import subprocess
                username = os.environ.get("USERNAME", os.environ.get("USER", ""))
                if username:
                    subprocess.run(
                        ["icacls", str(self._ca_key_path), "/inheritance:r",
                         "/grant:r", f"{username}:(R,W)"],
                        capture_output=True, timeout=10,
                    )
                else:
                    logger.warning("Cannot restrict CA key permissions: USERNAME/USER not set")
        except Exception:
            logger.debug("Failed to restrict CA key file permissions", exc_info=True)

        logger.info("CA cert generated: %s", self._ca_cert_path)
        return key, cert

    # ------------------------------------------------------------------
    # Per-host leaf certificates
    # ------------------------------------------------------------------

    def get_host_cert(self, hostname: str) -> CertKeyPair:
        """Return a TLS certificate for *hostname*, generating if needed.

        Results are cached in a bounded LRU.  All cache access is
        serialized through ``_host_cache_lock`` (B4) — without the
        lock, concurrent MITM tunnels (running in worker threads via
        ``asyncio.to_thread``) can race on ``move_to_end``/eviction
        and raise ``KeyError``.

        RSA generation is heavy and is performed *outside* the cache
        lock under a per-hostname generation lock, so:
          (a) cache hits are O(lock acquire), and
          (b) concurrent CONNECTs for the same hostname don't all
              regenerate the certificate (thundering herd).

        R70-13 fix: normalize ``hostname`` (lowercase, strip trailing
        dot) before any cache/lock lookup.  ``Example.COM``,
        ``example.com.``, and ``example.com`` previously generated
        three independent leaf certs, three RSA key generations, and
        three cache entries → wasted CPU + cache fragmentation.
        """
        # R70-13 fix: canonicalize hostname before cache/lock lookup.
        hostname = (hostname or "").strip().rstrip(".").lower()
        if not hostname:
            raise ValueError("get_host_cert: hostname is empty after normalization")
        # Fast path: cache hit under cache lock.
        with self._host_cache_lock:
            cached = self._host_cache.get(hostname)
            if cached is not None:
                self._host_cache.move_to_end(hostname)
                return cached

        # Slow path: get/create a per-hostname generation lock so we
        # don't generate the same cert twice in parallel.
        with self._host_gen_meta_lock:
            gen_lock = self._host_gen_locks.setdefault(hostname, __import__("threading").Lock())
            # Bound the gen-lock dict in sync with the cert cache.  A
            # local client that triggers CONNECTs to many unique
            # provider-matching hostnames must not be able to grow
            # this map indefinitely.  We cap it at 4× the cert cache
            # size: enough headroom for in-flight generations plus the
            # full cached set, but still bounded.
            if len(self._host_gen_locks) > self._host_cache_max * 4:
                # Evict any gen-locks for hostnames that are no longer
                # in the cert cache AND not currently held by another
                # thread (C6 fix).  Evicting a held lock would let a
                # subsequent thread create a different lock for the
                # same hostname, breaking the thundering-herd dedup.
                # ``acquire(blocking=False)`` returns False if held;
                # we release immediately if we got it.
                with self._host_cache_lock:
                    cached_hosts = set(self._host_cache)
                stale = [
                    h for h, lk in self._host_gen_locks.items()
                    if h not in cached_hosts and h != hostname and lk.acquire(blocking=False)
                ]
                # R53-6 fix: pop BEFORE release.  Releasing first
                # leaves a window where another thread can `setdefault`
                # the same lock object, acquire it, and start cert
                # generation; our subsequent `pop()` then orphans that
                # in-flight lock and a third thread `setdefault`s a
                # NEW lock for the same hostname → two RSA generations
                # run in parallel for one host, defeating C6 dedup.
                # R66-3 / R67-10 fix: collapse to a single loop.
                # The previous code split `stale` in half between two
                # loops to handle a thread-race in the second loop,
                # but R66-3 made both loops byte-identical (both
                # pop-then-release).  The whole eviction is under
                # `_host_gen_meta_lock` so the half-split serves no
                # purpose and is a maintenance hazard.
                for h in stale:
                    lk = self._host_gen_locks.pop(h, None)
                    if lk is not None:
                        lk.release()

        with gen_lock:
            # Double-check under cache lock — another thread may have
            # finished generating while we were waiting on gen_lock.
            with self._host_cache_lock:
                cached = self._host_cache.get(hostname)
                if cached is not None:
                    self._host_cache.move_to_end(hostname)
                    return cached

            # Generate outside both locks (RSA generation is slow).
            pair = self._generate_host_cert(hostname)

            # Insert + LRU bookkeeping under cache lock.
            with self._host_cache_lock:
                self._host_cache[hostname] = pair
                self._host_cache.move_to_end(hostname)
                while len(self._host_cache) > self._host_cache_max:
                    self._host_cache.popitem(last=False)
            return pair

    def _generate_host_cert(self, hostname: str) -> CertKeyPair:
        """Generate a leaf certificate for *hostname* signed by the CA."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])

        # Build SAN with the right type: IPAddress for IPs, DNSName otherwise.
        try:
            ip = ipaddress.ip_address(hostname)
            san = x509.SubjectAlternativeName([x509.IPAddress(ip)])
        except ValueError:
            san = x509.SubjectAlternativeName([x509.DNSName(hostname)])

        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=_LEAF_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(san, critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._ca_key.public_key()
                ),
                critical=False,
            )
        )

        cert = builder.sign(self._ca_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        logger.debug("Generated leaf cert for %s", hostname)
        return CertKeyPair(cert_pem=cert_pem, key_pem=key_pem)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def ca_cert_path(self) -> Path:
        """Path to the CA certificate PEM file."""
        return self._ca_cert_path

    @property
    def ca_cert_expiry(self) -> datetime.datetime:
        """Expiry date of the CA certificate (UTC)."""
        return self._ca_cert.not_valid_after_utc

    @property
    def ca_cert_pem(self) -> bytes:
        """PEM-encoded CA certificate bytes."""
        return self._ca_cert.public_bytes(serialization.Encoding.PEM)
