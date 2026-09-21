"""TLS certificate collector.

Performs a single read-only TLS handshake to retrieve the peer certificate,
then decodes it. This is *passive* inspection of a certificate the server
presents to every client; we do not probe TLS versions, ciphers, or attempt any
exploitation.

Decoding strategy:

* If the ``cryptography`` package is present, parse the DER for rich fields
  (SAN, key info, signature algorithm, validity).
* Otherwise fall back to :func:`ssl.SSLSocket.getpeercert`, which yields
  subject/issuer/SAN/validity but not key size or signature algorithm.
"""

from __future__ import annotations

import socket
import ssl
from typing import Any

from vxrecon.collectors.base import BaseCollector
from vxrecon.utils.validators import host_from_target, is_domain, is_ip

try:  # optional rich parsing
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import (  # type: ignore
        ec,
        ed25519,
        ed448,
        rsa,
    )

    _HAS_CRYPTO = True
except Exception:  # noqa: BLE001
    _HAS_CRYPTO = False


class TlsCollector(BaseCollector):
    """Retrieve and decode the TLS certificate presented by a host."""

    name = "tls"
    requires_network = True
    provides = ("certificate",)

    def collect(self, target: str) -> dict[str, Any]:
        host = host_from_target(target)
        if not (is_domain(host) or is_ip(host)):
            return self._error(f"not a valid host: {target!r}")

        port = 443
        der, chain, error = self._handshake(host, port)
        if der is None:
            return {"target": host, "_error": error or "TLS handshake failed"}

        cert = self._decode(der, host)
        cert["chain"] = chain
        cert["port"] = port
        return {"target": host, "certificate": cert}

    # -- handshake -------------------------------------------------------

    def _handshake(self, host: str, port: int) -> tuple[bytes | None, list[str], str | None]:
        context = ssl.create_default_context()
        # We are *inspecting* the certificate, so hostname/verify must be
        # permissive: expired or self-signed certs are still evidence. This
        # never weakens the target; it only lets us read public data.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        chain: list[str] = []
        try:
            with socket.create_connection((host, port), timeout=self.ctx.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
                    try:
                        peer = tls.getpeercert()
                        chain = self._chain_fingerprints(peer)
                    except (ValueError, ssl.SSLError):
                        chain = []
                    if der:
                        return der, chain, None
        except socket.timeout:
            return None, [], "connection timed out"
        except (ConnectionRefusedError, OSError) as exc:
            return None, [], f"connection error: {exc}"
        except ssl.SSLError as exc:
            return None, [], f"TLS error: {exc}"
        return None, [], "no certificate presented"

    @staticmethod
    def _chain_fingerprints(peer: dict) -> list[str]:
        chain: list[str] = []
        for entry in peer.get("subjectAltName", []):
            chain.append(str(entry))
        return chain

    # -- decoding --------------------------------------------------------

    def _decode(self, der: bytes, host: str) -> dict[str, Any]:
        if _HAS_CRYPTO:
            try:
                return self._decode_rich(der)
            except Exception as exc:  # noqa: BLE001 - fall back rather than fail
                fallback = self._decode_stdlib(host)
                fallback["decode_error"] = f"rich parse failed: {exc}"
                return fallback
        return self._decode_stdlib(host)

    def _decode_rich(self, der: bytes) -> dict[str, Any]:
        import hashlib

        cert = x509.load_der_x509_certificate(der)
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = []
            for name in san_ext.value.get_values_for_type(x509.DNSName):
                san.append(getattr(name, "value", name))
            for ip in san_ext.value.get_values_for_type(x509.IPAddress):
                san.append(str(ip))
        except x509.ExtensionNotFound:
            san = []

        key = cert.public_key()
        key_type, key_bits = _describe_key(key)

        return {
            "target": None,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "subject": subject,
            "subject_cn": _cn(cert.subject),
            "issuer": issuer,
            "issuer_cn": _cn(cert.issuer),
            "serial": format(cert.serial_number, "x"),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "sig_alg": cert.signature_algorithm_oid._name,
            "key_type": key_type,
            "key_bits": key_bits,
            "san": san,
            "der_sha256": hashlib.sha256(der).hexdigest(),
        }

    def _decode_stdlib(self, host: str) -> dict[str, Any]:
        """Minimal decode using ssl.getpeercert() when cryptography is absent."""

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, 443), timeout=self.ctx.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    peer = tls.getpeercert()
        except (OSError, ssl.SSLError) as exc:
            return {"decode_error": str(exc)}
        return {
            "subject": str(peer.get("subject", "")),
            "issuer": str(peer.get("issuer", "")),
            "subject_cn": _cn_from_rfc(peer.get("subject", ())),
            "issuer_cn": _cn_from_rfc(peer.get("issuer", ())),
            "san": [v for k, v in peer.get("subjectAltName", ())],
            "not_before": peer.get("notBefore"),
            "not_after": peer.get("notAfter"),
        }


def _describe_key(key: Any) -> tuple[str, int | None]:
    """Return (key_type, key_bits) for a public key object."""

    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size
    if isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return "EdDSA", None
    return type(key).__name__, None


def _cn(name: Any) -> str | None:
    """Extract the common name from a cryptography Name."""

    try:
        attrs = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        return attrs[0].value if attrs else None
    except Exception:  # noqa: BLE001
        return None


def _cn_from_rfc(rdns: Any) -> str | None:
    """Extract the CN from an ssl-module RDN tuple structure."""

    for rdn in rdns:
        for key, value in rdn:
            if key == "commonName":
                return value
    return None
