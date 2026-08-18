from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent
PKI = ROOT / "pki"
P12_PASSWORD = b"changeit"

REQUIRED = [
    "ca.cert.pem", "ca.key.pem",
    "token-signing.cert.pem", "token-signing.key.pem",
    "linux-laptop-001.cert.pem", "linux-laptop-001.key.pem", "linux-laptop-001.p12",
    "agent-gpu-planner-dev.cert.pem", "agent-gpu-planner-dev.key.pem", "agent-gpu-planner-dev.p12",
]


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(path: Path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _subject(common_name: str, organizational_unit: str):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TokenSystem Enterprise Lab"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _create_ca():
    key = _new_key()
    subject = _subject("TokenSystem Demo Root CA", "Local Lab PKI")
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _create_leaf(
    ca_key,
    ca_cert,
    *,
    common_name: str,
    organizational_unit: str,
    client_auth: bool = False,
    server_auth: bool = False,
):
    key = _new_key()
    now = _utcnow()

    builder = (
        x509.CertificateBuilder()
        .subject_name(_subject(common_name, organizational_unit))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )

    eku = []
    if client_auth:
        eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if server_auth:
        eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)

    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _write_pkcs12(path: Path, name: bytes, key, cert, ca_cert):
    path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            name=name,
            key=key,
            cert=cert,
            cas=[ca_cert],
            encryption_algorithm=serialization.BestAvailableEncryption(P12_PASSWORD),
        )
    )


def generate_demo_pki():
    PKI.mkdir(parents=True, exist_ok=True)

    # Regenerate the entire lab trust set together. This avoids partial/mixed
    # CA state if a previous local run was interrupted.
    ca_key, ca_cert = _create_ca()
    token_key, token_cert = _create_leaf(
        ca_key,
        ca_cert,
        common_name="token-signing",
        organizational_unit="Token Service",
        server_auth=True,
    )
    device_key, device_cert = _create_leaf(
        ca_key,
        ca_cert,
        common_name="linux-laptop-001",
        organizational_unit="Managed Devices",
        client_auth=True,
    )
    agent_key, agent_cert = _create_leaf(
        ca_key,
        ca_cert,
        common_name="agent-gpu-planner-dev",
        organizational_unit="Agent Identities",
        client_auth=True,
    )

    _write_key(PKI / "ca.key.pem", ca_key)
    _write_cert(PKI / "ca.cert.pem", ca_cert)

    _write_key(PKI / "token-signing.key.pem", token_key)
    _write_cert(PKI / "token-signing.cert.pem", token_cert)

    _write_key(PKI / "linux-laptop-001.key.pem", device_key)
    _write_cert(PKI / "linux-laptop-001.cert.pem", device_cert)
    _write_pkcs12(
        PKI / "linux-laptop-001.p12",
        b"linux-laptop-001",
        device_key,
        device_cert,
        ca_cert,
    )

    _write_key(PKI / "agent-gpu-planner-dev.key.pem", agent_key)
    _write_cert(PKI / "agent-gpu-planner-dev.cert.pem", agent_cert)
    _write_pkcs12(
        PKI / "agent-gpu-planner-dev.p12",
        b"agent-gpu-planner-dev",
        agent_key,
        agent_cert,
        ca_cert,
    )


def main():
    missing = [f for f in REQUIRED if not (PKI / f).exists()]
    if not missing:
        print("PKI files already exist and are ready for the demo.")
        print("Includes demo CA, token-signing certificate, managed-device certificate, agent certificate, and PKCS#12 bundles.")
        print("PKCS#12 demo password: changeit")
        return

    print("Fresh/partial lab PKI detected.")
    print("Generating a complete local demo trust set...")
    generate_demo_pki()

    missing_after = [f for f in REQUIRED if not (PKI / f).exists()]
    if missing_after:
        raise SystemExit("PKI generation failed; still missing: " + ", ".join(missing_after))

    print("Local demo PKI generated successfully.")
    print(f"Location: {PKI}")
    print("PKCS#12 demo password: changeit")
    print("These are local training credentials only. The pki/ directory must remain git-ignored.")


if __name__ == "__main__":
    main()
