#!/usr/bin/env python3
"""EC521 demo: a CA whose P-384 private key has only 8 bits of entropy.

Everything here is generated locally for the demo (a toy CA, no real CA
involved). Steps:
  1. Create a "weak" CA: P-384 key whose private scalar d is a single byte.
  2. Attacker sees only the CA certificate (public key) and brute-forces d.
  3. Attacker forges a leaf cert for bank.example, signed with recovered key.
  4. Verify the forged cert chains to the CA with `openssl verify`.
  5. For contrast: show the same search is hopeless for a properly random key.

Usage: .venv/bin/python demo.py [--bits N]   (N = entropy of weak key, default 8)
"""
import argparse
import datetime
import secrets
import subprocess
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CURVE = ec.SECP384R1()
NOW = datetime.datetime.now(datetime.timezone.utc)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(key):
    return (
        x509.CertificateBuilder()
        .subject_name(name("Weak Demo Root CA"))
        .issuer_name(name("Weak Demo Root CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA384())
    )


def make_leaf(ca_key, ca_cert, cn):
    leaf_key = ec.generate_private_key(CURVE)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(ca_key, hashes.SHA384())
    )
    return cert


def brute_force(target_pub, max_bits):
    """Try d = 1, 2, 3, ... until d*G matches the CA's public key."""
    target = target_pub.public_numbers()
    for d in range(1, 2**max_bits):
        pub = ec.derive_private_key(d, CURVE).public_key().public_numbers()
        if (pub.x, pub.y) == (target.x, target.y):
            return d, d
    return None, 2**max_bits - 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bits", type=int, default=8)
    args = ap.parse_args()

    # 1. Weak CA
    d_secret = secrets.randbelow(2**args.bits - 1) + 1
    ca_key = ec.derive_private_key(d_secret, CURVE)
    ca_cert = make_ca(ca_key)
    print(f"[1] Weak CA created. Its private key d has {args.bits} bits of entropy.")
    print("    d (hex, 48 bytes) =", d_secret.to_bytes(48, "big").hex())
    print("    (attacker does NOT get to see this)\n")

    # 2. Attack: only the certificate is used
    pub = ca_cert.public_key()
    print(f"[2] Attacker brute-forcing d from the CA certificate's public key "
          f"(<= {2**args.bits - 1} candidates)...")
    t0 = time.perf_counter()
    d, tries = brute_force(pub, args.bits)
    dt = time.perf_counter() - t0
    print(f"    RECOVERED d = {d} after {tries} tries in {dt*1000:.1f} ms\n")
    assert d == d_secret

    # 3. Forge
    stolen_key = ec.derive_private_key(d, CURVE)
    forged = make_leaf(stolen_key, ca_cert, "bank.example")
    print("[3] Forged certificate for bank.example signed with the recovered CA key.")

    # 4. Verify with openssl, as a real client would
    with tempfile.TemporaryDirectory() as tmp:
        ca_pem, leaf_pem = Path(tmp, "ca.pem"), Path(tmp, "leaf.pem")
        ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        leaf_pem.write_bytes(forged.public_bytes(serialization.Encoding.PEM))
        out = subprocess.run(
            ["openssl", "verify", "-CAfile", str(ca_pem), str(leaf_pem)],
            capture_output=True, text=True,
        )
        print("[4] openssl verify:", (out.stdout + out.stderr).strip().replace(str(tmp) + "/", ""))
        Path("forged_leaf.pem").write_bytes(leaf_pem.read_bytes())
        Path("weak_ca.pem").write_bytes(ca_pem.read_bytes())
    print("    (saved weak_ca.pem and forged_leaf.pem in the current directory)\n")

    # 5. Contrast
    rate = tries / dt if dt > 0 else float("inf")
    years = 2**383 / rate / 3.15e7
    print("[5] For a properly generated P-384 key (384 bits of entropy):")
    print(f"    at this machine's {rate:,.0f} guesses/s, expected time ~ {years:.1e} years")


if __name__ == "__main__":
    main()
