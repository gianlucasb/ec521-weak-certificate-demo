#!/usr/bin/env python3
"""EC521 demo: a CA whose P-384 private key has only 8 bits of entropy.

Everything here is generated locally for the demo (a toy CA, no real CA
involved). Steps:
  1. Create a "weak" CA: P-384 key whose private scalar d is a single byte.
  2. Attacker sees only the CA certificate (public key) and brute-forces d.
  3. Attacker forges a leaf cert for bank.example, signed with recovered key.
  4. Verify the forged cert chains to the CA with `openssl verify`.
  5. Serve it over TLS on localhost; a client that trusts only the weak CA
     connects to "bank.example" and accepts it. A cert signed with a random
     (wrong) key is served too, and the client rejects it.
  6. For contrast: show the same search is hopeless for a properly random key.

Usage: .venv/bin/python demo.py [--bits N] [--serve]
  N = entropy of weak key (default 8); --serve keeps the TLS server running
  so you can connect with the curl command it prints.
"""
import argparse
import datetime
import secrets
import socket
import ssl
import subprocess
import threading
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
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA384())
    )


def make_leaf(ca_key, ca_cert, cn):
    """Leaf cert for `cn` signed by ca_key. Returns (cert, leaf_private_key)."""
    leaf_key = ec.generate_private_key(CURVE)
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    cert = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW)
        .not_valid_after(NOW + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA384())
    )
    return cert, leaf_key


def start_tls_server(cert, key, tmpname):
    """Serve a tiny HTTPS page on 127.0.0.1 (random port) in a background thread."""
    certfile, keyfile = Path(f"{tmpname}.crt.pem"), Path(f"{tmpname}.key.pem")
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)

    def serve():
        while True:
            conn, _ = sock.accept()
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(4096)
                    body = b"Welcome to bank.example (served by the attacker)\n"
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                                b"Connection: close\r\n\r\n" % len(body) + body)
            except (ssl.SSLError, OSError):
                pass  # client rejected our certificate

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def tls_fetch(port, cafile, hostname):
    """Connect like a browser: trust only `cafile`, verify the name `hostname`."""
    ctx = ssl.create_default_context(cafile=cafile)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            tls.sendall(b"GET / HTTP/1.0\r\nHost: " + hostname.encode() + b"\r\n\r\n")
            return tls.recv(4096).split(b"\r\n\r\n", 1)[1].decode().strip()


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
    ap.add_argument("--serve", action="store_true",
                    help="keep the forged TLS server running for manual curl")
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
    forged, forged_key = make_leaf(stolen_key, ca_cert, "bank.example")
    print("[3] Forged certificate for bank.example signed with the recovered CA key.")

    # 4. Verify with openssl, as a real client would
    ca_pem, leaf_pem = Path("weak_ca.pem"), Path("forged_leaf.pem")
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    leaf_pem.write_bytes(forged.public_bytes(serialization.Encoding.PEM))
    cmd = ["openssl", "verify", "-CAfile", str(ca_pem), str(leaf_pem)]
    print("[4] Saved weak_ca.pem and forged_leaf.pem. Verify it yourself with:")
    print("      " + " ".join(cmd))
    out = subprocess.run(cmd, capture_output=True, text=True)
    print("    openssl says:", (out.stdout + out.stderr).strip())
    print("    (inspect with: openssl x509 -in forged_leaf.pem -noout -subject -issuer)\n")

    # 5. TLS: a client that trusts only the weak CA
    port = start_tls_server(forged, forged_key, "forged_server")
    print(f"[5] TLS server with the forged cert listening on 127.0.0.1:{port}.")
    print("    Client trusts ONLY weak_ca.pem and checks the name bank.example:")
    page = tls_fetch(port, str(ca_pem), "bank.example")
    print(f"      ACCEPTED -> {page!r}")
    # control: same names, but signed with a random key instead of the recovered one
    bad, bad_key = make_leaf(ec.generate_private_key(CURVE), ca_cert, "bank.example")
    bad_port = start_tls_server(bad, bad_key, "wrongkey_server")
    try:
        tls_fetch(bad_port, str(ca_pem), "bank.example")
        print("      control unexpectedly accepted!")
    except ssl.SSLError as e:
        print(f"    Control: cert signed with a random key (attacker without d):\n"
              f"      REJECTED -> {e.reason or e}")
    curl = (f"curl --cacert weak_ca.pem --resolve bank.example:{port}:127.0.0.1 "
            f"https://bank.example:{port}/")
    print("    Try it yourself while the demo is running (use --serve to keep it up):")
    print("      " + curl + "\n")

    # 6. Contrast
    rate = tries / dt if dt > 0 else float("inf")
    years = 2**383 / rate / 3.15e7
    print("[6] For a properly generated P-384 key (384 bits of entropy):")
    print(f"    at this machine's {rate:,.0f} guesses/s, expected time ~ {years:.1e} years")

    if args.serve:
        print(f"\nServer still running on port {port}. Press Ctrl-C to stop.")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
