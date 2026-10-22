# Weak CA Key Demo (EC521)

A classroom demo of the eMudhra intermediate-CA incident described in Scott Helme's
write-up, [*Eight bits of trust: eMudhra's CA keys cracked in
milliseconds*](https://scotthelme.co.uk/eight-bits-of-trust-emudhras-ca-keys-cracked-in-milliseconds/).

## The bug

The affected CAs use P-384 keys. A good P-384 private key is a random 384-bit
scalar `d`, and the public key is `d·G`. The eMudhra keys had a single non-zero
byte, so there are only 255 possible values of `d`. The public key is still a
valid curve point, so structural checks pass and nothing looks wrong.

Recovery is plain brute force. Compute `1·G, 2·G, 3·G, ...` and compare each
result with the public key in the certificate. The cost is at most 255 point
multiplications. The root cause, per eMudhra, was a key-ceremony script bug that
created a second, weak key pair on the HSM and then used it for the CSR.

Mozilla incident: <https://bugzilla.mozilla.org/show_bug.cgi?id=2083449>

## How the crack works, step by step

**Background.** An elliptic-curve key pair on P-384 is defined by:
- `G`, a fixed, public base point on the curve (the same for everyone).
- `d`, the private key, a secret integer.
- `Q = d·G`, the public key: `G` added to itself `d` times. `Q` is published
  in the certificate.

Going from `d` to `Q` is fast. Going from `Q` back to `d` is the elliptic-curve
discrete log problem, and there is no known shortcut. That is only safe if `d`
is drawn from a huge space. The attack below needs no cleverness, only a small
search space.

**Step 1: Get the public key.** A certificate is public. Parse it and read the
subject public key, a point `Q = (x, y)`. In the code:
`cert.public_key().public_numbers()`.

**Step 2: Notice the search space is tiny.** A P-384 private key is 48 bytes. In
these CAs, 47 of the bytes are zero, so `d` is one of `1..255`. Zero is not a
valid key, so there are 255 candidates instead of about 2^384.

**Step 3: Try every candidate.** For each `d = 1, 2, 3, ...`, compute `d·G`
(`ec.derive_private_key(d, CURVE)` does this, and `.public_key()` gives the
point). This is the same operation a CA performs when it generates a key. We
are just doing it for every possible secret.

**Step 4: Compare with the certificate.** If `d·G` equals the `Q` from the
certificate, the secret is `d`. It is the only match, because different
private keys give different public keys.

**Step 5: Prove it.** Sign a message with the recovered `d`, then verify the
signature using only the public key from the certificate. If verification
passes, we hold a working private key for that CA. This is what
`crack_real.py` prints as `OK`.

**Step 6: Use it.** Anyone with this key can sign certificates that chain to
the CA, so they are trusted wherever the CA was. That is why the CAs had to be
revoked. `demo.py` shows this step on a toy CA.

**Cost.** The search takes at most `2^bits - 1` point multiplications. 8 bits
is 255 guesses, which takes milliseconds. 16 bits is 65,535 guesses, which
takes seconds. Every extra bit doubles the work, so a real 384-bit key is far
out of reach.

**Try it by hand** (in `.venv/bin/python`):

```python
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

cert = x509.load_pem_x509_certificate(open("certs/<any file>.pem", "rb").read())
Q = cert.public_key().public_numbers()
for d in range(1, 256):
    P = ec.derive_private_key(d, ec.SECP384R1()).public_key().public_numbers()
    if (P.x, P.y) == (Q.x, Q.y):
        print("found d =", d)
        break
```

The code in `crack_real.py` is the same loop plus the proof step.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Requires Python 3 and the `openssl` CLI (only `demo.py` uses it).

## Part 1: crack the real (revoked) certificates

`certs/` contains public certificates for the weak eMudhra intermediates,
downloaded from [crt.sh](https://crt.sh). Each CA appears twice, once issued by
eMudhra's own root and once cross-signed by Sectigo's "AAA Certificate Services".

```sh
.venv/bin/python -I crack_real.py certs/*.pem
```

Expected output: 10 certificates, 5 distinct keys (`d` = 66, 115, 156, 230, 237)
recovered in well under a second. Both certificates for the same CA give the
same `d`, so they share a key.

For each recovered key the script also prints:
- `d` as a full 48-byte hex string, last byte in bold. It is 47 zero bytes
  followed by one byte, which is the whole secret.
- A proof of possession: it signs a challenge with the recovered key and
  verifies the signature against the public key in the certificate. It prints
  `OK`, and the script raises an error if verification fails.

Talking points:
- Point out the 47 leading zero bytes in `d`. The key looks like a normal
  384-bit value but has one byte of content.
- The two certificates per CA share a key, so the cross-signing by Sectigo
  extended trust to a key that anyone could recover.
- This uses public data only and contacts no one.

### Fetching more certificates

Six of the sixteen certificates (EV G3C, OV TLS G3B/G3C, in both issuer
variants) aren't included because crt.sh rate-limited the download. To fetch
them, search crt.sh for the CA names below and save the PEM from
`https://crt.sh/?d=<id>` into `certs/`, with a pause between requests:

`EM DV TLS CA - G3B/G3C`, `EM EV TLS CA - G3B/G3C`, `EM OV TLS CA - G3B/G3C`,
`EM OV CS CA - G3B/G3C`

## Part 2: forge a certificate with a toy CA

`demo.py` builds its own throwaway "Weak Demo Root CA" with the same flaw and
runs the full attack, so you can show forgery without involving a real CA or
domain.

```sh
.venv/bin/python demo.py            # 8-bit key, as in the incident
.venv/bin/python demo.py --bits 16  # ~3-4 s, shows the cost doubling per bit
```

Steps it performs:
1. Creates a P-384 CA whose private scalar has only `--bits` bits of entropy.
2. Brute-forces `d` from the CA certificate's public key alone.
3. Signs a forged leaf certificate for `bank.example` with the recovered key.
4. Runs `openssl verify` on the forged certificate against the CA. It prints `OK`.
5. Estimates the time to do the same to a properly random P-384 key
   (about 10^104 years at the measured guess rate).

It writes `weak_ca.pem` and `forged_leaf.pem` to the current directory (both
git-ignored). Stay at 16 bits or below for a live run, because the search uses a
slow point multiplication per guess (about 4,000 guesses per second).

### Optional: show a TLS client accepting it

`demo.py` doesn't generate a leaf private key you can serve, so to show this over
TLS you'd extend it to save the leaf key and run `openssl s_server`, then connect
with `curl --cacert weak_ca.pem https://bank.example:4433 --resolve ...`.

## Suggested 10-minute flow

1. Explain how a CA key is supposed to look (384 random bits) and what a
   forged certificate lets an attacker do.
2. Run Part 1 and show the real keys falling in under a second.
3. Run Part 2 at 8 bits, then at 16 bits, to show the forgery and the scaling.
4. Discuss: why structural checks didn't catch it, why the cross-signing
   mattered, and how a ceremony script bug (not a bad algorithm) caused this.
   Mention what could have caught it: key-quality linting, such as checking that
   `d` isn't tiny, and independent review of ceremony output.

## Scope and ethics

Everything here uses public, revoked certificates or locally generated toy keys.
Don't use recovered keys to sign certificates for real domains. The toy CA in
`demo.py` exists so the forgery step never needs a real CA key.
