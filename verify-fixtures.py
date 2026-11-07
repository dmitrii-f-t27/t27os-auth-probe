"""Generate synthetic signed inputs without reading any account credentials."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent
exe = Path(sys.argv[1]).resolve()

def compact(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

with tempfile.TemporaryDirectory(dir=root) as work:
    key = Path(work) / "fixture.pem"
    subprocess.run(["/usr/bin/openssl", "genrsa", "-out", key, "2048"], check=True)
    der = subprocess.check_output(
        ["/usr/bin/openssl", "rsa", "-in", key, "-RSAPublicKey_out", "-outform", "DER"],
        stderr=subprocess.DEVNULL,
    )
    header = {"alg": "RS256", "kid": "fixture-key"}
    claims = {"iss": "https://issuer.invalid", "sub": "fixture-subject", "aud": "native-client",
              "azp": "native-client", "exp": 1700000120, "iat": 1700000000, "nonce": "fixture-nonce"}
    signing_input = compact(header) + "." + compact(claims)
    sig = subprocess.check_output(
        ["/usr/bin/openssl", "dgst", "-sha256", "-sign", key], input=signing_input.encode()
    )
    corrupted_sig = bytes([sig[0] ^ 1]) + sig[1:]
    cases = [
        ("signed", signing_input, sig, 0),
        ("tampered payload", compact(header) + "." + compact(claims | {"nonce": "bad"}), sig, 1),
        ("tampered signature", signing_input, corrupted_sig, 1),
    ]
    def signed_case(name, new_header, new_claims, expected=1):
        message = compact(new_header) + "." + compact(new_claims)
        signature = subprocess.check_output(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", key], input=message.encode()
        )
        cases.append((name, message, signature, expected))

    signed_case("single trusted audience array", header, claims | {"aud": ["native-client"]}, 0)
    for name, value in [
        ("aud", []), ("aud", [4]), ("aud", "native-client-suffix"),
        ("iss", "https://other.invalid"), ("aud", "other-client"), ("azp", "other-client"),
        ("exp", 1700000030), ("iat", 1700000031), ("iat", 1699999729), ("nonce", "bad"),
        ("exp", "1700000120"), ("iat", True), ("exp", 1700000120.5),
        ("aud", ["native-client", "untrusted"]), ("azp", None),
    ]:
        signed_case(f"signed wrong {name} {value}", header, claims | {name: value})
    for name, value in [("kid", "other-key"), ("alg", "none"), ("crit", ["unsupported"])]:
        signed_case(f"signed wrong {name}", header | {name: value}, claims)
    for name, message, signature, expected in cases:
        rc = subprocess.run([exe], env={
            "OIDC_PUBLIC_DER": base64.b64encode(der).decode(),
            "OIDC_SIGNATURE": base64.b64encode(signature).decode(),
            "OIDC_SIGNING_INPUT": message,
        }).returncode
        print(f"{name}: expected {expected}, got {rc}", flush=True)
        if rc != expected:
            raise SystemExit(1)
