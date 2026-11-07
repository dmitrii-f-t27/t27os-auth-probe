"""Synthetic, isolated broker acceptance. All credentials and keys are disposable."""
import base64
import hashlib
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import (
    HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, Request, build_opener, urlopen,
)

ROOT = Path(__file__).resolve().parent
UPSTREAM = "https://127.0.0.1:18081"
BROKER = "https://127.0.0.1:18080"
SSL_CONTEXT = None
REALM = "t27os-telegram"
ISSUER = f"{BROKER}/realms/{REALM}"
UPSTREAM_CLIENT = "synthetic-upstream"
UPSTREAM_SECRET = "synthetic-only-secret"
NATIVE_CLIENT = "t27os-telegram-native"
CALLBACK = f"{ISSUER}/broker/telegram/endpoint"
PKCE = "synthetic-verifier-A7kQmDb8vd3L3eaY2DbbRtT7Wxshe1_Aqlu"

def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

def json64(obj):
    return b64(json.dumps(obj, separators=(",", ":")).encode())

def request(url, form=None, *, opener=None, headers=None, data=None, method=None):
    if form is not None:
        data = urlencode(form).encode()
    req = Request(url, data=data, headers=headers or {}, method=method)
    if opener:
        return opener.open(req, timeout=10)
    return urlopen(req, timeout=10, context=SSL_CONTEXT)

def json_response(*args, **kwargs):
    with request(*args, **kwargs) as response:
        return json.load(response)

def decoded_claims(token):
    encoded = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))

def fixture_realm(output):
    realm = json.loads((ROOT / "realm.template.json").read_text())
    provider = realm["identityProviders"][0]
    provider["enabled"] = True
    provider["config"].update(
        issuer=UPSTREAM,
        authorizationUrl=UPSTREAM + "/auth",
        tokenUrl=UPSTREAM + "/token",
        jwksUrl=UPSTREAM + "/keys",
        clientId=UPSTREAM_CLIENT,
        clientSecret=UPSTREAM_SECRET,
    )
    Path(output).write_text(json.dumps(realm))

class Fixture:
    def __init__(self, private_key):
        self.private_key = private_key
        self.pending = {}
        self.mode = "valid"
        self.name = "Fixture Person"
        self.username = "fixture_initial"
        self.auth_calls = 0
        self.token_calls = 0
        self.userinfo_calls = 0
        modulus = subprocess.check_output(
            ["openssl", "rsa", "-in", private_key, "-noout", "-modulus"],
            stderr=subprocess.DEVNULL,
        ).decode().strip().split("=", 1)[1]
        self.jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256",
                              "kid": "fixture-key", "n": b64(bytes.fromhex(modulus)),
                              "e": b64(bytes([1, 0, 1]))}]}

    def signed(self, claims, *, tamper=False):
        message = json64({"alg": "RS256", "kid": "fixture-key"}) + "." + json64(claims)
        signature = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign", self.private_key], input=message.encode()
        )
        if tamper:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return message + "." + b64(signature)

class UpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    @property
    def fixture(self):
        return self.server.fixture

    def emit_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        uri = urlsplit(self.path)
        if uri.path == "/keys":
            self.emit_json(self.fixture.jwks)
            return
        if uri.path == "/userinfo":
            self.fixture.userinfo_calls += 1
        if uri.path != "/auth":
            self.send_error(404)
            return
        query = parse_qs(uri.query)
        required = {
            "client_id": [UPSTREAM_CLIENT], "redirect_uri": [CALLBACK],
            "response_type": ["code"], "code_challenge_method": ["S256"],
        }
        if any(query.get(k) != v for k, v in required.items()):
            self.send_error(400, "unexpected synthetic authorize parameters")
            return
        if not all(len(query.get(key, [])) == 1 for key in ("state", "nonce", "code_challenge")):
            self.send_error(400, "missing synthetic state nonce or PKCE")
            return
        if set(query.get("scope", [""])[0].split()) != {"openid", "profile"}:
            self.send_error(400, "unexpected synthetic authorize scope")
            return
        self.fixture.auth_calls += 1
        code = secrets.token_urlsafe(24)
        self.fixture.pending[code] = (query["nonce"][0], query["code_challenge"][0])
        self.send_response(302)
        self.send_header("Location", CALLBACK + "?" + urlencode({"code": code, "state": query["state"][0]}))
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if self.path != "/token":
            self.send_error(404)
            return
        basic = "Basic " + base64.b64encode(f"{UPSTREAM_CLIENT}:{UPSTREAM_SECRET}".encode()).decode()
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size < 4096 or self.headers.get("Authorization") != basic:
            self.send_error(401)
            return
        query = parse_qs(self.rfile.read(size).decode())
        saved = self.fixture.pending.pop(query.get("code", [""])[0], None)
        verifier = query.get("code_verifier", [""])[0]
        if (not saved or query.get("grant_type") != ["authorization_code"]
                or query.get("redirect_uri") != [CALLBACK]
                or b64(hashlib.sha256(verifier.encode()).digest()) != saved[1]):
            self.send_error(400)
            return
        self.fixture.token_calls += 1
        now = int(time.time())
        claims = {
            "iss": UPSTREAM, "aud": UPSTREAM_CLIENT, "sub": "908172635451",
            "nonce": saved[0], "iat": now, "exp": now + 90,
            "name": self.fixture.name, "preferred_username": self.fixture.username,
        }
        mode = self.fixture.mode
        overrides = {
            "issuer": {"iss": UPSTREAM + "/wrong"},
            "audience": {"aud": "wrong"},
            "nonce": {"nonce": "wrong"},
            "expired": {"exp": now - 10},
            "malformed": {"sub": "bad subject"},
            "collision": {"sub": "981234567890"},
            "invalid_email": {"sub": "985555555555", "email": "not-an-email"},
        }
        claims.update(overrides.get(mode, {}))
        if mode == "no_display":
            claims.pop("name")
            claims.pop("preferred_username")
        if mode == "absent":
            claims.pop("sub")
        if mode == "wrong_type":
            claims["sub"] = 123456789
        conflicting = claims | {"sub": "999999999999"}
        self.emit_json({
            "token_type": "Bearer", "expires_in": 90,
            "id_token": self.fixture.signed(claims, tamper=mode == "signature"),
            "access_token": self.fixture.signed(conflicting),
        })

class CaptureCallback(HTTPRedirectHandler):
    def __init__(self, callback):
        self.callback = callback
        self.result = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(self.callback + "?"):
            self.result = parse_qs(urlsplit(newurl).query)
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def authorize(fixture, cookies, *, port=19001, path="/t27os-telegram-callback", host="127.0.0.1",
              expect_callback=True, challenge=True):
    callback = f"http://{host}:{port}{path}"
    capture = CaptureCallback(callback)
    opener = build_opener(HTTPCookieProcessor(cookies), HTTPSHandler(context=SSL_CONTEXT), capture)
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    params = {
        "client_id": NATIVE_CLIENT, "redirect_uri": callback, "response_type": "code",
        "scope": "openid", "state": state, "nonce": nonce,
    }
    if challenge:
        params.update(code_challenge=b64(hashlib.sha256(PKCE.encode()).digest()), code_challenge_method="S256")
    before = fixture.auth_calls
    try:
        response = request(ISSUER + "/protocol/openid-connect/auth?" + urlencode(params), opener=opener)
    except HTTPError as error:
        response = error
    with response:
        status = response.status
        path_only = urlsplit(response.url).path
        page = response.read(16384).decode(errors="replace") if capture.result is None else ""
    if capture.result is None:
        title = re.search(r"<title>\s*([^<]{1,100})</title>", page)
        markers = [marker for marker in ("UPDATE_PROFILE", "UPDATE_PASSWORD", "login-actions/required-action",
                   "first-broker-login", "invalid", "error") if marker in page]
        print(f"fixture authorize status={status} path={path_only} title={title.group(1) if title else '-'} "
              f"markers={markers} upstream_auth={fixture.auth_calls} upstream_token={fixture.token_calls}", flush=True)
    result = capture.result or {}
    if not expect_callback:
        assert "code" not in result
        assert fixture.auth_calls == before
        return None
    assert fixture.auth_calls == before + 1, "fresh upstream authorization callback missing"
    if "code" not in result:
        allowed_errors = {"access_denied", "invalid_request", "server_error", "interaction_required", "login_required"}
        error = result.get("error", [""])[0]
        print("fixture callback error=" + (error if error in allowed_errors else "none-or-other"), flush=True)
        return None
    assert result.get("state") == [state]
    exchange = {
        "grant_type": "authorization_code", "client_id": NATIVE_CLIENT,
        "redirect_uri": callback, "code": result["code"][0], "code_verifier": PKCE,
    }
    token = json_response(ISSUER + "/protocol/openid-connect/token", exchange)
    assert "refresh_token" not in token
    claims = decoded_claims(token["id_token"])
    assert claims["iss"] == ISSUER and claims["aud"] == NATIVE_CLIENT and claims["nonce"] == nonce
    access = decoded_claims(token["access_token"])
    assert not {"telegram_sub", "identity_provider", "telegram_name", "telegram_username"} & access.keys()
    reject_replay(exchange)
    fixture.last_exchange = exchange
    return claims

def reject_replay(exchange):
    try:
        json_response(ISSUER + "/protocol/openid-connect/token", exchange)
    except HTTPError as error:
        assert error.code == 400
    else:
        raise AssertionError("native authorization code replay succeeded")

def wait_for_broker():
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        try:
            doc = json_response(ISSUER + "/.well-known/openid-configuration")
            if doc["issuer"] == ISSUER:
                return
        except OSError:
            pass
        time.sleep(1)
    raise RuntimeError("broker readiness timed out")

def require_identity(claims, *, username):
    assert claims is not None, "missing native authorization code"
    assert claims["telegram_sub"] == "908172635451"
    assert claims["sub"] != claims["telegram_sub"]
    assert claims["identity_provider"] == "telegram"
    assert claims["telegram_name"] == "Fixture Person"
    assert claims["telegram_username"] == username

def admin_headers():
    token = json_response(BROKER + "/realms/master/protocol/openid-connect/token", {
        "grant_type": "password", "client_id": "admin-cli", "username": "synthetic-admin",
        "password": "synthetic-admin-password",
    })["access_token"]
    return {"Authorization": "Bearer " + token, "Content-Type": "application/json"}

def configure_user_profile():
    endpoint = BROKER + f"/admin/realms/{REALM}/users/profile"
    headers = admin_headers()
    policy = json.loads((ROOT / "user-profile-policy.json").read_text())
    profile = json_response(endpoint, headers=headers)
    optional = set(policy["optionalAttributes"])
    assert optional <= {a["name"] for a in profile["attributes"]}
    for attribute in profile["attributes"]:
        if attribute["name"] in optional:
            attribute.pop("required", None)
    with request(endpoint, data=json.dumps(profile).encode(), headers=headers, method="PUT") as response:
        assert response.status in (200, 204)
    saved = json_response(endpoint, headers=headers)
    attrs = {a["name"]: a for a in saved["attributes"]}
    assert all(not attrs[name].get("required") for name in optional)
    assert saved == profile, "realm changed more profile settings than requested"
    print("PASS dedicated realm profile policy read back, existing validators preserved", flush=True)

def admin_add_conflicting_user():
    headers = admin_headers()
    body = json.dumps({"username": "telegram.981234567890", "enabled": True}).encode()
    with request(BROKER + f"/admin/realms/{REALM}/users", data=body, method="POST", headers=headers) as response:
        assert response.status == 201

def run(private_key, certificate, tls_key):
    global SSL_CONTEXT
    SSL_CONTEXT = ssl.create_default_context(cafile=certificate)
    server = ThreadingHTTPServer(("127.0.0.1", 18081), UpstreamHandler)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, tls_key)
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    fixture = Fixture(private_key)
    server.fixture = fixture
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        wait_for_broker()
        configure_user_profile()
        cookies = CookieJar()
        first = authorize(fixture, cookies)
        require_identity(first, username="fixture_initial")
        print("PASS first callback, ID-token-only upstream subject and provider", flush=True)
        fixture.username = "fixture_changed"
        returning = authorize(fixture, cookies, port=19002)
        require_identity(returning, username="fixture_changed")
        assert first["sub"] == returning["sub"]
        print("PASS new upstream callback with prior SSO, changed display and stable subject", flush=True)
        fixture.mode = "no_display"
        no_display = authorize(fixture, cookies)
        assert no_display is not None and no_display["telegram_sub"] == "908172635451"
        assert not {"telegram_name", "telegram_username"} & no_display.keys()
        fixture.mode = "valid"
        print("PASS missing display does not retain stale notes, no refresh token", flush=True)
        for args in ({"path": "/wrong"}, {"host": "localhost"}, {"challenge": False}):
            authorize(fixture, cookies, expect_callback=False, **args)
        print("PASS exact loopback path, IP and S256 enforcement", flush=True)
        for mode in ("issuer", "audience", "nonce", "expired", "signature"):
            fixture.mode = mode
            assert authorize(fixture, cookies) is None, f"accepted wrong {mode}"
            print(f"PASS rejected upstream {mode}", flush=True)
        for mode in ("absent", "wrong_type", "malformed"):
            fixture.mode = mode
            result = authorize(fixture, cookies)
            assert result is None or "telegram_sub" not in result, f"emitted invalid upstream subject: {mode}"
            print(f"PASS invalid subject not emitted: {mode}", flush=True)
        fixture.mode = "invalid_email"
        assert authorize(fixture, cookies) is None, "invalid supplied email was accepted"
        print("PASS supplied invalid profile field still rejected", flush=True)
        admin_add_conflicting_user()
        fixture.mode = "collision"
        assert authorize(fixture, cookies) is None, "linked existing username"
        print("PASS refused existing username collision", flush=True)
        fixture.mode = "valid"
        prior_exchange = fixture.last_exchange
        subprocess.run(["docker", "restart", "t27-auth-keycloak"], check=True, stdout=subprocess.DEVNULL)
        wait_for_broker()
        reject_replay(prior_exchange)
        reopened = authorize(fixture, cookies, port=19003)
        require_identity(reopened, username="fixture_changed")
        assert first["sub"] == reopened["sub"]
        assert fixture.userinfo_calls == 0
        print("PASS broker restart, previous browser cookies, stable subject, no UserInfo, replay rejected", flush=True)
    finally:
        server.shutdown()

if __name__ == "__main__":
    if sys.argv[1] == "render":
        fixture_realm(sys.argv[2])
    elif sys.argv[1] == "run":
        run(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        raise SystemExit(2)
