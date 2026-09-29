#!/usr/bin/env python3
"""Cloudflare Access token verifier for Traefik forwardAuth.

Traefik asks this service before it forwards a request to a protected host:
200 = let it through, anything else = Traefik answers the client with it.

Cloudflare Access signs a JWT (header Cf-Access-Jwt-Assertion) for every request
it lets through. A request that reaches the load balancer directly carries none,
or one that does not verify, and is refused here.

Standard library only, on purpose: no image to build, nothing to patch but Python.
Every failure path ends in "deny". Tests: tests/test_verify.py.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TEAM = os.environ["ACCESS_TEAM_DOMAIN"].rstrip("/")          # https://<team>.cloudflareaccess.com
CERTS_URL = TEAM + "/cdn-cgi/access/certs"
with open(os.environ.get("AUDIENCES_FILE", "/config/audiences.json")) as f:
    AUDIENCES = {h.lower(): a for h, a in json.load(f).items()}   # hostname -> AUD tag of its Access application
LEEWAY = 60                  # seconds of clock difference tolerated
KEYS_MAX_AGE = 3600          # re-read the signing keys hourly (Cloudflare rotates them every 6 weeks)
KEYS_MIN_INTERVAL = int(os.environ.get("KEYS_MIN_INTERVAL", "60"))   # ... and never more often than this, whatever the requests say
HEADER = "Cf-Access-Jwt-Assertion"
# DER prefix of a SHA-256 DigestInfo (RFC 8017, section 9.2)
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


class Deny(Exception):
    pass


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Keys:
    """The team's public signing keys, by key id. Keeps the last good set if a refresh fails."""

    def __init__(self):
        self.keys, self.tried, self.loaded, self.lock = {}, 0.0, 0.0, threading.Lock()

    def refresh(self):
        with self.lock:
            if time.time() - self.tried < KEYS_MIN_INTERVAL:
                return
            self.tried = time.time()
            try:
                with urllib.request.urlopen(CERTS_URL, timeout=5) as r:
                    doc = json.load(r)
                keys = {}
                for k in doc["keys"]:
                    if k.get("kty") != "RSA" or k.get("alg", "RS256") != "RS256":
                        continue
                    n, e = int.from_bytes(b64d(k["n"]), "big"), int.from_bytes(b64d(k["e"]), "big")
                    if n.bit_length() >= 2048 and e >= 3:
                        keys[k["kid"]] = (n, e)
                if not keys:
                    raise ValueError("no usable key in the document")
                self.keys, self.loaded = keys, time.time()
                log("keys", count=len(keys))
            except Exception as ex:                                  # keep the old keys; try again in 10 s
                self.tried = time.time() - max(KEYS_MIN_INTERVAL - 10, 0)
                log("keys-error", error=f"{type(ex).__name__}: {ex}"[:200])

    def get(self, kid):
        if kid not in self.keys or time.time() - self.loaded > KEYS_MAX_AGE:
            self.refresh()
        return self.keys.get(kid)


KEYS = Keys()


def verify(token, audience, now=None):
    """Return the claims of a valid token for this audience, or raise Deny."""
    now = time.time() if now is None else now
    parts = token.split(".")
    if len(parts) != 3:
        raise Deny("malformed")
    try:
        header = json.loads(b64d(parts[0]))
        signature = b64d(parts[2])
    except Exception:
        raise Deny("malformed")
    # The algorithm is fixed here, never taken from the token ("none", HS256 with the public key...).
    if not isinstance(header, dict) or header.get("alg") != "RS256":
        raise Deny("algorithm")
    key = KEYS.get(header.get("kid")) if isinstance(header.get("kid"), str) else None
    if key is None:
        raise Deny("unknown key")
    n, e = key
    size = (n.bit_length() + 7) // 8
    if len(signature) != size or int.from_bytes(signature, "big") >= n:
        raise Deny("signature")
    # RSASSA-PKCS1-v1_5: build the one encoding that is valid and compare whole. Nothing is parsed.
    digest = hashlib.sha256((parts[0] + "." + parts[1]).encode("ascii", "strict")).digest()
    expected = b"\x00\x01" + b"\xff" * (size - 3 - len(SHA256_PREFIX) - len(digest)) + b"\x00" + SHA256_PREFIX + digest
    actual = pow(int.from_bytes(signature, "big"), e, n).to_bytes(size, "big")
    if not hmac.compare_digest(actual, expected):
        raise Deny("signature")
    try:
        claims = json.loads(b64d(parts[1]))
    except Exception:
        raise Deny("malformed")
    if not isinstance(claims, dict):
        raise Deny("malformed")
    if claims.get("iss") != TEAM:
        raise Deny("issuer")
    aud = claims.get("aud")
    aud = [aud] if isinstance(aud, str) else aud
    if not isinstance(aud, list) or audience not in aud:
        raise Deny("audience")
    exp, nbf = claims.get("exp"), claims.get("nbf")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool) or now > exp + LEEWAY:
        raise Deny("expired")
    if nbf is not None and (not isinstance(nbf, (int, float)) or isinstance(nbf, bool) or now < nbf - LEEWAY):
        raise Deny("not yet valid")
    return claims


def log(event, **fields):
    print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event, **fields}), flush=True)


class Handler(BaseHTTPRequestHandler):
    timeout = 10
    server_version = "access-verify"
    sys_version = ""

    def answer(self, code, text, headers=()):
        body = (text + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def handle_any(self):
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            return self.answer(200, "ok")
        if path == "/readyz":
            if not KEYS.keys:            # a pod that started without network must be able to recover without traffic
                KEYS.refresh()
            return self.answer(200, "ready") if KEYS.keys else self.answer(503, "no signing keys loaded")
        if path != "/verify":
            return self.answer(404, "not found")
        host = (self.headers.get("X-Forwarded-Host") or "").split(",")[0].strip().lower().split(":")[0]
        try:
            audience = AUDIENCES.get(host)
            if audience is None:
                raise Deny("host not configured")
            token = self.headers.get(HEADER)
            if not token:
                raise Deny("no token")
            claims = verify(token.strip(), audience)
        except Deny as d:
            log("deny", reason=str(d), host=host, uri=(self.headers.get("X-Forwarded-Uri") or "")[:120],
                client=(self.headers.get("X-Forwarded-For") or "").split(",")[0].strip())
            return self.answer(401, "Sign in through Cloudflare Access.")
        except Exception as ex:                                      # a bug must not open the door
            log("error", error=f"{type(ex).__name__}: {ex}"[:200], host=host)
            return self.answer(401, "Sign in through Cloudflare Access.")
        user = claims.get("email") or claims.get("common_name") or claims.get("sub") or ""
        self.answer(200, "ok", [("X-Auth-User", str(user)[:254])])

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = handle_any

    def log_message(self, *args):                                    # allowed requests are in Traefik's access log
        pass


def main():
    KEYS.refresh()
    port = int(os.environ.get("PORT", "8080"))
    log("start", port=port, team=TEAM, hosts=sorted(AUDIENCES), keys=len(KEYS.keys))
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
