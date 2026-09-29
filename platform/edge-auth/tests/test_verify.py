#!/usr/bin/env python3
"""Black-box tests for verify.py. Standard library + the openssl command.

    python3 platform/edge-auth/tests/test_verify.py

Starts a fake Cloudflare certs endpoint and the real verifier as a subprocess,
then sends it what an attacker and what Cloudflare would send.
"""
import base64, hashlib, hmac, http.client, json, os, socket, subprocess, sys, tempfile, threading, time, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFY = os.path.join(HERE, "..", "verify.py")
SONAR, JENKINS = "a" * 64, "b" * 64


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Key:
    def __init__(self, kid, bits=2048):
        self.kid = kid
        self.pem = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
        subprocess.run(["openssl", "genrsa", "-out", self.pem, str(bits)], check=True, capture_output=True)
        mod = subprocess.run(["openssl", "rsa", "-in", self.pem, "-noout", "-modulus"], check=True, capture_output=True, text=True).stdout
        self.n = bytes.fromhex(mod.strip().split("=")[1])
        self.pub = subprocess.run(["openssl", "rsa", "-in", self.pem, "-pubout"], check=True, capture_output=True).stdout

    def jwk(self):
        return {"kid": self.kid, "kty": "RSA", "alg": "RS256", "use": "sig", "e": "AQAB", "n": b64(self.n)}

    def sign(self, data):
        return subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.pem], input=data, check=True, capture_output=True).stdout


class Certs:
    """Stands in for https://<team>.cloudflareaccess.com/cdn-cgi/access/certs"""
    def __init__(self):
        self.keys, self.up, self.hits = [], True, 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits += 1
                if not outer.up or self.path != "/cdn-cgi/access/certs":
                    self.send_response(503); self.end_headers(); return
                body = json.dumps({"keys": [k.jwk() for k in outer.keys]}).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def log_message(self, *a): pass

        self.port = free_port()
        self.server = HTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.issuer = f"http://127.0.0.1:{self.port}"


class Verifier:
    def __init__(self, certs, min_interval="1"):
        self.port = free_port()
        self.aud = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"sonar.example.test": SONAR, "jenkins.example.test": JENKINS}, self.aud); self.aud.close()
        env = dict(os.environ, ACCESS_TEAM_DOMAIN=certs.issuer, AUDIENCES_FILE=self.aud.name, PORT=str(self.port),
                   KEYS_MIN_INTERVAL=min_interval, PYTHONDONTWRITEBYTECODE="1")
        self.proc = subprocess.Popen([sys.executable, VERIFY], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close(); return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("verifier did not start: " + self.proc.stdout.read())

    def ask(self, token=None, host="sonar.example.test", path="/verify", method="GET"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"X-Forwarded-Host": host, "X-Forwarded-Uri": "/x", "X-Forwarded-For": "203.0.113.9"}
        if token is not None:
            h["Cf-Access-Jwt-Assertion"] = token
        c.request(method, path, headers=h)
        r = c.getresponse(); r.read(); c.close()
        return r.status, r.getheader("X-Auth-User")

    def stop(self):
        self.proc.terminate(); out = self.proc.communicate(timeout=5)[0]; return out


UNSET = object()


def token(key, issuer, aud=SONAR, header=None, sign=True, raw_aud=UNSET, **claims):
    """aud: one audience, sent the way Cloudflare does (a list). raw_aud: the claim exactly as given; None removes it."""
    now = int(time.time())
    body = {"iss": issuer, "aud": [aud], "exp": now + 600, "iat": now, "nbf": now, "email": "user@example.test", "type": "app"}
    if raw_aud is not UNSET:
        body["aud"] = raw_aud
    body.update(claims)
    body = {k: v for k, v in body.items() if v is not None}
    h = {"alg": "RS256", "kid": key.kid, "typ": "JWT"}
    h.update(header or {})
    signed = b64(json.dumps(h).encode()) + "." + b64(json.dumps(body).encode())
    return signed + "." + (b64(key.sign(signed.encode())) if sign else "")


class VerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key, cls.other, cls.weak = Key("kid-1"), Key("kid-1"), Key("kid-weak", 1024)
        cls.certs = Certs(); cls.certs.keys = [cls.key, cls.weak]
        cls.v = Verifier(cls.certs)
        cls.iss = cls.certs.issuer

    @classmethod
    def tearDownClass(cls):
        cls.log = cls.v.stop()

    def ok(self, *a, **k):
        self.assertEqual(self.v.ask(*a, **k)[0], 200)

    def denied(self, *a, **k):
        self.assertEqual(self.v.ask(*a, **k)[0], 401)

    # --- what Cloudflare sends
    def test_valid_token(self):
        self.assertEqual(self.v.ask(token(self.key, self.iss)), (200, "user@example.test"))

    def test_valid_token_any_method(self):
        for m in ("POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
            self.ok(token(self.key, self.iss), method=m)

    def test_audience_as_string_and_in_a_list(self):
        self.ok(token(self.key, self.iss, raw_aud=SONAR))
        self.ok(token(self.key, self.iss, raw_aud=["zzz", SONAR]))

    def test_host_header_with_port_and_capitals(self):
        self.ok(token(self.key, self.iss), host="Sonar.Example.Test:443")

    def test_expired_within_the_leeway(self):
        self.ok(token(self.key, self.iss, exp=int(time.time()) - 30))

    def test_service_token_has_no_email(self):
        t = token(self.key, self.iss, email=None, common_name="abc.access")
        self.assertEqual(self.v.ask(t), (200, "abc.access"))

    # --- what reaches the load balancer directly
    def test_no_token(self):
        self.denied(None)
        self.denied("")

    def test_garbage(self):
        for t in ("x", "a.b", "a.b.c", "a.b.c.d", "....", "!!!.???.***", "e30.e30.e30", "null.null.null"):
            self.denied(t)

    def test_header_or_payload_not_an_object(self):
        h = b64(b'"RS256"'); self.denied(h + "." + b64(b"{}") + "." + b64(b"x" * 256))
        signed = b64(json.dumps({"alg": "RS256", "kid": "kid-1"}).encode()) + "." + b64(b"[1,2]")
        self.denied(signed + "." + b64(self.key.sign(signed.encode())))

    # --- forgeries
    def test_algorithm_none(self):
        self.denied(token(self.key, self.iss, header={"alg": "none"}, sign=False))
        self.denied(token(self.key, self.iss, header={"alg": "None"}, sign=False))

    def test_algorithm_confusion_hs256_with_the_public_key(self):
        h = b64(json.dumps({"alg": "HS256", "kid": "kid-1"}).encode())
        p = b64(json.dumps({"iss": self.iss, "aud": [SONAR], "exp": int(time.time()) + 600}).encode())
        for secret in (self.key.pub, self.key.n):
            self.denied(h + "." + p + "." + b64(hmac.new(secret, (h + "." + p).encode(), hashlib.sha256).digest()))

    def test_signed_by_someone_else_with_our_key_id(self):
        self.denied(token(self.other, self.iss))

    def test_payload_changed_after_signing(self):
        good = token(self.key, self.iss, aud=JENKINS).split(".")
        forged = b64(json.dumps({"iss": self.iss, "aud": [SONAR], "exp": int(time.time()) + 600}).encode())
        self.denied(good[0] + "." + forged + "." + good[2])

    def test_signature_wrong_length_or_empty(self):
        good = token(self.key, self.iss).split(".")
        self.denied(good[0] + "." + good[1] + "." + b64(b"\x01" * 255))
        self.denied(good[0] + "." + good[1] + "." + b64(b"\x00" * 256))
        self.denied(good[0] + "." + good[1] + "." + b64(b"\xff" * 256))
        self.denied(good[0] + "." + good[1] + ".")

    def test_unknown_key_id(self):
        self.denied(token(self.key, self.iss, header={"kid": "nope"}))
        self.denied(token(self.key, self.iss, header={"kid": None}))
        self.denied(token(self.key, self.iss, header={"kid": ["kid-1"]}))

    def test_weak_key_in_the_certs_document_is_ignored(self):
        self.denied(token(self.weak, self.iss))

    # --- valid signature, wrong claims
    def test_token_for_another_application(self):
        t = token(self.key, self.iss, aud=JENKINS)
        self.denied(t, host="sonar.example.test")
        self.ok(t, host="jenkins.example.test")

    def test_wrong_issuer(self):
        self.denied(token(self.key, "https://evil.cloudflareaccess.com"))
        self.denied(token(self.key, self.iss + "/"))
        self.denied(token(self.key, None))

    def test_expired(self):
        self.denied(token(self.key, self.iss, exp=int(time.time()) - 120))

    def test_expiry_missing_or_not_a_number(self):
        for bad in (None, "9999999999", True, [9999999999], {}):
            self.denied(token(self.key, self.iss, exp=bad))

    def test_not_yet_valid(self):
        self.denied(token(self.key, self.iss, nbf=int(time.time()) + 600))
        self.denied(token(self.key, self.iss, nbf="0"))

    def test_audience_missing_or_wrong_type(self):
        for bad in ("", [], {SONAR: 1}, 5, [["a"]]):
            self.denied(token(self.key, self.iss, raw_aud=bad))
        self.denied(token(self.key, self.iss, raw_aud=None))

    def test_host_not_configured(self):
        self.denied(token(self.key, self.iss), host="other.example.test")
        self.denied(token(self.key, self.iss), host="")

    # --- the service itself
    def test_health_ready_and_unknown_path(self):
        self.assertEqual(self.v.ask(path="/healthz")[0], 200)
        self.assertEqual(self.v.ask(path="/readyz")[0], 200)
        self.assertEqual(self.v.ask(token(self.key, self.iss), path="/")[0], 404)
        self.assertEqual(self.v.ask(token(self.key, self.iss), path="/verify/../healthz")[0], 404)


class KeyLifecycleTests(unittest.TestCase):
    def test_rotation_outage_and_refresh_limit(self):
        a, b = Key("kid-a"), Key("kid-b")
        certs = Certs(); certs.keys = [a]
        v = Verifier(certs, min_interval="2")
        try:
            self.assertEqual(v.ask(token(a, certs.issuer))[0], 200)
            # Cloudflare is unreachable: the keys already loaded keep working
            certs.up = False
            time.sleep(2.1)
            self.assertEqual(v.ask(token(b, certs.issuer))[0], 401)          # triggers a refresh, which fails
            self.assertEqual(v.ask(token(a, certs.issuer))[0], 200)
            # a new key appears
            certs.up = True; certs.keys = [a, b]
            time.sleep(2.1)
            self.assertEqual(v.ask(token(b, certs.issuer))[0], 200)
            # unknown key ids cannot make the verifier hammer Cloudflare
            before = certs.hits
            for i in range(50):
                v.ask(token(a, certs.issuer, header={"kid": f"x{i}"}))
            self.assertLessEqual(certs.hits - before, 1)
        finally:
            v.stop()

    def test_no_keys_at_start_fails_closed_then_recovers(self):
        a = Key("kid-a")
        certs = Certs(); certs.keys = [a]; certs.up = False
        v = Verifier(certs, min_interval="1")
        try:
            self.assertEqual(v.ask(path="/readyz")[0], 503)
            self.assertEqual(v.ask(token(a, certs.issuer))[0], 401)
            certs.up = True
            time.sleep(1.1)
            self.assertEqual(v.ask(path="/readyz")[0], 200)                  # recovers on the probe alone, no traffic needed
            self.assertEqual(v.ask(token(a, certs.issuer))[0], 200)
        finally:
            v.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
