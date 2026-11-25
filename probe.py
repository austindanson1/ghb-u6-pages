#!/usr/bin/env python3
"""U6 Pages/Actions build boundary probe. Read-only."""
import json
import os
import re
import socket
import subprocess
import urllib.error
import urllib.request

OUT = []
TOK = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


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


def api(path, tok=TOK, jq=True):
    """GET api.github.com path with token; return (status, body)."""
    req = urllib.request.Request("https://api.github.com" + path)
    if tok:
        req.add_header("Authorization", "token " + tok)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "u6-probe")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read(3000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(500).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", repr(e)


def http(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(1500).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(800).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", repr(e)


# ---------------------------------------------------------------- 1. env
hdr("1. BUILD ENVIRONMENT")
sensitive = re.compile(r"(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)", re.I)
for k in sorted(os.environ):
    v = os.environ[k]
    if sensitive.search(k):
        v = "<set len=%d prefix=%s>" % (len(v), v[:6])
    if len(v) > 260:
        v = v[:260] + "...<trunc>"
    OUT.append("%s=%s" % (k, v))

hdr("1b. identity of the build host")
for c in ("uname -a", "hostname", "id", "nproc", "free -m | head -2",
          "cat /etc/os-release | head -3"):
    OUT.append("$ %s\n%s" % (c, sh(c)))

# ------------------------------------------------------- 2. token reach
hdr("2. GITHUB_TOKEN: does the build token reach beyond its own repo?")
OUT.append("GITHUB_TOKEN prefix=%s len=%d" % (TOK[:4], len(TOK)))
st, body = api("/rate_limit")
OUT.append("GET /rate_limit -> %s\n%s" % (st, body[:400]))

for repo in ("austindanson1/ghb-u6-pages", "austindanson1/codex-rainbow",
             "austindanson1/ghb-u6-private", "austindanson1/jane-street-dormant",
             "actions/checkout", "github/gitignore"):
    st, body = api("/repos/" + repo)
    try:
        d = json.loads(body)
        note = "private=%s msg=%s" % (d.get("private"), d.get("message", ""))
    except Exception:  # noqa: BLE001
        note = body[:120]
    OUT.append("GET /repos/%-32s -> %s  %s" % (repo, st, note))

hdr("2b. contents read from the OTHER PRIVATE repo (real data, not just 200)")
st, body = api("/repos/austindanson1/ghb-u6-private/contents/")
OUT.append("status=%s" % st)
try:
    for f in json.loads(body):
        OUT.append("  %-28s %8s bytes  sha=%s" % (f["name"], f.get("size"), f.get("sha", "")[:12]))
except Exception:  # noqa: BLE001
    OUT.append(body[:400])

hdr("2c. can the build token read a repo it was never granted? (org repos, others)")
for repo in ("cli/cli", "github/gh-ost"):
    st, body = api("/repos/" + repo + "/contents/")
    OUT.append("GET /repos/%s/contents -> %s %s" % (repo, st, body[:100].replace("\n", " ")))

# ------------------------------------------------- 3. runtime/artifact svc
hdr("3. ACTIONS RUNTIME TOKEN + ARTIFACT SERVICE")
rt = os.environ.get("ACTIONS_RUNTIME_TOKEN", "")
OUT.append("ACTIONS_RUNTIME_TOKEN len=%d prefix=%s" % (len(rt), rt[:8]))
for k in ("ACTIONS_RESULTS_URL", "ACTIONS_CACHE_URL", "ACTIONS_RUNTIME_URL",
          "ACTIONS_ID_TOKEN_REQUEST_URL"):
    OUT.append("%-32s %s" % (k, os.environ.get(k)))


def jwt(tok):
    try:
        parts = tok.split(".")
        def dec(s):
            s += "=" * (-len(s) % 4)
            return json.loads(__import__("base64").urlsafe_b64decode(s))
        return dec(parts[0]), dec(parts[1])
    except Exception as e:  # noqa: BLE001
        return {"_err": repr(e)}, {}


if rt:
    h_, c_ = jwt(rt)
    OUT.append("JWT header : %s" % json.dumps(h_))
    OUT.append("JWT claims : %s" % json.dumps(c_, indent=1))

# ------------------------------------------------------------- 4. network
hdr("4. NETWORK REACH FROM THE PAGES BUILD HOST")
HOSTS = [
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     {"Metadata": "true"}),
    ("http://169.254.169.254/latest/meta-data/", {}),
    ("http://metadata.google.internal/computeMetadata/v1/", {"Metadata-Flavor": "Google"}),
    ("http://100.100.100.200/latest/meta-data/", {}),
    ("https://api.github.com/meta", {}),
    ("https://githubapp.com", {}),
    ("https://github.net", {}),
]
for u, h in HOSTS:
    code, b = http(u, h)
    OUT.append("%-58s -> %s  %s" % (u, code, b.replace("\n", " ")[:200]))

hdr("4b. DNS resolution from the build host")
for name in ("github.net", "githubapp.com", "api.github.com", "metadata.google.internal",
             "instance-data", "kubernetes.default"):
    try:
        OUT.append("%-24s -> %s" % (name, socket.gethostbyname(name)))
    except Exception as e:  # noqa: BLE001
        OUT.append("%-24s -> FAIL %r" % (name, e))

hdr("4c. sockets, routes, resolv.conf, hosts")
OUT.append("$ /etc/resolv.conf\n" + sh("cat /etc/resolv.conf"))
OUT.append("$ /etc/hosts\n" + sh("cat /etc/hosts"))
OUT.append("$ ip route\n" + sh("ip route 2>/dev/null || route -n"))

hdr("4d. filesystem: anything belonging to GitHub (not the repo)?")
for p in ("/", "/home/runner", "/opt", "/var/run", "/mnt"):
    OUT.append("$ ls -la %s\n%s" % (p, sh("ls -la %s 2>&1 | head -14" % p)))

text = "\n".join(OUT)
print(text)
with open(os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "probe-A.txt"), "w") as f:
    f.write(text)
