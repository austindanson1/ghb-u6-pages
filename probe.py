#!/usr/bin/env python3
"""U6 Pages/Actions build boundary probe. Read-only."""
import json
import os
import re
import subprocess
import sys
import urllib.request

OUT = []


def hdr(t):
    OUT.append("\n" + "=" * 70)
    OUT.append("### " + t)
    OUT.append("=" * 70)


def run(cmd, timeout=25):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (p.stdout + p.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return "EXC: %r" % (e,)


def http(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(4000).decode("utf-8", "replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(1200).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", {}, repr(e)


# ---------------------------------------------------------------- 1. env
hdr("1. BUILD ENVIRONMENT (env, sanitized)")
sensitive = re.compile(r"(TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL)", re.I)
for k in sorted(os.environ):
    v = os.environ[k]
    if sensitive.search(k):
        # keep shape, not the value: length + prefix
        v = "<set len=%d prefix=%s>" % (len(v), v[:6])
    if len(v) > 300:
        v = v[:300] + "...<trunc>"
    OUT.append("%s=%s" % (k, v))

hdr("1b. ACTIONS_* / RUNNER_* / GITHUB_* split out")
for k in sorted(os.environ):
    if k.startswith(("ACTIONS_", "RUNNER_", "GITHUB_", "CI", "PAGES")) and not sensitive.search(k):
        OUT.append("%s=%s" % (k, os.environ[k][:400]))

hdr("1c. IDENTITY: who does the build think it is?")
OUT.append("uname: " + run("uname -a"))
OUT.append("hostname: " + run("hostname"))
OUT.append("whoami: " + run("id"))
OUT.append("cpu/mem: " + run("nproc; free -m | head -2"))

# ------------------------------------------------------- 2. token reach
hdr("2. GITHUB_TOKEN REACH (scopes + cross-repo)")
tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
OUT.append("token prefix=%s len=%d" % (tok[:4], len(tok)))
OUT.append("GET /user -> " + run(
    "curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: token $GITHUB_TOKEN' https://api.github.com/user"))
OUT.append("rate_limit (proves token validity + class): " + run(
    "curl -s -H 'Authorization: token $GITHUB_TOKEN' https://api.github.com/rate_limit "
    "| python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({k:d[\"resources\"][k] for k in (\"core\",\"graphql\",\"integration_manifest\")}, indent=1))'"))
OUT.append("X-OAuth-Scopes header: " + run(
    "curl -sI -H 'Authorization: token $GITHUB_TOKEN' https://api.github.com/user "
    "| grep -i -E 'x-oauth-scopes|x-accepted|github-authentication'"))

REPOS = [
    ("own_public_same", "austindanson1/ghb-u6-pages"),
    ("own_public_other", "austindanson1/codex-rainbow"),
    ("own_PRIVATE_other", "austindanson1/ghb-u6-private"),
    ("third_party_public", "actions/checkout"),
]
hdr("2b. cross-repo reads with the implicit token")
for label, repo in REPOS:
    code = run("curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: token $GITHUB_TOKEN' "
               "https://api.github.com/repos/%s" % repo)
    OUT.append("GET /repos/%-28s %-18s -> %s" % (repo, label, code))
OUT.append("\ncontents probe (actual data if readable):")
for label, repo in REPOS:
    body = run("curl -s -H 'Authorization: token $GITHUB_TOKEN' "
               "https://api.github.com/repos/%s/contents/ | head -c 200" % repo)
    OUT.append("-- %s (%s): %s" % (repo, label, body.replace("\n", " ")[:200]))

hdr("2c. does the token see the OTHER repo's private content?")
OUT.append(run("curl -s -H 'Authorization: token $GITHUB_TOKEN' "
               "https://api.github.com/repos/austindanson1/ghb-u6-private "
               "| python3 -c 'import json,sys; d=json.load(sys.stdin); "
               "print(d.get(\"full_name\"), d.get(\"private\"), d.get(\"message\",\"\"))'"))

# ------------------------------------------------- 3. runtime/artifact svc
hdr("3. ACTIONS RUNTIME TOKEN + ARTIFACT SERVICE")
rt = os.environ.get("ACTIONS_RUNTIME_TOKEN", "")
OUT.append("ACTIONS_RUNTIME_TOKEN len=%d prefix=%s" % (len(rt), rt[:6]))
OUT.append("ACTIONS_RESULTS_URL=%s" % os.environ.get("ACTIONS_RESULTS_URL"))
OUT.append("ACTIONS_CACHE_URL=%s" % os.environ.get("ACTIONS_CACHE_URL"))
OUT.append("ACTIONS_RUNTIME_URL=%s" % os.environ.get("ACTIONS_RUNTIME_URL"))
if rt:
    OUT.append("\n-- JWT claims of ACTIONS_RUNTIME_TOKEN:")
    OUT.append(run("python3 -c \"import base64,json,sys;"
                   "t='%s'.split('.')[1];t+='='*(-len(t)%%4);"
                   "print(json.dumps(json.loads(base64.urlsafe_b64decode(t)),indent=1))\"" % rt))
    ru = os.environ.get("ACTIONS_RESULTS_URL", "").rstrip("/")
    if ru:
        OUT.append("\n-- ArtifactService/ListArtifacts on the results endpoint:")
        OUT.append(run(
            "curl -s -m 15 -X POST '%s/_apis/artifactcache/list' -H 'Accept: application/json'" % ru)[:800])

# ------------------------------------------------------------- 4. network
hdr("4. NETWORK REACH FROM THE BUILD HOST")
HOSTS = [
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "https://api.github.com/meta",
    "https://github.com",
    "https://githubapp.com",
    "https://github.net",
    "https://pages.github.com",
]
for u in HOSTS:
    code, h, body = http(u, {"Metadata": "true", "Metadata-Flavor": "Google"})
    OUT.append("%-62s -> %s  %s" % (u, code, body.replace("\n", " ")[:220]))

hdr("4b. DNS for internal-ish names")
for h in ["github.net", "githubapp.com", "github.com", "metadata.google.internal",
          "instance-data", "169.254.169.254"]:
    OUT.append("%-24s %s" % (h, run("getent hosts %s || python3 -c 'import socket;print(socket.gethostbyname(\"%s\"))' 2>&1" % (h, h))))

hdr("4c. listening sockets / routes (what else is on this box)")
OUT.append(run("ss -lntup 2>/dev/null | head -20 || netstat -lnt 2>/dev/null | head -20"))
OUT.append(run("ip route 2>/dev/null || route -n 2>/dev/null"))

hdr("4d. interesting filesystem locations")
for p in ["/", "/home/runner", "/actions-runner", "/opt", "/etc/hosts", "/etc/resolv.conf",
          "/var/run", "/mnt"]:
    OUT.append("%-18s %s" % (p, run("ls -la %s 2>&1 | head -12" % p)))
OUT.append("\n/etc/hosts:\n" + run("cat /etc/hosts"))
OUT.append("\n/etc/resolv.conf:\n" + run("cat /etc/resolv.conf"))

text = "\n".join(OUT)
print(text)
with open("/tmp/probe-out.txt", "w") as f:
    f.write(text)
