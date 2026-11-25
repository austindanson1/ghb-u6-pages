#!/usr/bin/env python3
"""U6 probe2: artifact service + deploy token + cross-repo reach, post-upload."""
import base64
import json
import os
import subprocess


def sh(cmd, timeout=25):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (p.stdout + p.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return "EXC: %r" % (e,)


def jwt(tok):
    try:
        part = tok.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception as e:  # noqa: BLE001
        return {"_err": repr(e)}


print("=" * 70)
print("### A. ACTIONS_RUNTIME_TOKEN / RESULTS SERVICE")
print("=" * 70)
rt = os.environ.get("ACTIONS_RUNTIME_TOKEN", "")
print("len=%d prefix=%s" % (len(rt), rt[:6]))
for k in ("ACTIONS_RESULTS_URL", "ACTIONS_CACHE_URL", "ACTIONS_RUNTIME_URL",
          "ACTIONS_ID_TOKEN_REQUEST_URL"):
    print("%-30s %s" % (k, os.environ.get(k)))
if rt:
    c = jwt(rt)
    hdrpart = rt.split(".")[0]
    hdrpart += "=" * (-len(hdrpart) % 4)
    print("\nJWT header :", json.dumps(json.loads(base64.urlsafe_b64decode(hdrpart))))
    print("JWT claims :", json.dumps(c, indent=1))

print("\n" + "=" * 70)
print("### B. ARTIFACT LISTING VIA RUNTIME TOKEN")
print("=" * 70)
ru = os.environ.get("ACTIONS_RESULTS_URL", "").rstrip("/")
if ru and rt:
    # Twirp ArtifactService
    print("-- Twirp ListArtifacts:")
    print(sh("curl -s -m 20 -X POST '%s/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts' "
             "-H 'Authorization: Bearer %s' -H 'Content-Type: application/json' "
             "-d '{\"name_filter\":\"\"}' | head -c 1500" % (ru, rt)))
    print("\n-- legacy _apis/artifactcache/artifacts:")
    print(sh("curl -s -m 20 -X GET '%s/_apis/artifactcache/artifacts?api-version=6.0-preview' "
             "-H 'Authorization: Bearer %s' | head -c 1200" % (ru, rt)))

print("\n" + "=" * 70)
print("### C. GITHUB_TOKEN: exact scope of the default Actions token")
print("=" * 70)
print(sh("curl -s -H 'Authorization: token $GITHUB_TOKEN' https://api.github.com/rate_limit "
         "| head -c 400"))
print("\n-- token identity:")
print(sh("curl -s -H 'Authorization: token $GITHUB_TOKEN' https://api.github.com/user "
         "| head -c 300"))
print("\n-- can it read OTHER repos owned by the same user?")
for repo in ("austindanson1/ghb-u6-pages", "austindanson1/ghb-u6-private",
             "austindanson1/codex-rainbow", "actions/checkout"):
    code = sh("curl -s -o /dev/null -w '%%{http_code}' -H 'Authorization: token $GITHUB_TOKEN' "
              "https://api.github.com/repos/%s" % repo)
    print("   %-32s -> %s" % (repo, code))

print("\n" + "=" * 70)
print("### D. OIDC ID TOKEN (id-token: write) CLAIMS")
print("=" * 70)
url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
utok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
print("request_url=%s" % url)
print("request_token len=%d" % len(utok))
if url:
    body = sh("curl -s -m 20 '%s&audience=github-pages' -H 'Authorization: Bearer %s'" % (url, utok))
    print("resp head: %s" % body[:120])
    try:
        idt = json.loads(body).get("value", "")
        print("ID token len=%d" % len(idt))
        print("ID token claims:", json.dumps(jwt(idt), indent=1))
    except Exception as e:  # noqa: BLE001
        print("parse err", e)

print("\n" + "=" * 70)
print("### E. /tmp/probe-out.txt present? (artifact staging dir)")
print("=" * 70)
print(sh("ls -la /tmp 2>&1 | head -20"))
print(sh("ls -la $RUNNER_TEMP 2>&1 | head -20"))
print(sh("ls -la $RUNNER_TEMP/artifacts 2>&1 | head -20"))
