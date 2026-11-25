"""U6 probe 13: did probe 12's write SURVIVE into a new job? (VM reuse evidence)"""
import json, subprocess
P = "/opt/hca/.settings"
def sh(c): 
    r = subprocess.run(c, shell=True, capture_output=True, text=True); return (r.stdout+r.stderr).strip()
print("hostname:", sh("hostname"))
print("uid:", sh("id -u"))
cfg = json.load(open(P))
print("keys:", list(cfg.keys()))
print("u6WriteProbe present :", "u6WriteProbe" in cfg, "->", cfg.get("u6WriteProbe"))
print("schedulerApiUrl      :", cfg.get("schedulerApiUrl"))
print("REDIRECT SURVIVED    :", cfg.get("schedulerApiUrl") == "https://httpbin.org/anything")
print("mtime:", sh(f"ls -l --time-style=full-iso {P}"))
