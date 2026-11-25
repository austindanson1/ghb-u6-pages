"""U6 probe 14: WRITE marker only. Paired with probe15 which READS in the next run."""
import json, subprocess
P = "/opt/hca/.settings"
def sh(c):
    r = subprocess.run(c, shell=True, capture_output=True, text=True); return (r.stdout+r.stderr).strip()
print("hostname:", sh("hostname"))
print("file mtime before:", sh(f"stat -c '%y' {P}"))
cfg = json.load(open(P))
print("had marker before:", "u6Persist" in cfg)
cfg["u6Persist"] = "from-run-" + sh("echo $GITHUB_RUN_ID")
with open(P, "w") as f:
    json.dump(cfg, f)
back = json.load(open(P))
print("WROTE u6Persist =", back.get("u6Persist"))
print("file mtime after :", sh(f"stat -c '%y' {P}"))
