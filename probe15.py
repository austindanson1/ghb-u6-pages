"""U6 probe 15: READ the marker left by the previous run, if the VM is reused."""
import json, subprocess
P = "/opt/hca/.settings"
def sh(c):
    r = subprocess.run(c, shell=True, capture_output=True, text=True); return (r.stdout+r.stderr).strip()
print("hostname:", sh("hostname"))
print("SAME HOST AS PREV run:", sh("hostname") == "runnervm0hi8g")
print("file mtime:", sh(f"stat -c '%y' {P}"))
cfg = json.load(open(P))
print("keys:", list(cfg.keys()))
print("u6Persist PRESENT:", "u6Persist" in cfg, "->", cfg.get("u6Persist"))
