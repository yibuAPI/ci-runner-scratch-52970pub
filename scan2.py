#!/usr/bin/env python3
"""Robust WARP port map pass 2: low-concurrency full sweep + control probes + re-verification."""
import os, socket, json, time, concurrent.futures, threading
from collections import Counter
import socks

TARGET = os.environ.get("TARGET", "135.148.204.37")
PHP, PPP = "127.0.0.1", 40000
OUT = "results_scan2.json"

def mk(timeout):
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.set_proxy(socks.SOCKS5, PHP, PPP, rdns=True)
    s.settimeout(timeout)
    return s

def classify(e):
    name = type(e).__name__; msg = str(e); low = msg.lower()
    if isinstance(e, socket.timeout):
        return "timeout"
    if name.startswith("SOCKS5"):
        if "not allowed by ruleset" in low: return "policy_blocked"
        if "connection refused" in low: return "refused"
        if "network unreachable" in low or "host unreachable" in low: return "unreachable"
        return "socks_other:" + msg[:60]
    if "refused" in low: return "refused"
    if "unreachable" in low: return "unreachable"
    return "other:" + msg[:60]

def probe(host, port, timeout=8.0):
    t0 = time.time(); s = None
    try:
        s = mk(timeout); s.connect((host, port))
        return {"host": host, "port": port, "state": "open", "detail": "", "ms": int((time.time()-t0)*1000)}
    except Exception as e:
        return {"host": host, "port": port, "state": classify(e), "detail": f"{type(e).__name__}: {e}"[:120],
                "ms": int((time.time()-t0)*1000)}
    finally:
        if s:
            try: s.close()
            except Exception: pass

def sweep_ports(ports, threads, timeout, tag):
    res = []; lock = threading.Lock(); done = [0]; t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(probe, TARGET, p, timeout) for p in ports]
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            with lock:
                res.append(r); done[0] += 1
                if done[0] % 8000 == 0:
                    print(f"[{tag}] {done[0]}/{len(ports)} {int(time.time()-t0)}s open={sum(1 for x in res if x['state']=='open')}", flush=True)
    res.sort(key=lambda x: x["port"])
    print(f"[{tag}] DONE {len(res)} in {int(time.time()-t0)}s {dict(Counter(x['state'] for x in res))}", flush=True)
    return res

def main():
    out = {"target": TARGET, "stage": "pass2"}

    # ---- controls: calibrate what WARP SOCKS5 replies mean ----
    controls = [("github.com", 22), ("github.com", 443), ("1.1.1.1", 443), ("1.1.1.1", 22),
                ("1.1.1.1", 3306), ("scanme.nmap.org", 22), ("example.com", 443),
                (TARGET, 80), (TARGET, 3100), (TARGET, 22), (TARGET, 3306)]
    ctl = []
    for h, p in controls:
        runs = [probe(h, p, 9.0) for _ in range(3)]
        ctl.append({"host": h, "port": p, "runs": [{"state": r["state"], "ms": r["ms"], "detail": r["detail"][:70]} for r in runs]})
        print("CTL", json.dumps(ctl[-1])[:300], flush=True)
    out["controls"] = ctl

    # ---- full sweep, modest concurrency ----
    ports = list(range(1, 65536))
    a = sweep_ports(ports, 64, 8.0, "full2")
    out["full"] = a
    summ = dict(Counter(x["state"] for x in a))
    out["summary"] = summ
    open1 = [x["port"] for x in a if x["state"] == "open"]
    nonref = [x["port"] for x in a if x["state"] not in ("refused", "open")]
    out["open"] = open1
    out["nonrefused"] = nonref
    print("OPEN:", open1, flush=True)
    print("NONREFUSED_COUNT:", len(nonref), "first100:", nonref[:100], flush=True)

    # ---- verify every non-refused port 3x + a random refused sample (false-RST control) ----
    import random
    random.seed(7)
    refused = [x["port"] for x in a if x["state"] == "refused"]
    sample_refused = random.sample(refused, min(150, len(refused)))
    verify = []
    for p in sorted(set(nonref + [80, 3100])):
        runs = [probe(TARGET, p, 9.0) for _ in range(3)]
        verify.append({"port": p, "runs": [{"state": r["state"], "ms": r["ms"]} for r in runs],
                       "open_any": any(r["state"] == "open" for r in runs)})
        if any(r["state"] == "open" for r in runs):
            print("VERIFY_OPEN", p, [r["state"] for r in runs], flush=True)
    out["verify_nonrefused"] = verify
    out["verify_open_ports"] = [v["port"] for v in verify if v["open_any"]]

    rs = []
    for p in sample_refused:
        runs = [probe(TARGET, p, 9.0) for _ in range(2)]
        rs.append({"port": p, "states": [r["state"] for r in runs]})
    out["refused_sample"] = rs
    spurious = [r["port"] for r in rs if any(s != "refused" for s in r["states"])]
    out["refused_sample_spurious_rate"] = f"{len(spurious)}/{len(rs)}"
    out["refused_sample_spurious_ports"] = spurious[:50]
    print("REFUSED_SAMPLE spurious:", out["refused_sample_spurious_rate"], spurious[:30], flush=True)

    out["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    json.dump(out, open(OUT, "w"), indent=1)
    print("PASS2 DONE", flush=True)

if __name__ == "__main__":
    main()