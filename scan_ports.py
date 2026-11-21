#!/usr/bin/env python3
"""Full TCP port / service mapping for TARGET through the Cloudflare WARP SOCKS5 proxy
(and a direct-egress comparison pass), to find a non-Web channel on the target."""
import os, sys, json, socket, time, random, concurrent.futures, threading

import socks

TARGET = os.environ.get("TARGET", "135.148.204.37")
PHP = os.environ.get("PX_HOST", "127.0.0.1")
PPP = int(os.environ.get("PX_PORT", "40000"))
TIMEOUT = float(os.environ.get("TO", "4"))
THREADS = int(os.environ.get("TH", "256"))
FULL = os.environ.get("FULL", "1") == "1"
OUT = os.environ.get("OUT", "results_scan.json")

# ports worth a hard look even in the fast list
KEY_PORTS = [21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587,
             636, 873, 993, 995, 1080, 1099, 1433, 1521, 2049, 2082, 2083, 2086, 2087,
             2121, 2181, 2222, 2375, 2376, 2377, 2379, 3000, 3001, 3100, 3128, 3306,
             3389, 3690, 4000, 4369, 4444, 5000, 5432, 5601, 5672, 5900, 5984, 5985,
             5986, 6000, 6379, 6443, 7001, 7077, 8000, 8008, 8010, 8080, 8081, 8086,
             8088, 8090, 8091, 8161, 8443, 8880, 8888, 8983, 9000, 9001, 9042, 9090,
             9091, 9100, 9113, 9200, 9300, 9418, 9443, 10000, 10250, 10255, 11211,
             15672, 16379, 27017, 28017, 50000, 50070, 61616, 6380, 25565, 18080,
             18081, 20000, 31000, 32768]

USE_PROXY = os.environ.get("USE_PROXY", "1") == "1"

def mk(kind, timeout):
    if kind == "proxy" and USE_PROXY:
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, PHP, PPP, rdns=True)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    return s

def classify(e):
    name = type(e).__name__
    msg = str(e)
    low = msg.lower()
    if isinstance(e, socket.timeout):
        return "timeout", name + ": timed out"
    if name.startswith("SOCKS5"):
        if "not allowed by ruleset" in low:
            return "policy_blocked", name + ": " + msg
        if "connection refused" in low:
            return "refused", name + ": " + msg
        if "network unreachable" in low or "host unreachable" in low:
            return "unreachable", name + ": " + msg
        return "socks_other", name + ": " + msg
    if "refused" in low:
        return "refused", name + ": " + msg
    if "unreachable" in low:
        return "unreachable", name + ": " + msg
    return "other", name + ": " + msg

def probe(kind, port, timeout=None):
    timeout = timeout or TIMEOUT
    t0 = time.time()
    s = None
    try:
        s = mk(kind, timeout)
        s.connect((TARGET, port))
        return {"port": port, "state": "open", "detail": "", "ms": int((time.time()-t0)*1000)}
    except Exception as e:
        st, det = classify(e)
        return {"port": port, "state": st, "detail": det, "ms": int((time.time()-t0)*1000)}
    finally:
        if s:
            try: s.close()
            except Exception: pass

def sweep(kind, ports, threads, timeout, tag):
    res = []
    lock = threading.Lock()
    done = [0]
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe, kind, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            with lock:
                res.append(r); done[0] += 1
                if done[0] % 5000 == 0:
                    print(f"[{tag}] {done[0]}/{len(ports)} elapsed={int(time.time()-t0)}s open={sum(1 for x in res if x['state']=='open')}", flush=True)
    res.sort(key=lambda x: x["port"])
    print(f"[{tag}] DONE {len(res)} ports in {int(time.time()-t0)}s", flush=True)
    return res

def summarize(res):
    from collections import Counter
    c = Counter(x["state"] for x in res)
    return dict(c)

def main():
    out = {"target": TARGET, "proxy": f"{PHP}:{PPP}", "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # sanity: proxy works at all for raw TCP
    sanity = {
        "cf_1.1.1.1:443(proxy)": str(probe_via("proxy", "1.1.1.1", 443)),
        "target:80": probe("proxy", 80).get("state"),
        "target:3100": probe("proxy", 3100).get("state"),
    }
    out["use_proxy"] = USE_PROXY
    out["sanity"] = sanity
    print("SANITY", json.dumps(sanity), flush=True)

    # behaviour sample on presumably closed ports
    sample_ports = [random.randint(20000, 60000) for _ in range(12)]
    sample = [probe("proxy", p) for p in sample_ports]
    out["closed_sample"] = sample
    out["closed_sample_summary"] = summarize(sample)
    print("CLOSED_SAMPLE states:", summarize(sample), flush=True)

    # Phase A: key ports, detailed classification, proxy + direct
    print("=== PHASE A key ports (proxy) ===", flush=True)
    a_proxy = sweep("proxy", KEY_PORTS, min(32, THREADS), 6.0, "keyproxy")
    print("=== PHASE A key ports (direct, comparison) ===", flush=True)
    a_direct = sweep("direct", KEY_PORTS, min(32, THREADS), 5.0, "keydirect")
    out["key_ports_proxy"] = a_proxy
    out["key_ports_direct"] = a_direct
    out["key_ports_summary_proxy"] = summarize(a_proxy)
    out["key_ports_summary_direct"] = summarize(a_direct)
    opens = [r["port"] for r in a_proxy if r["state"] == "open"]
    out["open_key_ports"] = opens
    print("OPEN_KEY_PORTS", opens, flush=True)
    print("NON_TIMEOUT_KEY_PORTS", [(r["port"], r["state"]) for r in a_proxy if r["state"] != "timeout" and r["state"] != "open"], flush=True)

    # Phase B: full range through proxy (adaptive thread/timeout)
    if FULL:
        states = summarize(sample)
        fast = states.get("refused", 0) + states.get("policy_blocked", 0) + states.get("unreachable", 0) + states.get("socks_other", 0)
        if fast >= len(sample) * 0.7:
            th, to = 384, 3.0
        else:
            th, to = 700, 2.5
        print(f"=== PHASE B full 1-65535 via proxy threads={th} timeout={to} ===", flush=True)
        allp = list(range(1, 65536))
        b = sweep("proxy", allp, th, to, "full")
        out["full_proxy"] = b
        out["full_proxy_summary"] = summarize(b)
        out["full_open"] = [r["port"] for r in b if r["state"] == "open"]
        # ports whose errors are not timeout/refused are interesting too
        out["full_non_timeout_nonopen"] = [(r["port"], r["state"], r["detail"][:80]) for r in b
                                           if r["state"] not in ("open", "timeout")]
        print("FULL_OPEN", out["full_open"], flush=True)
        print("FULL_NON_TIMEOUT_NONOPEN", out["full_non_timeout_nonopen"][:200], flush=True)

    out["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with open(OUT, "w") as f:
        json.dump(out, f, indent=1)

def probe_via(kind, host, port):
    s = None
    try:
        if kind == "proxy" and USE_PROXY:
            s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            s.set_proxy(socks.SOCKS5, PHP, PPP, rdns=True)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((host, port))
        return "ok"
    except Exception as e:
        return f"{type(e).__name__}:{e}"
    finally:
        if s:
            try: s.close()
            except Exception: pass

if __name__ == "__main__":
    main()