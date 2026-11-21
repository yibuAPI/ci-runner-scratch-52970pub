#!/usr/bin/env python3
"""Runtime proxy scan (runs on the GHA runner).
Select upstreams that can reach the target New API AND Cloudflare Turnstile, preferring
non-datacenter (residential/mobile) egress IPs. Writes best.json:
  {"best": ["socks5://x:y", ...], "hits": [...], "phase2": [...]}
"""
import json, re, socket, struct, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET_H, TARGET_P = "135.148.204.37", 80
TARGET_REQ = (b"GET /api/status HTTP/1.0\r\nHost: 135.148.204.37\r\nUser-Agent: Mozilla/5.0\r\n"
              b"Connection: close\r\n\r\n")
EGRESS_REQ = b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\nUser-Agent: s\r\nConnection: close\r\n\r\n"


def read_all(s, limit=5000, timeout=8):
    s.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < limit:
            d = s.recv(4096)
            if not d:
                break
            buf += d
            if b"\r\n\r\n" in buf and len(buf) > 300:
                break
    except Exception:
        pass
    return buf


def socks5_conn(proxy, host, port, timeout=8):
    h, p = proxy
    s = socket.create_connection((h, p), timeout=timeout); s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close(); return None
    hb = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
    r = s.recv(10)
    if len(r) < 2 or r[1] != 0:
        s.close(); return None
    return s


def try_socks(proxy):
    try:
        s = socks5_conn(proxy, TARGET_H, TARGET_P)
        if not s: return None
        s.sendall(TARGET_REQ)
        d = read_all(s)
        s.close()
        if b" 200 " in d.split(b"\r\n", 1)[0] and b"turnstile_site_key" in d or b"system_name" in d and b" 200 " in d.split(b"\r\n",1)[0]:
            eg = None
            try:
                s2 = socks5_conn(proxy, "api.ipify.org", 80)
                if s2:
                    s2.sendall(EGRESS_REQ)
                    b = read_all(s2, 400, 6).split(b"\r\n\r\n", 1)[-1].strip()
                    s2.close()
                    if re.match(rb"^\d{1,3}(\.\d{1,3}){3}$", b): eg = b.decode()
            except Exception:
                pass
            return {"proto": "socks5", "proxy": "%s:%d" % proxy, "egress": eg}
    except Exception:
        return None
    return None


def try_http(proxy):
    try:
        h, p = proxy
        s = socket.create_connection((h, p), timeout=8); s.settimeout(8)
        s.sendall(b"GET http://135.148.204.37/api/status HTTP/1.0\r\nHost: 135.148.204.37\r\n"
                  b"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        d = read_all(s)
        s.close()
        if not (b" 200 " in d.split(b"\r\n", 1)[0] and (b"turnstile_site_key" in d or b"system_name" in d)):
            return None
        eg = None
        try:
            s2 = socket.create_connection((h, p), timeout=8)
            s2.sendall(b"GET http://api.ipify.org/ HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
            b = read_all(s2, 400, 6).split(b"\r\n\r\n", 1)[-1].strip()
            s2.close()
            if re.match(rb"^\d{1,3}(\.\d{1,3}){3}$", b): eg = b.decode()
        except Exception:
            pass
        return {"proto": "http", "proxy": "%s:%d" % (h, p), "egress": eg}
    except Exception:
        return None


def worker(proxy):
    r = try_socks(proxy)
    if r: return r
    return try_http(proxy)


def proxy_conn(hit, host, port, timeout=12):
    h, p = hit["proxy"].split(":")
    if hit["proto"] == "socks5":
        s = socks5_conn((h, int(p)), host, port, timeout)
        if not s: raise RuntimeError("socks5 fail")
        return s
    s = socket.create_connection((h, int(p)), timeout=timeout); s.settimeout(timeout)
    s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n" % (host, port, host)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(256)
        if not d: raise RuntimeError("closed")
        buf += d
    if b" 200" not in buf.split(b"\r\n")[0]:
        raise RuntimeError(buf.split(b"\r\n")[0][:40])
    return s


def tls_ok(hit, host, path="/cdn-cgi/challenge-platform/"):
    """Test CONNECT+TLS 443 through the proxy (what the browser needs)."""
    import ssl
    try:
        s = proxy_conn(hit, host, 443)
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        t0 = time.time()
        ss = ctx.wrap_socket(s, server_hostname=host)
        ss.sendall(("GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, host)).encode())
        d = ss.recv(200); ss.close()
        return {"ok": True, "t": round(time.time() - t0, 2), "line": d.split(b"\r\n", 1)[0].decode("latin1", "replace")}
    except Exception as e:
        return {"ok": False, "err": str(e)[:70]}


def plain_ok(hit, host, port=80):
    try:
        s = proxy_conn(hit, host, port)
        t0 = time.time()
        s.sendall(b"GET /api/status HTTP/1.0\r\nHost: 135.148.204.37\r\nConnection: close\r\n\r\n")
        d = read_all(s, 800, 10); s.close()
        return {"ok": b" 200 " in d.split(b"\r\n", 1)[0], "t": round(time.time() - t0, 2)}
    except Exception as e:
        return {"ok": False, "err": str(e)[:70]}


def main():
    srcs = sys.argv[1:] or ["proxies.txt"]
    if srcs == ["proxies.txt"]:
        pass
    proxies, seen = [], set()
    for si, src in enumerate(srcs):
        try:
            lines = open(src).read().splitlines()
        except Exception as e:
            print("skip src", src, e, flush=True)
            continue
        added = 0
        for line in lines:
            m = re.match(r"^\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)
            if not m:
                continue
            key = (m.group(1), int(m.group(2)))
            if key in seen:
                continue
            if si > 0 and added >= 500:
                break
            seen.add(key); proxies.append(key); added += 1
    print("candidates", len(proxies), flush=True)
    hits = []
    with ThreadPoolExecutor(max_workers=150) as ex:
        futs = [ex.submit(worker, p) for p in proxies]
        done = 0
        for f in as_completed(futs):
            done += 1
            try: r = f.result()
            except Exception: r = None
            if r:
                hits.append(r); print("HIT", json.dumps(r), flush=True)
            if done % 150 == 0: print("progress", done, "hits", len(hits), flush=True)
    print("phase1 hits", len(hits), flush=True)

    # ASN classify egress IPs
    info = {}
    egs = sorted({h["egress"] for h in hits if h.get("egress")})
    if egs:
        try:
            req = urllib.request.Request("http://ip-api.com/batch?fields=query,country,isp,as,hosting,proxy,mobile",
                                         data=json.dumps(egs).encode(), headers={"Content-Type": "application/json"})
            for x in json.loads(urllib.request.urlopen(req, timeout=30).read()):
                info[x["query"]] = x
        except Exception as e:
            print("ip-api err", e, flush=True)
    for h in hits:
        i = info.get(h.get("egress") or "", {})
        h["hosting"] = i.get("hosting")
        h["isp"] = i.get("isp")
        h["asn"] = i.get("as")

    # phase2: TLS both hosts through top candidates (prefer non-hosting)
    ranked = sorted(hits, key=lambda h: (1 if h.get("hosting") is False else 0), reverse=True)
    phase2 = []
    top = ranked[:14]
    with ThreadPoolExecutor(max_workers=7) as ex:
        futs = {ex.submit(lambda h=h: (h, tls_ok(h, "challenges.cloudflare.com"), plain_ok(h, "135.148.204.37"))): h
                for h in top}
        for f in as_completed(futs):
            try:
                h, a, b = f.result()
            except Exception:
                continue
            h2 = dict(h); h2["tls_cf"] = a; h2["tls_target"] = b
            phase2.append(h2)
            print("PHASE2", h["proto"], h["proxy"], "egress", h.get("egress"), "hosting", h.get("hosting"),
                  "cf", a.get("ok"), a.get("t", a.get("err")), "tgt", b.get("ok"), b.get("t", b.get("err")), flush=True)

    usable = [h for h in phase2 if h["tls_cf"].get("ok") and h["tls_target"].get("ok")]
    usable.sort(key=lambda h: (0 if h.get("hosting") is False else 1, (h["tls_cf"].get("t") or 99) + (h["tls_target"].get("t") or 99)))
    best = ["%s://%s" % (h["proto"], h["proxy"]) for h in usable[:6]]
    print("BEST", best, flush=True)
    json.dump({"best": best, "usable": usable, "hits": hits, "info": info}, open("best.json", "w"), indent=1)


if __name__ == "__main__":
    main()