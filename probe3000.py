#!/usr/bin/env python3
"""Probe haochi OVH host 40.160.69.132 :3000 (asset#44709) from a given vantage.
Mode: direct (no proxy) or via env PROXY (socks5h/http).
Read-only: TCP connects + a few GETs with benign paths.
"""
import os, socket, ssl, sys, time, json

TARGET = "40.160.69.132"
PORTS = [22, 80, 443, 3000, 3001, 3100, 4000, 4100, 8080, 8000, 3306]
PROXY = os.environ.get("PROXY", "").strip()
LABEL = os.environ.get("LABEL", "direct")

def egress():
    try:
        import urllib.request
        req = urllib.request.Request("https://api.ipify.org")
        if PROXY:
            op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
            return op.open(req, timeout=20).read().decode().strip()
        return urllib.request.urlopen(req, timeout=15).read().decode().strip()
    except Exception as e:
        return "EGRESS_FAIL:%s" % str(e)[:60]

def tcp_connect(host, port, timeout=10):
    t0 = time.time()
    try:
        if PROXY:
            from urllib.parse import urlparse
            u = urlparse(PROXY)
            ph = u.hostname; pp = u.port or 1080
            if u.scheme.startswith("http"):
                s = socket.create_connection((ph, pp), timeout=timeout)
                s.settimeout(timeout)
                s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port)).encode())
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = s.recv(256)
                    if not d: break
                    buf += d
                line = buf.split(b"\r\n")[0]
                ok = b" 200 " in line
                s.close()
                return ("OPEN" if ok else "PROXYREFUSED"), line.decode(errors="replace")[:60], round(time.time()-t0, 2)
            else:  # socks5
                s = socket.create_connection((ph, pp), timeout=timeout)
                s.settimeout(timeout)
                s.sendall(b"\x05\x01\x00")
                if s.recv(2) != b"\x05\x00":
                    s.close(); return "SOCKSFAIL", "auth", round(time.time()-t0, 2)
                ip = socket.inet_aton(host)
                s.sendall(b"\x05\x01\x00\x01" + ip + port.to_bytes(2, "big"))
                r = s.recv(10)
                if len(r) >= 2 and r[1] == 0:
                    s.close(); return "OPEN", "socks ok", round(time.time()-t0, 2)
                s.close(); return "SOCKSREFUSED", "rep=%s" % (r[1] if len(r) > 1 else "?"), round(time.time()-t0, 2)
        s = socket.create_connection((host, port), timeout=timeout)
        try:
            s.settimeout(3); s.send(b"\r\n"); banner = s.recv(120)
        except Exception:
            banner = b""
        s.close()
        return "OPEN", banner.decode(errors="replace").replace("\r", " ").replace("\n", " ")[:80], round(time.time()-t0, 2)
    except ConnectionRefusedError:
        return "REFUSED", "connection refused", round(time.time()-t0, 2)
    except socket.timeout:
        return "TIMEOUT", "timeout", round(time.time()-t0, 2)
    except Exception as e:
        return "ERR", "%s:%s" % (type(e).__name__, str(e)[:50]), round(time.time()-t0, 2)

def http_get(url, host_header=None, timeout=20):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
    if host_header:
        req.add_header("Host", host_header)
    try:
        if PROXY:
            op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
            r = op.open(req, timeout=timeout)
        else:
            r = urllib.request.urlopen(req, timeout=timeout)
        code = r.getcode(); body = r.read(1500)
        return code, r.headers.get("Content-Type", ""), body
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read(800)
    except Exception as e:
        return None, type(e).__name__, str(e)[:120].encode()

print("===== VANTAGE %s proxy=%r egress=%s =====" % (LABEL, PROXY, egress()))
for p in PORTS:
    st, info, dt = tcp_connect(TARGET, p)
    print("TCP %s:%d -> %s (%s) t=%ss" % (TARGET, p, st, info, dt))
    sys.stdout.flush()

for path in ["/api/status", "/", "/api/setup"]:
    code, ct, body = http_get("http://%s:3000%s" % (TARGET, path), timeout=15)
    print("HTTP :3000%s -> code=%s ct=%s body[:400]=%r" % (path, code, ct, body[:400]))
    sys.stdout.flush()
    code, ct, body = http_get("http://%s:3000%s" % (TARGET, path), host_header="haochi.yibuapi.com", timeout=15)
    print("HTTP :3000%s (Host=haochi.yibuapi.com) -> code=%s ct=%s body[:400]=%r" % (path, code, ct, body[:400]))
    sys.stdout.flush()
print("===== DONE %s =====" % LABEL)
