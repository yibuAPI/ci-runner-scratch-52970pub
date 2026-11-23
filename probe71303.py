#!/usr/bin/env python3
# ci71303: probe 147.135.76.13 (:3306/:443/:80/:22) from GitHub-Azure runner egress (direct)
# and from Cloudflare WARP socks5 (127.0.0.1:40000). Controls prove probe path.
# STRICTLY connectivity + protocol greeting only. NO credentials, NO login.
import os, sys, json, socket, ssl, time, subprocess

TARGET = "147.135.76.13"
PROXY_HOST, PROXY_PORT = "127.0.0.1", 40000

TESTS = [
    ("t13-3306", TARGET, 3306),
    ("t13-443",  TARGET, 443),
    ("t13-80",   TARGET, 80),
    ("t13-22",   TARGET, 22),
    ("c37-80",   "135.148.204.37", 80),
    ("c37-3100", "135.148.204.37", 3100),
    ("c146-443", "40.160.14.146", 443),
    ("c5080-3000", "40.160.50.80", 3000),
    ("cal-211-3306", "40.160.21.1", 3306),   # known real MySQL 8.0.x calibrator
    ("c1111-443", "1.1.1.1", 443),
]

OUT = {"runner": {}, "results": {"direct": [], "warp": []}, "notes": []}

def log(*a):
    print(*a, flush=True)

def http_get(url, timeout=15, proxy=None):
    try:
        import requests
        px = {"http": proxy, "https": proxy} if proxy else None
        r = requests.get(url, timeout=timeout, proxies=px,
                         headers={"User-Agent": "ci71303"})
        return r.status_code, r.text.strip()[:400]
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"

def tcp_probe(name, host, port, use_socks, timeout=10):
    r = {"test": name, "host": host, "port": port, "via": "warp" if use_socks else "direct"}
    t0 = time.time()
    s = None
    try:
        if use_socks:
            import socks
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT, rdns=True)
            s.settimeout(timeout)
            s.connect((host, port))
        else:
            s = socket.create_connection((host, port), timeout=timeout)
        r["connect"] = "open"
        r["ms"] = int((time.time() - t0) * 1000)
        s.settimeout(8)
        if port == 3306:
            data = s.recv(512)
            r["greeting_len"] = len(data)
            r["greeting_hex"] = data[:80].hex()
            if len(data) > 5 and data[4] == 10:
                ver = data[5:].split(b"\x00")[0]
                r["mysql_version"] = ver.decode("latin1", "replace")
                r["real_mysql"] = True
            else:
                r["real_mysql"] = False
                r["banner_txt"] = data[:120].decode("latin1", "replace")
        elif port == 443:
            for sni in (None, "mimir.observability.core.ovh.us"):
                try:
                    s2 = (socks.socksocket() if use_socks else socket.socket())
                    if use_socks:
                        s2.set_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT, rdns=True)
                    s2.settimeout(timeout)
                    s2.connect((host, port))
                    ctx = ssl._create_unverified_context()
                    ss = ctx.wrap_socket(s2, server_hostname=sni)
                    der = ss.getpeercert(binary_form=True)
                    # parse CN/SAN without external deps
                    import hashlib
                    r["tls"] = str(ss.version())
                    r["cert_sha256"] = hashlib.sha256(der).hexdigest()
                    try:
                        import subprocess as sp
                        pem = ssl.DER_cert_to_PEM_cert(der)
                        p = sp.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-ext", "subjectAltName"],
                                   input=pem.encode(), capture_output=True, timeout=10)
                        r["cert_" + (sni or "nosni")] = p.stdout.decode()[:400]
                    except Exception as e2:
                        r["cert_parse_err"] = str(e2)
                    ss.close()
                except Exception as e2:
                    r["tls_sni_" + (sni or "none")] = f"{type(e2).__name__}: {e2}"
            s2 = None
        else:
            try:
                data = s.recv(256)
                r["banner_txt"] = data[:120].decode("latin1", "replace")
            except Exception as e2:
                r["post"] = f"{type(e2).__name__}: {e2}"
    except Exception as e:
        r["connect"] = f"{type(e).__name__}: {e}"
        r["ms"] = int((time.time() - t0) * 1000)
    finally:
        try:
            if s: s.close()
        except Exception:
            pass
    log(json.dumps(r))
    return r

def main():
    # runner identity
    st, ip = http_get("https://api.ipify.org")
    OUT["runner"]["egress_v4"] = ip if st == 200 else f"err:{st}"
    st, tr = http_get("https://www.cloudflare.com/cdn-cgi/trace", proxy=f"socks5h://{PROXY_HOST}:{PROXY_PORT}")
    OUT["runner"]["warp_trace"] = tr if st == 200 else f"err:{st} {tr}"
    log("RUNNER_EGRESS_IP=", OUT["runner"]["egress_v4"])
    log("WARP_TRACE=", OUT["runner"]["warp_trace"][:300])

    # listener check
    try:
        s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=3); s.close()
        OUT["runner"]["socks40000"] = "LISTEN"
    except Exception as e:
        OUT["runner"]["socks40000"] = f"down: {e}"
    log("SOCKS40000=", OUT["runner"]["socks40000"])

    # direct
    for name, host, port in TESTS:
        OUT["results"]["direct"].append(tcp_probe(name, host, port, False))
        time.sleep(0.7)
    # warp
    use_warp = OUT["runner"]["socks40000"] == "LISTEN"
    if use_warp:
        for name, host, port in TESTS:
            OUT["results"]["warp"].append(tcp_probe(name, host, port, True))
            time.sleep(0.7)

    os.makedirs("results71303", exist_ok=True)
    json.dump(OUT, open("results71303/results.json", "w"), indent=1)

    # summary
    def sm(rows):
        return {r["test"]: r["connect"] for r in rows}
    log("SUMMARY direct:", json.dumps(sm(OUT["results"]["direct"])))
    log("SUMMARY warp:", json.dumps(sm(OUT["results"]["warp"])))

    # exfil small summary to ntfy
    nt = os.environ.get("NTFY", "")
    if nt:
        msg = "ci71303 " + (OUT["runner"]["egress_v4"] or "") + "\n" \
              + "warp:" + str(OUT["runner"]["socks40000"]) + " " + OUT["runner"]["warp_trace"][:200] + "\n" \
              + "direct:" + json.dumps(sm(OUT["results"]["direct"])) + "\n" \
              + "warp:" + json.dumps(sm(OUT["results"]["warp"]))
        try:
            import requests
            requests.post("https://ntfy.sh/" + nt, data=msg.encode()[:3500], timeout=20)
        except Exception as e:
            log("ntfy err", e)

if __name__ == "__main__":
    main()