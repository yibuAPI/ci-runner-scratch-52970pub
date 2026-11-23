#!/usr/bin/env python3
"""i70914: raw-dial target 51.79.66.166 from GitHub-hosted Actions runner NATIVE egress.
No proxy. Native socket. Controls included. Sequential, slow, few connections."""
import socket, time, sys, json, urllib.request

def egress():
    info = {}
    try:
        info['ipify'] = urllib.request.urlopen("https://api.ipify.org", timeout=15).read().decode().strip()
    except Exception as e:
        info['ipify'] = "FAIL:%s" % str(e)[:80]
    try:
        j = json.loads(urllib.request.urlopen("https://ipinfo.io/json", timeout=15).read().decode())
        info['org'] = j.get('org'); info['city'] = j.get('city'); info['country'] = j.get('country')
    except Exception as e:
        info['org'] = "FAIL:%s" % str(e)[:80]
    return info

def tcp(host, port, timeout=9):
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    st = '?'; info = ''; banner = ''
    try:
        s.connect((host, port))
        st = 'OPEN'
        # try to read a banner (SSH etc) briefly
        try:
            s.settimeout(3.0)
            b = s.recv(160)
            if b:
                banner = b.decode('utf-8', 'replace').replace('\r', ' ').replace('\n', ' ').strip()[:120]
        except Exception:
            pass
    except ConnectionRefusedError:
        st = 'REFUSED'; info = 'connection refused'
    except socket.timeout:
        st = 'TIMEOUT'; info = 'syn-drop/timeout'
    except Exception as e:
        st = 'ERR'; info = '%s:%s' % (type(e).__name__, str(e)[:60])
    finally:
        try: s.close()
        except Exception: pass
    dt = round(time.time() - t0, 2)
    return st, info, banner, dt

def http(url, timeout=12):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.5.0"})
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.getcode(), r.read(1000)
    except urllib.error.HTTPError as e:
        try: body = e.read(600)
        except Exception: body = b''
        return e.code, body
    except Exception as e:
        return None, str(e)[:120].encode()

TARGET = "51.79.66.166"
probes = [
    (TARGET, 3000, "target:3000"),
    (TARGET, 8787, "target:8787"),
    (TARGET, 10051, "target:10051"),
    (TARGET, 22, "target:22"),
    # controls (known OPEN expected)
    ("51.79.66.1", 22, "CTRL 51.79.66.1:22"),
    ("51.79.66.1", 80, "CTRL 51.79.66.1:80"),
    ("8.8.8.8", 443, "CTRL 8.8.8.8:443"),
    ("40.160.21.1", 3000, "CTRL 40.160.21.1:3000"),
    # a definitely-closed control for sanity
    ("127.0.0.1", 1, "CTRL 127.0.0.1:1"),
]

print("===== i70914 runner egress =====", flush=True)
eg = egress()
print("EGRESS", json.dumps(eg), flush=True)

results = {}
for h, p, n in probes:
    st, info, banner, dt = tcp(h, p)
    results[n] = st
    line = "TCP %s:%d [%s] -> %s (%s) t=%ss" % (h, p, n, st, info, dt)
    if banner:
        line += " banner=%r" % banner
    print(line, flush=True)
    time.sleep(1.0)

# If target:3000 open, fetch /api/status
if results.get("target:3000") == 'OPEN':
    for path in ['/api/status', '/']:
        code, body = http("http://%s:3000%s" % (TARGET, path))
        print("HTTP %s:3000%s -> code=%s body[:400]=%r" % (TARGET, path, code, body[:400]), flush=True)

print("SUMMARY", json.dumps(results), flush=True)
print("===== DONE i70914 =====", flush=True)
