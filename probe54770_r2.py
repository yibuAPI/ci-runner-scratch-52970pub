#!/usr/bin/env python3
# i54770 round2: diagnose WARP proxy reachability (port policy vs target drop) and
# re-test operator infra with explicit SOCKS error details + curl-based HTTP probes.
import os, json, socket, time, subprocess, ssl, sys, struct
import socks
import requests
requests.packages.urllib3.disable_warnings()
PROXY = '127.0.0.1'
PPORT = 40000
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36'
OUT = {}

CONTROLS = [
    ('ctrl-37-80', '135.148.204.37', 80),
    ('ctrl-37-3100', '135.148.204.37', 3100),
    ('ctrl-80-3000', '40.160.50.80', 3000),
    ('ctrl-211-22', '40.160.21.1', 22),
    ('ctrl-211-3306', '40.160.21.1', 3306),
    ('ctrl-776-8090', '40.160.7.76', 8090),
    ('ctrl-cf-443', '1.1.1.1', 443),
    ('ctrl-cf-warp-80', '104.28.210.137', 80),
]
TARGETS = [
    ('A', '51.222.15.95', [8080, 21, 22, 3001, 80, 443]),
    ('B', '54.36.150.244', [8080, 3000, 80, 443, 22]),
    ('C', '51.79.66.166', [8787, 3000, 443, 10051, 80, 22]),
]


def log(*a):
    print(*a, flush=True)


def tcp(ip, port, mode='proxy', t=8):
    s = None; st = time.time()
    try:
        if mode == 'proxy':
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, PROXY, PPORT, rdns=True)
        else:
            s = socket.socket()
        s.settimeout(t)
        s.connect((ip, port))
        out = {'state': 'open', 'ms': int((time.time() - st) * 1000)}
        if port in (21, 22):
            try:
                s.settimeout(3); out['banner'] = s.recv(256).decode('utf-8', 'replace').strip()[:200]
            except Exception:
                pass
        return out
    except Exception as e:
        args = getattr(e, 'args', None)
        cls = type(e).__name__
        return {'state': 'fail', 'exc': cls, 'args': repr(args)[:300],
                'str': repr(e)[:200], 'ms': int((time.time() - st) * 1000)}
    finally:
        try:
            s.close()
        except Exception:
            pass


def curl_probe(ip, port, path='/', host=None, tls=False, mode='proxy', timeout=12):
    scheme = 'https' if tls else 'http'
    url = '%s://%s:%d%s' % (scheme, ip, port, path)
    cmd = ['curl', '-sS', '-i', '--max-time', str(timeout), '--connect-timeout', '8']
    if tls:
        cmd += ['-k']
    if mode == 'proxy':
        cmd += ['--socks5-hostname', '%s:%d' % (PROXY, PPORT)]
    else:
        cmd += ['--noproxy', '*']
    if host:
        cmd += ['-H', 'Host: %s' % host]
    cmd += ['-A', UA, url]
    st = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
        raw = (p.stdout + p.stderr).decode('utf-8', 'replace')
        return {'rc': p.returncode, 'ms': int((time.time() - st) * 1000),
                'out': raw[:1200]}
    except Exception as e:
        return {'error': repr(e)[:200]}


def main():
    OUT['stage'] = 'controls'
    OUT['controls'] = {}
    for name, ip, port in CONTROLS:
        r = {'proxy': tcp(ip, port), 'direct': tcp(ip, port, 'direct')}
        for mode in ['proxy', 'direct']:
            if r[mode].get('state') == 'open' and port in (80, 443, 3000, 3100):
                r[mode]['http'] = curl_probe(ip, port, '/', None, port == 443, mode)
        OUT['controls'][name] = r
        log('CTRL', name, json.dumps(r)[:600])
    json.dump(OUT, open('results54770_r2.json', 'w'), ensure_ascii=False, indent=1)

    OUT['targets'] = {}
    for tag, ip, ports in TARGETS:
        t = {'ip': ip, 'ports': {}}
        for port in ports:
            r = {'proxy': tcp(ip, port), 'direct': tcp(ip, port, 'direct')}
            for mode in ['proxy', 'direct']:
                if r[mode].get('state') == 'open' and port not in (21, 22, 10051):
                    r[mode]['http'] = curl_probe(ip, port, '/', None, port == 443, mode)
            t['ports'][port] = r
            log('TGT', tag, ip, port, json.dumps(r)[:700])
        # HTTP vhost checks over WARP for web ports regardless (definitive app-layer evidence)
        vhosts = {'A': ['yimo.yibuapi.com', ip], 'B': ['jenkins.yibuapi.com', 'gitlab.yibuapi.com',
                                                      'grafana.yibuapi.com', ip],
                  'C': ['yibuapi.com', ip]}[tag]
        t['vhost_http'] = []
        for port in [p for p in ports if p in (80, 443, 3000, 8080, 8787, 3001)]:
            for host in vhosts:
                for path in ['/', '/api/health', '/api/json', '/api/status']:
                    t['vhost_http'].append({'port': port, 'host': host, 'path': path,
                                            'r': curl_probe(ip, port, path, host, port == 443, 'proxy')})
        OUT['targets'][tag] = t
        json.dump(OUT, open('results54770_r2.json', 'w'), ensure_ascii=False, indent=1)
    log('=== R2 SUMMARY ===')
    log(json.dumps(OUT, ensure_ascii=False)[:16000])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        import traceback; traceback.print_exc()
        json.dump(OUT, open('results54770_r2.partial.json', 'w'), ensure_ascii=False, indent=1)
        sys.exit(3)