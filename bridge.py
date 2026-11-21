#!/usr/bin/env python3
"""
Local HTTP proxy bridge -> upstream SOCKS5/HTTP proxies (residential egress).
Why: Chrome's built-in SOCKS5 handling is fragile (and resolves names locally), and the
Turnstile challenge host brunhild.challenges.cloudflare.com is IPv6-only in DNS while our
residential upstreams may not have IPv6. This bridge:
  * speaks plain HTTP proxy to Chrome (rock solid),
  * honours a NAME_MAP so brunhild -> known Cloudflare IPv4 (SNI/Host untouched),
  * tunnels everything through the selected upstream proxy (ATYP=IPv4 for mapped names),
  * rotates upstreams on failure and logs each request.

Usage: UPSTREAMS="socks5://1.2.3.4:1080,http://5.6.7.8:8080" python3 bridge.py 8899
"""
import asyncio, os, sys, time, re

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
UPSTREAMS = [u.strip() for u in os.environ.get("UPSTREAMS", "").split(",") if u.strip()]
NAME_MAP = {
    "brunhild.challenges.cloudflare.com": ["104.18.16.146", "104.18.17.146"],
    "hagen.challenges.cloudflare.com": ["104.18.16.146", "104.18.17.146"],
}
STATS = {"conns": 0, "ok": 0, "fail": 0}
COOLDOWN = {}   # upstream -> until ts


def log(*a):
    print("[bridge]", *a, flush=True)


async def socks5_connect(up, host, port, use_ip, timeout=25):
    hp = up[len("socks5://"):].split(":")
    r, w = await asyncio.wait_for(asyncio.open_connection(hp[0], int(hp[1])), timeout)
    w.write(b"\x05\x01\x00"); await w.drain()
    hdr = await asyncio.wait_for(r.readexactly(2), timeout)
    if hdr != b"\x05\x00":
        raise RuntimeError("socks5 auth reject %r" % hdr)
    if use_ip:
        w.write(b"\x05\x01\x00\x01" + bytes(int(x) for x in host.split(".")) + port.to_bytes(2, "big"))
    else:
        hb = host.encode()
        w.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + port.to_bytes(2, "big"))
    await w.drain()
    rep = await asyncio.wait_for(r.readexactly(4), timeout)
    if rep[1] != 0:
        raise RuntimeError("socks5 connect rep=%d" % rep[1])
    atyp = rep[3]
    if atyp == 1:
        await r.readexactly(4 + 2)
    elif atyp == 3:
        n = (await r.readexactly(1))[0]; await r.readexactly(n + 2)
    else:
        await r.readexactly(16 + 2)
    return r, w


async def http_connect(up, host, port, use_ip, timeout=25):
    hp = up[len("http://"):].split(":")
    r, w = await asyncio.wait_for(asyncio.open_connection(hp[0], int(hp[1])), timeout)
    w.write(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
             % (host, port, host, port)).encode())
    await w.drain()
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = await asyncio.wait_for(r.read(512), timeout)
        if not d:
            raise RuntimeError("http connect closed")
        buf += d
    line = buf.split(b"\r\n")[0]
    if b" 200" not in line:
        raise RuntimeError("http connect: " + line.decode("latin1", "replace")[:80])
    return r, w


async def open_upstream(host, port):
    """Try upstreams in order; returns (reader, writer, name)."""
    now = time.time()
    cands = [u for u in UPSTREAMS if COOLDOWN.get(u, 0) < now] or UPSTREAMS
    last = None
    for up in cands:
        use_ip = False
        ip = None
        if host in NAME_MAP:
            ip = NAME_MAP[host][0]
            use_ip = True
        try:
            if up.startswith("socks5://"):
                r, w = await socks5_connect(up, ip or host, port, use_ip)
            else:
                r, w = await http_connect(up, ip or host, port, use_ip)
            return r, w, up
        except Exception as e:
            last = e
            COOLDOWN[up] = now + 90
            log("upstream FAIL", up, host, port, str(e)[:90])
    raise RuntimeError("all upstreams failed: %s" % last)


async def pipe(a_r, a_w):
    try:
        while True:
            d = await a_r.read(65536)
            if not d:
                break
            a_w.write(d); await a_w.drain()
    except Exception:
        pass
    finally:
        try: a_w.close()
        except Exception: pass


async def handle(cr, cw):
    STATS["conns"] += 1
    t0 = time.time()
    host = None
    try:
        head = b""
        while b"\r\n\r\n" not in head:
            d = await asyncio.wait_for(cr.read(4096), 30)
            if not d:
                cw.close(); return
            head += d
            if len(head) > 65536:
                break
        hdr, rest = head.split(b"\r\n\r\n", 1)
        lines = hdr.decode("latin1", "replace").split("\r\n")
        parts = lines[0].split(" ")
        method, target = parts[0], parts[1]
        if method.upper() == "CONNECT":
            host, port = target.rsplit(":", 1)
            port = int(port)
            ur, uw, up = await open_upstream(host, port)
            cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n"); await cw.drain()
            if rest:
                uw.write(rest); await uw.drain()
            STATS["ok"] += 1
            log("CONNECT", host, port, "via", up, "%.1fs" % (time.time() - t0))
            await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
        else:
            m = re.match(r"https?://([^/\s:]+)(?::(\d+))?(/.*)?$", target)
            if not m:
                cw.write(b"HTTP/1.1 400 Bad Request\r\n\r\n"); cw.close(); return
            host = m.group(1)
            port = int(m.group(2) or 80)
            path = m.group(3) or "/"
            # if plain http to mapped host, connect to IP but keep Host header
            ur, uw, up = await open_upstream(host, port)
            del lines[0]
            newhdr = ("%s %s HTTP/1.1" % (method, path)) + "\r\n" + "\r\n".join(lines) + "\r\n\r\n"
            uw.write(newhdr.encode("latin1") + rest); await uw.drain()
            STATS["ok"] += 1
            log(method, host, port, path[:40], "via", up, "%.1fs" % (time.time() - t0))
            await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
    except Exception as e:
        STATS["fail"] += 1
        log("ERR", host, str(e)[:120])
        try:
            cw.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); cw.close()
        except Exception:
            pass


async def main():
    log("listening on", LISTEN_PORT, "upstreams", UPSTREAMS)
    srv = await asyncio.start_server(handle, "127.0.0.1", LISTEN_PORT)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())