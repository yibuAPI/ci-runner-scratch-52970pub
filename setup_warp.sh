#!/usr/bin/env bash
# Install + register Cloudflare WARP on a GitHub-hosted Ubuntu runner.
# Goal: Cloudflare-native egress WITH IPv6, exposed as a local SOCKS5 proxy
# (WARP "proxy mode": 127.0.0.1:40000) so Chrome/Playwright can use it directly.
# Falls back to wgcf + wireguard (tun) if the official client cannot be installed.
set -uo pipefail
log(){ echo "[warp] $*"; }

APT="apt-get -o Dpkg::Options::=--force-confnew -y"

echo "===== runner identity ====="
id; uname -a; . /etc/os-release; echo "CODENAME=$VERSION_CODENAME"

install_client() {
  local cn
  for cn in jammy noble "$VERSION_CODENAME"; do
    [ -z "$cn" ] && continue
    log "trying cloudflare-warp repo codename=$cn"
    if curl -fsSL --max-time 30 https://pkg.cloudflareclient.com/pubkey.gpg \
        | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null; then
      echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $cn main" \
        > /etc/apt/sources.list.d/cloudflare-warp.list
      if $APT update -qq >/dev/null 2>&1; then
        if $APT install -y --no-install-recommends cloudflare-warp >/tmp/warp_apt.log 2>&1; then
          log "installed cloudflare-warp via apt (codename=$cn)"; return 0
        fi
      fi
    fi
  done
  # direct .deb from the repo index (no apt codename match needed)
  log "apt path failed; downloading .deb directly from package index"
  local idx="https://pkg.cloudflareclient.com/dists/jammy/main/binary-amd64/Packages"
  local fn
  fn=$(curl -fsSL --max-time 40 "$idx" | awk '/^Filename: /{f=$2} /^Package: cloudflare-warp$/{p=1} p&&/^Version: /{v=$2} p&&f{print f; exit}')
  [ -z "$fn" ] && return 1
  log "deb path=$fn"
  curl -fsSL --max-time 120 "https://pkg.cloudflareclient.com/$fn" -o /tmp/warp.deb || return 1
  $APT install -y /tmp/warp.deb >/tmp/warp_deb.log 2>&1 || $APT -f install -y >>/tmp/warp_deb.log 2>&1 || return 1
  command -v warp-cli >/dev/null && return 0
  return 1
}

start_svc() {
  systemctl enable --now warp-svc >/dev/null 2>&1 && log "warp-svc via systemd" && return 0
  log "systemd start failed; launching warp-svc manually"
  (nohup warp-svc --accept-tos >/var/log/warp-svc.log 2>&1 &) || true
  sleep 4
  pgrep -a warp-svc || true
}

cli(){ warp-cli --accept-tos "$@" 2>&1; }

register_connect() {
  local i
  for i in $(seq 1 25); do cli status >/dev/null 2>&1 && break; sleep 1; done
  cli status | head -3
  log "registration"
  cli registration new || cli register || { log "register failed"; return 1; }
  sleep 2
  cli mode proxy || cli set-mode proxy || true
  cli connect || true
  for i in $(seq 1 30); do
    local st; st=$(cli status)
    echo "  status[$i]: $st"
    echo "$st" | grep -qiE 'Connected|已连接' && break
    [ $i -eq 12 ] && { cli connect || true; }
    sleep 2
  done
  cli status
  for i in $(seq 1 20); do
    (echo >/dev/tcp/127.0.0.1/40000) >/dev/null 2>&1 && { log "socks5 127.0.0.1:40000 listening"; return 0; }
    sleep 1
  done
  log "40000 not listening"; return 1
}

verify_egress() {
  local px="$1"
  echo "----- WARP egress identity through $px -----"
  curl -s -m 30 -x "$px" https://www.cloudflare.com/cdn-cgi/trace 2>&1 | grep -E '^(ip|warp|loc|colo|http)=' || echo "trace FAILED"
  echo "--- ipv4 ---"; curl -s -m 20 -x "$px" https://api.ipify.org 2>&1; echo
  echo "--- ipv6 (AAAA-only host) ---"; curl -s -m 20 -x "$px" https://ipv6.icanhazip.com 2>&1; echo
  echo "--- target reachability ---"
  curl -s -m 25 -x "$px" -o /dev/null -w "target /api/status http=%{http_code} t=%{time_total}\n" http://135.148.204.37/api/status || echo "target FAILED"
  echo "--- challenges.cloudflare.com reachability ---"
  curl -s -m 25 -x "$px" -o /dev/null -w "turnstile api.js http=%{http_code} size=%{size_download}\n" "https://challenges.cloudflare.com/turnstile/v0/api.js" || echo "cf api.js FAILED"
  echo "--- brunhild (AAAA-only challenge host) over WARP ---"
  curl -s -m 25 -x "$px" -o /dev/null -w "brunhild http=%{http_code} (404/403 ok, 000=fail)\n" "https://brunhild.challenges.cloudflare.com/cdn-cgi/challenge-platform/" || echo "brunhild FAILED"
}

METHOD=none
if install_client; then
  start_svc
  if register_connect; then
    if verify_egress socks5h://127.0.0.1:40000; then METHOD=warp-cli-proxy; fi
  fi
fi

if [ "$METHOD" = none ]; then
  log "===== FALLBACK: wgcf + wireguard ====="
  $APT install -y wireguard-tools curl >/dev/null 2>&1 || true
  ARCH=amd64; [ "$(uname -m)" = aarch64 ] && ARCH=arm64
  curl -fsSL -m 120 -o /usr/local/bin/wgcf "https://github.com/ViRb3/wgcf/releases/download/v2.2.27/wgcf_2.2.27_linux_${ARCH}" && chmod +x /usr/local/bin/wgcf || true
  if command -v wgcf >/dev/null; then
    wgcf register --accept-tos || true
    wgcf generate || true
  fi
  if [ -f wgcf-profile.conf ]; then
    modprobe wireguard >/dev/null 2>&1 || true
    if wg-quick up ./wgcf-profile.conf; then
      sleep 3
      echo "--- wg show ---"; wg show || true
      if verify_egress ""; then METHOD=wgcf-tunnel; fi
    fi
  fi
fi

echo "WARP_METHOD=$METHOD" | tee warp_method.env
[ "$METHOD" = none ] && { echo "WARP_SETUP_FAILED"; tail -40 /tmp/warp_apt.log /tmp/warp_deb.log /var/log/warp-svc.log 2>/dev/null; exit 1; }
echo "WARP_SETUP_OK method=$METHOD"