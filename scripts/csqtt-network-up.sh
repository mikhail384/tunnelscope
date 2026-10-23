#!/usr/bin/env bash
# Only CSQTT's own rules; never flush the host firewall or modify SSH.
set -Eeuo pipefail
action="${1:-up}"
peer="${2:?UDP port is required}"
web="${3:?HTTPS port is required}"
for port in "$peer" "$web"; do
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || exit 2
done
[[ "$action" == up || "$action" == down ]] || exit 2
rule() {
    local table="$1" chain="$2" position="$3"; shift 3
    if [[ "$action" == down ]]; then
        while iptables -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null; do
            iptables -w 5 -t "$table" -D "$chain" "$@"
        done
    elif ! iptables -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null; then
        if [[ "$position" == first ]]; then
            iptables -w 5 -t "$table" -I "$chain" 1 "$@"
        else
            iptables -w 5 -t "$table" -A "$chain" "$@"
        fi
    fi
}
if [[ "$action" == up ]]; then
    modprobe tun 2>/dev/null || true
    if [[ ! -e /dev/net/tun ]]; then
        install -d -m 0755 /dev/net
        mknod /dev/net/tun c 10 200
        chmod 0600 /dev/net/tun
    fi
    sysctl -q -w net.ipv4.ip_forward=1
fi
rule filter INPUT first -p udp --dport "$peer" -m comment --comment CSQTT_COMPAT_INSTALL -j ACCEPT
rule filter INPUT first -p tcp --dport "$web" -m comment --comment CSQTT_COMPAT_INSTALL -j ACCEPT
rule filter FORWARD first -i csqtt1 -s 10.66.67.0/24 -m comment --comment CSQTT_COMPAT_INSTALL -j ACCEPT
rule filter FORWARD first -o csqtt1 -d 10.66.67.0/24 -m comment --comment CSQTT_COMPAT_INSTALL -j ACCEPT
rule nat POSTROUTING last -s 10.66.67.0/24 ! -o csqtt1 -m comment --comment CSQTT_COMPAT_INSTALL -j MASQUERADE
