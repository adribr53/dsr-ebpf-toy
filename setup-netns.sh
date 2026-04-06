#!/usr/bin/env bash
# Three-network-namespace lab for eBPF / DSR-style path play.
#
# Topology (each segment is a /30):
#
#   +----------+     10.200.1.0/30      +----------+     10.200.2.0/30      +----------+
#   |  client  | <--------------------> |    lb    | <--------------------> |  server  |
#   +----------+   lb0 <-> cl0         +----------+   srv0 <-> lb0         +----------+
#        ^                                                      |
#        |              10.200.3.0/30                            |
#        +--------------------------------------------------------+
#                    srv0 <-> cl0
#
# Usage (root):  ./setup-netns.sh up | down | status
# sudo ip netns exec dsr-client ip r add 1.1.1.1/32 via 10.200.1.2
# sudo ip netns exec dsr-lb ip r add 1.1.1.1/32 via 10.200.2.2 # will be managed by lb, iptables in prerouting for dnat in first instance
#
#
set -euo pipefail

NS_C="${NS_PREFIX:-dsr}-client"
NS_L="${NS_PREFIX:-dsr}-lb"
NS_S="${NS_PREFIX:-dsr}-server"

# First usable addresses on each /30: .1 = left side of diagram, .2 = right (see assignments below).
P="${PREFIX:-10.200}"

die() { echo "error: $*" >&2; exit 1; }
need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root (namespaces, veth, sysctl)"; }

run_in() {
  local ns=$1
  shift
  ip netns exec "$ns" "$@"
}

up() {
  need_root

  for n in "$NS_C" "$NS_L" "$NS_S"; do
    if ip netns list | grep -qx "$n"; then
      die "netns $n already exists; run: $0 down"
    fi
  done

  ip netns add "$NS_C"
  ip netns add "$NS_L"
  ip netns add "$NS_S"

  # client <-> lb
  ip link add veth_cl_lb type veth peer name veth_lb_cl
  ip link set veth_cl_lb netns "$NS_C"
  ip link set veth_lb_cl netns "$NS_L"

  # lb <-> server
  ip link add veth_lb_sv type veth peer name veth_sv_lb
  ip link set veth_lb_sv netns "$NS_L"
  ip link set veth_sv_lb netns "$NS_S"

  # server <-> client (closes the ring)
  ip link add veth_sv_cl type veth peer name veth_cl_sv
  ip link set veth_sv_cl netns "$NS_S"
  ip link set veth_cl_sv netns "$NS_C"

  # Rename inside namespaces for stable names in bpftool / tcpdump.
  run_in "$NS_C" ip link set veth_cl_lb name lb0
  run_in "$NS_C" ip link set veth_cl_sv name srv0

  run_in "$NS_L" ip link set veth_lb_cl name cl0
  run_in "$NS_L" ip link set veth_lb_sv name srv0

  run_in "$NS_S" ip link set veth_sv_lb name lb0
  run_in "$NS_S" ip link set veth_sv_cl name cl0

  # client: lb0 .1, srv0 .2  |  lb: cl0 .2, srv0 .1  |  server: lb0 .2, cl0 .1
  run_in "$NS_C" ip addr add "${P}.1.1/30" dev lb0
  run_in "$NS_C" ip addr add "${P}.3.2/30" dev srv0
  run_in "$NS_C" ip link set lb0 up
  run_in "$NS_C" ip link set srv0 up
  run_in "$NS_C" ip link set lo up
  run_in "$NS_C" ip route add 1.1.1.1/32 via ${P}.1.2

  run_in "$NS_L" ip addr add "${P}.1.2/30" dev cl0
  run_in "$NS_L" ip addr add "${P}.2.1/30" dev srv0
  run_in "$NS_L" ip link set cl0 up
  run_in "$NS_L" ip link set srv0 up
  run_in "$NS_L" ip link set lo up
  #run_in "$NS_L" ip route add 1.1.1.1/32 via ${P}.1.1

  run_in "$NS_S" ip addr add "${P}.2.2/30" dev lb0
  run_in "$NS_S" ip addr add "${P}.3.1/30" dev cl0
  run_in "$NS_S" ip link set lb0 up
  run_in "$NS_S" ip link set cl0 up
  run_in "$NS_S" ip link set lo up

  # LB forwards when you hairpin or forward between legs.
  run_in "$NS_L" sysctl -q net.ipv4.ip_forward=1

  # Reachability: subnets not directly connected need a next hop.
  # client -> 10.200.2.0/30 via lb (ingress path through LB)
  run_in "$NS_C" ip route add "${P}.2.0/30" via "${P}.1.2" dev lb0
  # server -> 10.200.1.0/30 via lb
  run_in "$NS_S" ip route add "${P}.1.0/30" via "${P}.2.1" dev lb0
  # lb -> 10.200.3.0/30 via server (third leg of the ring)
  run_in "$NS_L" ip route add "${P}.3.0/30" via "${P}.2.2" dev srv0

  # dsr flow.  
  run_in "$NS_L" iptables -t nat -A PREROUTING -d 1.1.1.1 -j DNAT --to-destination "${P}.2.2"
  run_in "$NS_L" iptables -t nat -A POSTROUTING -d "${P}.2.2" -j MASQUERADE

  echo "up: $NS_C / $NS_L / $NS_S"
  echo "  client  lb0=${P}.1.1  srv0=${P}.3.2"
  echo "  lb      cl0=${P}.1.2  srv0=${P}.2.1  (ip_forward=1)"
  echo "  server  lb0=${P}.2.2  cl0=${P}.3.1"
  echo
  echo "Examples:"
  echo "  ip netns exec $NS_C ping -c1 ${P}.1.2"
  echo "  ip netns exec $NS_C ping -c1 ${P}.2.2"
  echo "  ip netns exec $NS_C ping -c1 ${P}.3.1"  
}

down() {
  need_root
  for n in "$NS_C" "$NS_L" "$NS_S"; do
    ip netns del "$n" 2>/dev/null || true
  done
  echo "down: removed $NS_C $NS_L $NS_S"
}

status() {
  for n in "$NS_C" "$NS_L" "$NS_S"; do
    if ip netns list | grep -qx "$n"; then
      echo "=== $n ==="
      ip netns exec "$n" ip -br addr
      ip netns exec "$n" ip -4 route
      echo
    else
      echo "=== $n (missing) ==="
    fi
  done
}

load_ebpf() {
  need_root
  # Example: load the same XDP program on all interfaces in the LB namespace.
  for iface in cl0; do
    sudo ip netns exec "$NS_L" tc qdisc add dev "$iface" clsact || echo true
    sudo ip netns exec "$NS_L" tc filter add dev "$iface" ingress bpf da obj ebpf/tc_lb.o sec tc
    map_id=$(sudo bpftool map list | grep service_dsr_ipv | cut -d: -f1)
    echo mapId is $map_id
    sudo bpftool map pin id $map_id /sys/fs/bpf/service_dsr_ipv4
  done
  for iface in lb0; do
    sudo bpftool prog load ebpf/tc_egress_backend.o /sys/fs/bpf/tc_egress_backend \
    pinmaps /sys/fs/bpf/
    sudo bpftool prog load ebpf/tc_ingress_backend.o /sys/fs/bpf/tc_ingress_backend \
    map name flow_to_dsr pinned /sys/fs/bpf/flow_to_dsr
    sudo nsenter --net=/var/run/netns/dsr-server \
    tc filter add dev $iface egress bpf da object-pinned /sys/fs/bpf/tc_egress_backend
    sudo nsenter --net=/var/run/netns/dsr-server \
    tc filter add dev $iface ingress bpf da object-pinned /sys/fs/bpf/tc_ingress_backend  
    sudo ./dsr-ebpf-toy &  
  done
}

unload_ebpf() {
  need_root
  # Example: load the same XDP program on all interfaces in the LB namespace.
  for iface in cl0; do
    sudo ip netns exec "$NS_L" tc filter del dev "$iface" ingress
    sudo rm /sys/fs/bpf/service_dsr_ipv4
  done
  for iface in lb0; do
    sudo nsenter --net=/var/run/netns/dsr-server tc filter del dev $iface egress
    sudo nsenter --net=/var/run/netns/dsr-server tc filter del dev $iface ingress
    sudo rm /sys/fs/bpf/tc_egress_backend
    sudo rm /sys/fs/bpf/tc_ingress_backend
    sudo rm /sys/fs/bpf/flow_to_dsr
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  load_ebpf) load_ebpf ;;
  unload_ebpf) unload_ebpf ;;
  *) echo "usage: $0 up | down | status" >&2; exit 1 ;;
esac
