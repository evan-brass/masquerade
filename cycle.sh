#!/usr/bin/bash
set -ex

# Enable IP forwarding
sysctl net.ipv6.conf.all.forwarding=1

# SCTP containment
ip netns add sctp-sux
ip netns exec sctp-sux ip link set lo up
ip link add name sctp-end type veth peer name veth0
ip link set veth0 netns sctp-sux
ip netns exec sctp-sux ip link set veth0 up
ip link set sctp-end up

# Load the SCTP kernel module, and configure UDP encapsulation on port 9899
modprobe sctp
ip netns exec sctp-sux sysctl net.sctp.udp_port=9899

# Use dstnat inside our sctp namespace
ip netns exec sctp-sux ip -6 address add fd00:0:0::/48 dev veth0 noprefixroute
ip netns exec sctp-sux ip -6 route add local fd00:0:0::/48 dev lo
ip netns exec sctp-sux ip -6 route add default via $(ip -6 addr show dev sctp-end scope link | grep -oP 'fe80::[a-f0-9:]+') dev veth0 onlink
ip netns exec sctp-sux nft add table inet sctp-dstnat
ip netns exec sctp-sux nft add chain inet sctp-dstnat prerouting { type nat hook prerouting priority dstnat \; }
ip netns exec sctp-sux nft add rule inet sctp-dstnat prerouting ip6 daddr fd00:0:0::/48 dnat to fd00:0:0::

# Create our interfaces
ip tuntap add mode tun dev turn-udp
ip tuntap add mode tun dev turn-tcp
ip tuntap add mode tun dev ice-dissolve
ip tuntap add mode tun dev dtls-proxy
# Set the links up so that we can use them in routing rules
ip link set turn-udp up
ip link set turn-tcp up
ip link set ice-dissolve up
ip link set dtls-proxy up

# Configure routes for our TURN interfaces
ip -6 route add A000::/3 dev turn-udp
ip -6 route add 2001:470:e9e0:100:2:0::/96 dev turn-udp
ip -6 route add 2001:470:e9e0:100:4::/79 dev turn-tcp

# Configure all TURN traffic to be ice-dissolve'd
ip -6 rule add iif turn-udp table 1
ip -6 rule add iif turn-tcp table 1
ip -6 route add ::/0 dev ice-dissolve table 1

# Configure our DTLS proxy
# 1. Route handshake/ciphertext to dtls-proxy
ip -6 route add fd00:0:0:c4b0::/64 dev dtls-proxy

# 2. Route decrypted input traffic to sctp-end
ip -6 rule add iif dtls-proxy table 2
ip -6 route add fd00:0:0::/48 via fd00:0:0:: dev sctp-end onlink table 2

# 3. Route plaintext output traffic to dtls-proxy
ip -6 rule add iif sctp-end from fd00:0:0:c4b0::/64 table 3
ip -6 route add ::/0 dev dtls-proxy table 3

# Startup our programs
opt/arm64/bin/turnserver-udp -i turn-udp -m "::ffff:0:0/96<->2001:470:e9e0:100:2:0::/96,2000::/3<->A000::/3" &
opt/arm64/bin/turnserver-tcp -i turn-tcp -s "2001:470:e9e0:100:4::/79" &
opt/arm64/bin/ice-dissolve -i ice-dissolve &
opt/arm64/bin/dtls-proxy -i dtls-proxy -c cfg/cert.pem &
ip netns exec sctp-sux opt/arm64/bin/sctp-echo &