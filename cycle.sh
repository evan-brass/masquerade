set -ex

# Enable IP forwarding
sysctl net.ipv6.conf.all.forwarding=1

# Load the SCTP kernel module, and configure UDP encapsulation on port 4666
modprobe sctp
sysctl net.sctp.udp_port=4666

# create our interfaces
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
ip -6 route add 2001:470:e9e0:100::/96 dev turn-udp
ip -6 route add 2001:470:e9e0:100:2::/79 dev turn-tcp

# Configure all TURN traffic to be ice-dissolve'd
ip -6 rule add iif turn-udp table 1
ip -6 rule add iif turn-tcp table 1
ip -6 route add ::/0 dev ice-dissolve table 1

# Configure our DTLS proxy
# 1. Assign our /48 subnet to lo (the only interface that can have a subnet as an address)
ip -6 address add fd00:0:0::/48 dev lo noprefixroute
# 2. Route decrypted input traffic to lo
ip -6 rule add iif dtls-proxy table 2
ip -6 route add local fd00:0:0:c4b0::/64 dev lo table 2
# 3. Route plaintext output traffic to dtls-proxy
ip -6 rule add oif lo from fd00:0:0:c4b0::/64 table 3
ip -6 route add ::/0 dev dtls-proxy table 3
# 4. Route handshake/ciphertext to dtls-proxy
ip -6 route add fd00:0:0:c4b0::/64 dev dtls-proxy

# Startup our programs
opt/arm64/bin/turnserver-udp -i turn-udp -m "::ffff:0:0/96<->2001:470:e9e0:100::/96,2000::/3<->A000::/3" &
opt/arm64/bin/turnserver-tcp -i turn-tcp -s "2001:470:e9e0:100:2::/79" &
opt/arm64/bin/ice-dissolve -i ice-dissolve &
opt/arm64/bin/dtls-proxy -i dtls-proxy -c cfg/cert.pem &
opt/arm64/bin/sctp-echo &