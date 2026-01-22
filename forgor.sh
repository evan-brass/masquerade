# proto insert conntrack
sudo conntrack -I conntrack -p udp -s fd00::c4b0:0:0:0 --sport 32768 -d fd00:: --dport 4666 -r fdff:: --reply-port-src 6742 -q fd00::c4b0:0:0:0 --reply-port-dst 32768 -t 120

# Run dtls proxy
sudo RUST_LOG="trace" opt/arm64/bin/dtls-proxy -c opt/cert.pem -i dtls1 -e [fd00::]:9899 -r [fd00::]:4666