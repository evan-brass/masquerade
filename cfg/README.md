# User masquerade
After copying the user config file file, run `sudo systemd-sysusers` to apply

# Certbot
```
sudo apt install certbot python3-certbot-nginx
sudo certbot -d turn.evan-brass.net
```

# ICE Dissolve and hosted
If you have a dtls proxy with a public route, and you wish to make it accessible directly (without going through the TURN server) then you'll need to allow random ports through your firewall.  I allow UDP on ports 32768-65535 from ipv6 peers.  dtls-proxy is not available over ipv4 anyway (all of my stuff checks for an ipv6 header).
