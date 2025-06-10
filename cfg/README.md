1. Compile polo for the target arch.  Copy the binary to /usr/sbin.
2. Copy relay-isolation to /usr/sbin and make it executable
3. Copy both .service files to /etc/systemd/system
3. `sudo systemctl enable polo.service` and `sudo systemctl enable relay-isolation.service`
4. Edit `/etc/sysctl.d/*some_name*.conf` to enable `net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1`
	- Ideally Only `relay-isolation`, `turn`, and other relay interfaces should be forwarding, but it wasn't working for me so will need to do more research.
5. Reboot the system and check `systemctl status` to see if everything came online.
