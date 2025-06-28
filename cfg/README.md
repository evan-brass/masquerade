* Edit `/etc/sysctl.d/*some_name*.conf` to enable `net.ipv4.ip_forward=1` and `net.ipv6.conf.all.forwarding=1`
* Make a system user `sudo useradd -r -U -M masquerade`
* Install SCTP `sudo apt install lksctp-tools`
* Cross-compile executables and upload them
* Upload systemd config files
* chown and chgrp everything to root
* Copy executables to /usr/sbin and config files to their destinations
* Reboot and check systemctl to make sure that everything is online
