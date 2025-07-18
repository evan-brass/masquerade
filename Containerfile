# I rely on the Kernel SCTP module, so your container runner will need to have that module enabled.
# For Podman on MacOS, go to Settings -> Resources -> Podman -> More options (⋮) -> Terminal -> `sudo echo "sctp" > /etc/modprobe.d/sctp.conf` then reboot.

FROM rust
RUN apt update && apt install -y \
	systemd \
	udev \
	nginx \
	clang \
	cmake \
	lksctp-tools

CMD ["systemd"]

RUN systemctl mask systemd-remount-fs.service getty.target systemd-logind.service dev-hugepages.mount
RUN systemctl enable systemd-networkd

ADD cfg/masquerade.conf /usr/lib/sysusers.d/
ADD cfg/network/* /etc/systemd/network/
ADD cfg/forwarding.conf /etc/sysctl.d/
ADD cfg/services/* /lib/systemd/system/
ADD cfg/cert.pem /opt/masquerade/

WORKDIR /src/masquerade
COPY . .
RUN cargo install --root /opt/masquerade --path turn-gateway && \
	cargo install --root /opt/masquerade --path dtls-proxy
RUN systemctl enable turn-gateway.service dtls-proxy.service

# TURN
EXPOSE 3478/udp
EXPOSE 3478/tcp
