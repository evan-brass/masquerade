# I rely on the Kernel SCTP module, so your container runner will need to have that module enabled.
# For Podman on MacOS, go to Settings -> Resources -> Podman -> More options (⋮) -> Terminal -> `sudo echo "sctp" > /etc/modprobe.d/sctp.conf` then reboot.

FROM rust AS rust-builder
RUN apt update \
	; apt install -y \
		clang \
		cmake
WORKDIR /src
RUN --mount=type=bind,dst=.,src=.,rw \
	cargo install \
		--root /opt/masquerade \
		--path .

FROM debian AS runner
COPY --from=rust-builder /opt/masquerade /opt/masquerade
RUN apt update \
	; apt install -y \
		systemd \
		udev \
		nginx-full \
		lksctp-tools \
		tcpdump \
		net-tools \
		certbot \
		python3-certbot-dns-cloudflare \
		openssh-server \
	; systemctl mask \
		getty.target \
		dev-hugepages.mount \
		dev-mqueue.mount \
		initrd-root-device.target \
		initrd-root-fs.target \
		systemd-random-seed.service \
		integritysetup.target \
		veritysetup.target \
		cryptsetup.target \
		time-set.target \
		systemd-logind.service \
	; systemctl enable \
		systemd-networkd.service \
	;

ENV container yes
CMD ["/lib/systemd/systemd", "--log-level=debug"]

WORKDIR /src/masquerade
COPY Cargo.toml Cargo.lock Rustfmt.toml ./
COPY src ./src
RUN cargo install \
		--root /opt/masquerade \
		--path . \
	; setcap \
		'cap_net_bind_service=+ep' \
		/opt/masquerade/bin/hosted \
	;

ADD cfg/user.conf /usr/lib/sysusers.d/masquerade.conf
ADD cfg/network/* /etc/systemd/network/
ADD cfg/sysctl.conf /etc/sysctl.d/masquerade.conf
ADD cfg/services/* /lib/systemd/system/
ADD cfg/cert.pem /opt/masquerade/
ADD cfg/nginx.conf /etc/nginx/
ADD www/* /usr/share/nginx/html/
RUN systemctl enable turn-gateway.service hosted.service

VOLUME ["/etc/letsencrypt"]

# TURN
EXPOSE 3478/udp
EXPOSE 3478/tcp
EXPOSE 5349/tcp
EXPOSE 53/udp
EXPOSE 80/tcp
EXPOSE 443/tcp
