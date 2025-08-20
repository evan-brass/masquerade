# I rely on the Kernel SCTP module, so your container runner will need to have that module enabled.
# For Podman on MacOS, go to Settings -> Resources -> Podman -> More options (⋮) -> Terminal -> `sudo echo "sctp" > /etc/modprobe.d/sctp.conf` then reboot.

FROM rust

RUN apt update \
	; apt install -y \
		systemd \
		udev \
		nginx \
		clang \
		cmake \
		lksctp-tools \
		tcpdump \
		net-tools \
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
CMD ["systemd", "--log-level=debug"]

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
RUN systemctl enable turn-gateway.service hosted.service

# TURN
EXPOSE 3478/udp
EXPOSE 3478/tcp
