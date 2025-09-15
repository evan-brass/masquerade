set -ex
podman build -t masquerade .
podman run \
	--rm \
	--privileged \
	--hostname local.evan-brass.net \
	--secret cloudflare-dns-token \
	-v letsencrypt:/etc/letsencrypt \
	-p 3478:3478/udp \
	-p 3478:3478/tcp \
	-p 5349:5349/tcp \
	-p 53:53/udp \
	-p 80:80/tcp \
	-p 443:443/tcp \
	-p 443:443/udp \
	masquerade
