FROM rust:1.85

WORKDIR /usr/src/masquerade
COPY . .

RUN cargo install --path ./server

EXPOSE 3478/tcp
EXPOSE 3478/udp

ENV RUST_LOG=""

CMD ["masquerade"]
