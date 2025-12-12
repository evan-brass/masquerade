#!/bin/sh
set -ex
cargo install --root opt/amd64 --path . --target x86_64-unknown-linux-gnu
cargo install --root opt/arm64 --path . --target aarch64-unknown-linux-gnu