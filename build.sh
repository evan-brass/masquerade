#!/bin/sh
set -ex

# I don't know shit about pkg-config, so this is prob wrong.  But I intend to switch dtls impl anyway eventually so
export PKG_CONFIG_PATH=
export PKG_CONFIG_SYSROOT_DIR=
PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig cargo install --root opt/arm64 --path . --target aarch64-unknown-linux-gnu
PKG_CONFIG_LIBDIR=/usr/lib/x86_64-linux-gnu/pkgconfig cargo install --root opt/amd64 --path . --target x86_64-unknown-linux-gnu
