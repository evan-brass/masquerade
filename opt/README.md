# Dependencies
My system is aarch64 so I install cross compiling tools for x86_64.  I use rustup so no rust toochain here.
```
sudo apt install build-essential crossbuild-essential-amd64
sudo apt install clang-dev
```
TODO: Figure out how to do libsrtp2 and cross compile.  Probably some combination of `libsrtp2-dev libsrtp2-dev:amd64`

# Build
```
cargo install --root opt/amd64 --path . --target x86_64-unknown-linux-gnu
cargo install --root opt/arm64 --path . --target aarch64-unknown-linux-gnu
```
