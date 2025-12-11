# Dependencies
My system is aarch64 so I install cross compiling tools for x86_64.  I use rustup so no rust toochain here.
```
sudo apt install build-essential crossbuild-essential-amd64
```

# Build
```
cargo install --root opt/amd64 --path . --target x86_64-unknown-linux-gnu
cargo install --root opt/arm64 --path . --target aarch64-unknown-linux-gnu
```
