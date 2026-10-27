build-bpf-dbg:
    cargo +nightly build --package bpf --target bpfel-unknown-none -Z build-std=core 

build-bpf:
    cargo +nightly build --package bpf --target bpfel-unknown-none -Z build-std=core --release

build-daemon: build-bpf
    cargo build --package daemon --release

run iface="lo": build-bpf-dbg
    sudo -E ~/.cargo/bin/cargo run --package daemon -- --iface {{iface}}
