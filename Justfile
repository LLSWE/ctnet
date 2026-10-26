build-bpf:
    cargo build --package ctnet-ebpf --target bpfel-unknown-none -Z build-std=core --release

build-daemon:
    cargo build --package ctnet-daemon --release

run iface="lo": build-bpf
    sudo -E cargo run --package ctnet-daemon -- --iface {{iface}}
