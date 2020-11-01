./build_macOS.sh
cargo build --release --target x86_64-unknown-linux-gnu
tar -czvf linux.tar.gz ./target/x86_64-unknown-linux-gnu/release/production_server
