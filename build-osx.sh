#!/bin/sh
# You have to have the following in your ~/.cargo/config.toml
# and have installed osxcross!
# [target.x86_64-apple-darwin]
# linker = "x86_64-apple-darwin14-clang"
# ar = "x86_64-apple-darwin14-ar"

export CC=o64-clang
cargo build --profile distribution --target x86_64-apple-darwin -F bin --bin moella
