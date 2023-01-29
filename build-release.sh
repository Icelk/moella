#!/bin/sh

# You have to have the following in your ~/.cargo/config.toml
# and have installed osxcross!
# [target.x86_64-apple-darwin]
# linker = "x86_64-apple-darwin14-clang"
# ar = "x86_64-apple-darwin14-ar"

cb() {
    cargo build --profile distribution $@
}
cb_mac() {
    CC=o64-clang cb --target x86_64-apple-darwin $@
}

cb_all() {
    cb $@ &
    cb_mac $@ &
    wait
}

wd=$PWD

cb_all -F bin --bin moella &

cd ../kvarn/ctl
cb_all &

cd ../chute
cb_all &

wait

cd $wd
cp ./target/x86_64-apple-darwin/distribution/moella moella-macos
cp ./target/distribution/moella moella-linux

cd ../kvarn/ctl
cp ../target/x86_64-apple-darwin/distribution/kvarnctl $wd/kvarnctl-macos
cp ../target/distribution/kvarnctl $wd/kvarnctl-linux

cd ../chute
cp ../target/x86_64-apple-darwin/distribution/chute $wd/chute-macos
cp ../target/distribution/chute $wd/chute-linux
