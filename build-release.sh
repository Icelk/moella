#!/bin/sh

# You have to have the following in your ~/.cargo/config.toml
# and have installed osxcross!
# [target.x86_64-apple-darwin]
# linker = "x86_64-apple-darwin14-clang"
# ar = "x86_64-apple-darwin14-ar"

cb() {
    echo "Run in $PWD" cargo build --profile distribution $@
    cargo build --profile distribution $@
}
cb_mac() {
    CC=o64-clang cb --target x86_64-apple-darwin $@
}
cb_win() {
    cb --target x86_64-pc-windows-gnu $@
}

cb_unix() {
    cb $@ &
    cb_mac $@ &
}
cb_all() {
    cb_unix $@ &
    cb_win $@ &
}

wd=$PWD

cb_all -F bin --bin moella &

cd ../kvarn/ctl
cb_mac --no-default-features &
cb &

cd ../chute
cb_mac --no-default-features -F date,bin &
cb_win &
cb &

wait

echo "All builds complete (except uring)"

cd $wd
cp ./target/x86_64-pc-windows-gnu/distribution/moella.exe $wd/
cp ./target/x86_64-apple-darwin/distribution/moella moella-macos
# we don't need to strip the win binaries (cargo actually handles that)
x86_64-apple-darwin14-strip $wd/moella-macos
cp ./target/distribution/moella moella-linux

echo "Starting uring build"
cb -F uring,bin
cp ./target/distribution/moella moella-linux-uring

cd ../kvarn/ctl
cp ../target/x86_64-apple-darwin/distribution/kvarnctl $wd/kvarnctl-macos
x86_64-apple-darwin14-strip $wd/kvarnctl-macos
cp ../target/distribution/kvarnctl $wd/kvarnctl-linux

cd ../chute
cp ../target/x86_64-pc-windows-gnu/distribution/chute.exe $wd/
cp ../target/x86_64-apple-darwin/distribution/chute $wd/chute-macos
x86_64-apple-darwin14-strip $wd/chute-macos
cp ../target/distribution/chute $wd/chute-linux
