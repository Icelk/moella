#!/usr/bin/sh

local=~/dev/Rust/Kvarn/*
remote=~/kvarn

rsync -avPhL --del $local icelk@server:$remote --exclude "**target**"
