#!/usr/bin/sh

local=~/dev/Rust/Kvarn/*
remote=~/kvarn

rsync -avPh --del $local icelk@server:$remote --exclude "**target**"
