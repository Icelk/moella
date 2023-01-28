# Mölla

This is the reference implementation of the Kvarn server library,
offering a **simple config** to get you started using Kvarn.

> See `moella --help` for config options

It's for my personal use on my domains [icelk.dev](https://icelk.dev/) and [kvarn.org](https://kvarn.org/).

An example config [is available](https://github.com/Icelk/moella/blob/main/example-config.ron).
You can also take a look at the [icelk.dev config](https://github.com/Icelk/icelk.dev/blob/main/icelk.dev.ron)

## Installation

[Install Rust](https://rust-lang.org/learn/get-started) and then run the following:

```shell
$ cargo install moella
```

There are also builds available for Linux in [Github Acctions](https://github.com/Icelk/moella/actions),
and possibly for other platforms under `Releases` (yet to be determined).

# Development

During development, this requires [Kvarn](https://github.com/Icelk/kvarn) to be cloned at `../kvarn`, [Kvarn Search](https://github.com/Icelk/kvarn-search) at `../kvarn-search`, and [Kvarn Auth](https://github.com/Icelk/kvarn-auth) at `../kvarn-auth`.
