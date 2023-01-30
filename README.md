# Mölla

This is the reference implementation of the Kvarn server library,
offering a [**simple config**](https://kvarn.org/moella/) to get you started using Kvarn.

> See `moella --help` for config options

It's for my personal use on my domains [icelk.dev](https://icelk.dev/) and [kvarn.org](https://kvarn.org/).

An example config [is available](https://github.com/Icelk/moella/blob/main/example-config.ron).
You can also take a look at the [icelk.dev config](https://github.com/Icelk/icelk.dev/blob/main/icelk.dev.ron)

## Installation

There are builds available for Linux in [Github Actions](https://github.com/Icelk/moella/actions),
and for other platforms under [Releases](https://github.com/Icelk/moella/releases).

To run it, download the binary appropriate for your platform.

-   Platform specifics:
    -   If you run Linux: run `chmod +x <downloaded binary>` to make it executable.
    -   If you run macOS: run `chmod +x <downloaded binary>`, then open Finder and find
        the binary. Right click and click `Open`. Accept the warning.
-   Lastly, run the command `./<downloaded binary> --help` in your shell to
    get usage information.

## Build from source

[Install Rust](https://rust-lang.org/learn/get-started) and then run the following:

> This doesn't currently work, as we haven't published to crates.io yet.
> You'll have to set up the [development environment](#development).

```shell
$ cargo install moella
```

# Documentation

- [Kvarn website](https://kvarn.org/moella/)
- [Library docs](https://doc.icelk.dev/moella/moella/)

# Development

During development, Mölla requires
[Kvarn](https://github.com/Icelk/kvarn) to be cloned at `../kvarn`,
[Kvarn Search](https://github.com/Icelk/kvarn-search) at `../kvarn-search`,
and [Kvarn Auth](https://github.com/Icelk/kvarn-auth) at `../kvarn-auth`.
