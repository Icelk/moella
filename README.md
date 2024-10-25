# [Mölla](https://kvarn.org/moella/)

This is the reference implementation of the Kvarn server library,
offering a [**simple config**](https://kvarn.org/moella/) to get you started using Kvarn.

> See `moella --help` for config options

It's e.g. currently used by my domains [icelk.dev](https://icelk.dev/) and [kvarn.org](https://kvarn.org/).

See [kvarn.org](https://kvarn.org/moella/) for an example config and the schema of the config.
You can also take a look at the [icelk.dev config](https://github.com/Icelk/icelk.dev/blob/main/icelk.dev.ron)
for a production example.

## Usage

First install `moella`.

Next, create a config file, let's say `host.ron`:

```ron
(
    hosts: [
        Plain (
            name: "my-website.com",
            pk: "pk.pem",
            cert: "cert.pem",
            auto_cert: true,
            path: "./",
            extensions: ["arbetrary-name"],
            options: (
                public_data_directory: "build",
                disable_server_cache: true,
                disable_client_cache: false,
            )
        ),
    ],
    extensions: {
        "arbetrary-name": [
            // most of this can be removed; it's just an example
            Csp ({
                "/*": FromDefault ({
                    script_src: [ UnsafeInline, WasmUnsafeEval ],
                    style_src: [
                        Uri("https://fonts.googleapis.com"),
                        Uri("https://fonts.googleapis.com"),
                        UnsafeInline,
                    ],
                    default_src: [ Uri("https://fonts.gstatic.com") ],
                    img_src: [ Uri("*"), Scheme("data:") ]
                }),
                // SVG XSS attacks if viewing file
                "/groups/logo-images/*": FromDefault ({}),

            }),
            ClientCache ({
                "/": MaxAge(3600),
                "/_app/immutable/": Full,
                "/groups/logo-images/": Changing,
                "/groups/data": Changing,
                "/groups/locations": Changing,
            }),
        ]
    },
    import: ["./some-other.config-file.ron"],
    ports: Standard(All),
)
```

Now, run `moella -c host.ron --dev`. Your website should be working. Remove the `--dev` flag when deploying.

> [Link to a systemd service template](https://github.com/Icelk/kvarn/blob/main/sample.service)

See [kvarn.org](https://kvarn.org/moella/) for more details.

## Installation

If you have `cargo` installed, simply run `cargo install moella`.

There are builds available for Linux in [Github Actions](https://github.com/Icelk/moella/actions),
and for other platforms under [Releases](https://github.com/Icelk/moella/releases).

To run it, download the binary appropriate for your platform.

-   Platform specifics:
    -   If you run Linux: run `chmod +x <downloaded binary>` to make it executable.
    -   If you run macOS: run `chmod +x <downloaded binary>`, then open Finder and find
        the binary. Right click and click `Open`. Accept the warning.
    -   On Windows, it should just run
-   Lastly, run the command `./<downloaded binary> --help` in your shell to
    get usage information.

## Build from latest source

[Install Rust](https://rust-lang.org/learn/get-started) and then run the following:

**If you're on macOS or Windows, you need to add `--no-default-features -F bin`.

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
