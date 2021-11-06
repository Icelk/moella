# Kvarn reference binary

This is a reference implementation of the Kvarn server library.
It's for my personal use for my domains [icelk.dev](https://icelk.dev/) and [kvarn.org](https://kvarn.org/)
and will therefore not work with most configurations.

For now, I suggest forking this repo and tweaking it to your liking.

## Installation

If you really want to install it, you can run the following.

```shell
$ cargo install kvarn-reference
```

# Folder structure

To get this example working, it is assumed you have the [Kvarn](https://github.com/Icelk/kvarn) library in `../kvarn`,
the files for `icelk.dev` and `kvarn.org` in `../icelk.dev` and `../kvarn.org`, respectively.

# Future

I plan to add support for a [config file](https://kvarn.org/config.) so you do *not* have to recompile the binary every time you want to support a new domain.
