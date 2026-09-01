# nydus-error

The [Nydus](https://github.com/dragonflyoss/nydus) error contract: the
project-wide `Error`/`Result` and the `Context` extension trait.

Nydus splits errors along two planes:

- The data plane (`storage`, `fs`, and the FUSE/fanotify/NBD/UFFD read
  paths) keeps `std::io::Result`: those errors must carry an OS errno so the
  service edges can answer the kernel with a meaningful POSIX code.
- Everything else (image building, config parsing, CLI, service setup)
  returns `Result` with the project-wide `Error` defined here.

`Error` wraps `io::Error` transparently, so data-plane failures cross into
the control plane with a plain `?`. Use `Context` to attach human-readable
context while keeping the source chain intact.

Following the std guidance that an error exposes its cause either through
`source()` or through `Display` but not both, `Display` prints only the
outermost layer. Print edges (logs, `eprintln!`) must format errors with
`Error::report` to keep the whole cause chain on one line.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
