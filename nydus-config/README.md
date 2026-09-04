# nydus-config

YAML storage configuration for
[Nydus](https://github.com/dragonflyoss/nydus): the typed schema, loading and
validation.

The schema sections mirror the crates that consume them — `BackendConfig` for
`nydus-backend`, `StorageConfig` and `PrefetchConfig` for `nydus-storage` —
so the data plane consumes these structs directly as constructor settings
while the control plane loads and validates the file.

It also owns the package identity — the name and the git commit constants
baked in by its build script — the CLI version flag parser built on them, and
the binary's default directories.

## License

Apache-2.0. This crate is part of the
[Nydus](https://github.com/dragonflyoss/nydus) project.
