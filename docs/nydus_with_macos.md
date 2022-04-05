# Nydus with macos

## Prepare

Please install macfuse(a.k.a osxfuse). The release can be found with https://osxfuse.github.io/.

## Env
- macfuse@4.2.4 has been tested.
- macos 11(Big Sur)/12(Monterey) has been tested.

## Support bin

For now only `nydusd` works on macos, other bin is open for pr.

## Support features
Only `fusedev` works on macos, by the way passthrough file system not work(passthrough fs has lot syscall is linux specific).

## Build instruction
```shell
cargo build --features=fusedev --release --target-dir target-fusedev --bin=nydusd
```
