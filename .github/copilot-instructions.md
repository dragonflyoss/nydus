# GitHub Copilot Instructions for Nydus

## Project Overview

Nydus is a high-performance container image service that implements a content-addressable file system on the RAFS format. It enhances the OCI image specification by enabling on-demand loading, chunk-level deduplication, and improved container startup performance.

### Key Components

- **nydusd**: User-space daemon that processes FUSE/fscache/virtiofs messages and serves Nydus images
- **nydus-image**: CLI tool to convert OCI image layers to Nydus format
- **nydusify**: Tool to convert entire OCI images to Nydus format with registry integration
- **nydusctl**: CLI client for managing and querying nydusd daemon
- **nydus-service**: Library crate for integrating Nydus services into other projects

## Architecture Guidelines

### Crate Structure
```
- api/          # Nydus Image Service APIs and data structures
- builder/      # Image building and conversion logic
- rafs/         # RAFS filesystem implementation
- service/      # Daemon and service management framework
- storage/      # Core storage subsystem with backends and caching
- utils/        # Common utilities and helper functions
- src/bin/      # Binary executables (nydusd, nydus-image, nydusctl)
```

### Key Technologies
- **Language**: Rust with memory safety focus
- **Filesystems**: FUSE, virtiofs, EROFS, fscache
- **Storage Backends**: Registry, OSS, S3, LocalFS, HTTP proxy
- **Compression**: LZ4, Gzip, Zstd
- **Async Runtime**: Tokio (current thread for io-uring compatibility)

## Code Style and Patterns

### Rust Conventions
- Use `#![deny(warnings)]` in all binary crates
- Follow standard Rust naming conventions (snake_case, PascalCase)
- Prefer `anyhow::Result` for error handling in applications
- Use custom error types with `thiserror` for libraries
- Apply `#[macro_use]` for frequently used external crates like `log`
- Always format the code with `cargo fmt`
- Use `clippy` for linting and follow its suggestions

### Error Handling
```rust
// Prefer anyhow for applications
use anyhow::{bail, Context, Result};

// Use custom error types for libraries
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NydusError {
    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
```

### Logging Patterns
- Use structured logging with appropriate levels (trace, debug, info, warn, error)
- Include context in error messages: `.with_context(|| "description")`
- Use `info!`, `warn!`, `error!` macros consistently

### Configuration Management
- Use `serde` for JSON configuration serialization/deserialization
- Support both file-based and environment variable configuration
- Validate configurations at startup with clear error messages
- Follow the `ConfigV2` pattern for versioned configurations

## Development Guidelines

### Storage Backend Development
When implementing new storage backends:
- Implement the `BlobBackend` trait
- Support timeout, retry, and connection management
- Add configuration in the backend config structure
- Consider mirror/proxy support for high availability
- Implement proper error handling and logging

### Daemon Service Development
- Use the `NydusDaemon` trait for service implementations
- Support save/restore for hot upgrade functionality
- Implement proper state machine transitions
- Use `DaemonController` for lifecycle management

### RAFS Filesystem Features
- Support both RAFS v5 and v6 formats
- Implement chunk-level deduplication
- Handle prefetch optimization for container startup
- Support overlay filesystem operations
- Maintain POSIX compatibility

### API Development
- Use versioned APIs (v1, v2) with backward compatibility
- Implement HTTP endpoints with proper error handling
- Support both Unix socket and TCP communication
- Follow OpenAPI specification patterns

## Testing Patterns

### Unit Tests
- Test individual functions and modules in isolation
- Use `#[cfg(test)]` modules within source files
- Mock external dependencies when necessary
- Focus on error conditions and edge cases

### Integration Tests
- Place integration tests in `tests/` directory
- Test complete workflows and component interactions
- Use temporary directories for filesystem operations
- Clean up resources properly in test teardown

### Smoke Tests
- Located in `smoke/` directory using Go
- Test real-world scenarios with actual images
- Verify performance and functionality
- Use Bats framework for shell-based testing

## Performance Considerations

### I/O Optimization
- Use async I/O patterns with Tokio
- Implement prefetching for predictable access patterns
- Optimize chunk size (default 1MB) for workload characteristics
- Consider io-uring for high-performance scenarios

### Memory Management
- Use `Arc<T>` for shared ownership of large objects
- Implement lazy loading for metadata structures
- Consider memory mapping for large files
- Profile memory usage in performance-critical paths

### Caching Strategy
- Implement blob caching with configurable backends
- Support compression in cache to save space
- Use chunk-level caching with efficient eviction policies
- Consider cache warming strategies for frequently accessed data

## Security Guidelines

### Data Integrity
- Implement end-to-end digest validation
- Support multiple hash algorithms (SHA256, Blake3)
- Verify chunk integrity on read operations
- Detect and prevent supply chain attacks

### Authentication
- Support registry authentication (basic auth, bearer tokens)
- Handle credential rotation and refresh
- Implement secure credential storage
- Support mutual TLS for backend connections

## Specific Code Patterns

### Configuration Loading
```rust
// Standard pattern for configuration loading
let config = match config_path {
    Some(path) => ConfigV2::from_file(path)?,
    None => ConfigV2::default(),
};

// Environment variable override
if let Ok(auth) = std::env::var("IMAGE_PULL_AUTH") {
    config.update_registry_auth_info(&auth);
}
```

### Daemon Lifecycle
```rust
// Standard daemon initialization pattern
let daemon = create_daemon(config, build_info)?;
DAEMON_CONTROLLER.set_daemon(daemon);

// Event loop management
if DAEMON_CONTROLLER.is_active() {
    DAEMON_CONTROLLER.run_loop();
}

// Graceful shutdown
DAEMON_CONTROLLER.shutdown();
```

### Blob Access Pattern
```rust
// Standard blob read pattern
let mut bio = BlobIoDesc::new(blob_id, blob_address, blob_size, user_io);
let blob_device = factory.get_device(&blob_info)?;
blob_device.read(&mut bio)?;
```

## Documentation Standards

### Code Documentation
- Document all public APIs with `///` comments
- Include examples in documentation
- Document safety requirements for unsafe code
- Explain complex algorithms and data structures

### Architecture Documentation
- Maintain design documents in `docs/` directory
- Update documentation when adding new features
- Include diagrams for complex interactions
- Document configuration options comprehensively

### Release Notes
- Document breaking changes clearly
- Include migration guides for major versions
- Highlight performance improvements
- List new features and bug fixes

## Container and Cloud Native Patterns

### OCI Compatibility
- Maintain compatibility with OCI image spec
- Support standard container runtimes (runc, Kata)
- Implement proper layer handling and manifest generation
- Support multi-architecture images

### Kubernetes Integration
- Design for Kubernetes CRI integration
- Support containerd snapshotter pattern
- Handle pod lifecycle events appropriately
- Implement proper resource cleanup

### Cloud Storage Integration
- Support major cloud providers (AWS S3, Alibaba OSS)
- Implement proper credential management
- Handle network interruptions gracefully
- Support cross-region replication patterns

## Build and Release

### Build Configuration
- Use `Cargo.toml` workspace configuration
- Support cross-compilation for multiple architectures
- Implement proper feature flags for optional components
- Use consistent dependency versioning

### Release Process
- Tag releases with semantic versioning
- Generate release binaries for supported platforms
- Update documentation with release notes
- Validate release artifacts before publishing

Remember to follow these guidelines when contributing to or working with the Nydus codebase. The project emphasizes performance, security, and compatibility with the broader container ecosystem.