# Apollo Sandboxd

A standalone Rust sandbox daemon built around Firecracker microVMs, with a local
Unix-socket API, command-line client, and guest supervisor communicating over vsock.

Sandboxd owns VM lifecycle, execution, file operations, image storage, and durable
sandbox state. Networking uses externally supplied attachments; output can be sent
to caller-provided file descriptors. No other Apollo daemon is required.

## Components

- `apollo-sandboxd`: host daemon.
- `apollo-sandboxctl`: CLI using the public daemon API.
- `apollo-sandbox-guest`: guest bootstrap and supervisor.
- `sandboxd-protocol`: host API types and framing.
- `guest-protocol`: host/guest messages.
- `firecracker-api`: typed Firecracker Unix-HTTP client.

## Build

```sh
cargo build --locked --workspace
cargo test --locked --workspace --all-targets
```

Runtime execution requires native Linux x86_64 or aarch64, KVM, a verified matching Firecracker/jailer
pair, and configured kernel/initramfs assets. Missing isolation prerequisites fail
closed. The example configuration contains placeholder paths and hashes; replace
them with verified operator-owned assets before use. ARM boot and the new per-execution
isolation/export contracts require native qualification before production use.

```sh
apollo-sandboxctl --help
apollo-sandboxctl --config /etc/apollo-sandboxd/config.toml doctor
apollo-sandboxd --config /etc/apollo-sandboxd/config.toml
```

## Documentation

- [Protocol](docs/PROTOCOL.md)
- [systemd setup](docs/SYSTEMD.md)
- [Process identity](docs/RUNTIME_PROCESS_IDENTITY.md)
- [Socket storage](docs/SOCKET_STORAGE.md)
- [Diagnostic limits](docs/DIAGNOSTIC_LIMITS.md)

## License

[MIT](LICENSE). Third-party dependencies retain their respective licenses.
